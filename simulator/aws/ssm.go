package aws

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// commandTimeout bounds one command run, like SSM's executionTimeout.
const commandTimeout = 20 * time.Minute

// ssmStore keeps the commands sent to the instances and their results (in
// memory).
type ssmStore struct {
	mu       sync.Mutex
	commands []*ssmCommand
}

func newSSMStore() *ssmStore { return &ssmStore{} }

type ssmCommand struct {
	ID          string
	Region      string
	Document    string
	Parameters  map[string][]string
	Instances   []string
	Requested   time.Time
	Caller      string
	invocations map[string]*invocation // by instance ID; guarded by ssmStore.mu
}

// invocation is one instance's run of a command.
type invocation struct {
	Status         string // InProgress, Success, Failed
	Started, Ended time.Time
	ExitCode       int
	Stdout, Stderr string
}

func (st *ssmStore) add(c *ssmCommand) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.commands = append(st.commands, c)
	if len(st.commands) > 200 {
		st.commands = st.commands[len(st.commands)-200:]
	}
}

// get returns a copy of the command and its invocations.
func (st *ssmStore) get(id string) (ssmCommand, map[string]invocation, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, c := range st.commands {
		if c.ID == id {
			return st.copyLocked(c)
		}
	}
	return ssmCommand{}, nil, false
}

func (st *ssmStore) copyLocked(c *ssmCommand) (ssmCommand, map[string]invocation, bool) {
	invs := map[string]invocation{}
	for id, inv := range c.invocations {
		invs[id] = *inv
	}
	cp := *c
	cp.invocations = nil
	return cp, invs, true
}

func (st *ssmStore) update(c *ssmCommand, instanceID string, fn func(*invocation)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(c.invocations[instanceID])
}

type commandView struct {
	ssmCommand
	Invocations map[string]invocation
}

func (st *ssmStore) recent() []commandView {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]commandView, 0, len(st.commands))
	for i := len(st.commands) - 1; i >= 0; i-- {
		c, invs, _ := st.copyLocked(st.commands[i])
		out = append(out, commandView{c, invs})
	}
	return out
}

// documents are the SSM documents that exist, with their parameters.
var documents = map[string][]string{
	"AWS-RunShellScript": {"commands", "workingDirectory", "executionTimeout"},
}

func (s *Server) ssmHandler(action string) func(http.ResponseWriter, *request) error {
	switch action {
	case "DescribeInstanceInformation":
		return s.ssmDescribeInstanceInformation
	case "SendCommand":
		return s.ssmSendCommand
	case "GetCommandInvocation":
		return s.ssmGetCommandInvocation
	case "ListCommandInvocations":
		return s.ssmListCommandInvocations
	}
	return nil
}

func epoch(t time.Time) float64 { return float64(t.UnixMilli()) / 1000 }

func (s *Server) ssmDescribeInstanceInformation(w http.ResponseWriter, req *request) error {
	var in struct {
		Filters []struct {
			Key    string
			Values []string
		}
		InstanceInformationFilterList []struct {
			Key      string   `json:"key"`
			ValueSet []string `json:"valueSet"`
		}
	}
	if err := readJSON(req, &in); err != nil {
		return err
	}
	var ids []string
	for _, f := range in.Filters {
		if f.Key != "InstanceIds" {
			return apiError{http.StatusBadRequest, "InvalidFilterKey", "The simulator only supports the InstanceIds filter, not " + f.Key}
		}
		ids = append(ids, f.Values...)
	}
	for _, f := range in.InstanceInformationFilterList {
		if f.Key != "InstanceIds" {
			return apiError{http.StatusBadRequest, "InvalidFilterKey", "The simulator only supports the InstanceIds filter, not " + f.Key}
		}
		ids = append(ids, f.ValueSet...)
	}

	list := []map[string]any{}
	for _, inst := range s.ec2 {
		if inst.Region != req.region || (len(ids) > 0 && !slices.Contains(ids, inst.ID)) {
			continue
		}
		ping := s.ssmPing(inst)
		lastPing := s.now().Add(-30 * time.Second)
		if ping != "Online" {
			lastPing = inst.Launched.Add(24 * time.Hour)
		}
		list = append(list, map[string]any{
			"InstanceId":        inst.ID,
			"PingStatus":        ping,
			"LastPingDateTime":  epoch(lastPing),
			"AgentVersion":      "3.3.1611.0",
			"IsLatestVersion":   true,
			"PlatformType":      inst.SSMPlatformType,
			"PlatformName":      inst.SSMPlatformName,
			"PlatformVersion":   inst.SSMPlatformVer,
			"ResourceType":      "EC2Instance",
			"IPAddress":         inst.PrivIP,
			"ComputerName":      strings.TrimSuffix(inst.xml().PrivateDNSName, ".compute.internal"),
			"AssociationStatus": "Success",
		})
	}
	s.writeJSON(w, map[string]any{"InstanceInformationList": list})
	return nil
}

func (s *Server) ssmSendCommand(w http.ResponseWriter, req *request) error {
	var in struct {
		DocumentName string
		InstanceIds  []string
		Parameters   map[string][]string
		Comment      string
	}
	if err := readJSON(req, &in); err != nil {
		return err
	}
	allowed, ok := documents[in.DocumentName]
	if !ok {
		return apiError{http.StatusBadRequest, "InvalidDocument", fmt.Sprintf("Document %s does not exist in %s", in.DocumentName, req.region)}
	}
	for name := range in.Parameters {
		if !slices.Contains(allowed, name) {
			// Teleport recognizes this error and retries without optional parameters.
			return apiError{http.StatusBadRequest, "InvalidParameters", fmt.Sprintf("Parameter %q is not defined in document %s", name, in.DocumentName)}
		}
	}
	if len(in.Parameters["commands"]) == 0 {
		return apiError{http.StatusBadRequest, "InvalidParameters", "Parameter \"commands\" is required"}
	}
	if len(in.InstanceIds) == 0 || len(in.InstanceIds) > 50 {
		return apiError{http.StatusBadRequest, "ValidationException", "InstanceIds must have 1 to 50 elements"}
	}
	var targets []instance
	for _, id := range in.InstanceIds {
		inst, ok := s.instance(req.region, id)
		if !ok || inst.State != "running" || s.ssmPing(inst) != "Online" {
			return apiError{http.StatusBadRequest, "InvalidInstanceId", "Instances not in a valid state for account " + s.cfg.AccountID}
		}
		targets = append(targets, inst)
	}
	c := &ssmCommand{
		ID:          newRequestID(),
		Region:      req.region,
		Document:    in.DocumentName,
		Parameters:  in.Parameters,
		Instances:   in.InstanceIds,
		Requested:   s.now(),
		Caller:      req.caller.arn,
		invocations: map[string]*invocation{},
	}
	for _, inst := range targets {
		c.invocations[inst.ID] = &invocation{Status: "InProgress", Started: c.Requested}
	}
	s.ssm.add(c)
	log.Printf("aws: ssm SendCommand %s (%s) to %s in %s", c.ID, c.Document, strings.Join(c.Instances, ", "), c.Region)
	for _, inst := range targets {
		go s.runCommand(c, inst)
	}

	s.writeJSON(w, map[string]any{"Command": map[string]any{
		"CommandId":             c.ID,
		"DocumentName":          c.Document,
		"DocumentVersion":       "1",
		"Comment":               in.Comment,
		"ExpiresAfter":          epoch(c.Requested.Add(time.Hour)),
		"Parameters":            c.Parameters,
		"InstanceIds":           c.Instances,
		"Targets":               []any{},
		"RequestedDateTime":     epoch(c.Requested),
		"Status":                "Pending",
		"StatusDetails":         "Pending",
		"TargetCount":           len(c.Instances),
		"CompletedCount":        0,
		"ErrorCount":            0,
		"DeliveryTimedOutCount": 0,
		"MaxConcurrency":        "50",
		"MaxErrors":             "0",
		"TimeoutSeconds":        3600,
	}})
	return nil
}

// runCommand is the instance's SSM agent running AWS-RunShellScript: the
// commands, one per line, as a root shell script.
func (s *Server) runCommand(c *ssmCommand, inst instance) {
	script := strings.Join(c.Parameters["commands"], "\n")
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	res, err := s.docker.exec(ctx, inst.Container, []string{"/bin/sh", "-c", script})
	if err != nil {
		res = execResult{exitCode: 1, stderr: "failed to run the command: " + err.Error()}
	}
	status := "Success"
	if res.exitCode != 0 {
		status = "Failed"
	}
	log.Printf("aws: ssm command %s on %s (%s): %s, exit code %d", c.ID, inst.ID, inst.Container, status, res.exitCode)
	s.ssm.update(c, inst.ID, func(inv *invocation) {
		inv.Status, inv.ExitCode, inv.Stdout, inv.Stderr, inv.Ended = status, res.exitCode, res.stdout, res.stderr, s.now()
	})
}

// pluginName is AWS-RunShellScript's only step.
const pluginName = "aws:runShellScript"

func (s *Server) ssmGetCommandInvocation(w http.ResponseWriter, req *request) error {
	var in struct {
		CommandId  string
		InstanceId string
		PluginName string
	}
	if err := readJSON(req, &in); err != nil {
		return err
	}
	c, invs, ok := s.ssm.get(in.CommandId)
	if !ok || c.Region != req.region {
		return apiError{http.StatusBadRequest, "InvocationDoesNotExist", ""}
	}
	if in.PluginName != "" && in.PluginName != pluginName {
		return apiError{http.StatusBadRequest, "InvalidPluginName", "Plugin " + in.PluginName + " is not part of the document"}
	}
	inv, ok := invs[in.InstanceId]
	if !ok {
		return apiError{http.StatusBadRequest, "InvocationDoesNotExist", ""}
	}
	out := map[string]any{
		"CommandId":              c.ID,
		"InstanceId":             in.InstanceId,
		"DocumentName":           c.Document,
		"DocumentVersion":        "1",
		"PluginName":             pluginName,
		"ResponseCode":           -1,
		"ExecutionStartDateTime": isoTime(inv.Started),
		"Status":                 inv.Status,
		"StatusDetails":          inv.Status,
		"StandardOutputContent":  "",
		"StandardErrorContent":   "",
		"StandardOutputUrl":      "",
		"StandardErrorUrl":       "",
	}
	if inv.Status != "InProgress" {
		out["ResponseCode"] = inv.ExitCode
		out["ExecutionEndDateTime"] = isoTime(inv.Ended)
		out["ExecutionElapsedTime"] = fmt.Sprintf("PT%dS", int(inv.Ended.Sub(inv.Started).Seconds()))
		// SSM returns at most the first 24,000 characters.
		out["StandardOutputContent"] = truncate(inv.Stdout, 24000)
		out["StandardErrorContent"] = truncate(inv.Stderr, 8000)
	}
	s.writeJSON(w, out)
	return nil
}

func (s *Server) ssmListCommandInvocations(w http.ResponseWriter, req *request) error {
	var in struct {
		CommandId  string
		InstanceId string
		Details    bool
	}
	if err := readJSON(req, &in); err != nil {
		return err
	}
	list := []map[string]any{}
	for _, c := range s.ssm.recent() {
		if c.Region != req.region || (in.CommandId != "" && c.ID != in.CommandId) {
			continue
		}
		ids := slices.Clone(c.Instances)
		sort.Strings(ids)
		for _, id := range ids {
			if in.InstanceId != "" && id != in.InstanceId {
				continue
			}
			inv := c.Invocations[id]
			inst, _ := s.instance(c.Region, id)
			entry := map[string]any{
				"CommandId":         c.ID,
				"InstanceId":        id,
				"InstanceName":      inst.Name,
				"DocumentName":      c.Document,
				"DocumentVersion":   "1",
				"RequestedDateTime": epoch(c.Requested),
				"Status":            inv.Status,
				"StatusDetails":     inv.Status,
			}
			if in.Details {
				plugin := map[string]any{
					"Name":                  pluginName,
					"Status":                inv.Status,
					"StatusDetails":         inv.Status,
					"ResponseStartDateTime": epoch(inv.Started),
				}
				if inv.Status != "InProgress" {
					plugin["ResponseCode"] = inv.ExitCode
					plugin["ResponseFinishDateTime"] = epoch(inv.Ended)
					plugin["Output"] = truncate(inv.Stdout, 2500)
				}
				entry["CommandPlugins"] = []any{plugin}
			}
			list = append(list, entry)
		}
	}
	s.writeJSON(w, map[string]any{"CommandInvocations": list})
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
