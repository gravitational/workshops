// Package workflow parses and validates GitHub Actions workflow files for a
// simulated GitHub Enterprise Server. Only the subset of syntax the simulator
// can execute is accepted; anything else is rejected with an error containing
// "not supported by the simulator".
package workflow

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow is a parsed workflow file.
type Workflow struct {
	Name        string         // `name:`, defaults to the file path like GitHub
	On          map[string]any // triggers; string/list/map forms all normalized to map keys
	Permissions Permissions
	Env         map[string]string
	Jobs        []Job // file order
}

// Permissions records the parts of a `permissions:` block the simulator cares about.
type Permissions struct {
	IDTokenWrite bool
	Set          bool // false means the `permissions` key was absent
}

// Job is a single entry under `jobs:`.
type Job struct {
	ID, Name    string
	Permissions Permissions
	Env         map[string]string
	Steps       []Step
}

// Step is a single entry in a job's `steps:` list.
type Step struct {
	ID, Name string
	Env      map[string]string
	Run      string // exactly one of Run/Uses is set
	Uses     string
	With     map[string]string // scalar values stringified
}

// Supported keys at each level. `run-name`, `runs-on` and `needs` are
// accepted but ignored.
var (
	workflowKeys = keySet("name", "on", "permissions", "env", "jobs", "run-name")
	jobKeys      = keySet("name", "runs-on", "needs", "permissions", "env", "steps")
	stepKeys     = keySet("id", "name", "env", "run", "uses", "with")
)

func keySet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// Parse parses workflow YAML. path is the repo-relative workflow path (for
// example ".github/workflows/deploy.yaml") and is used as the default name.
func Parse(path string, data []byte) (*Workflow, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("%s: empty workflow file", path)
	}
	w, err := parseWorkflow(doc.Content[0])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if w.Name == "" {
		w.Name = path
	}
	return w, nil
}

func parseWorkflow(n *yaml.Node) (*Workflow, error) {
	w := &Workflow{}
	sawJobs := false
	err := eachKey(n, "workflow", workflowKeys, func(key string, v *yaml.Node) error {
		var err error
		switch key {
		case "name":
			w.Name, err = scalar(v, key)
		case "on":
			w.On, err = parseOn(v)
		case "permissions":
			w.Permissions, err = parsePermissions(v, key)
		case "env":
			w.Env, err = stringMap(v, key)
		case "jobs":
			sawJobs = true
			w.Jobs, err = parseJobs(v)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if !sawJobs || len(w.Jobs) == 0 {
		return nil, errors.New("workflow has no jobs")
	}
	return w, nil
}

func parseOn(n *yaml.Node) (map[string]any, error) {
	on := map[string]any{}
	switch n.Kind {
	case yaml.ScalarNode:
		on[n.Value] = nil
	case yaml.SequenceNode:
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: on: list entries must be event names", item.Line)
			}
			on[item.Value] = nil
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			var v any
			if err := n.Content[i+1].Decode(&v); err != nil {
				return nil, fmt.Errorf("on.%s: %w", n.Content[i].Value, err)
			}
			on[n.Content[i].Value] = v
		}
	default:
		return nil, fmt.Errorf("line %d: on: must be a string, list or mapping", n.Line)
	}
	return on, nil
}

func parsePermissions(n *yaml.Node, ctx string) (Permissions, error) {
	p := Permissions{Set: true}
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Value {
		case "write-all":
			p.IDTokenWrite = true
		case "read-all":
		default:
			return p, fmt.Errorf("line %d: %s: invalid value %q", n.Line, ctx, n.Value)
		}
	case yaml.MappingNode:
		perms, err := stringMap(n, ctx)
		if err != nil {
			return p, err
		}
		p.IDTokenWrite = perms["id-token"] == "write"
	default:
		return p, fmt.Errorf("line %d: %s: must be a string or mapping", n.Line, ctx)
	}
	return p, nil
}

func parseJobs(n *yaml.Node) ([]Job, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: jobs: must be a mapping", n.Line)
	}
	var jobs []Job
	for i := 0; i < len(n.Content); i += 2 {
		job, err := parseJob(n.Content[i].Value, n.Content[i+1])
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func parseJob(id string, n *yaml.Node) (Job, error) {
	job := Job{ID: id}
	ctx := "jobs." + id
	err := eachKey(n, ctx, jobKeys, func(key string, v *yaml.Node) error {
		var err error
		switch key {
		case "name":
			job.Name, err = scalar(v, ctx+".name")
		case "permissions":
			job.Permissions, err = parsePermissions(v, ctx+".permissions")
		case "env":
			job.Env, err = stringMap(v, ctx+".env")
		case "steps":
			job.Steps, err = parseSteps(v, ctx+".steps")
		}
		return err
	})
	if err != nil {
		return job, err
	}
	if len(job.Steps) == 0 {
		return job, fmt.Errorf("%s: job has no steps", ctx)
	}
	return job, nil
}

func parseSteps(n *yaml.Node, ctx string) ([]Step, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("line %d: %s: must be a list", n.Line, ctx)
	}
	steps := make([]Step, 0, len(n.Content))
	for i, item := range n.Content {
		step, err := parseStep(item, fmt.Sprintf("%s[%d]", ctx, i))
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func parseStep(n *yaml.Node, ctx string) (Step, error) {
	var s Step
	err := eachKey(n, ctx, stepKeys, func(key string, v *yaml.Node) error {
		var err error
		switch key {
		case "id":
			s.ID, err = scalar(v, ctx+".id")
		case "name":
			s.Name, err = scalar(v, ctx+".name")
		case "env":
			s.Env, err = stringMap(v, ctx+".env")
		case "run":
			s.Run, err = scalar(v, ctx+".run")
		case "uses":
			s.Uses, err = scalar(v, ctx+".uses")
		case "with":
			s.With, err = stringMap(v, ctx+".with")
		}
		return err
	})
	if err != nil {
		return s, err
	}
	if (s.Run == "") == (s.Uses == "") {
		return s, fmt.Errorf("line %d: %s: step must have exactly one of run or uses", n.Line, ctx)
	}
	return s, nil
}

// eachKey walks a mapping node, rejecting keys not in allowed.
func eachKey(n *yaml.Node, ctx string, allowed map[string]bool, fn func(key string, v *yaml.Node) error) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: %s: must be a mapping", n.Line, ctx)
	}
	for i := 0; i < len(n.Content); i += 2 {
		k := n.Content[i]
		if !allowed[k.Value] {
			return fmt.Errorf("line %d: %s: not supported by the simulator: %s", k.Line, ctx, k.Value)
		}
		if err := fn(k.Value, n.Content[i+1]); err != nil {
			return err
		}
	}
	return nil
}

func scalar(n *yaml.Node, ctx string) (string, error) {
	if n.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("line %d: %s: must be a string", n.Line, ctx)
	}
	return n.Value, nil
}

// stringMap decodes a mapping of scalars, stringifying the values. A null
// value (an empty mapping written as `key:`) yields an empty map.
func stringMap(n *yaml.Node, ctx string) (map[string]string, error) {
	m := map[string]string{}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return m, nil
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: %s: must be a mapping", n.Line, ctx)
	}
	for i := 0; i < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("line %d: %s.%s: must be a string", v.Line, ctx, k.Value)
		}
		m[k.Value] = v.Value
	}
	return m, nil
}

// Dispatchable reports whether the workflow has a workflow_dispatch trigger.
func (w *Workflow) Dispatchable() bool {
	_, ok := w.On["workflow_dispatch"]
	return ok
}

// DisplayName returns the step's name, falling back to GitHub's convention of
// "Run <first line of run>" or "Run <uses>".
func (s Step) DisplayName() string {
	if s.Name != "" {
		return s.Name
	}
	if s.Uses != "" {
		return "Run " + s.Uses
	}
	first, _, _ := strings.Cut(strings.TrimSpace(s.Run), "\n")
	return "Run " + first
}
