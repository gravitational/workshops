package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// regions are the account's enabled regions (account:ListRegions,
// ec2:DescribeRegions). The instances live in us-east-1.
var regions = []string{"us-east-1", "us-west-2"}

// instance is an EC2 instance and what SSM knows about it.
type instance struct {
	ID       string
	Region   string
	Name     string
	Type     string
	State    string // running, stopped
	Tags     map[string]string
	PrivIP   string
	Platform string // EC2 platformDetails
	Launched time.Time

	// Container is the Docker container that is this instance. The simulator
	// is its SSM agent (it runs commands with docker exec) and its IMDS
	// (instance identity and instance profile credentials). The SSM agent is
	// Online while the container runs. Empty: the instance exists only in
	// API responses, and its SSM agent is ConnectionLost.
	Container string
	// Role is the instance profile's IAM role (IMDS credentials).
	Role string

	SSMPlatformType string // Linux
	SSMPlatformName string
	SSMPlatformVer  string
}

// fakeInstances is the account's instances: one Teleport enrolls through SSM
// and that joins the cluster, and one whose SSM agent has lost its
// connection (a Discover EC2 user task in Teleport).
func fakeInstances(account string) []instance {
	launched := time.Date(2026, 1, 15, 9, 30, 0, 0, time.UTC)
	return []instance{
		{
			ID: "i-0a1b2c3d4e5f60001", Region: "us-east-1", Name: "web-1", Type: "t3.micro", State: "running",
			Tags:   map[string]string{"Name": "web-1", "env": "dev", "team": "web"},
			PrivIP: "10.0.1.11", Platform: "Linux/UNIX", Launched: launched,
			Container: "ec2-web-1", Role: "workshop-ec2-instance",
			SSMPlatformType: "Linux", SSMPlatformName: "Ubuntu", SSMPlatformVer: "24.04",
		},
		{
			ID: "i-0a1b2c3d4e5f60002", Region: "us-east-1", Name: "web-2", Type: "t3.micro", State: "running",
			Tags:   map[string]string{"Name": "web-2", "env": "dev", "team": "web"},
			PrivIP: "10.0.1.12", Platform: "Linux/UNIX", Launched: launched,
			SSMPlatformType: "Linux", SSMPlatformName: "Ubuntu", SSMPlatformVer: "24.04",
		},
	}
}

// ssmPing is the instance's SSM agent status.
func (s *Server) ssmPing(i instance) string {
	if i.Container != "" && s.docker.running(i.Container) {
		return "Online"
	}
	return "ConnectionLost"
}

func (s *Server) instance(region, id string) (instance, bool) {
	for _, i := range s.ec2 {
		if i.Region == region && i.ID == id {
			return i, true
		}
	}
	return instance{}, false
}

const ec2XMLNS = "http://ec2.amazonaws.com/doc/2016-11-15/"

func (s *Server) ec2Handler(action string) func(http.ResponseWriter, *request) error {
	switch action {
	case "DescribeInstances":
		return s.ec2DescribeInstances
	case "DescribeRegions":
		return s.ec2DescribeRegions
	}
	return nil
}

type ec2Filter struct {
	name   string
	values []string
}

func ec2Filters(form map[string][]string) []ec2Filter {
	var out []ec2Filter
	for i := 1; ; i++ {
		name := formValue(form, fmt.Sprintf("Filter.%d.Name", i))
		if name == "" {
			return out
		}
		out = append(out, ec2Filter{name, listParam(form, fmt.Sprintf("Filter.%d.Value", i))})
	}
}

// matches implements the filters Teleport uses; any other filter is an
// error, so an unexpected one isn't silently ignored.
func (f ec2Filter) matches(i instance) (bool, error) {
	match := func(v string) bool {
		return slices.ContainsFunc(f.values, func(p string) bool { return wildcardMatch(p, v) })
	}
	switch {
	case f.name == "instance-state-name":
		return match(i.State), nil
	case f.name == "instance-id":
		return match(i.ID), nil
	case f.name == "tag-key":
		for k := range i.Tags {
			if match(k) {
				return true, nil
			}
		}
		return false, nil
	case strings.HasPrefix(f.name, "tag:"):
		v, ok := i.Tags[strings.TrimPrefix(f.name, "tag:")]
		return ok && match(v), nil
	}
	return false, apiError{http.StatusBadRequest, "InvalidParameterValue", fmt.Sprintf("The filter '%s' is invalid", f.name)}
}

type xmlEC2Tag struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

type xmlInstance struct {
	InstanceID string `xml:"instanceId"`
	ImageID    string `xml:"imageId"`
	State      struct {
		Code int    `xml:"code"`
		Name string `xml:"name"`
	} `xml:"instanceState"`
	PrivateDNSName   string      `xml:"privateDnsName"`
	DNSName          string      `xml:"dnsName"`
	InstanceType     string      `xml:"instanceType"`
	LaunchTime       string      `xml:"launchTime"`
	AvailabilityZone string      `xml:"placement>availabilityZone"`
	SubnetID         string      `xml:"subnetId"`
	VpcID            string      `xml:"vpcId"`
	PrivateIP        string      `xml:"privateIpAddress"`
	Architecture     string      `xml:"architecture"`
	Platform         string      `xml:"platform,omitempty"`
	PlatformDetails  string      `xml:"platformDetails"`
	Tags             []xmlEC2Tag `xml:"tagSet>item"`
}

type xmlReservation struct {
	ReservationID string        `xml:"reservationId"`
	OwnerID       string        `xml:"ownerId"`
	Instances     []xmlInstance `xml:"instancesSet>item"`
}

func (s *Server) ec2DescribeInstances(w http.ResponseWriter, req *request) error {
	filters := ec2Filters(req.form)
	ids := listParam(req.form, "InstanceId")
	var reservations []xmlReservation
	for _, inst := range s.ec2 {
		if inst.Region != req.region {
			continue
		}
		if len(ids) > 0 && !slices.Contains(ids, inst.ID) {
			continue
		}
		ok := true
		for _, f := range filters {
			m, err := f.matches(inst)
			if err != nil {
				return err
			}
			ok = ok && m
		}
		if !ok {
			continue
		}
		reservations = append(reservations, xmlReservation{
			ReservationID: "r-" + strings.TrimPrefix(inst.ID, "i-"),
			OwnerID:       s.cfg.AccountID,
			Instances:     []xmlInstance{inst.xml()},
		})
	}
	s.writeXML(w, http.StatusOK, struct {
		XMLName      xml.Name         `xml:"DescribeInstancesResponse"`
		Xmlns        string           `xml:"xmlns,attr"`
		RequestID    string           `xml:"requestId"`
		Reservations []xmlReservation `xml:"reservationSet>item"`
	}{Xmlns: ec2XMLNS, RequestID: newRequestID(), Reservations: reservations})
	return nil
}

func (i instance) xml() xmlInstance {
	x := xmlInstance{
		InstanceID:       i.ID,
		ImageID:          "ami-0123456789abcdef0",
		PrivateDNSName:   "ip-" + strings.ReplaceAll(i.PrivIP, ".", "-") + "." + i.Region + ".compute.internal",
		InstanceType:     i.Type,
		LaunchTime:       isoTime(i.Launched),
		AvailabilityZone: i.Region + "a",
		SubnetID:         "subnet-0" + strings.TrimPrefix(i.ID, "i-0")[:16],
		VpcID:            "vpc-0123456789abcdef0",
		PrivateIP:        i.PrivIP,
		Architecture:     "x86_64",
		PlatformDetails:  i.Platform,
	}
	x.State.Name = i.State
	x.State.Code = map[string]int{"running": 16, "stopped": 80}[i.State]
	keys := make([]string, 0, len(i.Tags))
	for k := range i.Tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		x.Tags = append(x.Tags, xmlEC2Tag{k, i.Tags[k]})
	}
	return x
}

func (s *Server) ec2DescribeRegions(w http.ResponseWriter, req *request) error {
	type region struct {
		Name     string `xml:"regionName"`
		Endpoint string `xml:"regionEndpoint"`
		Status   string `xml:"optInStatus"`
	}
	var list []region
	for _, r := range regions {
		list = append(list, region{r, "ec2." + r + ".amazonaws.com", "opt-in-not-required"})
	}
	s.writeXML(w, http.StatusOK, struct {
		XMLName   xml.Name `xml:"DescribeRegionsResponse"`
		Xmlns     string   `xml:"xmlns,attr"`
		RequestID string   `xml:"requestId"`
		Regions   []region `xml:"regionInfo>item"`
	}{Xmlns: ec2XMLNS, RequestID: newRequestID(), Regions: list})
	return nil
}

// accountHandler serves the Account API's ListRegions (REST-JSON).
func (s *Server) accountHandler(action string) func(http.ResponseWriter, *request) error {
	if action != "ListRegions" {
		return nil
	}
	return func(w http.ResponseWriter, req *request) error {
		var in struct {
			RegionOptStatusContains []string
		}
		if err := readJSON(req, &in); err != nil {
			return err
		}
		type region struct {
			RegionName      string
			RegionOptStatus string
		}
		var out []region
		for _, r := range regions {
			if len(in.RegionOptStatusContains) == 0 || slices.Contains(in.RegionOptStatusContains, "ENABLED_BY_DEFAULT") {
				out = append(out, region{r, "ENABLED_BY_DEFAULT"})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		s.writeJSON(w, map[string]any{"Regions": out})
		return nil
	}
}
