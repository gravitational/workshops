package aws

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// IMDSHandler serves the EC2 Instance Metadata Service to the instance
// containers, which forward 169.254.169.254:80 to it. The caller is the
// instance whose container has the request's source IP. Both IMDSv1 and
// IMDSv2 (session token) requests are accepted.
func (s *Server) IMDSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte("ok"))
			return
		}
		inst, ok := s.instanceForIP(r.RemoteAddr)
		if !ok {
			log.Printf("aws: imds: %s %s from %s: not an instance container", r.Method, r.URL.Path, r.RemoteAddr)
			http.Error(w, "not an EC2 instance", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			ttl := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
			if ttl == "" {
				http.Error(w, "missing X-aws-ec2-metadata-token-ttl-seconds", http.StatusBadRequest)
				return
			}
			w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", ttl)
			w.Write([]byte("SimulatorIMDSToken-" + randomID(24)))
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, ok := s.imdsPath(inst, strings.TrimPrefix(r.URL.Path, "/latest"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(body, "{") {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "text/plain")
		}
		w.Write([]byte(body))
	})
}

func (s *Server) instanceForIP(remoteAddr string) (instance, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return instance{}, false
	}
	for _, inst := range s.ec2 {
		if inst.Container != "" && slices.Contains(s.docker.inspect(inst.Container).ips, host) {
			return inst, true
		}
	}
	return instance{}, false
}

func (s *Server) imdsPath(inst instance, p string) (string, bool) {
	tagKeys := make([]string, 0, len(inst.Tags))
	for k := range inst.Tags {
		tagKeys = append(tagKeys, k)
	}
	slices.Sort(tagKeys)
	x := inst.xml()
	meta := map[string]string{
		"instance-id":                 inst.ID,
		"instance-type":               inst.Type,
		"ami-id":                      x.ImageID,
		"hostname":                    x.PrivateDNSName,
		"local-hostname":              x.PrivateDNSName,
		"local-ipv4":                  inst.PrivIP,
		"placement/region":            inst.Region,
		"placement/availability-zone": x.AvailabilityZone,
		"iam/security-credentials":    inst.Role,
		"tags/instance":               strings.Join(tagKeys, "\n"),
	}
	for _, k := range tagKeys {
		meta["tags/instance/"+k] = inst.Tags[k]
	}

	switch p = strings.TrimSuffix(p, "/"); {
	case p == "/meta-data":
		return "ami-id\nhostname\niam/\ninstance-id\ninstance-type\nlocal-hostname\nlocal-ipv4\nplacement/\ntags/", true
	case p == "/meta-data/iam/info":
		b, _ := json.Marshal(map[string]string{
			"Code":               "Success",
			"LastUpdated":        isoTime(s.now()),
			"InstanceProfileArn": fmt.Sprintf("arn:aws:iam::%s:instance-profile/%s", s.cfg.AccountID, inst.Role),
			"InstanceProfileId":  stableID("AIPA", inst.Role),
		})
		return string(b), true
	case p == "/meta-data/iam/security-credentials/"+inst.Role:
		return s.instanceCredentials(inst), true
	case strings.HasPrefix(p, "/meta-data/"):
		v, ok := meta[strings.TrimPrefix(p, "/meta-data/")]
		return v, ok
	case p == "/dynamic/instance-identity/document":
		b, _ := json.MarshalIndent(map[string]any{
			"accountId":        s.cfg.AccountID,
			"architecture":     x.Architecture,
			"availabilityZone": x.AvailabilityZone,
			"imageId":          x.ImageID,
			"instanceId":       inst.ID,
			"instanceType":     inst.Type,
			"pendingTime":      isoTime(inst.Launched),
			"privateIp":        inst.PrivIP,
			"region":           inst.Region,
			"version":          "2017-09-30",
		}, "", "  ")
		return string(b), true
	}
	return "", false
}

// instanceCredentials issues the instance profile role's credentials. The
// role needn't exist in IAM: the instance only uses them to sign the
// sts:GetCallerIdentity request of Teleport's IAM join method.
func (s *Server) instanceCredentials(inst instance) string {
	exp := s.now().Add(6 * time.Hour)
	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", s.cfg.AccountID, inst.Role)
	b, _ := json.Marshal(map[string]string{
		"Code":            "Success",
		"LastUpdated":     isoTime(s.now()),
		"Type":            "AWS-HMAC",
		"AccessKeyId":     "ASIA" + randomID(16),
		"SecretAccessKey": randomID(40),
		"Token":           encodeSession(session{Role: roleARN, Name: inst.ID, Expires: exp}),
		"Expiration":      isoTime(exp),
	})
	return string(b)
}
