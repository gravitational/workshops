package aws

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// principal is who made a request.
type principal struct {
	arn     string
	userID  string
	account string
	// role is set for temporary credentials from AssumeRole*: what the
	// caller may do is what the role's policies allow. Empty means an
	// administrator (any long-term access key).
	role string
}

// sessionTokenPrefix marks the session tokens this simulator issues. The
// token carries the session itself, so sessions survive simulator restarts.
const sessionTokenPrefix = "SimulatorSession."

type session struct {
	Role    string    `json:"role"`
	Name    string    `json:"name"`
	Expires time.Time `json:"exp"`
}

func encodeSession(s session) string {
	b, _ := json.Marshal(s)
	return sessionTokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeSession(token string) (session, bool) {
	raw, ok := strings.CutPrefix(token, sessionTokenPrefix)
	if !ok {
		return session{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return session{}, false
	}
	var s session
	if json.Unmarshal(b, &s) != nil || s.Role == "" {
		return session{}, false
	}
	return s, true
}

func (s *Server) adminPrincipal() principal {
	return principal{
		arn:     fmt.Sprintf("arn:aws:iam::%s:user/workshop-admin", s.cfg.AccountID),
		userID:  "AIDA" + strings.Repeat("S", 17),
		account: s.cfg.AccountID,
	}
}

// authenticate works out the caller. Signatures aren't checked.
func (s *Server) authenticate(req *request) (principal, error) {
	if req.service == "sts" && req.action == "AssumeRoleWithWebIdentity" {
		return principal{arn: "web-identity"}, nil // authenticated by its token
	}
	if req.accessKey == "" {
		return principal{}, apiError{http.StatusForbidden, "MissingAuthenticationToken", "Request is missing Authentication Token"}
	}
	token := req.Header.Get("X-Amz-Security-Token")
	if token == "" {
		return s.adminPrincipal(), nil
	}
	sess, ok := decodeSession(token)
	if !ok {
		return principal{}, apiError{http.StatusForbidden, "InvalidClientTokenId", "The security token included in the request is invalid."}
	}
	if s.now().After(sess.Expires) {
		return principal{}, apiError{http.StatusForbidden, "ExpiredToken", "The security token included in the request is expired"}
	}
	roleName := sess.Role[strings.LastIndex(sess.Role, "/")+1:]
	return principal{
		arn:     fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", s.cfg.AccountID, roleName, sess.Name),
		userID:  roleID(roleName) + ":" + sess.Name,
		account: s.cfg.AccountID,
		role:    sess.Role,
	}, nil
}

// authorize checks a temporary-credential caller's role policies allow the
// action. Only actions and Effect are evaluated; Resource and Condition
// are ignored (the module only ever uses "*").
func (s *Server) authorize(req *request) error {
	if req.caller.role == "" {
		return nil
	}
	action := req.service + ":" + req.action
	if action == "sts:GetCallerIdentity" {
		return nil // always allowed in AWS
	}
	docs, err := s.iam.rolePolicyDocuments(req.caller.role)
	if err != nil {
		return s.accessDenied(req, action, "the assumed role no longer exists")
	}
	allowed := false
	for _, doc := range docs {
		for _, st := range parsePolicy(doc) {
			if !st.matches(action) {
				continue
			}
			if strings.EqualFold(st.Effect, "Deny") {
				return s.accessDenied(req, action, "an explicit deny in an identity-based policy")
			}
			allowed = true
		}
	}
	if !allowed {
		return s.accessDenied(req, action, "no identity-based policy allows the "+action+" action")
	}
	return nil
}

func (s *Server) accessDenied(req *request, action, why string) error {
	msg := fmt.Sprintf("User: %s is not authorized to perform: %s because %s", req.caller.arn, action, why)
	code := "AccessDenied"
	switch req.service {
	case "ec2":
		code = "UnauthorizedOperation"
	case "ssm", "account":
		code = "AccessDeniedException"
	}
	return apiError{http.StatusForbidden, code, msg}
}

type statement struct {
	Effect    string
	Action    []string
	Principal map[string][]string
	Condition map[string]map[string][]string
}

// parsePolicy returns a policy document's statements; Action, principals and
// condition values may each be a string or a list.
func parsePolicy(doc string) []statement {
	var raw struct {
		Statement json.RawMessage
	}
	if json.Unmarshal([]byte(doc), &raw) != nil {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw.Statement, &list) != nil {
		list = []json.RawMessage{raw.Statement}
	}
	var out []statement
	for _, item := range list {
		var st struct {
			Effect    string
			Action    stringList
			Principal map[string]stringList
			Condition map[string]map[string]stringList
		}
		if json.Unmarshal(item, &st) != nil {
			continue
		}
		s := statement{Effect: st.Effect, Action: st.Action, Principal: map[string][]string{}, Condition: map[string]map[string][]string{}}
		for k, v := range st.Principal {
			s.Principal[k] = v
		}
		for op, kv := range st.Condition {
			s.Condition[op] = map[string][]string{}
			for k, v := range kv {
				s.Condition[op][k] = v
			}
		}
		out = append(out, s)
	}
	return out
}

func (st statement) matches(action string) bool {
	for _, pattern := range st.Action {
		if wildcardMatch(pattern, action) {
			return true
		}
	}
	return false
}

// wildcardMatch matches IAM action patterns: case-insensitive, * and ?.
func wildcardMatch(pattern, s string) bool {
	re := "(?i)^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(pattern)) + "$"
	ok, _ := regexp.MatchString(re, s)
	return ok
}

// stringList is a JSON string or list of strings.
type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*l = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}
