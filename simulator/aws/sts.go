package aws

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const stsXMLNS = "https://sts.amazonaws.com/doc/2011-06-15/"

func (s *Server) stsHandler(action string) func(http.ResponseWriter, *request) error {
	h, ok := map[string]func(*request) (any, error){
		"GetCallerIdentity":         s.stsGetCallerIdentity,
		"AssumeRole":                s.stsAssumeRole,
		"AssumeRoleWithWebIdentity": s.stsAssumeRoleWithWebIdentity,
	}[action]
	if !ok {
		return nil
	}
	return func(w http.ResponseWriter, req *request) error {
		result, err := h(req)
		if err != nil {
			return err
		}
		if strings.Contains(req.Header.Get("Accept"), "application/json") {
			// STS answers in JSON when asked. Teleport's IAM join method asks.
			w.Header().Set("Content-Type", "application/json")
			s.writeJSON(w, map[string]any{action + "Response": map[string]any{
				action + "Result":  result,
				"ResponseMetadata": map[string]string{"RequestId": newRequestID()},
			}})
			return nil
		}
		return s.writeQuery(w, action, stsXMLNS, result)
	}
}

func (s *Server) stsGetCallerIdentity(req *request) (any, error) {
	if req.caller.role != "" {
		log.Printf("aws: sts GetCallerIdentity from %s (Host %s)", req.caller.arn, req.Host)
	}
	return struct {
		Arn     string
		UserId  string
		Account string
	}{req.caller.arn, req.caller.userID, req.caller.account}, nil
}

type xmlCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

type xmlAssumedRoleUser struct {
	AssumedRoleId string
	Arn           string
}

// issueCredentials returns temporary credentials for the role.
func (s *Server) issueCredentials(r *role, sessionName, duration string) (xmlCredentials, xmlAssumedRoleUser, error) {
	d := time.Hour
	if duration != "" {
		secs, err := strconv.Atoi(duration)
		if err != nil || secs < 900 {
			return xmlCredentials{}, xmlAssumedRoleUser{}, apiError{http.StatusBadRequest, "ValidationError", "DurationSeconds must be at least 900"}
		}
		if secs > r.MaxSessionDuration {
			return xmlCredentials{}, xmlAssumedRoleUser{}, apiError{http.StatusBadRequest, "ValidationError",
				fmt.Sprintf("The requested DurationSeconds exceeds the MaxSessionDuration set for this role (%d).", r.MaxSessionDuration)}
		}
		d = time.Duration(secs) * time.Second
	}
	if sessionName == "" {
		return xmlCredentials{}, xmlAssumedRoleUser{}, apiError{http.StatusBadRequest, "ValidationError", "RoleSessionName is required"}
	}
	exp := s.now().Add(d)
	creds := xmlCredentials{
		AccessKeyId:     "ASIA" + randomID(16),
		SecretAccessKey: randomID(40),
		SessionToken:    encodeSession(session{Role: r.ARN, Name: sessionName, Expires: exp}),
		Expiration:      isoTime(exp),
	}
	user := xmlAssumedRoleUser{
		AssumedRoleId: r.ID + ":" + sessionName,
		Arn:           fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", s.cfg.AccountID, r.Name, sessionName),
	}
	return creds, user, nil
}

func (s *Server) roleForAssume(roleARN string) (*role, error) {
	s.iam.mu.Lock()
	defer s.iam.mu.Unlock()
	r := s.iam.roleByARN(roleARN)
	if r == nil {
		return nil, apiError{http.StatusForbidden, "AccessDenied", "Not authorized to perform sts:AssumeRole: role " + roleARN + " does not exist"}
	}
	cp := *r
	return &cp, nil
}

func (s *Server) stsAssumeRole(req *request) (any, error) {
	roleARN := formValue(req.form, "RoleArn")
	r, err := s.roleForAssume(roleARN)
	if err != nil {
		return nil, err
	}
	externalID := formValue(req.form, "ExternalId")
	trusted := false
	for _, st := range parsePolicy(r.AssumeRolePolicy) {
		if !strings.EqualFold(st.Effect, "Allow") || !st.matches("sts:AssumeRole") {
			continue
		}
		principals := st.Principal["AWS"]
		accountRoot := fmt.Sprintf("arn:aws:iam::%s:root", req.caller.account)
		if !slices.ContainsFunc(principals, func(p string) bool {
			return p == "*" || p == req.caller.arn || p == req.caller.account || p == accountRoot ||
				(req.caller.role != "" && p == req.caller.role)
		}) {
			continue
		}
		if want := st.Condition["StringEquals"]["sts:ExternalId"]; len(want) > 0 && !slices.Contains(want, externalID) {
			continue
		}
		trusted = true
	}
	if !trusted {
		return nil, apiError{http.StatusForbidden, "AccessDenied",
			fmt.Sprintf("User: %s is not authorized to perform: sts:AssumeRole on resource: %s", req.caller.arn, roleARN)}
	}
	creds, user, err := s.issueCredentials(r, formValue(req.form, "RoleSessionName"), formValue(req.form, "DurationSeconds"))
	if err != nil {
		return nil, err
	}
	return struct {
		Credentials     xmlCredentials
		AssumedRoleUser xmlAssumedRoleUser
	}{creds, user}, nil
}

// stsAssumeRoleWithWebIdentity follows AWS: the token's issuer must have an
// IAM OIDC provider whose client ID list has the token's audience, the
// signature must verify against the issuer's JWKS, and the role's trust
// policy must allow that provider (with any :aud/:sub conditions).
//
// One deliberate difference: AWS OIDC providers can't have a port, and the
// Terraform module strips it ("teleport.localhost"), but Teleport's issuer
// here is https://teleport.localhost:3080. AWS would fetch the JWKS from
// port 443; the simulator matches providers by host and fetches the JWKS
// from the issuer itself.
func (s *Server) stsAssumeRoleWithWebIdentity(req *request) (any, error) {
	token := formValue(req.form, "WebIdentityToken")
	roleARN := formValue(req.form, "RoleArn")
	invalid := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		log.Printf("aws: AssumeRoleWithWebIdentity %s: %s", roleARN, msg)
		return apiError{http.StatusBadRequest, "InvalidIdentityToken", msg}
	}

	header, claims, signed, sig, err := parseJWT(token)
	if err != nil {
		return nil, invalid("The web identity token is malformed: %v", err)
	}
	now := s.now().Unix()
	if claims.Expiry != 0 && now > claims.Expiry {
		return nil, apiError{http.StatusBadRequest, "ExpiredTokenException", "Token is expired"}
	}
	if claims.NotBefore != 0 && now+60 < claims.NotBefore {
		return nil, invalid("Token is not yet valid")
	}
	iss, err := url.Parse(claims.Issuer)
	if err != nil || iss.Scheme != "https" {
		return nil, invalid("The token's issuer %q is not an https URL", claims.Issuer)
	}
	providerURL := iss.Hostname() + strings.TrimRight(iss.Path, "/")

	s.iam.mu.Lock()
	var provider *oidcProvider
	for _, p := range s.iam.state.OIDCProviders {
		if p.URL == providerURL {
			cp := *p
			provider = &cp
		}
	}
	s.iam.mu.Unlock()
	if provider == nil {
		return nil, invalid("No OpenIDConnect provider found in your account for %s", claims.Issuer)
	}
	aud := ""
	for _, a := range claims.Audience {
		if slices.Contains(provider.ClientIDs, a) {
			aud = a
		}
	}
	if aud == "" {
		return nil, invalid("Incorrect token audience %v (the provider's client IDs are %v)", []string(claims.Audience), provider.ClientIDs)
	}
	if err := s.oidc.verify(claims.Issuer, header.Alg, header.Kid, signed, sig); err != nil {
		return nil, apiError{http.StatusBadRequest, "IDPCommunicationError", err.Error()}
	}

	r, err := s.roleForAssume(roleARN)
	if err != nil {
		return nil, err
	}
	if !trustsWebIdentity(r.AssumeRolePolicy, provider, claims, aud) {
		return nil, apiError{http.StatusForbidden, "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity"}
	}
	creds, user, err := s.issueCredentials(r, formValue(req.form, "RoleSessionName"), formValue(req.form, "DurationSeconds"))
	if err != nil {
		return nil, err
	}
	log.Printf("aws: %s assumed %s with a web identity token from %s (sub %s)", claims.Issuer, r.ARN, provider.ARN, claims.Subject)
	return struct {
		SubjectFromWebIdentityToken string
		Audience                    string
		AssumedRoleUser             xmlAssumedRoleUser
		Credentials                 xmlCredentials
		Provider                    string
	}{claims.Subject, aud, user, creds, provider.URL}, nil
}

func trustsWebIdentity(doc string, provider *oidcProvider, claims jwtClaims, aud string) bool {
	values := map[string]string{
		provider.URL + ":aud": aud,
		provider.URL + ":sub": claims.Subject,
	}
	for _, st := range parsePolicy(doc) {
		if !strings.EqualFold(st.Effect, "Allow") || !st.matches("sts:AssumeRoleWithWebIdentity") {
			continue
		}
		if !slices.Contains(st.Principal["Federated"], provider.ARN) {
			continue
		}
		ok := true
		for op, kv := range st.Condition {
			for key, want := range kv {
				have, known := values[key]
				if !known {
					continue // conditions on other keys aren't simulated
				}
				switch op {
				case "StringEquals":
					ok = ok && slices.Contains(want, have)
				case "StringLike":
					ok = ok && slices.ContainsFunc(want, func(p string) bool { return wildcardMatch(p, have) })
				}
			}
		}
		if ok {
			return true
		}
	}
	return false
}
