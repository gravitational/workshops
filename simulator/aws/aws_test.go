package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestWildcardMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"ec2:DescribeInstances", "ec2:DescribeInstances", true},
		{"ec2:describeinstances", "ec2:DescribeInstances", true},
		{"ssm:*", "ssm:SendCommand", true},
		{"*", "account:ListRegions", true},
		{"ssm:Get*", "ssm:SendCommand", false},
		{"ec2:Describe?nstances", "ec2:DescribeInstances", true},
		{"ec2:Describe.*", "ec2:DescribeInstances", false}, // regexp metacharacters are literal
	} {
		if got := wildcardMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

// The trust policy the Terraform module generates.
const moduleTrustPolicy = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/teleport.localhost"},
    "Condition": {"StringEquals": {"teleport.localhost:aud": "discover.teleport"}}
  }]
}`

func TestTrustsWebIdentity(t *testing.T) {
	provider := &oidcProvider{ARN: "arn:aws:iam::123456789012:oidc-provider/teleport.localhost", URL: "teleport.localhost"}
	claims := jwtClaims{Subject: "system:proxy"}
	if !trustsWebIdentity(moduleTrustPolicy, provider, claims, "discover.teleport") {
		t.Error("module trust policy should allow audience discover.teleport")
	}
	if trustsWebIdentity(moduleTrustPolicy, provider, claims, "sts.amazonaws.com") {
		t.Error("module trust policy should reject another audience")
	}
	other := &oidcProvider{ARN: "arn:aws:iam::123456789012:oidc-provider/other.example", URL: "other.example"}
	if trustsWebIdentity(moduleTrustPolicy, other, claims, "discover.teleport") {
		t.Error("module trust policy should reject another provider")
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{URL: "https://aws.localhost:12443", AccountID: "123456789012", StateFile: filepath.Join(t.TempDir(), "iam.json")})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func doCall(t *testing.T, s *Server, service string, form url.Values, token string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20261124/us-east-1/"+service+"/aws4_request, SignedHeaders=host, Signature=x")
	if token != "" {
		r.Header.Set("X-Amz-Security-Token", token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b)
}

func TestRoleAndPolicyAccess(t *testing.T) {
	s := newTestServer(t)
	code, body := doCall(t, s, "iam", url.Values{
		"Action": {"CreateRole"}, "RoleName": {"discovery"}, "AssumeRolePolicyDocument": {moduleTrustPolicy},
		"Tags.member.1.Key": {"origin"}, "Tags.member.1.Value": {"workshop"},
	}, "")
	if code != 200 || !strings.Contains(body, "<CreateRoleResult><Role>") || !strings.Contains(body, "<Key>origin</Key>") {
		t.Fatalf("CreateRole: %d %s", code, body)
	}
	if !strings.Contains(body, url.QueryEscape(moduleTrustPolicy)) {
		t.Errorf("AssumeRolePolicyDocument should be URL-encoded, as in AWS: %s", body)
	}

	// A session for the role, with no policy attached yet: denied.
	token := encodeSession(session{Role: "arn:aws:iam::123456789012:role/discovery", Name: "test", Expires: s.now().Add(3600e9)})
	code, body = doCall(t, s, "ec2", url.Values{"Action": {"DescribeInstances"}}, token)
	if code != 403 || !strings.Contains(body, "UnauthorizedOperation") {
		t.Fatalf("DescribeInstances without policy: %d %s", code, body)
	}

	code, body = doCall(t, s, "iam", url.Values{
		"Action": {"CreatePolicy"}, "PolicyName": {"discovery"},
		"PolicyDocument": {`{"Statement":[{"Effect":"Allow","Action":["ec2:DescribeInstances"],"Resource":"*"}]}`},
	}, "")
	if code != 200 {
		t.Fatalf("CreatePolicy: %d %s", code, body)
	}
	code, body = doCall(t, s, "iam", url.Values{"Action": {"AttachRolePolicy"}, "RoleName": {"discovery"}, "PolicyArn": {"arn:aws:iam::123456789012:policy/discovery"}}, "")
	if code != 200 {
		t.Fatalf("AttachRolePolicy: %d %s", code, body)
	}

	code, body = doCall(t, s, "ec2", url.Values{
		"Action": {"DescribeInstances"}, "Filter.1.Name": {"instance-state-name"}, "Filter.1.Value.1": {"running"},
		"Filter.2.Name": {"tag:Name"}, "Filter.2.Value.1": {"web-2"},
	}, token)
	if code != 200 || !strings.Contains(body, "i-0a1b2c3d4e5f60002") || strings.Contains(body, "i-0a1b2c3d4e5f60001") {
		t.Fatalf("DescribeInstances Name=web-2 should return only web-2: %d %s", code, body)
	}

	// Deleting an attached policy conflicts, as in AWS.
	code, body = doCall(t, s, "iam", url.Values{"Action": {"DeletePolicy"}, "PolicyArn": {"arn:aws:iam::123456789012:policy/discovery"}}, "")
	if code != 409 || !strings.Contains(body, "DeleteConflict") {
		t.Fatalf("DeletePolicy while attached: %d %s", code, body)
	}

	// State survives a restart.
	s2, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := doCall(t, s2, "iam", url.Values{"Action": {"GetRole"}, "RoleName": {"discovery"}}, ""); code != 200 {
		t.Fatalf("GetRole after reload: %d %s", code, body)
	}
}

// Teleport's IAM join method sends a presigned GetCallerIdentity with
// "Accept: application/json" and parses the JSON reply.
func TestGetCallerIdentityJSON(t *testing.T) {
	s := newTestServer(t)
	r := httptest.NewRequest(http.MethodPost, "https://sts.us-east-1.amazonaws.com/", strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/20261124/us-east-1/sts/aws4_request, SignedHeaders=host;x-teleport-challenge, Signature=x")
	r.Header.Set("X-Amz-Security-Token", encodeSession(session{Role: "arn:aws:iam::123456789012:role/workshop-ec2-instance", Name: "i-0a1b2c3d4e5f60001", Expires: s.now().Add(3600e9)}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	want := `"Arn":"arn:aws:sts::123456789012:assumed-role/workshop-ec2-instance/i-0a1b2c3d4e5f60001"`
	if body := w.Body.String(); w.Code != 200 || !strings.Contains(body, `{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{`) || !strings.Contains(body, want) {
		t.Fatalf("GetCallerIdentity JSON: %d %s", w.Code, body)
	}
}
