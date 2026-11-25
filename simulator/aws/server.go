// Package aws is a small simulated AWS account: just the API calls that
// Teleport's EC2 auto-discovery and the Terraform discovery/aws module make.
//
//   - IAM: OIDC providers, roles, managed policies and role attachments
//     (what the Terraform AWS provider creates, reads and deletes).
//   - STS: GetCallerIdentity, AssumeRole and AssumeRoleWithWebIdentity. Web
//     identity tokens are verified against the issuer's JWKS, and the role's
//     trust policy must name an OIDC provider for that issuer and audience,
//     as in AWS.
//   - EC2: DescribeInstances (and DescribeRegions) over two instances. One
//     is a Docker container: the simulator is its SSM agent (SendCommand runs
//     the commands in it with docker exec) and its Instance Metadata Service
//     (IMDSHandler), so Teleport's installer really runs and the instance
//     joins with the IAM join method. The other exists only in API
//     responses, with an SSM agent that has lost its connection.
//   - SSM: DescribeInstanceInformation, SendCommand, GetCommandInvocation and
//     ListCommandInvocations.
//   - Account: ListRegions (used when a matcher has regions ["*"]).
//
// STS is also served on its real regional hostnames: Teleport's Auth Service
// sends the IAM join method's presigned sts:GetCallerIdentity request there.
//
// Every AWS SDK client reaches it through one base endpoint (AWS_ENDPOINT_URL
// or Terraform's `endpoints` block). Requests are told apart by the SigV4
// credential scope's service name, or the Query protocol's Action for unsigned
// STS calls. Signatures are not verified: any access key works and acts as an
// account administrator, except the temporary credentials this simulator
// issues, which only get what the assumed role's attached policies allow.
package aws

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config configures the simulated AWS account.
type Config struct {
	URL       string // AWS_URL, e.g. https://aws.localhost:12443 (endpoint and console)
	AccountID string // AWS_ACCOUNT_ID, 12 digits
	StateFile string // where IAM state is persisted (Terraform expects it to survive restarts)
	// DockerSocket is the Docker Engine API socket, for the instances that
	// are containers. Empty: those instances' SSM agents are offline.
	DockerSocket string
	// HTTPClient fetches OIDC discovery documents and JWKS from token issuers
	// (the Teleport proxy). Defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// Server is the simulated AWS account.
type Server struct {
	cfg    Config
	iam    *iamStore
	ec2    []instance
	ssm    *ssmStore
	docker *dockerClient
	oidc   *jwksCache
	calls  callLog
	now    func() time.Time
}

// New returns a simulated AWS account, loading IAM state from cfg.StateFile.
func New(cfg Config) (*Server, error) {
	if !regexp.MustCompile(`^\d{12}$`).MatchString(cfg.AccountID) {
		return nil, fmt.Errorf("account ID %q must be 12 digits", cfg.AccountID)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	iam, err := loadIAMStore(cfg.StateFile, cfg.AccountID)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:    cfg,
		iam:    iam,
		ec2:    fakeInstances(cfg.AccountID),
		ssm:    newSSMStore(),
		docker: newDockerClient(cfg.DockerSocket),
		oidc:   newJWKSCache(cfg.HTTPClient),
		now:    time.Now,
	}, nil
}

// Handler serves the AWS APIs, plus a read-only console at GET /.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			w.Write([]byte("ok"))
			return
		}
		if r.Method == http.MethodGet && r.Header.Get("Authorization") == "" {
			s.serveConsole(w, r)
			return
		}
		s.serveAPI(w, r)
	})
}

// request is one parsed API call.
type request struct {
	*http.Request
	service   string // SigV4 signing name: iam, sts, ec2, ssm, account
	region    string
	accessKey string
	action    string
	form      map[string][]string // Query protocol parameters
	caller    principal
}

var credentialScope = regexp.MustCompile(`Credential=([^/,\s]+)/\d{8}/([^/]+)/([^/]+)/aws4_request`)

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	req := &request{Request: r}
	if m := credentialScope.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		req.accessKey, req.region, req.service = m[1], m[2], m[3]
	}

	switch {
	case strings.HasPrefix(r.Header.Get("X-Amz-Target"), "AmazonSSM."):
		req.service = "ssm"
		req.action = strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonSSM.")
	case req.service == "account":
		// REST-JSON: POST /listRegions
		req.action = restJSONAction(r.URL.Path)
	default:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			s.queryError(w, req, apiError{http.StatusBadRequest, "MalformedQueryString", err.Error()})
			return
		}
		req.form = r.Form
		req.action = r.Form.Get("Action")
		if req.service == "" {
			// Unsigned calls (AssumeRoleWithWebIdentity) only exist in STS.
			req.service = "sts"
		}
	}
	if req.region == "" {
		req.region = "us-east-1"
	}

	caller, err := s.authenticate(req)
	if err == nil {
		req.caller = caller
		err = s.authorize(req)
	}
	if err != nil {
		log.Printf("aws: %s:%s denied: %v", req.service, req.action, err)
		s.calls.add(s.now(), req, errorCode(err))
		s.writeError(w, req, err)
		return
	}

	var handler func(http.ResponseWriter, *request) error
	switch req.service {
	case "iam":
		handler = s.iamHandler(req.action)
	case "sts":
		handler = s.stsHandler(req.action)
	case "ec2":
		handler = s.ec2Handler(req.action)
	case "ssm":
		handler = s.ssmHandler(req.action)
	case "account":
		handler = s.accountHandler(req.action)
	}
	if handler == nil {
		// Logged loudly: a missing action is the first thing to look for when
		// a new Teleport or Terraform provider version fails against this.
		log.Printf("aws: UNSUPPORTED %s:%s", req.service, req.action)
		s.calls.add(s.now(), req, "unsupported")
		s.writeError(w, req, apiError{http.StatusBadRequest, "InvalidAction",
			fmt.Sprintf("The AWS simulator does not implement %s:%s.", req.service, req.action)})
		return
	}
	if err := handler(w, req); err != nil {
		s.calls.add(s.now(), req, errorCode(err))
		s.writeError(w, req, err)
		return
	}
	s.calls.add(s.now(), req, "ok")
}

// restJSONAction maps a REST-JSON path (/listRegions) to its action name.
func restJSONAction(path string) string {
	p := strings.Trim(path, "/")
	if p == "" {
		return ""
	}
	return strings.ToUpper(p[:1]) + p[1:]
}

// apiError is an AWS error response.
type apiError struct {
	status  int
	code    string
	message string
}

func (e apiError) Error() string { return e.code + ": " + e.message }

func errorCode(err error) string {
	if e, ok := err.(apiError); ok {
		return e.code
	}
	return "InternalFailure"
}

func (s *Server) writeError(w http.ResponseWriter, req *request, err error) {
	e, ok := err.(apiError)
	if !ok {
		log.Printf("aws: %s:%s: %v", req.service, req.action, err)
		e = apiError{http.StatusInternalServerError, "InternalFailure", err.Error()}
	}
	switch req.service {
	case "ssm", "account":
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Header().Set("X-Amzn-ErrorType", e.code)
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(map[string]string{"__type": e.code, "message": e.message})
	case "ec2":
		s.writeXML(w, e.status, ec2ErrorResponse{
			Errors:    []ec2Error{{Code: e.code, Message: e.message}},
			RequestID: newRequestID(),
		})
	default:
		s.queryError(w, req, e)
	}
}

// queryError writes an IAM/STS (awsQuery) error.
func (s *Server) queryError(w http.ResponseWriter, req *request, e apiError) {
	typ := "Sender"
	if e.status >= 500 {
		typ = "Receiver"
	}
	s.writeXML(w, e.status, queryErrorResponse{
		Error:     queryErrorBody{Type: typ, Code: e.code, Message: e.message},
		RequestID: newRequestID(),
	})
}

type queryErrorResponse struct {
	XMLName   xml.Name       `xml:"ErrorResponse"`
	Error     queryErrorBody `xml:"Error"`
	RequestID string         `xml:"RequestId"`
}

type queryErrorBody struct {
	Type    string
	Code    string
	Message string
}

type ec2ErrorResponse struct {
	XMLName   xml.Name   `xml:"Response"`
	Errors    []ec2Error `xml:"Errors>Error"`
	RequestID string     `xml:"RequestID"`
}

type ec2Error struct {
	Code    string
	Message string
}

func (s *Server) writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("X-Amzn-RequestId", newRequestID())
	w.WriteHeader(status)
	w.Write([]byte(xml.Header))
	if err := xml.NewEncoder(w).Encode(v); err != nil {
		log.Printf("aws: encode response: %v", err)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	}
	w.Header().Set("X-Amzn-RequestId", newRequestID())
	json.NewEncoder(w).Encode(v)
}

// readJSON decodes a JSON-protocol request body.
func readJSON(req *request, v any) error {
	if err := json.NewDecoder(http.MaxBytesReader(nil, req.Body, 1<<20)).Decode(v); err != nil {
		return apiError{http.StatusBadRequest, "SerializationException", err.Error()}
	}
	return nil
}

// responseMetadata is the trailer of every awsQuery response.
type responseMetadata struct {
	RequestID string `xml:"RequestId"`
}

func meta() responseMetadata { return responseMetadata{RequestID: newRequestID()} }

func newRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// randomID returns n random characters from [A-Z0-9], as in AWS IDs.
func randomID(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func isoTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// listParam returns the members of a Query protocol list: Name.member.1,
// Name.member.2, ... (IAM/STS) or Name.1, Name.2, ... (EC2).
func listParam(form map[string][]string, prefix string) []string {
	var out []string
	for i := 1; ; i++ {
		v, ok := form[fmt.Sprintf("%s.%d", prefix, i)]
		if !ok || len(v) == 0 {
			return out
		}
		out = append(out, v[0])
	}
}

func formValue(form map[string][]string, key string) string {
	if v := form[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// callLog keeps the most recent API calls for the console.
type callLog struct {
	mu    sync.Mutex
	calls []call
}

type call struct {
	Time    time.Time
	Service string
	Action  string
	Region  string
	Caller  string
	Result  string
}

func (l *callLog) add(t time.Time, req *request, result string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, call{t, req.service, req.action, req.region, req.caller.arn, result})
	if len(l.calls) > 100 {
		l.calls = l.calls[len(l.calls)-100:]
	}
}

func (l *callLog) recent() []call {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]call, len(l.calls))
	for i, c := range l.calls {
		out[len(l.calls)-1-i] = c
	}
	return out
}
