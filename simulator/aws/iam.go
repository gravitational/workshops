package aws

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IAM state, persisted to a JSON file after every change.

type tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type oidcProvider struct {
	ARN         string    `json:"arn"`
	URL         string    `json:"url"` // without https://, as AWS returns it
	ClientIDs   []string  `json:"client_ids"`
	Thumbprints []string  `json:"thumbprints"`
	Tags        []tag     `json:"tags"`
	Created     time.Time `json:"created"`
}

type role struct {
	Name               string    `json:"name"`
	Path               string    `json:"path"`
	ARN                string    `json:"arn"`
	ID                 string    `json:"id"`
	Description        string    `json:"description"`
	AssumeRolePolicy   string    `json:"assume_role_policy"`
	MaxSessionDuration int       `json:"max_session_duration"`
	Tags               []tag     `json:"tags"`
	Created            time.Time `json:"created"`
	AttachedPolicies   []string  `json:"attached_policies"` // ARNs
}

type policyVersion struct {
	ID       string    `json:"id"`
	Document string    `json:"document"`
	Created  time.Time `json:"created"`
}

type policy struct {
	Name           string          `json:"name"`
	Path           string          `json:"path"`
	ARN            string          `json:"arn"`
	ID             string          `json:"id"`
	Description    string          `json:"description"`
	Tags           []tag           `json:"tags"`
	Created        time.Time       `json:"created"`
	Updated        time.Time       `json:"updated"`
	DefaultVersion string          `json:"default_version"`
	Versions       []policyVersion `json:"versions"`
}

type iamState struct {
	OIDCProviders map[string]*oidcProvider `json:"oidc_providers"` // by ARN
	Roles         map[string]*role         `json:"roles"`          // by name
	Policies      map[string]*policy       `json:"policies"`       // by ARN
}

type iamStore struct {
	mu      sync.Mutex
	file    string
	account string
	state   iamState
}

func loadIAMStore(file, account string) (*iamStore, error) {
	st := &iamStore{file: file, account: account, state: iamState{
		OIDCProviders: map[string]*oidcProvider{},
		Roles:         map[string]*role{},
		Policies:      map[string]*policy{},
	}}
	if file == "" {
		return st, nil
	}
	b, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &st.state); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return st, nil
}

// save persists the state; callers hold mu.
func (st *iamStore) save() error {
	if st.file == "" {
		return nil
	}
	b, err := json.MarshalIndent(st.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(st.file), 0o755); err != nil {
		return err
	}
	tmp := st.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, st.file)
}

// rolePolicyDocuments returns the default version of every policy attached
// to the role with this ARN.
func (st *iamStore) rolePolicyDocuments(roleARN string) ([]string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	r := st.roleByARN(roleARN)
	if r == nil {
		return nil, errNoSuchEntity("role", roleARN)
	}
	var docs []string
	for _, arn := range r.AttachedPolicies {
		if p := st.state.Policies[arn]; p != nil {
			docs = append(docs, p.defaultDocument())
		}
	}
	return docs, nil
}

func (st *iamStore) roleByARN(arn string) *role {
	for _, r := range st.state.Roles {
		if r.ARN == arn {
			return r
		}
	}
	return nil
}

// snapshot returns a deep-enough copy for the console.
func (st *iamStore) snapshot() (providers []oidcProvider, roles []role, policies []policy) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, p := range st.state.OIDCProviders {
		providers = append(providers, *p)
	}
	for _, r := range st.state.Roles {
		roles = append(roles, *r)
	}
	for _, p := range st.state.Policies {
		policies = append(policies, *p)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].ARN < providers[j].ARN })
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	return
}

func (p *policy) defaultDocument() string {
	for _, v := range p.Versions {
		if v.ID == p.DefaultVersion {
			return v.Document
		}
	}
	return ""
}

func errNoSuchEntity(kind, name string) error {
	return apiError{http.StatusNotFound, "NoSuchEntity", fmt.Sprintf("The %s with name %s cannot be found.", kind, name)}
}

func errInvalidInput(msg string) error {
	return apiError{http.StatusBadRequest, "InvalidInput", msg}
}

// stableID returns an AWS-style unique ID (prefix + 17 chars) for seed.
func stableID(prefix, seed string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	h := sha256.Sum256([]byte(seed))
	b := make([]byte, 17)
	for i := range b {
		b[i] = alphabet[int(h[i])%len(alphabet)]
	}
	return prefix + string(b)
}

func roleID(name string) string { return stableID("AROA", "role:"+name) }

var iamName = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)

func parseTags(form map[string][]string) []tag {
	var tags []tag
	for i := 1; ; i++ {
		k := formValue(form, fmt.Sprintf("Tags.member.%d.Key", i))
		if k == "" {
			return tags
		}
		tags = append(tags, tag{k, formValue(form, fmt.Sprintf("Tags.member.%d.Value", i))})
	}
}

func mergeTags(have, add []tag) []tag {
	for _, t := range add {
		i := slices.IndexFunc(have, func(h tag) bool { return h.Key == t.Key })
		if i >= 0 {
			have[i] = t
		} else {
			have = append(have, t)
		}
	}
	return have
}

func removeTags(have []tag, keys []string) []tag {
	return slices.DeleteFunc(have, func(t tag) bool { return slices.Contains(keys, t.Key) })
}

func validPolicyDocument(doc string) error {
	var v struct {
		Statement json.RawMessage
	}
	if err := json.Unmarshal([]byte(doc), &v); err != nil || len(v.Statement) == 0 {
		return apiError{http.StatusBadRequest, "MalformedPolicyDocument", "The policy document is not valid JSON with a Statement."}
	}
	return nil
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// XML shapes.

type xmlTag struct {
	Key   string
	Value string
}

func xmlTags(tags []tag) []xmlTag {
	out := make([]xmlTag, len(tags))
	for i, t := range tags {
		out[i] = xmlTag{t.Key, t.Value}
	}
	return out
}

type xmlRole struct {
	Path                     string
	RoleName                 string
	RoleId                   string
	Arn                      string
	CreateDate               string
	AssumeRolePolicyDocument string   `xml:",omitempty"`
	Description              string   `xml:",omitempty"`
	MaxSessionDuration       int      `xml:",omitempty"`
	Tags                     []xmlTag `xml:"Tags>member,omitempty"`
}

func (r *role) xml() xmlRole {
	return xmlRole{
		Path:                     r.Path,
		RoleName:                 r.Name,
		RoleId:                   r.ID,
		Arn:                      r.ARN,
		CreateDate:               isoTime(r.Created),
		AssumeRolePolicyDocument: url.QueryEscape(r.AssumeRolePolicy),
		Description:              r.Description,
		MaxSessionDuration:       r.MaxSessionDuration,
		Tags:                     xmlTags(r.Tags),
	}
}

type xmlPolicy struct {
	PolicyName                    string
	PolicyId                      string
	Arn                           string
	Path                          string
	DefaultVersionId              string
	AttachmentCount               int
	PermissionsBoundaryUsageCount int
	IsAttachable                  bool
	Description                   string `xml:",omitempty"`
	CreateDate                    string
	UpdateDate                    string
	Tags                          []xmlTag `xml:"Tags>member,omitempty"`
}

func (st *iamStore) policyXML(p *policy) xmlPolicy {
	attachments := 0
	for _, r := range st.state.Roles {
		if slices.Contains(r.AttachedPolicies, p.ARN) {
			attachments++
		}
	}
	return xmlPolicy{
		PolicyName:       p.Name,
		PolicyId:         p.ID,
		Arn:              p.ARN,
		Path:             p.Path,
		DefaultVersionId: p.DefaultVersion,
		AttachmentCount:  attachments,
		IsAttachable:     true,
		Description:      p.Description,
		CreateDate:       isoTime(p.Created),
		UpdateDate:       isoTime(p.Updated),
		Tags:             xmlTags(p.Tags),
	}
}

type xmlPolicyVersion struct {
	Document         string `xml:",omitempty"`
	VersionId        string
	IsDefaultVersion bool
	CreateDate       string
}

func (p *policy) versionXML(v policyVersion, withDoc bool) xmlPolicyVersion {
	x := xmlPolicyVersion{VersionId: v.ID, IsDefaultVersion: v.ID == p.DefaultVersion, CreateDate: isoTime(v.Created)}
	if withDoc {
		x.Document = url.QueryEscape(v.Document)
	}
	return x
}

type xmlAttachedPolicy struct {
	PolicyName string
	PolicyArn  string
}

// queryResponse renders <{Action}Response><{Action}Result>result</...>.
type queryResponse struct {
	XMLName  xml.Name
	Xmlns    string `xml:"xmlns,attr"`
	Result   any
	Metadata responseMetadata `xml:"ResponseMetadata"`
}

// resultWrapper encodes Inner's fields directly inside <XMLName>.
type resultWrapper struct {
	XMLName xml.Name
	Inner   any
}

func (r resultWrapper) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	return e.EncodeElement(r.Inner, xml.StartElement{Name: r.XMLName})
}

func (s *Server) writeQuery(w http.ResponseWriter, action, xmlns string, result any) error {
	resp := queryResponse{
		XMLName:  xml.Name{Local: action + "Response"},
		Xmlns:    xmlns,
		Metadata: meta(),
	}
	if result != nil {
		resp.Result = resultWrapper{XMLName: xml.Name{Local: action + "Result"}, Inner: result}
	}
	s.writeXML(w, http.StatusOK, resp)
	return nil
}

const iamXMLNS = "https://iam.amazonaws.com/doc/2010-05-08/"

func (s *Server) iamHandler(action string) func(http.ResponseWriter, *request) error {
	h, ok := map[string]func(*request) (any, error){
		"CreateOpenIDConnectProvider":             s.iamCreateOIDCProvider,
		"GetOpenIDConnectProvider":                s.iamGetOIDCProvider,
		"ListOpenIDConnectProviders":              s.iamListOIDCProviders,
		"DeleteOpenIDConnectProvider":             s.iamDeleteOIDCProvider,
		"UpdateOpenIDConnectProviderThumbprint":   s.iamUpdateOIDCThumbprint,
		"AddClientIDToOpenIDConnectProvider":      s.iamAddClientID,
		"RemoveClientIDFromOpenIDConnectProvider": s.iamRemoveClientID,
		"TagOpenIDConnectProvider":                s.iamTagOIDCProvider,
		"UntagOpenIDConnectProvider":              s.iamUntagOIDCProvider,
		"ListOpenIDConnectProviderTags":           s.iamListOIDCProviderTags,
		"CreateRole":                              s.iamCreateRole,
		"GetRole":                                 s.iamGetRole,
		"UpdateRole":                              s.iamUpdateRole,
		"UpdateRoleDescription":                   s.iamUpdateRole,
		"UpdateAssumeRolePolicy":                  s.iamUpdateAssumeRolePolicy,
		"DeleteRole":                              s.iamDeleteRole,
		"TagRole":                                 s.iamTagRole,
		"UntagRole":                               s.iamUntagRole,
		"ListRoleTags":                            s.iamListRoleTags,
		"ListRolePolicies":                        s.iamListRolePolicies,
		"ListAttachedRolePolicies":                s.iamListAttachedRolePolicies,
		"ListInstanceProfilesForRole":             s.iamListInstanceProfilesForRole,
		"AttachRolePolicy":                        s.iamAttachRolePolicy,
		"DetachRolePolicy":                        s.iamDetachRolePolicy,
		"CreatePolicy":                            s.iamCreatePolicy,
		"GetPolicy":                               s.iamGetPolicy,
		"DeletePolicy":                            s.iamDeletePolicy,
		"GetPolicyVersion":                        s.iamGetPolicyVersion,
		"ListPolicyVersions":                      s.iamListPolicyVersions,
		"CreatePolicyVersion":                     s.iamCreatePolicyVersion,
		"DeletePolicyVersion":                     s.iamDeletePolicyVersion,
		"SetDefaultPolicyVersion":                 s.iamSetDefaultPolicyVersion,
		"TagPolicy":                               s.iamTagPolicy,
		"UntagPolicy":                             s.iamUntagPolicy,
		"ListPolicyTags":                          s.iamListPolicyTags,
		"ListEntitiesForPolicy":                   s.iamListEntitiesForPolicy,
	}[action]
	if !ok {
		return nil
	}
	return func(w http.ResponseWriter, req *request) error {
		s.iam.mu.Lock()
		result, err := h(req)
		if err == nil && !strings.HasPrefix(action, "Get") && !strings.HasPrefix(action, "List") {
			err = s.iam.save()
		}
		s.iam.mu.Unlock()
		if err != nil {
			return err
		}
		return s.writeQuery(w, action, iamXMLNS, result)
	}
}

// OIDC providers.

func (s *Server) oidcProvider(req *request) (*oidcProvider, error) {
	arn := formValue(req.form, "OpenIDConnectProviderArn")
	p := s.iam.state.OIDCProviders[arn]
	if p == nil {
		return nil, apiError{http.StatusNotFound, "NoSuchEntity", fmt.Sprintf("OpenIDConnect Provider not found for arn %s", arn)}
	}
	return p, nil
}

func (s *Server) iamCreateOIDCProvider(req *request) (any, error) {
	raw := formValue(req.form, "Url")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errInvalidInput("Url must be an https:// URL")
	}
	if u.Port() != "" {
		// As in AWS. The Terraform module strips the proxy's port.
		return nil, errInvalidInput("Url must not contain a port")
	}
	name := u.Host + strings.TrimRight(u.Path, "/")
	arn := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", s.cfg.AccountID, name)
	if s.iam.state.OIDCProviders[arn] != nil {
		return nil, apiError{http.StatusConflict, "EntityAlreadyExists", "Provider with url " + raw + " already exists."}
	}
	p := &oidcProvider{
		ARN:         arn,
		URL:         name,
		ClientIDs:   listParam(req.form, "ClientIDList.member"),
		Thumbprints: listParam(req.form, "ThumbprintList.member"),
		Tags:        parseTags(req.form),
		Created:     s.now(),
	}
	s.iam.state.OIDCProviders[arn] = p
	return struct {
		OpenIDConnectProviderArn string
		Tags                     []xmlTag `xml:"Tags>member,omitempty"`
	}{arn, xmlTags(p.Tags)}, nil
}

func (s *Server) iamGetOIDCProvider(req *request) (any, error) {
	p, err := s.oidcProvider(req)
	if err != nil {
		return nil, err
	}
	return struct {
		Url            string
		ClientIDList   []string `xml:"ClientIDList>member"`
		ThumbprintList []string `xml:"ThumbprintList>member"`
		CreateDate     string
		Tags           []xmlTag `xml:"Tags>member,omitempty"`
	}{p.URL, p.ClientIDs, p.Thumbprints, isoTime(p.Created), xmlTags(p.Tags)}, nil
}

func (s *Server) iamListOIDCProviders(req *request) (any, error) {
	type entry struct{ Arn string }
	var list []entry
	for arn := range s.iam.state.OIDCProviders {
		list = append(list, entry{arn})
	}
	return struct {
		OpenIDConnectProviderList []entry `xml:"OpenIDConnectProviderList>member"`
	}{list}, nil
}

func (s *Server) iamDeleteOIDCProvider(req *request) (any, error) {
	p, err := s.oidcProvider(req)
	if err != nil {
		return nil, err
	}
	delete(s.iam.state.OIDCProviders, p.ARN)
	return nil, nil
}

func (s *Server) iamUpdateOIDCThumbprint(req *request) (any, error) {
	p, err := s.oidcProvider(req)
	if err != nil {
		return nil, err
	}
	p.Thumbprints = listParam(req.form, "ThumbprintList.member")
	return nil, nil
}

func (s *Server) iamAddClientID(req *request) (any, error) {
	p, err := s.oidcProvider(req)
	if err != nil {
		return nil, err
	}
	if id := formValue(req.form, "ClientID"); !slices.Contains(p.ClientIDs, id) {
		p.ClientIDs = append(p.ClientIDs, id)
	}
	return nil, nil
}

func (s *Server) iamRemoveClientID(req *request) (any, error) {
	p, err := s.oidcProvider(req)
	if err != nil {
		return nil, err
	}
	id := formValue(req.form, "ClientID")
	p.ClientIDs = slices.DeleteFunc(p.ClientIDs, func(c string) bool { return c == id })
	return nil, nil
}

func (s *Server) iamTagOIDCProvider(req *request) (any, error) {
	p, err := s.oidcProvider(req)
	if err != nil {
		return nil, err
	}
	p.Tags = mergeTags(p.Tags, parseTags(req.form))
	return nil, nil
}

func (s *Server) iamUntagOIDCProvider(req *request) (any, error) {
	p, err := s.oidcProvider(req)
	if err != nil {
		return nil, err
	}
	p.Tags = removeTags(p.Tags, listParam(req.form, "TagKeys.member"))
	return nil, nil
}

func (s *Server) iamListOIDCProviderTags(req *request) (any, error) {
	p, err := s.oidcProvider(req)
	if err != nil {
		return nil, err
	}
	return tagList(p.Tags), nil
}

func tagList(tags []tag) any {
	return struct {
		Tags        []xmlTag `xml:"Tags>member"`
		IsTruncated bool
	}{xmlTags(tags), false}
}

// Roles.

func (s *Server) role(req *request) (*role, error) {
	name := formValue(req.form, "RoleName")
	r := s.iam.state.Roles[name]
	if r == nil {
		return nil, errNoSuchEntity("role", name)
	}
	return r, nil
}

func (s *Server) iamCreateRole(req *request) (any, error) {
	name := formValue(req.form, "RoleName")
	if !iamName.MatchString(name) || len(name) > 64 {
		return nil, apiError{http.StatusBadRequest, "ValidationError", "Invalid RoleName " + strconv.Quote(name)}
	}
	if s.iam.state.Roles[name] != nil {
		return nil, apiError{http.StatusConflict, "EntityAlreadyExists", "Role with name " + name + " already exists."}
	}
	doc := formValue(req.form, "AssumeRolePolicyDocument")
	if err := validPolicyDocument(doc); err != nil {
		return nil, err
	}
	maxSession := 3600
	if v := formValue(req.form, "MaxSessionDuration"); v != "" {
		maxSession, _ = strconv.Atoi(v)
	}
	path := normalizePath(formValue(req.form, "Path"))
	r := &role{
		Name:               name,
		Path:               path,
		ARN:                fmt.Sprintf("arn:aws:iam::%s:role%s%s", s.cfg.AccountID, path, name),
		ID:                 roleID(name),
		Description:        formValue(req.form, "Description"),
		AssumeRolePolicy:   doc,
		MaxSessionDuration: maxSession,
		Tags:               parseTags(req.form),
		Created:            s.now(),
	}
	s.iam.state.Roles[name] = r
	return struct{ Role xmlRole }{r.xml()}, nil
}

func (s *Server) iamGetRole(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	return struct{ Role xmlRole }{r.xml()}, nil
}

func (s *Server) iamUpdateRole(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	if _, ok := req.form["Description"]; ok {
		r.Description = formValue(req.form, "Description")
	}
	if v := formValue(req.form, "MaxSessionDuration"); v != "" {
		r.MaxSessionDuration, _ = strconv.Atoi(v)
	}
	if req.action == "UpdateRoleDescription" {
		return struct{ Role xmlRole }{r.xml()}, nil
	}
	return nil, nil
}

func (s *Server) iamUpdateAssumeRolePolicy(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	doc := formValue(req.form, "PolicyDocument")
	if err := validPolicyDocument(doc); err != nil {
		return nil, err
	}
	r.AssumeRolePolicy = doc
	return nil, nil
}

func (s *Server) iamDeleteRole(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	if len(r.AttachedPolicies) > 0 {
		return nil, apiError{http.StatusConflict, "DeleteConflict", "Cannot delete entity, must detach all policies first."}
	}
	delete(s.iam.state.Roles, r.Name)
	return nil, nil
}

func (s *Server) iamTagRole(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	r.Tags = mergeTags(r.Tags, parseTags(req.form))
	return nil, nil
}

func (s *Server) iamUntagRole(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	r.Tags = removeTags(r.Tags, listParam(req.form, "TagKeys.member"))
	return nil, nil
}

func (s *Server) iamListRoleTags(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	return tagList(r.Tags), nil
}

// ListRolePolicies lists inline policies; the module creates none.
func (s *Server) iamListRolePolicies(req *request) (any, error) {
	if _, err := s.role(req); err != nil {
		return nil, err
	}
	return struct {
		PolicyNames []string `xml:"PolicyNames>member"`
		IsTruncated bool
	}{nil, false}, nil
}

func (s *Server) iamListAttachedRolePolicies(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	var list []xmlAttachedPolicy
	for _, arn := range r.AttachedPolicies {
		if p := s.iam.state.Policies[arn]; p != nil {
			list = append(list, xmlAttachedPolicy{p.Name, p.ARN})
		}
	}
	return struct {
		AttachedPolicies []xmlAttachedPolicy `xml:"AttachedPolicies>member"`
		IsTruncated      bool
	}{list, false}, nil
}

func (s *Server) iamListInstanceProfilesForRole(req *request) (any, error) {
	if _, err := s.role(req); err != nil {
		return nil, err
	}
	return struct {
		InstanceProfiles []string `xml:"InstanceProfiles>member"`
		IsTruncated      bool
	}{nil, false}, nil
}

func (s *Server) iamAttachRolePolicy(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	arn := formValue(req.form, "PolicyArn")
	if s.iam.state.Policies[arn] == nil {
		return nil, apiError{http.StatusNotFound, "NoSuchEntity", "Policy " + arn + " does not exist or is not attachable."}
	}
	if !slices.Contains(r.AttachedPolicies, arn) {
		r.AttachedPolicies = append(r.AttachedPolicies, arn)
	}
	return nil, nil
}

func (s *Server) iamDetachRolePolicy(req *request) (any, error) {
	r, err := s.role(req)
	if err != nil {
		return nil, err
	}
	arn := formValue(req.form, "PolicyArn")
	if !slices.Contains(r.AttachedPolicies, arn) {
		return nil, apiError{http.StatusNotFound, "NoSuchEntity", "Policy " + arn + " was not found."}
	}
	r.AttachedPolicies = slices.DeleteFunc(r.AttachedPolicies, func(a string) bool { return a == arn })
	return nil, nil
}

// Managed policies.

func (s *Server) policy(req *request) (*policy, error) {
	arn := formValue(req.form, "PolicyArn")
	p := s.iam.state.Policies[arn]
	if p == nil {
		return nil, apiError{http.StatusNotFound, "NoSuchEntity", "Policy " + arn + " does not exist or is not attachable."}
	}
	return p, nil
}

func (s *Server) iamCreatePolicy(req *request) (any, error) {
	name := formValue(req.form, "PolicyName")
	if !iamName.MatchString(name) {
		return nil, apiError{http.StatusBadRequest, "ValidationError", "Invalid PolicyName " + strconv.Quote(name)}
	}
	doc := formValue(req.form, "PolicyDocument")
	if err := validPolicyDocument(doc); err != nil {
		return nil, err
	}
	path := normalizePath(formValue(req.form, "Path"))
	arn := fmt.Sprintf("arn:aws:iam::%s:policy%s%s", s.cfg.AccountID, path, name)
	if s.iam.state.Policies[arn] != nil {
		return nil, apiError{http.StatusConflict, "EntityAlreadyExists", "A policy called " + name + " already exists."}
	}
	now := s.now()
	p := &policy{
		Name:           name,
		Path:           path,
		ARN:            arn,
		ID:             stableID("ANPA", arn+now.String()),
		Description:    formValue(req.form, "Description"),
		Tags:           parseTags(req.form),
		Created:        now,
		Updated:        now,
		DefaultVersion: "v1",
		Versions:       []policyVersion{{ID: "v1", Document: doc, Created: now}},
	}
	s.iam.state.Policies[arn] = p
	return struct{ Policy xmlPolicy }{s.iam.policyXML(p)}, nil
}

func (s *Server) iamGetPolicy(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	return struct{ Policy xmlPolicy }{s.iam.policyXML(p)}, nil
}

func (s *Server) iamDeletePolicy(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	for _, r := range s.iam.state.Roles {
		if slices.Contains(r.AttachedPolicies, p.ARN) {
			return nil, apiError{http.StatusConflict, "DeleteConflict", "Cannot delete a policy attached to entities."}
		}
	}
	if len(p.Versions) > 1 {
		return nil, apiError{http.StatusConflict, "DeleteConflict", "This policy has more than one version. Before you delete a policy, you must delete the policy's versions. The default version is deleted with the policy."}
	}
	delete(s.iam.state.Policies, p.ARN)
	return nil, nil
}

func (s *Server) iamGetPolicyVersion(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	id := formValue(req.form, "VersionId")
	for _, v := range p.Versions {
		if v.ID == id {
			return struct{ PolicyVersion xmlPolicyVersion }{p.versionXML(v, true)}, nil
		}
	}
	return nil, apiError{http.StatusNotFound, "NoSuchEntity", "Policy " + p.ARN + " version " + id + " does not exist or is not attachable."}
}

func (s *Server) iamListPolicyVersions(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	var list []xmlPolicyVersion
	for _, v := range p.Versions {
		list = append(list, p.versionXML(v, false))
	}
	return struct {
		Versions    []xmlPolicyVersion `xml:"Versions>member"`
		IsTruncated bool
	}{list, false}, nil
}

func (s *Server) iamCreatePolicyVersion(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	if len(p.Versions) >= 5 {
		return nil, apiError{http.StatusConflict, "LimitExceeded", "A managed policy can have up to 5 versions."}
	}
	doc := formValue(req.form, "PolicyDocument")
	if err := validPolicyDocument(doc); err != nil {
		return nil, err
	}
	n := 0
	for _, v := range p.Versions {
		if i, _ := strconv.Atoi(strings.TrimPrefix(v.ID, "v")); i > n {
			n = i
		}
	}
	v := policyVersion{ID: fmt.Sprintf("v%d", n+1), Document: doc, Created: s.now()}
	p.Versions = append(p.Versions, v)
	if formValue(req.form, "SetAsDefault") == "true" {
		p.DefaultVersion = v.ID
	}
	p.Updated = s.now()
	return struct{ PolicyVersion xmlPolicyVersion }{p.versionXML(v, false)}, nil
}

func (s *Server) iamDeletePolicyVersion(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	id := formValue(req.form, "VersionId")
	if id == p.DefaultVersion {
		return nil, apiError{http.StatusConflict, "DeleteConflict", "Cannot delete the default version of a policy."}
	}
	i := slices.IndexFunc(p.Versions, func(v policyVersion) bool { return v.ID == id })
	if i < 0 {
		return nil, apiError{http.StatusNotFound, "NoSuchEntity", "Policy version " + id + " not found."}
	}
	p.Versions = slices.Delete(p.Versions, i, i+1)
	return nil, nil
}

func (s *Server) iamSetDefaultPolicyVersion(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	id := formValue(req.form, "VersionId")
	if !slices.ContainsFunc(p.Versions, func(v policyVersion) bool { return v.ID == id }) {
		return nil, apiError{http.StatusNotFound, "NoSuchEntity", "Policy version " + id + " not found."}
	}
	p.DefaultVersion = id
	return nil, nil
}

func (s *Server) iamTagPolicy(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	p.Tags = mergeTags(p.Tags, parseTags(req.form))
	return nil, nil
}

func (s *Server) iamUntagPolicy(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	p.Tags = removeTags(p.Tags, listParam(req.form, "TagKeys.member"))
	return nil, nil
}

func (s *Server) iamListPolicyTags(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	return tagList(p.Tags), nil
}

func (s *Server) iamListEntitiesForPolicy(req *request) (any, error) {
	p, err := s.policy(req)
	if err != nil {
		return nil, err
	}
	type entry struct{ RoleName, RoleId string }
	var list []entry
	for _, r := range s.iam.state.Roles {
		if slices.Contains(r.AttachedPolicies, p.ARN) {
			list = append(list, entry{r.Name, r.ID})
		}
	}
	return struct {
		PolicyRoles  []entry  `xml:"PolicyRoles>member"`
		PolicyUsers  []string `xml:"PolicyUsers>member"`
		PolicyGroups []string `xml:"PolicyGroups>member"`
		IsTruncated  bool
	}{PolicyRoles: list}, nil
}
