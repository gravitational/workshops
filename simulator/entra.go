package main

// A fake Microsoft Entra ID tenant: enough of the Microsoft identity platform
// (login.microsoftonline.com) and Microsoft Graph (graph.microsoft.com) for
// Teleport's Entra ID integration (SAML SSO + group/Access List sync).
// Any client ID, client assertion or bearer token is accepted.
//
// Teleport only talks to Microsoft's real hostnames, so in Docker those names
// are network aliases for this container (see docker-compose.yml).

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

const (
	entraEpoch     = "2026-01-01T00:00:00Z"
	entraDeltaLink = "sim1" // the directory never changes, so one delta token suffices
)

// stableUUID returns a deterministic v4-shaped UUID for seed.
func stableUUID(seed string) string {
	s := sha256.Sum256([]byte(seed))
	s[6] = (s[6] & 0x0f) | 0x40
	s[8] = (s[8] & 0x3f) | 0x80
	h := hex.EncodeToString(s[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

type entraGroup struct {
	ID, Name string
	Members  []User
	Owners   []User
}

type entraDir struct {
	browserURL string // e.g. https://entra.localhost:10443 (SAML SSO in the browser)

	TenantID    string
	ClientID    string // application (client) ID of the "Teleport" enterprise app
	appObjectID string
	spID        string // service principal object ID

	groups []entraGroup
	key    *rsa.PrivateKey
	cert   *x509.Certificate

	calls callLog // recent login/Graph calls, for the console
}

func newEntraDir(cfg Config) (*entraDir, error) {
	key, cert, err := loadOrCreateKeyPair(cfg.DataDir, "entra-idp", &x509.Certificate{
		Subject:  pkix.Name{CommonName: "Microsoft Azure Federated SSO Certificate (simulator)"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		return nil, err
	}
	d := &entraDir{
		browserURL:  cfg.EntraURL,
		TenantID:    stableUUID("entra:tenant"),
		ClientID:    stableUUID("entra:app:teleport:client"),
		appObjectID: stableUUID("entra:app:teleport:object"),
		spID:        stableUUID("entra:app:teleport:sp"),
		key:         key,
		cert:        cert,
	}
	owner := EntraUsers[0] // Andrew owns every group
	for _, g := range staticGroups(EntraUsers) {
		d.groups = append(d.groups, entraGroup{ID: stableUUID("entra:group:" + g.Name), Name: g.Name, Members: g.Members, Owners: []User{owner}})
	}
	return d, nil
}

func (d *entraDir) userID(u User) string { return stableUUID("entra:user:" + u.ID) }

func (d *entraDir) userByID(id string) (User, bool) {
	for _, u := range EntraUsers {
		if d.userID(u) == id || strings.EqualFold(u.UserName, id) {
			return u, true
		}
	}
	return User{}, false
}

func (d *entraDir) groupByID(id string) (entraGroup, bool) {
	for _, g := range d.groups {
		if g.ID == id {
			return g, true
		}
	}
	return entraGroup{}, false
}

func (d *entraDir) userGroups(u User) []entraGroup {
	var out []entraGroup
	for _, g := range d.groups {
		if slices.ContainsFunc(g.Members, func(m User) bool { return m.ID == u.ID }) {
			out = append(out, g)
		}
	}
	return out
}

// ---- Graph JSON ----

func (d *entraDir) userJSON(u User) obj {
	return obj{
		"@odata.type": "#microsoft.graph.user",
		"id":          d.userID(u), "displayName": u.DisplayName(),
		"givenName": u.GivenName, "surname": u.Surname, "jobTitle": u.Title,
		"mail": u.Email, "userPrincipalName": u.UserName, "accountEnabled": true,
		"businessPhones": []string{}, "mobilePhone": nil, "officeLocation": nil, "preferredLanguage": "en-US",
		"onPremisesSamAccountName": nil, "onPremisesDomainName": nil, "onPremisesNetBiosName": nil,
	}
}

func (d *entraDir) groupJSON(g entraGroup) obj {
	return obj{
		"@odata.type": "#microsoft.graph.group",
		"id":          g.ID, "displayName": g.Name, "description": "Simulator group " + g.Name,
		"groupTypes": []string{}, "securityEnabled": true, "mailEnabled": false,
		"mail": nil, "mailNickname": g.Name, "createdDateTime": entraEpoch,
		"onPremisesSamAccountName": nil, "onPremisesDomainName": nil, "onPremisesNetBiosName": nil,
	}
}

func (d *entraDir) applicationJSON(appID string) obj {
	return obj{
		"@odata.type": "#microsoft.graph.application",
		"id":          d.appObjectID, "appId": appID, "displayName": "Teleport",
		"identifierUris":        []string{},
		"groupMembershipClaims": "SecurityGroup",
		"web":                   obj{"redirectUris": []string{}},
		"optionalClaims":        obj{"saml2Token": []obj{}, "idToken": []obj{}, "accessToken": []obj{}},
		"createdDateTime":       entraEpoch,
	}
}

func (d *entraDir) servicePrincipalJSON(appID string) obj {
	return obj{
		"@odata.type": "#microsoft.graph.servicePrincipal",
		"id":          d.spID, "appId": appID, "displayName": "Teleport",
		"accountEnabled": true, "appRoleAssignmentRequired": true,
		"preferredSingleSignOnMode":          "saml",
		"preferredTokenSigningKeyThumbprint": certThumbprint(d.cert),
		"servicePrincipalType":               "Application",
		"appRoles":                           []obj{},
		"tags":                               []string{"WindowsAzureActiveDirectoryCustomSingleSignOnApplication", "WindowsAzureActiveDirectoryIntegratedApp"},
	}
}

func (d *entraDir) appRoleAssignments() []obj {
	var out []obj
	for _, g := range d.groups {
		out = append(out, obj{
			"id": stableUUID("entra:assignment:" + g.ID), "appRoleId": "00000000-0000-0000-0000-000000000000",
			"principalId": g.ID, "principalType": "Group", "principalDisplayName": g.Name,
			"resourceId": d.spID, "resourceDisplayName": "Teleport", "createdDateTime": entraEpoch,
		})
	}
	return out
}

func certThumbprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:20]))
}

// ---- HTTP ----

// handler serves the login host, the Graph host and the browser console; they
// share one listener and are told apart by path.
func (d *entraDir) handler() http.Handler {
	api := d.calls.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sso/saml/metadata": // short, static alias
			d.idpFor(d.TenantID).ServeMetadata(w, r)
		case strings.HasPrefix(r.URL.Path, "/v1.0/") || strings.HasPrefix(r.URL.Path, "/beta/"):
			d.graph(w, r)
		default:
			d.login(w, r)
		}
	}), true) // with host: login.microsoftonline.com and graph.microsoft.com share this listener
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			healthz(w, r)
		case "/":
			d.console(w, r)
		default:
			api.ServeHTTP(w, r)
		}
	})
}

// login implements the Microsoft identity platform endpoints Teleport uses:
// instance/tenant discovery, the token endpoint, and SAML (metadata + SSO).
func (d *entraDir) login(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	tenant := parts[0]
	rest := strings.Join(parts[1:], "/")
	loginBase := "https://" + r.Host + "/" + tenant
	switch {
	case rest == "discovery/instance":
		writeJSON(w, http.StatusOK, obj{
			"tenant_discovery_endpoint": "https://" + r.Host + "/" + tenant + "/v2.0/.well-known/openid-configuration",
			"api-version":               "1.1",
			"metadata": []obj{{
				"preferred_network": r.Host, "preferred_cache": r.Host,
				"aliases": []string{r.Host},
			}},
		})
	case rest == "v2.0/.well-known/openid-configuration" || rest == ".well-known/openid-configuration":
		writeJSON(w, http.StatusOK, obj{
			"issuer":                                "https://login.microsoftonline.com/" + tenant + "/v2.0",
			"authorization_endpoint":                loginBase + "/oauth2/v2.0/authorize",
			"token_endpoint":                        loginBase + "/oauth2/v2.0/token",
			"device_authorization_endpoint":         loginBase + "/oauth2/v2.0/devicecode",
			"end_session_endpoint":                  loginBase + "/oauth2/v2.0/logout",
			"jwks_uri":                              loginBase + "/discovery/v2.0/keys",
			"response_types_supported":              []string{"code", "id_token", "code id_token", "id_token token"},
			"subject_types_supported":               []string{"pairwise"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt", "client_secret_basic"},
			"tenant_region_scope":                   "NA",
			"cloud_instance_name":                   "microsoftonline.com",
		})
	case rest == "discovery/v2.0/keys" || rest == "discovery/keys":
		writeJSON(w, http.StatusOK, obj{"keys": []obj{{
			"kty": "RSA", "use": "sig", "kid": "simulator", "x5t": "simulator",
			"n":   base64.RawURLEncoding.EncodeToString(d.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(d.key.E)).Bytes()),
			"x5c": []string{base64.StdEncoding.EncodeToString(d.cert.Raw)},
		}}})
	case r.Method == http.MethodPost && (rest == "oauth2/v2.0/token" || rest == "oauth2/token"):
		d.token(w, r, tenant)
	case strings.EqualFold(rest, "federationmetadata/2007-06/federationmetadata.xml"):
		d.idpFor(tenant).ServeMetadata(w, r)
	case rest == "saml2":
		d.idpFor(tenant).ServeSSO(w, r)
	default:
		log.Printf("entra: UNIMPLEMENTED %s %s%s", r.Method, r.Host, r.URL.RequestURI())
		writeJSON(w, http.StatusNotFound, obj{"error": "not_found", "error_description": "AADSTS90002: endpoint not implemented by the simulator: " + r.URL.Path})
	}
}

// token accepts any client credentials or client assertion and returns a
// signed, Graph-shaped access token.
func (d *entraDir) token(w http.ResponseWriter, r *http.Request, tenant string) {
	r.ParseForm()
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		clientID = d.ClientID
	}
	now := time.Now()
	claims := obj{
		"aud": "https://graph.microsoft.com", "iss": "https://sts.windows.net/" + tenant + "/",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"tid": tenant, "appid": clientID, "azp": clientID, "oid": d.spID, "sub": d.spID,
		"idtyp": "app", "ver": "1.0",
		"roles": []string{"Application.Read.All", "Directory.Read.All", "Group.Read.All", "GroupMember.Read.All", "User.Read.All", "Policy.Read.All"},
	}
	tok, err := d.signJWT(claims)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, obj{"error": "server_error", "error_description": err.Error()})
		return
	}
	log.Printf("entra: issued access token (tenant=%s client_id=%s grant_type=%s)", tenant, clientID, r.Form.Get("grant_type"))
	writeJSON(w, http.StatusOK, obj{"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": tok})
}

func (d *entraDir) signJWT(claims obj) (string, error) {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signing := enc(obj{"alg": "RS256", "typ": "JWT", "kid": "simulator", "x5t": "simulator"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, d.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// idpFor returns the SAML IdP for a tenant, shaped like Entra's:
//
//	entity ID: https://sts.windows.net/{tenant}/
//	SSO:       {browserURL}/{tenant}/saml2
func (d *entraDir) idpFor(tenant string) *saml.IdentityProvider {
	entity, _ := url.Parse("https://sts.windows.net/" + tenant + "/")
	sso, _ := url.Parse(d.browserURL + "/" + tenant + "/saml2")
	return &saml.IdentityProvider{
		Key:                     d.key,
		Certificate:             d.cert,
		Logger:                  logger.DefaultLogger,
		MetadataURL:             *entity, // crewjam uses MetadataURL as the entity ID
		SSOURL:                  *sso,
		ServiceProviderProvider: anySP{},
		SessionProvider:         pickerSessions{template: "entra_login.html", users: EntraUsers, attributes: d.claims(tenant)},
		AssertionMaker:          saml.DefaultAssertionMaker{},
	}
}

// claims returns Entra's default SAML claims for a user, plus groups as
// object IDs (what the Teleport Entra ID enterprise app is configured with).
func (d *entraDir) claims(tenant string) func(User) []saml.Attribute {
	attr := func(name string, vals ...string) saml.Attribute {
		a := saml.Attribute{Name: name}
		for _, v := range vals {
			a.Values = append(a.Values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		return a
	}
	return func(u User) []saml.Attribute {
		var groupIDs []string
		for _, g := range d.userGroups(u) {
			groupIDs = append(groupIDs, g.ID)
		}
		return []saml.Attribute{
			attr("http://schemas.microsoft.com/identity/claims/tenantid", tenant),
			attr("http://schemas.microsoft.com/identity/claims/objectidentifier", d.userID(u)),
			attr("http://schemas.microsoft.com/identity/claims/displayname", u.DisplayName()),
			attr("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", groupIDs...),
			attr("http://schemas.microsoft.com/identity/claims/identityprovider", "https://sts.windows.net/"+tenant+"/"),
			attr("http://schemas.microsoft.com/claims/authnmethodsreferences", "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"),
			attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", u.GivenName),
			attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", u.Surname),
			attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", u.Email),
			attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", u.UserName),
		}
	}
}

// graph implements the Microsoft Graph subset Teleport uses.
func (d *entraDir) graph(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		graphError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is empty.")
		return
	}
	version, path, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	seg := strings.Split(strings.Trim(path, "/"), "/")
	base := "https://" + r.Host + "/" + version
	get := r.Method == http.MethodGet

	notFound := func(what string) {
		graphError(w, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist or one of its queried reference-property objects are not present.", what))
	}
	users := func() []obj {
		var out []obj
		for _, u := range EntraUsers {
			out = append(out, d.userJSON(u))
		}
		return out
	}
	groups := func() []obj {
		var out []obj
		for _, g := range d.groups {
			out = append(out, d.groupJSON(g))
		}
		return out
	}

	switch {
	// users
	case get && path == "users":
		graphList(w, r, base, "users", users())
	case get && path == "users/delta":
		d.delta(w, r, base, "users", users())
	case get && len(seg) == 2 && seg[0] == "users":
		if u, ok := d.userByID(seg[1]); ok {
			writeJSON(w, http.StatusOK, d.userJSON(u))
		} else {
			notFound(seg[1])
		}
	case get && len(seg) >= 3 && seg[0] == "users" && (seg[2] == "memberOf" || seg[2] == "transitiveMemberOf"):
		u, ok := d.userByID(seg[1])
		if !ok {
			notFound(seg[1])
			return
		}
		var out []obj
		for _, g := range d.userGroups(u) {
			out = append(out, d.groupJSON(g))
		}
		graphList(w, r, base, "groups", out)

	// groups
	case get && path == "groups":
		graphList(w, r, base, "groups", groups())
	case get && path == "groups/delta":
		var out []obj
		for _, g := range d.groups {
			j := d.groupJSON(g)
			var members []obj
			for _, m := range g.Members {
				members = append(members, obj{"@odata.type": "#microsoft.graph.user", "id": d.userID(m)})
			}
			j["members@delta"] = members
			out = append(out, j)
		}
		d.delta(w, r, base, "groups", out)
	case get && len(seg) == 2 && seg[0] == "groups":
		if g, ok := d.groupByID(seg[1]); ok {
			writeJSON(w, http.StatusOK, d.groupJSON(g))
		} else {
			notFound(seg[1])
		}
	case get && len(seg) >= 3 && seg[0] == "groups" && (seg[2] == "members" || seg[2] == "transitiveMembers" || seg[2] == "owners"):
		g, ok := d.groupByID(seg[1])
		if !ok {
			notFound(seg[1])
			return
		}
		list := g.Members
		if seg[2] == "owners" {
			list = g.Owners
		}
		var out []obj
		for _, u := range list {
			out = append(out, d.userJSON(u))
		}
		graphList(w, r, base, "directoryObjects", out)

	// applications / service principals
	case get && path == "applications":
		graphList(w, r, base, "applications", []obj{d.applicationJSON(appIDFromFilter(r, d.ClientID))})
	case get && len(seg) == 1 && byAppID("applications", seg[0]) != "":
		// Any client ID is accepted: it's always the Teleport app.
		writeJSON(w, http.StatusOK, d.applicationJSON(byAppID("applications", seg[0])))
	case get && len(seg) == 2 && seg[0] == "applications":
		writeJSON(w, http.StatusOK, d.applicationJSON(d.ClientID))
	case r.Method == http.MethodPatch && len(seg) == 2 && (seg[0] == "applications" || seg[0] == "servicePrincipals"):
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && len(seg) == 3 && seg[0] == "applications" && seg[2] == "federatedIdentityCredentials":
		var body obj
		json.NewDecoder(r.Body).Decode(&body)
		body["id"] = stableUUID("entra:fic:" + fmt.Sprint(body["name"]))
		writeJSON(w, http.StatusCreated, body)
	case get && path == "servicePrincipals":
		graphList(w, r, base, "servicePrincipals", []obj{d.servicePrincipalJSON(appIDFromFilter(r, d.ClientID))})
	case get && len(seg) == 1 && byAppID("servicePrincipals", seg[0]) != "":
		writeJSON(w, http.StatusOK, d.servicePrincipalJSON(byAppID("servicePrincipals", seg[0])))
	case get && len(seg) == 2 && seg[0] == "servicePrincipals":
		writeJSON(w, http.StatusOK, d.servicePrincipalJSON(d.ClientID))
	case get && len(seg) == 3 && seg[0] == "servicePrincipals" && seg[2] == "appRoleAssignedTo":
		graphList(w, r, base, "appRoleAssignments", d.appRoleAssignments())
	case r.Method == http.MethodPost && len(seg) == 3 && seg[0] == "servicePrincipals" && seg[2] == "appRoleAssignedTo":
		var body obj
		json.NewDecoder(r.Body).Decode(&body)
		body["id"] = stableUUID("entra:assignment:" + fmt.Sprint(body["principalId"]))
		writeJSON(w, http.StatusCreated, body)
	case get && path == "organization":
		graphList(w, r, base, "organization", []obj{{"id": d.TenantID, "displayName": "Simulator", "verifiedDomains": []obj{{"name": "entra.example.com", "isDefault": true}}}})
	case get && path == "deviceManagement/managedDevices":
		graphList(w, r, base, "deviceManagement/managedDevices", []obj{})

	default:
		log.Printf("entra: UNIMPLEMENTED graph %s %s", r.Method, r.URL.RequestURI())
		graphError(w, http.StatusNotImplemented, "NotImplemented", "Not implemented by the simulator: "+r.Method+" "+r.URL.Path)
	}
}

// delta serves a Graph delta query. The directory is static, so the
// "latest" or current token returns no changes, and anything else returns
// everything.
func (d *entraDir) delta(w http.ResponseWriter, r *http.Request, base, kind string, all []obj) {
	link := base + "/" + kind + "/delta?$deltatoken=" + entraDeltaLink
	items := all
	if t := r.URL.Query().Get("$deltatoken"); t == "latest" || t == entraDeltaLink {
		items = []obj{}
	}
	writeJSON(w, http.StatusOK, obj{
		"@odata.context":   base + "/$metadata#" + kind,
		"value":            items,
		"@odata.deltaLink": link,
	})
}

// graphList writes a Graph collection honoring $filter, $top and $skiptoken.
func graphList(w http.ResponseWriter, r *http.Request, base, kind string, items []obj) {
	if items == nil {
		items = []obj{}
	}
	q := r.URL.Query()
	if f := q.Get("$filter"); f != "" {
		items = slices.DeleteFunc(slices.Clone(items), func(it obj) bool { return !odataMatch(it, f) })
	}
	start, _ := strconv.Atoi(q.Get("$skiptoken"))
	start = min(max(start, 0), len(items))
	top := len(items)
	if t, err := strconv.Atoi(q.Get("$top")); err == nil && t > 0 {
		top = t
	}
	end := min(start+top, len(items))
	resp := obj{"@odata.context": base + "/$metadata#" + kind, "value": items[start:end]}
	if q.Has("$count") {
		resp["@odata.count"] = len(items)
	}
	if end < len(items) {
		q.Set("$skiptoken", strconv.Itoa(end))
		resp["@odata.nextLink"] = "https://" + r.Host + r.URL.Path + "?" + q.Encode()
	}
	writeJSON(w, http.StatusOK, resp)
}

var (
	odataEq         = regexp.MustCompile(`^\(?\s*(\w+)\s+eq\s+'([^']*)'\s*\)?$`)
	odataStartsWith = regexp.MustCompile(`^\(?\s*startswith\((\w+)\s*,\s*'([^']*)'\)\s*\)?$`)
	odataBool       = regexp.MustCompile(`^\(?\s*(\w+)\s+eq\s+(true|false)\s*\)?$`)
)

// odataMatch evaluates simple OData filters ("a eq 'x' and startswith(b,'y')").
// Anything it doesn't understand matches, so unknown filters never hide data.
func odataMatch(it obj, filter string) bool {
	for _, or := range orRE.Split(filter, -1) {
		ok := true
		for _, c := range andRE.Split(or, -1) {
			c = strings.TrimSpace(c)
			if m := odataEq.FindStringSubmatch(c); m != nil {
				ok = ok && strings.EqualFold(fmt.Sprint(it[m[1]]), m[2])
			} else if m := odataStartsWith.FindStringSubmatch(c); m != nil {
				ok = ok && strings.HasPrefix(strings.ToLower(fmt.Sprint(it[m[1]])), strings.ToLower(m[2]))
			} else if m := odataBool.FindStringSubmatch(c); m != nil {
				ok = ok && fmt.Sprint(it[m[1]]) == m[2]
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func graphError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, obj{"error": obj{
		"code": code, "message": msg,
		"innerError": obj{"date": time.Now().UTC().Format(time.RFC3339), "request-id": stableUUID(time.Now().String())},
	}})
}

// console is the browser home page.
func (d *entraDir) console(w http.ResponseWriter, r *http.Request) {
	var users, groups []consoleRow
	for _, u := range EntraUsers {
		var gs []string
		for _, g := range d.userGroups(u) {
			gs = append(gs, g.Name)
		}
		users = append(users, consoleRow{Name: u.DisplayName(), ID: d.userID(u), Detail: u.UserName, Members: gs})
	}
	for _, g := range d.groups {
		var ms []string
		for _, u := range g.Members {
			ms = append(ms, u.UserName)
		}
		groups = append(groups, consoleRow{Name: g.Name, ID: g.ID, Members: ms})
	}
	idp := d.idpFor(d.TenantID)
	render(w, "entra_home.html", map[string]any{
		"TenantID":    d.TenantID,
		"ClientID":    d.ClientID,
		"MetadataURL": d.metadataURL(),
		"EntityID":    idp.MetadataURL.String(),
		"SSOURL":      idp.SSOURL.String(),
		"Users":       users,
		"Groups":      groups,
		"Calls":       d.calls.recent(),
	})
}

// metadataURL is what Teleport derives from the tenant and client IDs.
func (d *entraDir) metadataURL() string {
	return "https://login.microsoftonline.com/" + d.TenantID + "/federationmetadata/2007-06/federationmetadata.xml?appid=" + d.ClientID
}

var byAppIDRE = regexp.MustCompile(`^(\w+)\(appId='\{?([^'}]*)\}?'\)$`)

// byAppID returns X from "<kind>(appId='X')" path segments, or "".
func byAppID(kind, seg string) string {
	if m := byAppIDRE.FindStringSubmatch(seg); m != nil && m[1] == kind {
		return m[2]
	}
	return ""
}

var appIDFilterRE = regexp.MustCompile(`appId\s+eq\s+'([^']*)'`)

// appIDFromFilter returns X from a "$filter=appId eq 'X'" query, so lists
// filtered by any client ID still find the Teleport app; def otherwise.
func appIDFromFilter(r *http.Request, def string) string {
	if m := appIDFilterRE.FindStringSubmatch(r.URL.Query().Get("$filter")); m != nil {
		return m[1]
	}
	return def
}
