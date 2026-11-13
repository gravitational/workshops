package main

// A fake Okta org: enough of the Okta Management API, OAuth token endpoint and
// SAML app surface for Teleport's Okta integration (SSO, SCIM, user sync,
// app/group sync). Any API token, client ID or client assertion is accepted.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
)

// oktaEpoch is the fixed "created" time for all seeded objects.
const oktaEpoch = "2026-01-01T00:00:00.000Z"

// oktaID returns a stable Okta-style 20 character ID, e.g. 00u1a2b3c...
func oktaID(prefix, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return prefix + hex.EncodeToString(sum[:])[:17]
}

type oktaGroupDef struct {
	ID, Name, Description, Type string
}

type oktaAppDef struct {
	ID, Name, Label string
}

// oktaState is the mutable part of the org, persisted to the data dir.
type oktaState struct {
	GroupMembers map[string][]string `json:"groupMembers"` // group ID -> user IDs
	AppUsers     map[string][]string `json:"appUsers"`     // app ID -> directly assigned user IDs
	AppGroups    map[string][]string `json:"appGroups"`    // app ID -> assigned group IDs
	SCIMURL      string              `json:"scimUrl"`      // provisioning target pasted from Teleport
	SCIMToken    string              `json:"scimToken"`
}

type oktaOrg struct {
	browserURL string // e.g. https://okta.localhost:9443 (SSO, app links)
	orgURL     string // what Teleport is given (default browserURL)
	statePath  string

	groups   []oktaGroupDef
	apps     []oktaAppDef
	teleport oktaAppDef // the SAML app Teleport signs in with

	mu    sync.Mutex
	state oktaState

	calls callLog // recent API calls, for the console
}

func newOktaOrg(cfg Config) (*oktaOrg, error) {
	o := &oktaOrg{
		browserURL: cfg.OktaURL,
		orgURL:     cfg.OktaOrgURL,
		statePath:  filepath.Join(cfg.DataDir, "okta-state.json"),
		teleport:   oktaAppDef{ID: oktaID("0oa", "app:teleport"), Name: "teleport", Label: "Teleport"},
	}
	everyone := oktaGroupDef{ID: oktaID("00g", "group:Everyone"), Name: "Everyone", Description: "All users in your organization", Type: "BUILT_IN"}
	o.groups = []oktaGroupDef{everyone}
	for _, g := range Groups() {
		o.groups = append(o.groups, oktaGroupDef{ID: oktaID("00g", "group:"+g), Name: g, Description: "Simulator group " + g, Type: "OKTA_GROUP"})
	}
	grafana := oktaAppDef{ID: oktaID("0oa", "app:grafana"), Name: "grafana", Label: "Grafana"}
	jenkins := oktaAppDef{ID: oktaID("0oa", "app:jenkins"), Name: "jenkins", Label: "Jenkins"}
	o.apps = []oktaAppDef{o.teleport, grafana, jenkins}

	if err := o.load(); err != nil {
		return nil, err
	}
	if o.state.GroupMembers == nil { // first start: seed memberships and assignments
		o.state.GroupMembers = map[string][]string{}
		for _, u := range OktaUsers {
			o.state.GroupMembers[everyone.ID] = append(o.state.GroupMembers[everyone.ID], o.userID(u))
			for _, g := range u.Groups {
				gid := o.groupByName(g).ID
				o.state.GroupMembers[gid] = append(o.state.GroupMembers[gid], o.userID(u))
			}
		}
		o.state.AppUsers = map[string][]string{}
		o.state.AppGroups = map[string][]string{
			o.teleport.ID: {everyone.ID},
			grafana.ID:    {o.groupByName("admins").ID},
			jenkins.ID:    {o.groupByName("readonly").ID},
		}
		if err := o.save(); err != nil {
			return nil, err
		}
	}
	return o, nil
}

func (o *oktaOrg) load() error {
	b, err := os.ReadFile(o.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &o.state)
}

// save persists state; callers hold o.mu (or are single-threaded at startup).
func (o *oktaOrg) save() error {
	if err := os.MkdirAll(filepath.Dir(o.statePath), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(o.state, "", "  ")
	return os.WriteFile(o.statePath, b, 0o600)
}

func (o *oktaOrg) userID(u User) string { return oktaID("00u", "user:"+u.ID) }

func (o *oktaOrg) userByID(id string) (User, bool) {
	for _, u := range OktaUsers {
		if o.userID(u) == id || strings.EqualFold(u.UserName, id) {
			return u, true
		}
	}
	return User{}, false
}

func (o *oktaOrg) groupByName(name string) oktaGroupDef {
	for _, g := range o.groups {
		if g.Name == name {
			return g
		}
	}
	return oktaGroupDef{}
}

func (o *oktaOrg) groupByID(id string) (oktaGroupDef, bool) {
	for _, g := range o.groups {
		if g.ID == id {
			return g, true
		}
	}
	return oktaGroupDef{}, false
}

func (o *oktaOrg) appByID(id string) (oktaAppDef, bool) {
	for _, a := range o.apps {
		if a.ID == id {
			return a, true
		}
	}
	return oktaAppDef{}, false
}

// userGroups returns the groups a user is in (callers hold o.mu).
func (o *oktaOrg) userGroups(uid string) []oktaGroupDef {
	var out []oktaGroupDef
	for _, g := range o.groups {
		if slices.Contains(o.state.GroupMembers[g.ID], uid) {
			out = append(out, g)
		}
	}
	return out
}

// appUserScopes returns user ID -> "USER" or "GROUP" for everyone assigned to
// the app, directly or via a group (callers hold o.mu).
func (o *oktaOrg) appUserScopes(appID string) map[string]string {
	out := map[string]string{}
	for _, gid := range o.state.AppGroups[appID] {
		for _, uid := range o.state.GroupMembers[gid] {
			out[uid] = "GROUP"
		}
	}
	for _, uid := range o.state.AppUsers[appID] {
		out[uid] = "USER"
	}
	return out
}

// GroupNamesFor is used by the SAML assertion and the SCIM push.
func (o *oktaOrg) GroupNamesFor(u User) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var names []string
	for _, g := range o.userGroups(o.userID(u)) {
		names = append(names, g.Name)
	}
	return names
}

// ---- JSON representations (shaped like the Okta API) ----

type obj = map[string]any

func (o *oktaOrg) link(base, path string) obj { return obj{"href": base + path} }

func (o *oktaOrg) userJSON(base string, u User) obj {
	id := o.userID(u)
	return obj{
		"id": id, "status": "ACTIVE",
		"created": oktaEpoch, "activated": oktaEpoch, "statusChanged": oktaEpoch,
		"lastLogin": nil, "lastUpdated": oktaEpoch, "passwordChanged": oktaEpoch,
		"type": obj{"id": oktaID("oty", "usertype")},
		"profile": obj{
			"firstName": u.GivenName, "lastName": u.Surname, "displayName": u.DisplayName(),
			"login": u.UserName, "email": u.Email, "title": u.Title,
			"mobilePhone": nil, "secondEmail": nil,
		},
		"credentials": obj{"provider": obj{"type": "OKTA", "name": "OKTA"}},
		"_links":      obj{"self": o.link(base, "/api/v1/users/"+id)},
	}
}

func (o *oktaOrg) groupJSON(base string, g oktaGroupDef) obj {
	return obj{
		"id": g.ID, "created": oktaEpoch, "lastUpdated": oktaEpoch, "lastMembershipUpdated": oktaEpoch,
		"objectClass": []string{"okta:user_group"}, "type": g.Type,
		"profile": obj{"name": g.Name, "description": g.Description},
		"_links": obj{
			"self":  o.link(base, "/api/v1/groups/"+g.ID),
			"users": o.link(base, "/api/v1/groups/"+g.ID+"/users"),
			"apps":  o.link(base, "/api/v1/groups/"+g.ID+"/apps"),
		},
	}
}

func (o *oktaOrg) appJSON(base string, a oktaAppDef) obj {
	return obj{
		"id": a.ID, "name": a.Name, "label": a.Label, "status": "ACTIVE",
		"created": oktaEpoch, "lastUpdated": oktaEpoch,
		"signOnMode": "SAML_2_0", "features": []string{},
		"accessibility": obj{"selfService": false},
		"visibility":    obj{"autoSubmitToolbar": false, "hide": obj{"iOS": false, "web": false}},
		"credentials":   obj{"userNameTemplate": obj{"template": "${source.login}", "type": "BUILT_IN"}},
		"settings":      obj{"app": obj{}},
		"_links": obj{
			"self":     o.link(base, "/api/v1/apps/"+a.ID),
			"users":    o.link(base, "/api/v1/apps/"+a.ID+"/users"),
			"groups":   o.link(base, "/api/v1/apps/"+a.ID+"/groups"),
			"metadata": o.link(base, "/api/v1/apps/"+a.ID+"/sso/saml/metadata"),
			"appLinks": []obj{{"name": a.Name + "_link", "type": "text/html",
				"href": o.browserURL + "/home/" + a.Name + "/" + a.ID + "/aln1"}},
		},
	}
}

func (o *oktaOrg) appUserJSON(base, appID string, u User, scope string) obj {
	id := o.userID(u)
	return obj{
		"id": id, "externalId": nil, "created": oktaEpoch, "lastUpdated": oktaEpoch,
		"scope": scope, "status": "ACTIVE", "statusChanged": oktaEpoch, "syncState": "DISABLED",
		"credentials": obj{"userName": u.UserName},
		"profile":     obj{},
		"_links": obj{
			"app":  o.link(base, "/api/v1/apps/"+appID),
			"user": o.link(base, "/api/v1/users/"+id),
		},
	}
}

func (o *oktaOrg) appGroupJSON(base, appID, gid string) obj {
	return obj{
		"id": gid, "lastUpdated": oktaEpoch, "priority": 0, "profile": obj{},
		"_links": obj{
			"app":   o.link(base, "/api/v1/apps/"+appID),
			"group": o.link(base, "/api/v1/groups/"+gid),
		},
	}
}

// ---- HTTP ----

// apiHandler serves /api/v1/... and /oauth2/... on the Okta listener.
func (o *oktaOrg) apiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/v1/token", o.token)
	mux.HandleFunc("POST /oauth2/default/v1/token", o.token)

	api := func(pattern string, h func(w http.ResponseWriter, r *http.Request, base string)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" { // any token is fine, but one is required
				oktaError(w, http.StatusUnauthorized, "E0000011", "Invalid token provided")
				return
			}
			h(w, r, "https://"+r.Host)
		})
	}
	api("GET /api/v1/users", o.listUsers)
	api("GET /api/v1/users/{id}", o.getUser)
	api("GET /api/v1/users/{id}/groups", o.listUserGroups)
	api("GET /api/v1/users/{id}/appLinks", o.listUserAppLinks)
	api("GET /api/v1/groups", o.listGroups)
	api("GET /api/v1/groups/{id}", o.getGroup)
	api("GET /api/v1/groups/{id}/users", o.listGroupUsers)
	api("PUT /api/v1/groups/{id}/users/{uid}", o.addGroupUser)
	api("DELETE /api/v1/groups/{id}/users/{uid}", o.removeGroupUser)
	api("GET /api/v1/groups/{id}/apps", o.listGroupApps)
	api("GET /api/v1/apps", o.listApps)
	api("GET /api/v1/apps/{id}", o.getApp)
	api("GET /api/v1/apps/{id}/users", o.listAppUsers)
	api("GET /api/v1/apps/{id}/users/{uid}", o.getAppUser)
	api("POST /api/v1/apps/{id}/users", o.assignAppUser)
	api("PUT /api/v1/apps/{id}/users/{uid}", o.assignAppUser)
	api("DELETE /api/v1/apps/{id}/users/{uid}", o.unassignAppUser)
	api("GET /api/v1/apps/{id}/groups", o.listAppGroups)
	api("GET /api/v1/apps/{id}/groups/{gid}", o.getAppGroup)
	api("PUT /api/v1/apps/{id}/groups/{gid}", o.assignAppGroup)
	api("DELETE /api/v1/apps/{id}/groups/{gid}", o.unassignAppGroup)
	api("GET /api/v1/logs", func(w http.ResponseWriter, r *http.Request, _ string) { writeJSON(w, http.StatusOK, []obj{}) })

	// Anything else: log loudly so gaps are easy to spot.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("okta: UNIMPLEMENTED %s %s", r.Method, r.URL.RequestURI())
		oktaNotFound(w, r.URL.Path)
	})

	return o.calls.wrap(mux, false)
}

// token accepts any client credentials / client assertion and returns an
// opaque access token with whatever scopes were requested.
func (o *oktaOrg) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	b := make([]byte, 24)
	rand.Read(b)
	log.Printf("okta: issued access token (client_id=%q grant_type=%q)", r.Form.Get("client_id"), r.Form.Get("grant_type"))
	writeJSON(w, http.StatusOK, obj{
		"token_type":   "Bearer",
		"expires_in":   3600,
		"access_token": hex.EncodeToString(b),
		"scope":        r.Form.Get("scope"),
	})
}

func (o *oktaOrg) listUsers(w http.ResponseWriter, r *http.Request, base string) {
	var items []obj
	for _, u := range OktaUsers {
		items = append(items, o.userJSON(base, u))
	}
	items = filterItems(items, r, "profile.login", "profile.email", "profile.firstName", "profile.lastName")
	if s := r.URL.Query().Get("search"); s != "" {
		items = applyFilter(items, s)
	}
	paginate(w, r, items)
}

func (o *oktaOrg) getUser(w http.ResponseWriter, r *http.Request, base string) {
	u, ok := o.userByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (User)")
		return
	}
	writeJSON(w, http.StatusOK, o.userJSON(base, u))
}

func (o *oktaOrg) listUserGroups(w http.ResponseWriter, r *http.Request, base string) {
	u, ok := o.userByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (User)")
		return
	}
	o.mu.Lock()
	groups := o.userGroups(o.userID(u))
	o.mu.Unlock()
	items := []obj{}
	for _, g := range groups {
		items = append(items, o.groupJSON(base, g))
	}
	paginate(w, r, items)
}

func (o *oktaOrg) listUserAppLinks(w http.ResponseWriter, r *http.Request, base string) {
	u, ok := o.userByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (User)")
		return
	}
	uid := o.userID(u)
	o.mu.Lock()
	defer o.mu.Unlock()
	items := []obj{}
	for i, a := range o.apps {
		if _, ok := o.appUserScopes(a.ID)[uid]; ok {
			items = append(items, obj{
				"id": oktaID("00a", a.ID+uid), "label": a.Label, "appName": a.Name,
				"appInstanceId": a.ID, "appAssignmentId": oktaID("0ua", a.ID+uid),
				"linkUrl": o.browserURL + "/home/" + a.Name + "/" + a.ID + "/aln1",
				"logoUrl": "", "hidden": false, "sortOrder": i, "credentialsSetup": false,
			})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (o *oktaOrg) listGroups(w http.ResponseWriter, r *http.Request, base string) {
	var items []obj
	for _, g := range o.groups {
		items = append(items, o.groupJSON(base, g))
	}
	items = filterItems(items, r, "profile.name")
	if s := r.URL.Query().Get("search"); s != "" {
		items = applyFilter(items, s)
	}
	paginate(w, r, items)
}

func (o *oktaOrg) getGroup(w http.ResponseWriter, r *http.Request, base string) {
	g, ok := o.groupByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (UserGroup)")
		return
	}
	writeJSON(w, http.StatusOK, o.groupJSON(base, g))
}

func (o *oktaOrg) listGroupUsers(w http.ResponseWriter, r *http.Request, base string) {
	g, ok := o.groupByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (UserGroup)")
		return
	}
	o.mu.Lock()
	members := slices.Clone(o.state.GroupMembers[g.ID])
	o.mu.Unlock()
	items := []obj{}
	for _, uid := range members {
		if u, ok := o.userByID(uid); ok {
			items = append(items, o.userJSON(base, u))
		}
	}
	paginate(w, r, items)
}

func (o *oktaOrg) addGroupUser(w http.ResponseWriter, r *http.Request, _ string) {
	o.mutateGroupMembership(w, r, true)
}

func (o *oktaOrg) removeGroupUser(w http.ResponseWriter, r *http.Request, _ string) {
	o.mutateGroupMembership(w, r, false)
}

func (o *oktaOrg) mutateGroupMembership(w http.ResponseWriter, r *http.Request, add bool) {
	g, ok := o.groupByID(r.PathValue("id"))
	u, uok := o.userByID(r.PathValue("uid"))
	if !ok || !uok {
		oktaNotFound(w, r.URL.Path)
		return
	}
	if g.Type == "BUILT_IN" {
		oktaError(w, http.StatusBadRequest, "E0000001", "Api validation failed: Cannot modify the Everyone group")
		return
	}
	uid := o.userID(u)
	o.mu.Lock()
	o.state.GroupMembers[g.ID] = setMember(o.state.GroupMembers[g.ID], uid, add)
	err := o.save()
	o.mu.Unlock()
	if err != nil {
		oktaError(w, http.StatusInternalServerError, "E0000009", err.Error())
		return
	}
	log.Printf("okta: %s %s group %s", verbAddRemove(add), u.UserName, g.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (o *oktaOrg) listGroupApps(w http.ResponseWriter, r *http.Request, base string) {
	gid := r.PathValue("id")
	o.mu.Lock()
	defer o.mu.Unlock()
	items := []obj{}
	for _, a := range o.apps {
		if slices.Contains(o.state.AppGroups[a.ID], gid) {
			items = append(items, o.appJSON(base, a))
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (o *oktaOrg) listApps(w http.ResponseWriter, r *http.Request, base string) {
	var items []obj
	for _, a := range o.apps {
		items = append(items, o.appJSON(base, a))
	}
	items = filterItems(items, r, "label", "name")
	paginate(w, r, items)
}

func (o *oktaOrg) getApp(w http.ResponseWriter, r *http.Request, base string) {
	a, ok := o.appByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (AppInstance)")
		return
	}
	writeJSON(w, http.StatusOK, o.appJSON(base, a))
}

func (o *oktaOrg) listAppUsers(w http.ResponseWriter, r *http.Request, base string) {
	a, ok := o.appByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (AppInstance)")
		return
	}
	o.mu.Lock()
	scopes := o.appUserScopes(a.ID)
	o.mu.Unlock()
	items := []obj{}
	for _, u := range OktaUsers {
		if scope, ok := scopes[o.userID(u)]; ok {
			items = append(items, o.appUserJSON(base, a.ID, u, scope))
		}
	}
	paginate(w, r, items)
}

func (o *oktaOrg) getAppUser(w http.ResponseWriter, r *http.Request, base string) {
	a, ok := o.appByID(r.PathValue("id"))
	u, uok := o.userByID(r.PathValue("uid"))
	if !ok || !uok {
		oktaNotFound(w, r.URL.Path)
		return
	}
	o.mu.Lock()
	scope, assigned := o.appUserScopes(a.ID)[o.userID(u)]
	o.mu.Unlock()
	if !assigned {
		oktaNotFound(w, r.PathValue("uid")+" (AppUser)")
		return
	}
	writeJSON(w, http.StatusOK, o.appUserJSON(base, a.ID, u, scope))
}

func (o *oktaOrg) assignAppUser(w http.ResponseWriter, r *http.Request, base string) {
	a, ok := o.appByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (AppInstance)")
		return
	}
	userRef := r.PathValue("uid")
	if userRef == "" {
		var body struct {
			ID string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		userRef = body.ID
	}
	u, uok := o.userByID(userRef)
	if !uok {
		oktaNotFound(w, userRef+" (User)")
		return
	}
	o.mu.Lock()
	o.state.AppUsers[a.ID] = setMember(o.state.AppUsers[a.ID], o.userID(u), true)
	err := o.save()
	o.mu.Unlock()
	if err != nil {
		oktaError(w, http.StatusInternalServerError, "E0000009", err.Error())
		return
	}
	log.Printf("okta: assigned %s to app %s", u.UserName, a.Label)
	writeJSON(w, http.StatusOK, o.appUserJSON(base, a.ID, u, "USER"))
}

func (o *oktaOrg) unassignAppUser(w http.ResponseWriter, r *http.Request, _ string) {
	a, ok := o.appByID(r.PathValue("id"))
	u, uok := o.userByID(r.PathValue("uid"))
	if !ok || !uok {
		oktaNotFound(w, r.URL.Path)
		return
	}
	o.mu.Lock()
	o.state.AppUsers[a.ID] = setMember(o.state.AppUsers[a.ID], o.userID(u), false)
	err := o.save()
	o.mu.Unlock()
	if err != nil {
		oktaError(w, http.StatusInternalServerError, "E0000009", err.Error())
		return
	}
	log.Printf("okta: unassigned %s from app %s", u.UserName, a.Label)
	w.WriteHeader(http.StatusNoContent)
}

func (o *oktaOrg) listAppGroups(w http.ResponseWriter, r *http.Request, base string) {
	a, ok := o.appByID(r.PathValue("id"))
	if !ok {
		oktaNotFound(w, r.PathValue("id")+" (AppInstance)")
		return
	}
	o.mu.Lock()
	gids := slices.Clone(o.state.AppGroups[a.ID])
	o.mu.Unlock()
	items := []obj{}
	for _, gid := range gids {
		items = append(items, o.appGroupJSON(base, a.ID, gid))
	}
	paginate(w, r, items)
}

func (o *oktaOrg) getAppGroup(w http.ResponseWriter, r *http.Request, base string) {
	a, ok := o.appByID(r.PathValue("id"))
	gid := r.PathValue("gid")
	o.mu.Lock()
	assigned := ok && slices.Contains(o.state.AppGroups[a.ID], gid)
	o.mu.Unlock()
	if !assigned {
		oktaNotFound(w, gid+" (ApplicationGroupAssignment)")
		return
	}
	writeJSON(w, http.StatusOK, o.appGroupJSON(base, a.ID, gid))
}

func (o *oktaOrg) assignAppGroup(w http.ResponseWriter, r *http.Request, base string) {
	o.mutateAppGroup(w, r, base, true)
}

func (o *oktaOrg) unassignAppGroup(w http.ResponseWriter, r *http.Request, base string) {
	o.mutateAppGroup(w, r, base, false)
}

func (o *oktaOrg) mutateAppGroup(w http.ResponseWriter, r *http.Request, base string, add bool) {
	a, ok := o.appByID(r.PathValue("id"))
	g, gok := o.groupByID(r.PathValue("gid"))
	if !ok || !gok {
		oktaNotFound(w, r.URL.Path)
		return
	}
	o.mu.Lock()
	o.state.AppGroups[a.ID] = setMember(o.state.AppGroups[a.ID], g.ID, add)
	err := o.save()
	o.mu.Unlock()
	if err != nil {
		oktaError(w, http.StatusInternalServerError, "E0000009", err.Error())
		return
	}
	if add {
		log.Printf("okta: assigned group %s to app %s", g.Name, a.Label)
		writeJSON(w, http.StatusOK, o.appGroupJSON(base, a.ID, g.ID))
		return
	}
	log.Printf("okta: unassigned group %s from app %s", g.Name, a.Label)
	w.WriteHeader(http.StatusNoContent)
}

// SetProvisioning stores the SCIM target pasted from Teleport's wizard. A
// blank token keeps the saved one (the form never echoes it back).
func (o *oktaOrg) SetProvisioning(rawURL, token string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.state.SCIMURL = scimTargetURL(rawURL)
	if t := strings.TrimSpace(token); t != "" {
		o.state.SCIMToken = t
	}
	return o.save()
}

// scimTargetURL normalizes a pasted SCIM base URL. The push runs inside the
// simulator container, where localhost is the simulator itself, so localhost
// is rewritten to Teleport's Docker network alias.
func scimTargetURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		if p := u.Port(); p != "" {
			u.Host = "teleport.localhost:" + p
		} else {
			u.Host = "teleport.localhost"
		}
		return u.String()
	}
	return raw
}

// Provisioning returns the SCIM target, if configured.
func (o *oktaOrg) Provisioning() (url, token string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.state.SCIMURL, o.state.SCIMToken
}

// SCIMGroups returns the groups Okta would push (not Everyone), with members.
func (o *oktaOrg) SCIMGroups() []scimGroup {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []scimGroup
	for _, g := range o.groups {
		if g.Type == "BUILT_IN" {
			continue
		}
		sg := scimGroup{Name: g.Name}
		for _, uid := range o.state.GroupMembers[g.ID] {
			if u, ok := o.userByID(uid); ok {
				sg.Members = append(sg.Members, u)
			}
		}
		out = append(out, sg)
	}
	return out
}

// ---- helpers ----

func setMember(list []string, id string, add bool) []string {
	list = slices.DeleteFunc(slices.Clone(list), func(s string) bool { return s == id })
	if add {
		list = append(list, id)
	}
	sort.Strings(list)
	return list
}

func verbAddRemove(add bool) string {
	if add {
		return "added"
	}
	return "removed"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// oktaNotFound writes Okta's 404, e.g. "Not found: Resource not found: 00u... (User)".
func oktaNotFound(w http.ResponseWriter, what string) {
	oktaError(w, http.StatusNotFound, "E0000007", "Not found: Resource not found: "+what)
}

func oktaError(w http.ResponseWriter, status int, code, summary string) {
	b := make([]byte, 8)
	rand.Read(b)
	writeJSON(w, status, obj{
		"errorCode": code, "errorSummary": summary, "errorLink": code,
		"errorId": "oae" + hex.EncodeToString(b), "errorCauses": []obj{},
	})
}

// filterItems applies Okta's q (prefix match on the given fields) and filter params.
func filterItems(items []obj, r *http.Request, qFields ...string) []obj {
	if q := strings.ToLower(r.URL.Query().Get("q")); q != "" {
		items = slices.DeleteFunc(items, func(it obj) bool {
			for _, f := range qFields {
				if v, ok := lookup(it, f).(string); ok && strings.HasPrefix(strings.ToLower(v), q) {
					return false
				}
			}
			return true
		})
	}
	if f := r.URL.Query().Get("filter"); f != "" {
		items = applyFilter(items, f)
	}
	return items
}

var (
	clauseRE = regexp.MustCompile(`^\(*\s*([\w.]+)\s+(eq|ne|sw|co|ew|pr|gt|ge|lt|le)\s*(?:"([^"]*)"|(\S+))?\s*\)*$`)
	// orRE and andRE split Okta and OData filters into clauses.
	orRE  = regexp.MustCompile(`(?i)\s+or\s+`)
	andRE = regexp.MustCompile(`(?i)\s+and\s+`)
)

// applyFilter evaluates a simple SCIM-style filter: clauses joined by "or"
// (outer) and "and" (inner). Comparisons other than eq/ne/sw/co/ew/pr match
// everything, so date filters never hide data.
func applyFilter(items []obj, filter string) []obj {
	orParts := orRE.Split(filter, -1)
	return slices.DeleteFunc(items, func(it obj) bool {
		for _, part := range orParts {
			all := true
			for _, clause := range andRE.Split(part, -1) {
				if !matchClause(it, strings.TrimSpace(clause)) {
					all = false
					break
				}
			}
			if all {
				return false
			}
		}
		return true
	})
}

func matchClause(it obj, clause string) bool {
	m := clauseRE.FindStringSubmatch(clause)
	if m == nil {
		return true // unknown syntax: don't filter
	}
	field, op, want := m[1], m[2], m[3]+m[4]
	got := fmt.Sprint(lookup(it, field))
	switch op {
	case "eq":
		return strings.EqualFold(got, want)
	case "ne":
		return !strings.EqualFold(got, want)
	case "sw":
		return strings.HasPrefix(strings.ToLower(got), strings.ToLower(want))
	case "ew":
		return strings.HasSuffix(strings.ToLower(got), strings.ToLower(want))
	case "co":
		return strings.Contains(strings.ToLower(got), strings.ToLower(want))
	case "pr":
		return lookup(it, field) != nil
	}
	return true
}

func lookup(it obj, path string) any {
	var cur any = it
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(obj)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// paginate writes items honoring limit/after and sets an Okta-style Link header.
func paginate(w http.ResponseWriter, r *http.Request, items []obj) {
	if items == nil {
		items = []obj{}
	}
	q := r.URL.Query()
	start := 0
	if after := q.Get("after"); after != "" {
		for i, it := range items {
			if it["id"] == after {
				start = i + 1
				break
			}
		}
	}
	limit := len(items)
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	end := min(start+limit, len(items))
	page := items[start:end]

	self := url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path, RawQuery: q.Encode()}
	links := []string{fmt.Sprintf("<%s>; rel=\"self\"", self.String())}
	if end < len(items) {
		q.Set("after", fmt.Sprint(page[len(page)-1]["id"]))
		q.Set("limit", strconv.Itoa(limit))
		nu := url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path, RawQuery: q.Encode()}
		links = append(links, fmt.Sprintf("<%s>; rel=\"next\"", nu.String()))
	}
	for _, l := range links {
		w.Header().Add("Link", l)
	}
	writeJSON(w, http.StatusOK, page)
}
