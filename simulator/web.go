package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"join":   strings.Join,
	"suffix": func(s string, n int) string { return s[max(0, len(s)-n):] },
}).ParseFS(templateFS, "templates/*.html"))

type loginPage struct {
	SAMLRequest string
	RelayState  string
	SP          string
	Users       []User
}

func render(w http.ResponseWriter, tmpl string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, tmpl, data); err != nil {
		log.Printf("render %s: %v", tmpl, err)
	}
}

func homeHandler(idp *saml.IdentityProvider, scim *scimClient, oktaURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, "home.html", map[string]any{
			"MetadataURL": idp.MetadataURL.String(),
			"SSOURL":      idp.SSOURL.String(),
			"EntityID":    idp.MetadataURL.String(),
			"Users":       DuoUsers,
			"SCIM":        scim.status(),
			"OktaURL":     oktaURL,
		})
	}
}

// consoleRow is one row of a users/groups/apps table on a console page.
type consoleRow struct {
	Name, ID, Detail string
	Members          []string
}

// callLog keeps the most recent API calls for display on a console page.
type callLog struct {
	mu    sync.Mutex
	calls []string // newest last
}

// wrap records every request next handles, with its response status.
func (c *callLog) wrap(next http.Handler, withHost bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		target := r.URL.RequestURI()
		if withHost {
			target = r.Host + target
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.calls = append(c.calls, fmt.Sprintf("%s %s %s → %d", time.Now().Format("15:04:05"), r.Method, target, rec.status))
		if len(c.calls) > 100 {
			c.calls = c.calls[len(c.calls)-100:]
		}
	})
}

// recent returns the logged calls, newest first.
func (c *callLog) recent() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := slices.Clone(c.calls)
	slices.Reverse(out)
	return out
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }

func oktaHomeHandler(org *oktaOrg, idp *saml.IdentityProvider, scim *scimClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org.mu.Lock()
		var users, groups, apps []consoleRow
		for _, u := range OktaUsers {
			var gs []string
			for _, g := range org.userGroups(org.userID(u)) {
				gs = append(gs, g.Name)
			}
			users = append(users, consoleRow{Name: u.DisplayName(), ID: org.userID(u), Detail: u.UserName, Members: gs})
		}
		for _, g := range org.groups {
			var ms []string
			for _, uid := range org.state.GroupMembers[g.ID] {
				if u, ok := org.userByID(uid); ok {
					ms = append(ms, u.UserName)
				}
			}
			groups = append(groups, consoleRow{Name: g.Name, ID: g.ID, Detail: g.Type, Members: ms})
		}
		for _, a := range org.apps {
			var as []string
			for _, gid := range org.state.AppGroups[a.ID] {
				if g, ok := org.groupByID(gid); ok {
					as = append(as, "group:"+g.Name)
				}
			}
			for _, uid := range org.state.AppUsers[a.ID] {
				if u, ok := org.userByID(uid); ok {
					as = append(as, "user:"+u.UserName)
				}
			}
			apps = append(apps, consoleRow{Name: a.Label, ID: a.ID, Detail: a.Name, Members: as})
		}
		scimURL, scimToken := org.state.SCIMURL, org.state.SCIMToken
		org.mu.Unlock()

		render(w, "okta_home.html", map[string]any{
			"OrgURL":      org.orgURL,
			"BrowserURL":  org.browserURL,
			"AppID":       org.teleport.ID,
			"MetadataURL": org.orgURL + "/sso/saml/metadata",
			"EntityID":    idp.MetadataURL.String(),
			"SSOURL":      idp.SSOURL.String(),
			"Users":       users,
			"Groups":      groups,
			"Apps":        apps,
			"SCIMURL":     scimURL,
			"HasToken":    scimToken != "",
			"SCIM":        scim.status(),
			"Calls":       org.calls.recent(),
		})
	}
}
