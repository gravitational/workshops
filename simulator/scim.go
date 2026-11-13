package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimJSON    = "application/scim+json"
)

// errNotConfigured means the client has no target yet; it waits quietly.
var errNotConfigured = errors.New("provisioning target not configured")

// scimGroup is a group to push, with its members.
type scimGroup struct {
	Name    string
	Members []User
}

// scimClient pushes Users and Groups to a SCIM 2.0 service provider, acting
// the way an IdP's provisioning engine would. It upserts on every sync.
type scimClient struct {
	name     string                                    // log prefix, e.g. "scim" or "okta-scim"
	target   func() (baseURL, token string, err error) // where to push; errNotConfigured to wait
	users    []User                                    // users to push
	groups   func() []scimGroup                        // groups to push
	disabled bool

	// externalIds sent for users and groups. Okta sends its own object IDs,
	// which Teleport uses to look users up in the Okta API.
	userExternalID  func(User) string
	groupExternalID func(name string) string

	interval time.Duration
	http     *http.Client
	kick     chan struct{}

	base, bearer string // target for the sync in progress; only touched by run()

	mu       sync.Mutex
	lastSync time.Time
	lastErr  error
	log      []string
}

func newSCIMClient(cfg Config, name string, users []User, target func() (string, string, error), groups func() []scimGroup) *scimClient {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.SCIMInsecure}
	return &scimClient{
		name:            name,
		users:           users,
		target:          target,
		groups:          groups,
		userExternalID:  func(u User) string { return u.ID },
		groupExternalID: func(name string) string { return name },
		interval:        cfg.SCIMInterval,
		http:            &http.Client{Transport: tr, Timeout: 30 * time.Second},
		kick:            make(chan struct{}, 1),
	}
}

// envSCIMTarget is the env-configured target (SCIM_URL + SCIM_TOKEN[_FILE]).
func envSCIMTarget(cfg Config) func() (string, string, error) {
	return func() (string, string, error) {
		if cfg.SCIMTokenFile == "" {
			return cfg.SCIMURL, cfg.SCIMToken, nil
		}
		b, err := os.ReadFile(cfg.SCIMTokenFile)
		if err != nil || len(bytes.TrimSpace(b)) == 0 {
			return "", "", fmt.Errorf("waiting for token file %s", cfg.SCIMTokenFile)
		}
		return cfg.SCIMURL, string(bytes.TrimSpace(b)), nil
	}
}

// staticGroups derives groups from the fixed directory.
func staticGroups(users []User) []scimGroup {
	var out []scimGroup
	for _, g := range Groups() {
		sg := scimGroup{Name: g}
		for _, u := range users {
			if slices.Contains(u.Groups, g) {
				sg.Members = append(sg.Members, u)
			}
		}
		out = append(out, sg)
	}
	return out
}

func (c *scimClient) trigger() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (c *scimClient) run(ctx context.Context) {
	if c.disabled {
		log.Printf("%s: SCIM_URL not set; provisioning disabled", c.name)
		return
	}
	for {
		wait := c.interval
		if err := c.sync(ctx); err != nil && !errors.Is(err, errNotConfigured) {
			wait = 10 * time.Second // retry quickly while the target comes up
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-c.kick:
		}
	}
}

type scimStatus struct {
	Enabled  bool
	URL      string
	LastSync time.Time
	LastErr  error
	Log      []string
}

func (c *scimClient) status() scimStatus {
	base, _, _ := c.target()
	c.mu.Lock()
	defer c.mu.Unlock()
	return scimStatus{Enabled: !c.disabled, URL: base, LastSync: c.lastSync, LastErr: c.lastErr, Log: append([]string(nil), c.log...)}
}

func (c *scimClient) sync(ctx context.Context) error {
	var lines []string
	logf := func(format string, args ...any) {
		s := fmt.Sprintf(format, args...)
		log.Printf("%s: %s", c.name, s)
		lines = append(lines, s)
	}

	err := func() error {
		base, tok, err := c.target()
		if err != nil {
			return err
		}
		if base == "" {
			return errNotConfigured
		}
		c.base, c.bearer = strings.TrimRight(base, "/"), tok
		userIDs := map[string]string{} // simulator ID -> SCIM id
		for _, u := range c.users {
			id, created, err := c.upsert(ctx, "Users", "userName", u.UserName, userResource(u, c.userExternalID(u)))
			if err != nil {
				return fmt.Errorf("user %s: %w", u.UserName, err)
			}
			userIDs[u.ID] = id
			logf("%s user %s (id %s)", verb(created), u.UserName, id)
		}
		for _, g := range c.groups() {
			members := []map[string]string{}
			for _, u := range g.Members {
				members = append(members, map[string]string{"value": userIDs[u.ID], "display": u.UserName})
			}
			id, created, err := c.upsert(ctx, "Groups", "displayName", g.Name, map[string]any{
				"schemas":     []string{schemaGroup},
				"externalId":  c.groupExternalID(g.Name),
				"displayName": g.Name,
				"members":     members,
			})
			if err != nil {
				return fmt.Errorf("group %s: %w", g.Name, err)
			}
			logf("%s group %s (id %s, %d members)", verb(created), g.Name, id, len(members))
		}
		return nil
	}()
	if err != nil && !errors.Is(err, errNotConfigured) {
		logf("sync failed: %v", err)
	}

	c.mu.Lock()
	c.lastSync, c.lastErr, c.log = time.Now(), err, lines
	c.mu.Unlock()
	return err
}

func verb(created bool) string {
	if created {
		return "created"
	}
	return "updated"
}

func userResource(u User, externalID string) map[string]any {
	return map[string]any{
		"schemas":     []string{schemaUser},
		"externalId":  externalID,
		"userName":    u.UserName,
		"displayName": u.DisplayName(),
		"title":       u.Title,
		"active":      true,
		"name":        map[string]string{"givenName": u.GivenName, "familyName": u.Surname, "formatted": u.DisplayName()},
		"emails":      []map[string]any{{"value": u.Email, "type": "work", "primary": true}},
	}
}

// upsert finds a resource by attr eq value; PUTs it if found, POSTs otherwise.
func (c *scimClient) upsert(ctx context.Context, kind, attr, value string, body map[string]any) (id string, created bool, err error) {
	filter := fmt.Sprintf("%s eq %q", attr, value)
	var list struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if err := c.do(ctx, http.MethodGet, kind+"?filter="+url.QueryEscape(filter), nil, &list); err != nil {
		return "", false, err
	}
	var out struct {
		ID string `json:"id"`
	}
	if len(list.Resources) > 0 {
		id = list.Resources[0].ID
		body["id"] = id
		err = c.do(ctx, http.MethodPut, kind+"/"+url.PathEscape(id), body, &out)
		return id, false, err
	}
	err = c.do(ctx, http.MethodPost, kind, body, &out)
	return out.ID, true, err
}

func (c *scimClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", scimJSON)
	if in != nil {
		req.Header.Set("Content-Type", scimJSON)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
