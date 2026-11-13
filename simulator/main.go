// Command simulator is a fake identity provider for exercising Teleport.
//
// It runs two independent IdPs in one process:
//   - "Duo": a SAML 2.0 IdP with a password-less user picker, plus a SCIM
//     client that pushes users and groups to SCIM_URL.
//   - "Okta": a fake Okta org on its own port: Okta-shaped SAML app, the
//     Okta Management API and OAuth token endpoint (any credential accepted),
//     and SCIM provisioning configured from its admin console.
//   - "Entra ID": a fake Entra ID tenant on its own port: Entra-shaped SAML,
//     Microsoft identity platform token/discovery endpoints and Microsoft
//     Graph (any credential accepted). Teleport only calls Microsoft's real
//     hostnames, so Docker aliases them to this container.
//
// It runs with no CLI flags. Everything is optional and configured via env:
//
//	SIMULATOR_LISTEN_ADDR      Duo HTTP listen address  (default ":8080")
//	SIMULATOR_TLS_LISTEN_ADDR  Duo HTTPS listen address (default ":8443")
//	SIMULATOR_URL              Duo URL browsers use     (default "https://duo.localhost:8443")
//	SIMULATOR_DATA_DIR         keys and state           (default "./data")
//	SIMULATOR_CA_EXPORT_DIR    write the simulator CA cert here for others to trust
//	SIMULATOR_TLS_CERT         browser-trusted cert (e.g. mkcert) for all HTTPS listeners
//	SIMULATOR_TLS_KEY          its private key (both unset: internal CA cert everywhere)
//	OKTA_LISTEN_ADDR           Okta HTTPS listen address (default ":9443")
//	OKTA_URL                   Okta URL browsers use     (default "https://okta.localhost:9443")
//	OKTA_ORG_URL               Okta org URL given to Teleport (default OKTA_URL)
//	ENTRA_LISTEN_ADDR          Entra ID HTTPS listen address (default ":10443")
//	ENTRA_URL                  Entra ID URL browsers use     (default "https://entra.localhost:10443")
//	SCIM_URL                   Duo SCIM base URL to push to (Duo SCIM disabled if empty)
//	SCIM_TOKEN                 bearer token for SCIM_URL
//	SCIM_TOKEN_FILE            file holding the bearer token; re-read each sync
//	SCIM_INSECURE              "true" to skip TLS verification when pushing SCIM
//	SCIM_SYNC_INTERVAL         how often to re-sync (default "5m")
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"
)

// User is a directory user known to the simulator.
type User struct {
	ID        string // stable identifier, used as SCIM externalId
	UserName  string // login name; also the SAML NameID
	GivenName string
	Surname   string
	Email     string
	Title     string
	Groups    []string
}

func (u User) DisplayName() string { return u.GivenName + " " + u.Surname }
func (u User) Initials() string    { return u.GivenName[:1] + u.Surname[:1] }

// people is the fixed directory; UserName is the local part only.
var people = []User{
	{ID: "andrew", UserName: "andrew.admin", GivenName: "Andrew", Surname: "Admin", Title: "Administrator", Groups: []string{"admins", "dba"}},
	{ID: "roger", UserName: "roger.requester", GivenName: "Roger", Surname: "Requester", Title: "Access Requester", Groups: []string{"readonly"}},
	{ID: "randy", UserName: "randy.reviewer", GivenName: "Randy", Surname: "Reviewer", Title: "Access Reviewer", Groups: []string{"admins"}},
}

// Each IdP has the same people under its own email domain, so each Teleport
// integration gets its own users (an integration won't manage users that
// another one created).
var (
	DuoUsers   = inDomain("duo.example.com")
	OktaUsers  = inDomain("okta.example.com")
	EntraUsers = inDomain("entra.example.com")
)

func inDomain(domain string) []User {
	out := slices.Clone(people)
	for i := range out {
		out[i].UserName += "@" + domain
		out[i].Email = out[i].UserName
	}
	return out
}

func findUser(users []User, id string) (User, bool) {
	for _, u := range users {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

// Groups returns every group name referenced by a user, in stable order.
func Groups() []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range people {
		for _, g := range u.Groups {
			if !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
	}
	return out
}

type Config struct {
	ListenAddr    string
	TLSListenAddr string
	BaseURL       string
	DataDir       string
	SCIMURL       string
	SCIMToken     string
	SCIMTokenFile string
	SCIMInsecure  bool
	SCIMInterval  time.Duration

	CAExportDir string
	TLSCertFile string
	TLSKeyFile  string

	OktaListenAddr string
	OktaURL        string
	OktaOrgURL     string

	EntraListenAddr string
	EntraURL        string
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	interval, err := time.ParseDuration(env("SCIM_SYNC_INTERVAL", "5m"))
	if err != nil {
		log.Fatalf("invalid SCIM_SYNC_INTERVAL: %v", err)
	}
	cfg := Config{
		ListenAddr:    env("SIMULATOR_LISTEN_ADDR", ":8080"),
		TLSListenAddr: env("SIMULATOR_TLS_LISTEN_ADDR", ":8443"),
		BaseURL:       strings.TrimRight(env("SIMULATOR_URL", "https://duo.localhost:8443"), "/"),
		DataDir:       env("SIMULATOR_DATA_DIR", "./data"),
		SCIMURL:       strings.TrimRight(env("SCIM_URL", ""), "/"),
		SCIMToken:     env("SCIM_TOKEN", ""),
		SCIMTokenFile: env("SCIM_TOKEN_FILE", ""),
		SCIMInsecure:  env("SCIM_INSECURE", "") == "true",
		SCIMInterval:  interval,
		CAExportDir:   env("SIMULATOR_CA_EXPORT_DIR", ""),
		TLSCertFile:   env("SIMULATOR_TLS_CERT", ""),
		TLSKeyFile:    env("SIMULATOR_TLS_KEY", ""),

		OktaListenAddr: env("OKTA_LISTEN_ADDR", ":9443"),
		OktaURL:        strings.TrimRight(env("OKTA_URL", "https://okta.localhost:9443"), "/"),

		EntraListenAddr: env("ENTRA_LISTEN_ADDR", ":10443"),
		EntraURL:        strings.TrimRight(env("ENTRA_URL", "https://entra.localhost:10443"), "/"),
	}
	cfg.OktaOrgURL = strings.TrimRight(env("OKTA_ORG_URL", cfg.OktaURL), "/")
	return cfg
}

func main() {
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tlsConfig, err := serverTLSConfig(cfg.DataDir, cfg.CAExportDir, cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	// Duo-style IdP.
	idp, err := newIDP(cfg)
	if err != nil {
		log.Fatalf("saml: %v", err)
	}
	scim := newSCIMClient(cfg, "scim", DuoUsers, envSCIMTarget(cfg), func() []scimGroup { return staticGroups(DuoUsers) })
	scim.disabled = cfg.SCIMURL == ""
	go scim.run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", homeHandler(idp, scim, cfg.OktaURL))
	mux.HandleFunc("POST /scim/sync", func(w http.ResponseWriter, r *http.Request) {
		scim.trigger()
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /saml/metadata", idp.ServeMetadata)
	mux.HandleFunc("GET /sso/saml/metadata", idp.ServeMetadata) // same URL shape as Okta/Entra
	mux.HandleFunc("/saml/sso", idp.ServeSSO)
	mux.HandleFunc("GET /healthz", healthz)

	// Okta org.
	org, err := newOktaOrg(cfg)
	if err != nil {
		log.Fatalf("okta: %v", err)
	}
	oktaIDP, err := newOktaIDP(cfg, org)
	if err != nil {
		log.Fatalf("okta saml: %v", err)
	}
	oktaSCIM := newSCIMClient(cfg, "okta-scim", OktaUsers, func() (string, string, error) {
		u, t := org.Provisioning()
		return u, t, nil
	}, org.SCIMGroups)
	oktaSCIM.userExternalID = org.userID
	oktaSCIM.groupExternalID = func(name string) string { return org.groupByName(name).ID }
	go oktaSCIM.run(ctx)

	// Entra ID tenant.
	entra, err := newEntraDir(cfg)
	if err != nil {
		log.Fatalf("entra: %v", err)
	}

	// Duo: HTTP (in-network metadata) and HTTPS (browsers). Okta, Entra: HTTPS only.
	servers := []*http.Server{
		{Addr: cfg.ListenAddr, Handler: logRequests("duo", mux)},
		{Addr: cfg.TLSListenAddr, Handler: logRequests("duo", mux), TLSConfig: tlsConfig},
		{Addr: cfg.OktaListenAddr, Handler: logRequests("okta", oktaHandler(org, oktaIDP, oktaSCIM)), TLSConfig: tlsConfig},
		{Addr: cfg.EntraListenAddr, Handler: logRequests("entra", entra.handler()), TLSConfig: tlsConfig},
	}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		srv.ReadHeaderTimeout = 10 * time.Second
		go func() {
			if srv.TLSConfig != nil {
				errc <- srv.ListenAndServeTLS("", "")
			} else {
				errc <- srv.ListenAndServe()
			}
		}()
	}
	log.Printf("duo:  listening on %s (http) and %s (https); console %s", cfg.ListenAddr, cfg.TLSListenAddr, cfg.BaseURL)
	log.Printf("okta: listening on %s (https); console %s; org URL %s", cfg.OktaListenAddr, cfg.OktaURL, cfg.OktaOrgURL)
	log.Printf("entra: listening on %s (https); console %s", cfg.EntraListenAddr, cfg.EntraURL)
	printOktaWizardValues(org)
	printEntraWizardValues(entra)

	select {
	case <-ctx.Done():
	case err := <-errc:
		log.Fatal(err)
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(shutdown)
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }

func logRequests(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			log.Printf("%s: %s %s", name, r.Method, r.URL.RequestURI())
		}
		next.ServeHTTP(w, r)
	})
}

// printOktaWizardValues prints what to paste into Teleport's Okta enrollment
// wizard (/web/integrations/new/okta), so it's visible in the startup logs.
func printOktaWizardValues(org *oktaOrg) {
	for _, l := range []string{
		"Values for Teleport's Okta wizard (/web/integrations/new/okta):",
		"  Metadata URL:          " + org.orgURL + "/sso/saml/metadata",
		"  Okta organization URL: " + org.orgURL,
		"  Teleport app ID:       " + org.teleport.ID,
		"  OAuth client ID:       any value (e.g. 0oasimulatorclient)",
		"  API token:             any value",
		"  SCIM: paste the wizard's base URL and token at " + org.browserURL + "/#provisioning",
	} {
		log.Printf("okta: %s", l)
	}
}

// printEntraWizardValues prints what to paste into Teleport's Entra ID
// enrollment wizard (/web/integrations/new/entra-id).
func printEntraWizardValues(d *entraDir) {
	for _, l := range []string{
		"Values for Teleport's Entra ID wizard (/web/integrations/new/entra-id):",
		"  Tenant ID: " + d.TenantID,
		"  Client ID: " + d.ClientID,
		"  (skip the Azure Cloud Shell script; Teleport derives the metadata URL from these IDs)",
	} {
		log.Printf("entra: %s", l)
	}
}
