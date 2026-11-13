package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

// newOktaIDP builds the SAML IdP for the Okta "Teleport" app. It has its own
// signing key and Okta-shaped URLs and entity ID, so Teleport sees it as a
// different IdP from the Duo-style one:
//
//	entity ID: http://www.okta.com/{appId}
//	metadata:  {orgURL}/app/{appId}/sso/saml/metadata
//	SSO:       {browserURL}/app/teleport/{appId}/sso/saml
func newOktaIDP(cfg Config, org *oktaOrg) (*saml.IdentityProvider, error) {
	key, cert, err := loadOrCreateKeyPair(cfg.DataDir, "okta-idp", &x509.Certificate{
		Subject:  pkix.Name{CommonName: "okta-simulator", Organization: []string{"Simulator"}},
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		return nil, err
	}
	entityID, _ := url.Parse("http://www.okta.com/" + org.teleport.ID)
	sso, err := url.Parse(fmt.Sprintf("%s/app/%s/%s/sso/saml", cfg.OktaURL, org.teleport.Name, org.teleport.ID))
	if err != nil {
		return nil, fmt.Errorf("invalid OKTA_URL: %w", err)
	}
	return &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		Logger:                  logger.DefaultLogger,
		MetadataURL:             *entityID, // crewjam uses MetadataURL as the entity ID
		SSOURL:                  *sso,
		ServiceProviderProvider: anySP{},
		SessionProvider: pickerSessions{template: "okta_login.html", users: OktaUsers, attributes: func(u User) []saml.Attribute {
			// What Okta's Teleport app sends: login as username, all groups.
			return []saml.Attribute{
				samlAttr("username", u.UserName),
				samlAttr("groups", org.GroupNamesFor(u)...),
			}
		}},
		AssertionMaker: saml.DefaultAssertionMaker{},
	}, nil
}

// oktaHandler is everything served on the Okta listener.
func oktaHandler(org *oktaOrg, idp *saml.IdentityProvider, scim *scimClient) http.Handler {
	mux := http.NewServeMux()
	api := org.apiHandler()
	mux.Handle("/api/", api)
	mux.Handle("/oauth2/", api)

	metadata := func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != org.teleport.ID {
			oktaNotFound(w, r.PathValue("id")+" (AppInstance)")
			return
		}
		idp.ServeMetadata(w, r)
	}
	mux.HandleFunc("GET /app/{id}/sso/saml/metadata", metadata)
	mux.HandleFunc("GET /api/v1/apps/{id}/sso/saml/metadata", metadata)
	mux.HandleFunc("GET /sso/saml/metadata", idp.ServeMetadata) // short, static alias
	mux.HandleFunc("/app/{name}/{id}/sso/saml", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != org.teleport.ID {
			http.NotFound(w, r)
			return
		}
		idp.ServeSSO(w, r)
	})

	// App launch links (Teleport imports Okta apps with these as their URIs).
	mux.HandleFunc("GET /home/{name}/{id}/{link}", func(w http.ResponseWriter, r *http.Request) {
		a, ok := org.appByID(r.PathValue("id"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		render(w, "okta_app.html", map[string]any{"Label": a.Label, "ID": a.ID})
	})

	mux.HandleFunc("GET /{$}", oktaHomeHandler(org, idp, scim))
	mux.HandleFunc("POST /provisioning", func(w http.ResponseWriter, r *http.Request) {
		if err := org.SetProvisioning(r.FormValue("url"), r.FormValue("token")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("okta: provisioning target set to %q", r.FormValue("url"))
		scim.trigger()
		http.Redirect(w, r, "/#provisioning", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /provisioning/sync", func(w http.ResponseWriter, r *http.Request) {
		scim.trigger()
		http.Redirect(w, r, "/#provisioning", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /healthz", healthz)
	return mux
}
