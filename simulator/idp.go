package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"compress/flate"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

const attrFormatBasic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

// newIDP builds a SAML IdP whose signing key is persisted in cfg.DataDir so
// the certificate (and therefore IdP metadata) is stable across restarts.
func newIDP(cfg Config) (*saml.IdentityProvider, error) {
	key, cert, err := loadOrCreateKeyPair(cfg.DataDir, "idp", &x509.Certificate{
		Subject:  pkix.Name{CommonName: "simulator", Organization: []string{"Simulator"}},
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SIMULATOR_URL: %w", err)
	}
	return &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		Logger:                  logger.DefaultLogger,
		MetadataURL:             *base.JoinPath("saml", "metadata"),
		SSOURL:                  *base.JoinPath("saml", "sso"),
		ServiceProviderProvider: anySP{},
		SessionProvider:         pickerSessions{template: "login.html", users: DuoUsers, attributes: duoAttributes},
		AssertionMaker:          saml.DefaultAssertionMaker{},
	}, nil
}

// anySP trusts any service provider. Metadata is synthesized from the
// AuthnRequest itself, so no SP registration is needed. Fine for a simulator,
// never for a real IdP.
type anySP struct{}

func (anySP) GetServiceProvider(r *http.Request, spID string) (*saml.EntityDescriptor, error) {
	req, err := parseAuthnRequest(r)
	if err != nil {
		return nil, err
	}
	if req.AssertionConsumerServiceURL == "" {
		return nil, errors.New("AuthnRequest has no AssertionConsumerServiceURL")
	}
	return &saml.EntityDescriptor{
		EntityID: spID,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			AssertionConsumerServices: []saml.IndexedEndpoint{{
				Binding:  saml.HTTPPostBinding,
				Location: req.AssertionConsumerServiceURL,
				Index:    1,
			}},
		}},
	}, nil
}

// parseAuthnRequest decodes the AuthnRequest from either the HTTP-Redirect
// binding (deflated, query string) or HTTP-POST binding (form body).
func parseAuthnRequest(r *http.Request) (*saml.AuthnRequest, error) {
	var raw []byte
	switch r.Method {
	case http.MethodGet:
		b, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLRequest"))
		if err != nil {
			return nil, err
		}
		raw, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(b)), 1<<20))
		if err != nil {
			return nil, err
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
		if err != nil {
			return nil, err
		}
		raw = b
	default:
		return nil, errors.New("method not allowed")
	}
	var req saml.AuthnRequest
	if err := xml.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// pickerSessions shows the user picker until a user is chosen. The picker
// posts the original SAMLRequest back to the SSO URL with a "user" field, so
// no cookies or server-side session state are required.
type pickerSessions struct {
	template   string                      // login page template
	users      []User                      // who can sign in
	attributes func(User) []saml.Attribute // assertion attributes for a user
}

func (p pickerSessions) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	if r.Method == http.MethodPost {
		if u, ok := findUser(p.users, r.PostForm.Get("user")); ok {
			log.Printf("saml: signing in %s for %s", u.UserName, req.ServiceProviderMetadata.EntityID)
			return sessionFor(u, p.attributes(u))
		}
	}
	render(w, p.template, loginPage{
		SAMLRequest: base64.StdEncoding.EncodeToString(req.RequestBuffer),
		RelayState:  req.RelayState,
		SP:          req.ServiceProviderMetadata.EntityID,
		Users:       p.users,
	})
	return nil
}

// samlAttr builds a plainly named string attribute.
func samlAttr(name string, vals ...string) saml.Attribute {
	a := saml.Attribute{FriendlyName: name, Name: name, NameFormat: attrFormatBasic}
	for _, v := range vals {
		a.Values = append(a.Values, saml.AttributeValue{Type: "xs:string", Value: v})
	}
	return a
}

// duoAttributes are the attributes the Duo-style IdP sends.
func duoAttributes(u User) []saml.Attribute {
	return []saml.Attribute{
		samlAttr("username", u.UserName),
		samlAttr("email", u.Email),
		samlAttr("firstName", u.GivenName),
		samlAttr("lastName", u.Surname),
		samlAttr("displayName", u.DisplayName()),
		samlAttr("groups", u.Groups...),
	}
}

func sessionFor(u User, attrs []saml.Attribute) *saml.Session {
	id := make([]byte, 16)
	rand.Read(id)
	now := saml.TimeNow()
	return &saml.Session{
		ID:           base64.RawURLEncoding.EncodeToString(id),
		CreateTime:   now,
		ExpireTime:   now.Add(8 * time.Hour),
		Index:        base64.RawURLEncoding.EncodeToString(id[:8]),
		NameID:       u.UserName,
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		// Only custom, plainly named attributes, so connector mappings stay readable.
		CustomAttributes: attrs,
	}
}

// loadOrCreateKeyPair loads <name>.key/<name>.crt from dir, or generates a
// self-signed pair from tmpl on first run so it stays stable across restarts.
func loadOrCreateKeyPair(dir, name string, tmpl *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyPath, certPath := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".crt")
	if keyPEM, err := os.ReadFile(keyPath); err == nil {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, nil, err
		}
		kb, _ := pem.Decode(keyPEM)
		cb, _ := pem.Decode(certPEM)
		if kb == nil || cb == nil {
			return nil, nil, fmt.Errorf("invalid PEM in %s", dir)
		}
		key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil {
			return nil, nil, err
		}
		cert, err := x509.ParseCertificate(cb.Bytes)
		return key, cert, err
	}

	log.Printf("generating new %s key pair in %s", name, dir)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().AddDate(10, 0, 0)
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}
