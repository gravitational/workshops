// Package ghes implements a simulated GitHub Enterprise Server.
package ghes

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

// Issuer signs GitHub Actions ID tokens and serves the OIDC discovery
// document and JWKS that verifiers (Teleport's github join method) fetch.
type Issuer struct {
	key       *rsa.PrivateKey
	kid       string
	issuerURL string
}

// NewIssuer returns an issuer for issuerURL
// (on GHES, https://<host>/_services/token)
// signing with key.
func NewIssuer(key *rsa.PrivateKey, issuerURL string) *Issuer {
	return &Issuer{key: key, kid: thumbprint(&key.PublicKey), issuerURL: issuerURL}
}

// URL returns the issuer URL, the value of the `iss` claim.
func (i *Issuer) URL() string { return i.issuerURL }

// Sign returns claims as an RS256 JWT whose header kid matches the JWKS.
func (i *Issuer) Sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": i.kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// DiscoveryHandler serves {issuer}/.well-known/openid-configuration.
func (i *Issuer) DiscoveryHandler() http.HandlerFunc {
	doc := map[string]any{
		"issuer":                                i.issuerURL,
		"jwks_uri":                              i.issuerURL + "/.well-known/jwks",
		"subject_types_supported":               []string{"public", "pairwise"},
		"response_types_supported":              []string{"id_token"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid"},
		"claims_supported": []string{
			"sub", "aud", "exp", "iat", "iss", "jti", "nbf",
			"ref", "ref_protected", "ref_type", "sha",
			"repository", "repository_id", "repository_owner", "repository_owner_id", "repository_visibility",
			"run_id", "run_number", "run_attempt", "runner_environment",
			"actor", "actor_id", "workflow", "workflow_ref", "workflow_sha",
			"job_workflow_ref", "job_workflow_sha",
			"head_ref", "base_ref", "event_name", "environment", "enterprise", "enterprise_id",
		},
	}
	return jsonHandler(doc)
}

// JWKSHandler serves {issuer}/.well-known/jwks with the issuer's public key.
func (i *Issuer) JWKSHandler() http.HandlerFunc {
	pub := i.key.PublicKey
	set := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": i.kid,
		"n":   b64(pub.N.Bytes()),
		"e":   b64(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	return jsonHandler(set)
}

func jsonHandler(v any) http.HandlerFunc {
	body, err := json.Marshal(v)
	if err != nil {
		panic(err) // static maps of strings; can't fail
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}
}

// thumbprint returns the RFC 7638 JWK thumbprint of pub, base64url-encoded.
func thumbprint(pub *rsa.PublicKey) string {
	// Members in lexicographic order, no whitespace, per RFC 7638 §3.
	e := b64(big.NewInt(int64(pub.E)).Bytes())
	n := b64(pub.N.Bytes())
	sum := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))
	return b64(sum[:])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
