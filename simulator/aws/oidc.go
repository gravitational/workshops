package aws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwtClaims are the web identity token claims STS looks at.
type jwtClaims struct {
	Issuer    string     `json:"iss"`
	Subject   string     `json:"sub"`
	Audience  stringList `json:"aud"`
	Expiry    int64      `json:"exp"`
	NotBefore int64      `json:"nbf"`
	raw       map[string]any
}

// parseJWT splits a compact JWS and decodes its header and claims, without
// verifying it.
func parseJWT(token string) (header struct{ Alg, Kid string }, claims jwtClaims, signed, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return header, claims, nil, nil, errors.New("not a JWT")
	}
	h, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	p, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return header, claims, nil, nil, err
	}
	if err := json.Unmarshal(h, &header); err != nil {
		return header, claims, nil, nil, err
	}
	if err := json.Unmarshal(p, &claims); err != nil {
		return header, claims, nil, nil, err
	}
	json.Unmarshal(p, &claims.raw)
	return header, claims, []byte(parts[0] + "." + parts[1]), sig, nil
}

// jwksCache fetches and caches issuers' signing keys, as STS does.
type jwksCache struct {
	client *http.Client
	mu     sync.Mutex
	keys   map[string]cachedKeys // by issuer
}

type cachedKeys struct {
	fetched time.Time
	keys    map[string]crypto.PublicKey // by kid
}

func newJWKSCache(client *http.Client) *jwksCache {
	return &jwksCache{client: client, keys: map[string]cachedKeys{}}
}

// verify checks the token's signature against its issuer's JWKS.
func (c *jwksCache) verify(issuer string, alg, kid string, signed, sig []byte) error {
	keys, err := c.issuerKeys(issuer, false)
	if err != nil {
		return err
	}
	if _, ok := keys[kid]; !ok {
		// Keys may have rotated: refetch once.
		if keys, err = c.issuerKeys(issuer, true); err != nil {
			return err
		}
	}
	var candidates []crypto.PublicKey
	if k, ok := keys[kid]; ok {
		candidates = []crypto.PublicKey{k}
	} else if kid == "" {
		for _, k := range keys {
			candidates = append(candidates, k)
		}
	}
	digest := sha256.Sum256(signed)
	for _, key := range candidates {
		switch k := key.(type) {
		case *rsa.PublicKey:
			if alg == "RS256" && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil {
				return nil
			}
		case *ecdsa.PublicKey:
			if alg == "ES256" && len(sig) == 64 &&
				ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				return nil
			}
		}
	}
	return fmt.Errorf("signature does not verify with any %s key from %s", alg, issuer)
}

func (c *jwksCache) issuerKeys(issuer string, refresh bool) (map[string]crypto.PublicKey, error) {
	c.mu.Lock()
	cached, ok := c.keys[issuer]
	c.mu.Unlock()
	if ok && !refresh && time.Since(cached.fetched) < 5*time.Minute {
		return cached.keys, nil
	}

	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := c.getJSON(strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", &discovery); err != nil {
		return nil, err
	}
	if discovery.JWKSURI == "" {
		return nil, fmt.Errorf("%s: openid-configuration has no jwks_uri", issuer)
	}
	var jwks struct {
		Keys []struct {
			Kty, Kid, Crv, N, E, X, Y string
		} `json:"keys"`
	}
	if err := c.getJSON(discovery.JWKSURI, &jwks); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range jwks.Keys {
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	c.mu.Lock()
	c.keys[issuer] = cachedKeys{fetched: time.Now(), keys: keys}
	c.mu.Unlock()
	return keys, nil
}

func (c *jwksCache) getJSON(url string, v any) error {
	resp, err := c.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(v)
}
