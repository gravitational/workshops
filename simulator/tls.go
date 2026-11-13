package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// microsoftNames are aliased to this container inside Docker only. They are
// always served with the internal simulator CA, which only Teleport trusts,
// so no certificate your host trusts is ever valid for Microsoft's domains.
var microsoftNames = []string{"login.microsoftonline.com", "graph.microsoft.com"}

// internalNames are the names on the internal-CA server certificate. Besides
// the Microsoft names it covers everything else too, as a fallback when no
// trusted (mkcert) certificate is configured.
var internalNames = append([]string{
	"localhost", "duo.localhost", "okta.localhost", "entra.localhost", "simulator",
}, microsoftNames...)

func caCertTemplate() *x509.Certificate {
	return &x509.Certificate{
		Subject:  pkix.Name{CommonName: "Simulator CA", Organization: []string{"Simulator"}},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
}

// serverTLSConfig loads (or creates) the simulator CA and issues a fresh
// server certificate from it. The CA is stable across restarts; the server
// cert is reissued each start so its names always match internalNames.
//
// If exportDir is set, the CA certificate is written there as
// simulator-ca.crt so other containers (Teleport) can trust it.
//
// If certFile and keyFile are set (a browser-trusted certificate, e.g. from
// mkcert), it is served for every name except the Microsoft ones.
func serverTLSConfig(dataDir, exportDir, certFile, keyFile string) (*tls.Config, error) {
	caKey, caCert, err := loadOrCreateKeyPair(dataDir, "ca", caCertTemplate())
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	if exportDir != "" {
		if err := os.MkdirAll(exportDir, 0o755); err != nil {
			return nil, err
		}
		path := filepath.Join(exportDir, "simulator-ca.crt")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0o644); err != nil {
			return nil, err
		}
		log.Printf("tls: exported CA certificate to %s", path)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: internalNames[0], Organization: []string{"Simulator"}},
		DNSNames:     internalNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	internal := &tls.Certificate{Certificate: [][]byte{der, caCert.Raw}, PrivateKey: key}

	if certFile == "" || keyFile == "" {
		return &tls.Config{Certificates: []tls.Certificate{*internal}}, nil
	}
	trusted, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", certFile, err)
	}
	log.Printf("tls: serving %s (internal CA only for %s)", certFile, strings.Join(microsoftNames, ", "))
	return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if slices.Contains(microsoftNames, strings.ToLower(hello.ServerName)) {
			return internal, nil
		}
		return &trusted, nil
	}}, nil
}
