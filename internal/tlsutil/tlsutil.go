// Package tlsutil builds the TLS configurations Flapjack services share:
// servers that require client certificates from the site CA (mutual TLS),
// and clients that trust only that CA and present their own certificate.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func pool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no PEM certificates", caFile)
	}
	return p, nil
}

// Server returns a TLS 1.3 server config. If clientCA is set, every client
// must present a certificate it signed.
func Server(certFile, keyFile, clientCA string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("TLS needs both a certificate and a key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	if clientCA != "" {
		if c.ClientCAs, err = pool(clientCA); err != nil {
			return nil, err
		}
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c, nil
}

// Client returns a TLS 1.3 client config trusting only caFile (system roots
// if empty) and presenting certFile/keyFile if set.
func Client(caFile, certFile, keyFile string) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS13}
	var err error
	if caFile != "" {
		if c.RootCAs, err = pool(caFile); err != nil {
			return nil, err
		}
	}
	if certFile != "" || keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		c.Certificates = []tls.Certificate{cert}
	}
	return c, nil
}
