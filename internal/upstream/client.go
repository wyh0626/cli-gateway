package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
)

// NewClient returns a no-proxy, no-redirect client with a safe DNS dial path.
func NewClient(timeout time.Duration, allowLocal, insecureTLS bool) *http.Client {
	client, _ := NewClientWithTLS(timeout, allowLocal, model.TLSConfig{InsecureSkipVerify: insecureTLS})
	return client
}

// NewStreamingClient bounds connection and response-header setup but leaves
// response body lifetime to request cancellation and the caller's idle timer.
func NewStreamingClient(headerTimeout time.Duration, allowLocal, insecureTLS bool) *http.Client {
	client, _ := NewStreamingClientWithTLS(headerTimeout, allowLocal, model.TLSConfig{InsecureSkipVerify: insecureTLS})
	return client
}

// NewClientWithTLS loads trust roots and an optional client certificate.
func NewClientWithTLS(timeout time.Duration, allowLocal bool, options model.TLSConfig) (*http.Client, error) {
	return newClient(timeout, timeout, allowLocal, options)
}

// NewStreamingClientWithTLS constructs a streaming transport with TLS options.
func NewStreamingClientWithTLS(headerTimeout time.Duration, allowLocal bool, options model.TLSConfig) (*http.Client, error) {
	return newClient(0, headerTimeout, allowLocal, options)
}

func newClient(overallTimeout, headerTimeout time.Duration, allowLocal bool, options model.TLSConfig) (*http.Client, error) {
	if headerTimeout > 30*time.Second {
		headerTimeout = 30 * time.Second
	}
	tlsConfig, err := loadTLSConfig(options)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (SafeDialer{AllowLocal: allowLocal}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		MaxConnsPerHost:       256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
		TLSClientConfig:       tlsConfig,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   overallTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func loadTLSConfig(options model.TLSConfig) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.InsecureSkipVerify} //nolint:gosec -- manifest validation forbids this in production
	if options.CAFile != "" {
		contents, err := os.ReadFile(options.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read TLS CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate pool: %w", err)
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(contents) {
			return nil, errors.New("TLS CA file contains no certificates")
		}
		config.RootCAs = roots
	}
	if (options.ClientCertFile == "") != (options.ClientKeyFile == "") {
		return nil, errors.New("TLS client certificate and key must be configured together")
	}
	if options.ClientCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(options.ClientCertFile, options.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}
