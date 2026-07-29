package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
	"github.com/wyh0626/cli-gateway/internal/upstream"
)

const maxDiscoveryBytes = 1 << 20

// IssuerMetadata is the subset required by the protected resource.
type IssuerMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// DiscoverIssuer fetches and validates OIDC authorization-server metadata.
func DiscoverIssuer(ctx context.Context, issuer string, allowLocal bool) (IssuerMetadata, error) {
	return DiscoverIssuerWithTLS(ctx, issuer, allowLocal, model.TLSConfig{})
}

// DiscoverIssuerWithTLS fetches discovery with private-CA or mTLS trust.
func DiscoverIssuerWithTLS(ctx context.Context, issuer string, allowLocal bool, tlsConfig model.TLSConfig) (IssuerMetadata, error) {
	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return IssuerMetadata{}, err
	}
	request.Header.Set("Accept", "application/json")
	client, err := upstream.NewClientWithTLS(10*time.Second, allowLocal, tlsConfig)
	if err != nil {
		return IssuerMetadata{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return IssuerMetadata{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return IssuerMetadata{}, fmt.Errorf("OIDC discovery returned status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryBytes+1))
	if err != nil {
		return IssuerMetadata{}, err
	}
	if len(body) > maxDiscoveryBytes {
		return IssuerMetadata{}, errors.New("OIDC discovery exceeds 1 MiB")
	}
	var metadata IssuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return IssuerMetadata{}, fmt.Errorf("decode OIDC discovery: %w", err)
	}
	if strings.TrimSuffix(metadata.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		return IssuerMetadata{}, errors.New("OIDC discovery issuer mismatch")
	}
	if metadata.JWKSURI == "" {
		return IssuerMetadata{}, errors.New("OIDC discovery jwks_uri is missing")
	}
	jwksURL, err := url.Parse(metadata.JWKSURI)
	if err != nil || jwksURL.Hostname() == "" || jwksURL.User != nil || jwksURL.RawQuery != "" || jwksURL.Fragment != "" {
		return IssuerMetadata{}, errors.New("OIDC discovery jwks_uri is invalid")
	}
	host := jwksURL.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
	if jwksURL.Scheme != "https" && !(allowLocal && jwksURL.Scheme == "http" && loopback) {
		return IssuerMetadata{}, errors.New("OIDC discovery jwks_uri must use HTTPS except on loopback development issuers")
	}
	return metadata, nil
}
