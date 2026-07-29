// Package upstream builds HTTP clients that enforce cli-gateway network boundaries.
package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// SafeDialer resolves a hostname, validates every result, and dials only the
// validated address. Proxying is disabled by the transport factory.
type SafeDialer struct {
	AllowLocal bool
	Resolver   *net.Resolver
	Dialer     *net.Dialer
}

// DialContext implements http.Transport.DialContext.
func (d SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split upstream address: %w", err)
	}
	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	addresses, err := resolve(ctx, resolver, host)
	if err != nil {
		return nil, err
	}
	for _, candidate := range addresses {
		if err := validateAddress(candidate, d.AllowLocal); err != nil {
			return nil, fmt.Errorf("upstream address %s rejected: %w", candidate, err)
		}
	}

	var lastErr error
	for _, candidate := range addresses {
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	return nil, fmt.Errorf("dial upstream: %w", lastErr)
}

func resolve(ctx context.Context, resolver *net.Resolver, host string) ([]netip.Addr, error) {
	if direct, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{direct.Unmap()}, nil
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream host: %w", err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve upstream host: no addresses")
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.Unmap())
	}
	return result, nil
}

func validateAddress(address netip.Addr, allowLocal bool) error {
	if !address.IsValid() || address.IsUnspecified() {
		return fmt.Errorf("unspecified address")
	}
	if address.IsMulticast() || address.IsLinkLocalUnicast() {
		return fmt.Errorf("multicast and link-local addresses are forbidden")
	}
	if address.IsLoopback() && !allowLocal {
		return fmt.Errorf("loopback requires network.allow_local=true")
	}
	return nil
}
