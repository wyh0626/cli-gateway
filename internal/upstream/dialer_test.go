package upstream

import (
	"net/netip"
	"testing"
)

func TestValidateAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		address    string
		allowLocal bool
		wantError  bool
	}{
		{name: "public ipv4", address: "8.8.8.8"},
		{name: "private internal ipv4", address: "10.20.30.40"},
		{name: "loopback denied", address: "127.0.0.1", wantError: true},
		{name: "loopback development", address: "127.0.0.1", allowLocal: true},
		{name: "mapped loopback denied", address: "::ffff:127.0.0.1", wantError: true},
		{name: "link local always denied", address: "169.254.169.254", allowLocal: true, wantError: true},
		{name: "ipv6 loopback denied", address: "::1", wantError: true},
		{name: "unspecified denied", address: "0.0.0.0", allowLocal: true, wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address := netip.MustParseAddr(test.address).Unmap()
			err := validateAddress(address, test.allowLocal)
			if (err != nil) != test.wantError {
				t.Fatalf("validateAddress() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
