package upstream

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/internal/model"
)

func TestNewClientWithTLSPreflightsTrustFiles(t *testing.T) {
	t.Parallel()
	_, err := NewClientWithTLS(time.Second, false, model.TLSConfig{ClientCertFile: "client.pem"})
	if err == nil {
		t.Fatal("incomplete client certificate pair was accepted")
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewClientWithTLS(time.Second, false, model.TLSConfig{CAFile: caFile})
	if err == nil {
		t.Fatal("invalid CA file was accepted")
	}
}
