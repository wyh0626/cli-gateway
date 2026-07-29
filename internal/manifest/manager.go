package manifest

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

const reloadDebounce = 150 * time.Millisecond

// Manager owns the active immutable manifest snapshot.
type Manager struct {
	path    string
	current atomic.Pointer[Snapshot]
	reload  sync.Mutex
}

// NewManager loads the initial manifest. Initial failure is fatal to the caller.
func NewManager(path string) (*Manager, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve manifest path: %w", err)
	}
	snapshot, err := LoadFile(absolutePath)
	if err != nil {
		return nil, err
	}
	manager := &Manager{path: absolutePath}
	manager.current.Store(snapshot)
	return manager, nil
}

// Current returns the active immutable-by-contract snapshot.
func (m *Manager) Current() *Snapshot {
	return m.current.Load()
}

// Reload compiles the file completely before atomically replacing Current.
func (m *Manager) Reload() error {
	m.reload.Lock()
	defer m.reload.Unlock()

	next, err := LoadFile(m.path)
	if err != nil {
		return err
	}
	previous := m.current.Load()
	if err := restartOnlyChanged(previous, next); err != nil {
		return err
	}
	m.current.Store(next)
	return nil
}

// Watch reloads on writes, creates, and renames of the manifest file.
// Reload failures are reported and the previous snapshot remains active.
func (m *Manager) Watch(ctx context.Context, report func(error)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create manifest watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(filepath.Dir(m.path)); err != nil {
		return fmt.Errorf("watch manifest directory: %w", err)
	}

	var timer *time.Timer
	var timerChannel <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case watchErr, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			if report != nil {
				report(fmt.Errorf("manifest watcher: %w", watchErr))
			}
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			eventPath, pathErr := filepath.Abs(event.Name)
			if pathErr != nil || eventPath != m.path {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(reloadDebounce)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(reloadDebounce)
			}
			timerChannel = timer.C
		case <-timerChannel:
			timerChannel = nil
			if err := m.Reload(); err != nil && report != nil {
				report(fmt.Errorf("reload manifest: %w", err))
			}
		}
	}
}

func restartOnlyChanged(previous, next *Snapshot) error {
	if previous == nil || next == nil {
		return nil
	}
	if previous.Listen != next.Listen {
		return fmt.Errorf("server.listen requires restart")
	}
	if previous.PublicURL != next.PublicURL {
		return fmt.Errorf("server.public_url requires restart")
	}
	if previous.AuthMode != next.AuthMode {
		return fmt.Errorf("auth.mode requires restart")
	}
	if previous.AuthIssuer != next.AuthIssuer {
		return fmt.Errorf("auth.issuer requires restart")
	}
	if previous.AuthAudience != next.AuthAudience {
		return fmt.Errorf("auth.audience requires restart")
	}
	if previous.AuthClientID != next.AuthClientID {
		return fmt.Errorf("auth.client_id requires restart")
	}
	if previous.AuthResourceParameter != next.AuthResourceParameter {
		return fmt.Errorf("auth.resource_parameter requires restart")
	}
	if previous.AuthTrustedJWKS != next.AuthTrustedJWKS {
		return fmt.Errorf("auth.trusted_jwks requires restart")
	}
	if previous.AuthTLS != next.AuthTLS {
		return fmt.Errorf("auth.tls requires restart")
	}
	if previous.IdentityKeyFile != next.IdentityKeyFile {
		return fmt.Errorf("server.identity_key_file requires restart")
	}
	if !slices.Equal(previous.IdentityPreviousKeyFiles, next.IdentityPreviousKeyFiles) {
		return fmt.Errorf("server.identity_previous_key_files requires restart")
	}
	if previous.OAuthTokenStoreFile != next.OAuthTokenStoreFile {
		return fmt.Errorf("downstream_oauth.token_store_file requires restart")
	}
	if previous.OAuthEncryptionKeyRef != next.OAuthEncryptionKeyRef {
		return fmt.Errorf("downstream_oauth.encryption_key_ref requires restart")
	}
	if previous.OAuthStateTTL != next.OAuthStateTTL {
		return fmt.Errorf("downstream_oauth.state_ttl requires restart")
	}
	return nil
}

// CheckReloadCompatibility rejects fields whose supporting process-wide
// resources cannot be replaced safely through a hot reload.
func CheckReloadCompatibility(previous, next *Snapshot) error {
	return restartOnlyChanged(previous, next)
}
