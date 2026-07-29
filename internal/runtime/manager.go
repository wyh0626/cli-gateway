// Package runtime owns immutable, reference-counted data-plane generations.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyh0626/cli-gateway/internal/audit"
	"github.com/wyh0626/cli-gateway/internal/catalog"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/model"

	"github.com/fsnotify/fsnotify"
)

const reloadDebounce = 150 * time.Millisecond

// Components are generation-scoped services produced by a Builder.
type Components struct {
	Invoker model.InvocationService
	Audit   *audit.Dispatcher
	Close   func() error
}

// Builder preflights and creates all mutable resources for a snapshot before
// the generation is published.
type Builder func(*manifest.Snapshot) (Components, error)

// Generation is immutable after publication. Its lifecycle fields are private.
type Generation struct {
	ID       uint64
	Snapshot *manifest.Snapshot
	Catalog  *catalog.Service
	Invoker  model.InvocationService
	Audit    *audit.Dispatcher

	closeFn   func() error
	closeOnce sync.Once
	mu        sync.Mutex
	retired   bool
	active    int
	drained   chan struct{}
}

// Retain creates another lease on this generation while it is still active.
// It is used by stateful protocol sessions to protect in-flight calls during a
// generation migration.
func (g *Generation) Retain() (*Lease, bool) {
	if g == nil || !g.acquire() {
		return nil, false
	}
	return &Lease{Generation: g}, true
}

func newGeneration(id uint64, snapshot *manifest.Snapshot, components Components) (*Generation, error) {
	if snapshot == nil {
		return nil, errors.New("runtime snapshot is required")
	}
	if components.Invoker == nil {
		return nil, errors.New("runtime invocation service is required")
	}
	return &Generation{
		ID: id, Snapshot: snapshot, Catalog: catalog.New(snapshot), Invoker: components.Invoker,
		Audit: components.Audit, closeFn: components.Close, drained: make(chan struct{}),
	}, nil
}

func (g *Generation) acquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.retired {
		return false
	}
	g.active++
	return true
}

func (g *Generation) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active <= 0 {
		panic("runtime generation released without an active lease")
	}
	g.active--
	if g.retired && g.active == 0 {
		close(g.drained)
	}
}

func (g *Generation) retire() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.retired {
		return
	}
	g.retired = true
	if g.active == 0 {
		close(g.drained)
	}
}

func (g *Generation) close() error {
	var closeErr error
	g.closeOnce.Do(func() {
		if g.closeFn != nil {
			closeErr = g.closeFn()
		}
	})
	return closeErr
}

// Lease keeps one generation alive for an entire invocation or stream.
type Lease struct {
	Generation *Generation
	once       sync.Once
}

// Close releases the generation. It is safe to call more than once.
func (l *Lease) Close() error {
	if l == nil || l.Generation == nil {
		return nil
	}
	l.once.Do(l.Generation.release)
	return nil
}

// Manager compiles, preflights, and atomically publishes runtime generations.
type Manager struct {
	path         string
	builder      Builder
	drainTimeout time.Duration
	current      atomic.Pointer[Generation]
	nextID       atomic.Uint64
	reload       sync.Mutex
	subMu        sync.RWMutex
	subscribers  []func(previous, next *Generation)
	closed       atomic.Bool
}

// NewManager builds and publishes the initial runtime.
func NewManager(path string, drainTimeout time.Duration, builder Builder) (*Manager, error) {
	if builder == nil {
		return nil, errors.New("runtime builder is required")
	}
	if drainTimeout <= 0 {
		drainTimeout = 10 * time.Second
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve manifest path: %w", err)
	}
	snapshot, err := manifest.LoadFile(absolutePath)
	if err != nil {
		return nil, err
	}
	manager := &Manager{path: absolutePath, builder: builder, drainTimeout: drainTimeout}
	generation, err := manager.build(snapshot)
	if err != nil {
		return nil, err
	}
	manager.current.Store(generation)
	return manager, nil
}

func (m *Manager) build(snapshot *manifest.Snapshot) (*Generation, error) {
	components, err := m.builder(snapshot)
	if err != nil {
		return nil, fmt.Errorf("build runtime components: %w", err)
	}
	generation, err := newGeneration(m.nextID.Add(1), snapshot, components)
	if err != nil {
		if components.Close != nil {
			_ = components.Close()
		}
		return nil, err
	}
	return generation, nil
}

// Current returns the active generation for diagnostics only. Request paths
// must use Acquire so reload cannot close resources still in use.
func (m *Manager) Current() *Generation {
	if m == nil {
		return nil
	}
	return m.current.Load()
}

// Acquire retains the active generation.
func (m *Manager) Acquire() (*Lease, bool) {
	if m == nil || m.closed.Load() {
		return nil, false
	}
	for {
		generation := m.current.Load()
		if generation == nil {
			return nil, false
		}
		if generation.acquire() {
			return &Lease{Generation: generation}, true
		}
	}
}

// Reload publishes a fully built generation and drains the previous one.
func (m *Manager) Reload() error {
	m.reload.Lock()
	defer m.reload.Unlock()
	if m.closed.Load() {
		return errors.New("runtime manager is closed")
	}
	nextSnapshot, err := manifest.LoadFile(m.path)
	if err != nil {
		return err
	}
	previous := m.current.Load()
	if previous != nil {
		if err := manifest.CheckReloadCompatibility(previous.Snapshot, nextSnapshot); err != nil {
			return err
		}
	}
	next, err := m.build(nextSnapshot)
	if err != nil {
		return err
	}
	m.current.Store(next)
	m.notify(previous, next)
	if previous != nil {
		go m.drain(previous)
	}
	return nil
}

// Subscribe registers a best-effort generation change callback. Callbacks must
// return quickly and tolerate the manager being closed.
func (m *Manager) Subscribe(callback func(previous, next *Generation)) {
	if m == nil || callback == nil {
		return
	}
	m.subMu.Lock()
	defer m.subMu.Unlock()
	m.subscribers = append(m.subscribers, callback)
}

func (m *Manager) notify(previous, next *Generation) {
	m.subMu.RLock()
	callbacks := append([]func(previous, next *Generation){}, m.subscribers...)
	m.subMu.RUnlock()
	for _, callback := range callbacks {
		go callback(previous, next)
	}
}

func (m *Manager) drain(generation *Generation) {
	generation.retire()
	timer := time.NewTimer(m.drainTimeout)
	defer timer.Stop()
	select {
	case <-generation.drained:
	case <-timer.C:
	}
	_ = generation.close()
}

// Watch reloads the complete runtime after atomic file replacement or writes.
func (m *Manager) Watch(ctx context.Context, report func(error)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create runtime watcher: %w", err)
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
				report(fmt.Errorf("runtime watcher: %w", watchErr))
			}
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			eventPath, pathErr := filepath.Abs(event.Name)
			if pathErr != nil || eventPath != m.path || event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
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
				report(fmt.Errorf("reload runtime: %w", err))
			}
		}
	}
}

// Close stops new acquisitions, drains the active generation, and releases its
// resources. A context deadline bounds shutdown.
func (m *Manager) Close(ctx context.Context) error {
	if m == nil || !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	generation := m.current.Swap(nil)
	if generation == nil {
		return nil
	}
	generation.retire()
	select {
	case <-generation.drained:
	case <-ctx.Done():
		_ = generation.close()
		return ctx.Err()
	}
	return generation.close()
}
