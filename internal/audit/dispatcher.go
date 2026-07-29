package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyh0626/cli-gateway/internal/breaker"
	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/upstream"
)

// Sink writes one redacted audit event.
type Sink interface {
	Write(context.Context, Event) error
	Close() error
}

// DropObserver receives aggregate-safe audit loss telemetry.
type DropObserver interface {
	AddAuditDrops(uint64)
	RecordCircuitRejection()
}

// Dispatcher fan-outs events asynchronously through a bounded queue.
type Dispatcher struct {
	queue     chan Event
	sinks     []Sink
	logger    *slog.Logger
	closed    atomic.Bool
	dropped   atomic.Uint64
	closeOnce sync.Once
	mu        sync.RWMutex
	done      chan struct{}
	observer  DropObserver
}

// NewDispatcher starts a bounded audit worker.
func NewDispatcher(sinks []Sink, capacity int, logger *slog.Logger, observers ...DropObserver) (*Dispatcher, error) {
	if capacity <= 0 {
		return nil, errors.New("audit queue capacity must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	dispatcher := &Dispatcher{
		queue: make(chan Event, capacity), sinks: append([]Sink(nil), sinks...),
		logger: logger, done: make(chan struct{}),
	}
	if len(observers) != 0 {
		dispatcher.observer = observers[0]
	}
	go dispatcher.run()
	return dispatcher, nil
}

// Build opens all configured sinks. A failure closes sinks already opened.
func Build(configs []manifest.CompiledAuditSink, logger *slog.Logger, stdout io.Writer, observers ...DropObserver) (*Dispatcher, error) {
	if stdout == nil {
		stdout = os.Stdout
	}
	sinks := make([]Sink, 0, len(configs))
	closeOpened := func() {
		for _, sink := range sinks {
			_ = sink.Close()
		}
	}
	for _, config := range configs {
		var sink Sink
		switch config.Type {
		case "jsonl":
			created, err := newJSONLSink(config.Path)
			if err != nil {
				closeOpened()
				return nil, err
			}
			sink = created
		case "stdout":
			sink = &writerSink{writer: stdout}
		case "webhook":
			httpClient, err := upstream.NewClientWithTLS(config.Timeout, false, config.TLS)
			if err != nil {
				closeOpened()
				return nil, fmt.Errorf("initialize audit webhook transport: %w", err)
			}
			sink = &webhookSink{
				url:     config.URL.String(),
				http:    httpClient,
				timeout: config.Timeout,
				breaker: breaker.New(3, 30*time.Second),
			}
			if len(observers) != 0 {
				sink.(*webhookSink).observer = observers[0]
			}
		default:
			closeOpened()
			return nil, fmt.Errorf("unsupported audit sink %q", config.Type)
		}
		sinks = append(sinks, sink)
	}
	return NewDispatcher(sinks, 1024, logger, observers...)
}

// Record enqueues an event without blocking business traffic.
func (d *Dispatcher) Record(event Event) {
	if d == nil {
		return
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed.Load() {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	select {
	case d.queue <- event:
	default:
		d.dropped.Add(1)
		if d.observer != nil {
			d.observer.AddAuditDrops(1)
		}
		d.logger.Warn("audit event dropped", "trace_id", event.TraceID, "event", event.Event)
	}
}

// Dropped returns the number of events rejected by the bounded queue.
func (d *Dispatcher) Dropped() uint64 {
	if d == nil {
		return 0
	}
	return d.dropped.Load()
}

func (d *Dispatcher) run() {
	defer close(d.done)
	for event := range d.queue {
		for _, sink := range d.sinks {
			if err := sink.Write(context.Background(), event); err != nil {
				d.logger.Error("audit sink failed", "error", err, "trace_id", event.TraceID)
			}
		}
	}
}

// Close drains queued events until ctx expires and closes all sinks.
func (d *Dispatcher) Close(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.closed.Store(true)
		close(d.queue)
	})
	select {
	case <-d.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	var result error
	for _, sink := range d.sinks {
		result = errors.Join(result, sink.Close())
	}
	return result
}

type writerSink struct {
	mu     sync.Mutex
	writer io.Writer
}

func (s *writerSink) Write(_ context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.NewEncoder(s.writer).Encode(event)
}

func (*writerSink) Close() error { return nil }

type jsonlSink struct {
	writerSink
	file *os.File
}

func newJSONLSink(path string) (*jsonlSink, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit JSONL: %w", err)
	}
	return &jsonlSink{writerSink: writerSink{writer: file}, file: file}, nil
}

func (s *jsonlSink) Close() error { return s.file.Close() }

type webhookSink struct {
	url      string
	http     *http.Client
	timeout  time.Duration
	breaker  *breaker.Breaker
	observer DropObserver
}

func (s *webhookSink) Write(ctx context.Context, event Event) error {
	if allowed, retryAfter := s.breaker.Allow(); !allowed {
		if s.observer != nil {
			s.observer.RecordCircuitRejection()
		}
		return fmt.Errorf("audit webhook circuit is open for %s", retryAfter.Round(time.Second))
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	callContext, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callContext, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "cli-gateway/audit")
	request.Header.Set("X-Cli-Gateway-Trace-Id", event.TraceID)
	request.Header.Set("traceparent", httpx.TraceParent(event.TraceID))
	response, err := s.http.Do(request)
	if err != nil {
		s.breaker.Failure()
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode >= http.StatusInternalServerError {
			s.breaker.Failure()
		} else {
			s.breaker.Success()
		}
		return fmt.Errorf("audit webhook returned status %d", response.StatusCode)
	}
	s.breaker.Success()
	return nil
}

func (s *webhookSink) Close() error {
	s.http.CloseIdleConnections()
	return nil
}
