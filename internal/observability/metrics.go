// Package observability contains bounded-cardinality gateway telemetry.
package observability

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

var durationBounds = [...]float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30}

// Registry is a dependency-free Prometheus text registry for core metrics.
type Registry struct {
	requestsTotal     atomic.Uint64
	inFlight          atomic.Int64
	authFailures      atomic.Uint64
	policyDenials     atomic.Uint64
	upstreamFailures  atomic.Uint64
	limiterRejections atomic.Uint64
	tokenCacheHits    atomic.Uint64
	tokenCacheMisses  atomic.Uint64
	tokenCacheWaiters atomic.Uint64
	auditDrops        atomic.Uint64
	tokenExchanges    atomic.Uint64
	tokenExchangeErrs atomic.Uint64
	tokenExchangeNS   atomic.Uint64
	reloadSuccesses   atomic.Uint64
	reloadFailures    atomic.Uint64
	activeMCPSessions atomic.Int64
	circuitRejections atomic.Uint64
	generation        atomic.Uint64
	durationCount     atomic.Uint64
	durationNanos     atomic.Uint64
	durationBuckets   [len(durationBounds)]atomic.Uint64
}

// Middleware records request count, in-flight work, and duration.
func (r *Registry) Middleware(next http.Handler) http.Handler {
	if r == nil {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		r.requestsTotal.Add(1)
		r.inFlight.Add(1)
		defer func() {
			r.inFlight.Add(-1)
			elapsed := time.Since(started)
			r.durationCount.Add(1)
			r.durationNanos.Add(uint64(elapsed))
			seconds := elapsed.Seconds()
			for index, bound := range durationBounds {
				if seconds <= bound {
					r.durationBuckets[index].Add(1)
				}
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func (r *Registry) RecordAuthFailure()      { r.authFailures.Add(1) }
func (r *Registry) RecordPolicyDenial()     { r.policyDenials.Add(1) }
func (r *Registry) RecordUpstreamFailure()  { r.upstreamFailures.Add(1) }
func (r *Registry) RecordLimiterRejection() { r.limiterRejections.Add(1) }
func (r *Registry) RecordTokenCache(result string) {
	switch result {
	case "hit", "stale":
		r.tokenCacheHits.Add(1)
	case "waiter":
		r.tokenCacheWaiters.Add(1)
	default:
		r.tokenCacheMisses.Add(1)
	}
}
func (r *Registry) AddAuditDrops(count uint64) { r.auditDrops.Add(count) }
func (r *Registry) SetGeneration(value uint64) { r.generation.Store(value) }
func (r *Registry) RecordTokenExchange(duration time.Duration, failed bool) {
	r.tokenExchanges.Add(1)
	r.tokenExchangeNS.Add(uint64(duration))
	if failed {
		r.tokenExchangeErrs.Add(1)
	}
}
func (r *Registry) RecordReload(success bool) {
	if success {
		r.reloadSuccesses.Add(1)
	} else {
		r.reloadFailures.Add(1)
	}
}
func (r *Registry) SetActiveMCPSessions(count int64) { r.activeMCPSessions.Store(count) }
func (r *Registry) RecordCircuitRejection()          { r.circuitRejections.Add(1) }

// ServeHTTP exports Prometheus text format with no principal or raw-path labels.
func (r *Registry) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	values := []struct {
		name  string
		kind  string
		value string
	}{
		{"cli_gateway_requests_total", "counter", strconv.FormatUint(r.requestsTotal.Load(), 10)},
		{"cli_gateway_in_flight", "gauge", strconv.FormatInt(r.inFlight.Load(), 10)},
		{"cli_gateway_auth_failures_total", "counter", strconv.FormatUint(r.authFailures.Load(), 10)},
		{"cli_gateway_policy_denials_total", "counter", strconv.FormatUint(r.policyDenials.Load(), 10)},
		{"cli_gateway_upstream_failures_total", "counter", strconv.FormatUint(r.upstreamFailures.Load(), 10)},
		{"cli_gateway_limiter_rejections_total", "counter", strconv.FormatUint(r.limiterRejections.Load(), 10)},
		{"cli_gateway_token_cache_hits_total", "counter", strconv.FormatUint(r.tokenCacheHits.Load(), 10)},
		{"cli_gateway_token_cache_misses_total", "counter", strconv.FormatUint(r.tokenCacheMisses.Load(), 10)},
		{"cli_gateway_token_cache_waiters_total", "counter", strconv.FormatUint(r.tokenCacheWaiters.Load(), 10)},
		{"cli_gateway_audit_drops_total", "counter", strconv.FormatUint(r.auditDrops.Load(), 10)},
		{"cli_gateway_token_exchanges_total", "counter", strconv.FormatUint(r.tokenExchanges.Load(), 10)},
		{"cli_gateway_token_exchange_failures_total", "counter", strconv.FormatUint(r.tokenExchangeErrs.Load(), 10)},
		{"cli_gateway_manifest_reload_successes_total", "counter", strconv.FormatUint(r.reloadSuccesses.Load(), 10)},
		{"cli_gateway_manifest_reload_failures_total", "counter", strconv.FormatUint(r.reloadFailures.Load(), 10)},
		{"cli_gateway_active_mcp_sessions", "gauge", strconv.FormatInt(r.activeMCPSessions.Load(), 10)},
		{"cli_gateway_circuit_rejections_total", "counter", strconv.FormatUint(r.circuitRejections.Load(), 10)},
		{"cli_gateway_runtime_generation", "gauge", strconv.FormatUint(r.generation.Load(), 10)},
	}
	for _, value := range values {
		_, _ = fmt.Fprintf(writer, "# TYPE %s %s\n%s %s\n", value.name, value.kind, value.name, value.value)
	}
	for index, bound := range durationBounds {
		_, _ = fmt.Fprintf(writer, "cli_gateway_request_duration_seconds_bucket{le=%q} %d\n", strconv.FormatFloat(bound, 'g', -1, 64), r.durationBuckets[index].Load())
	}
	_, _ = fmt.Fprintf(writer, "cli_gateway_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", r.durationCount.Load())
	_, _ = fmt.Fprintf(writer, "cli_gateway_request_duration_seconds_sum %g\n", float64(r.durationNanos.Load())/float64(time.Second))
	_, _ = fmt.Fprintf(writer, "cli_gateway_request_duration_seconds_count %d\n", r.durationCount.Load())
	_, _ = fmt.Fprintf(writer, "# TYPE cli_gateway_token_exchange_duration_seconds summary\n")
	_, _ = fmt.Fprintf(writer, "cli_gateway_token_exchange_duration_seconds_sum %g\n", float64(r.tokenExchangeNS.Load())/float64(time.Second))
	_, _ = fmt.Fprintf(writer, "cli_gateway_token_exchange_duration_seconds_count %d\n", r.tokenExchanges.Load())
}
