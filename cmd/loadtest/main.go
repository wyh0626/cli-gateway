// loadtest is a small dependency-free HTTP concurrency probe for cli-gateway E2E tests.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type report struct {
	Target            string           `json:"target"`
	Concurrency       int              `json:"concurrency"`
	DurationSeconds   float64          `json:"duration_seconds"`
	Completed         int64            `json:"completed"`
	Errors            int64            `json:"errors"`
	RequestsPerSecond float64          `json:"requests_per_second"`
	LatencyMS         latencyReport    `json:"latency_ms"`
	StatusCounts      map[string]int64 `json:"status_counts"`
	ErrorSamples      []string         `json:"error_samples,omitempty"`
}

type latencyReport struct {
	Average float64 `json:"average"`
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99"`
	Maximum float64 `json:"maximum"`
}

func main() {
	target := flag.String("url", "", "request URL")
	method := flag.String("method", http.MethodGet, "HTTP method")
	body := flag.String("body", "", "request body")
	tokenURL := flag.String("token-url", "", "optional URL returning access_token JSON")
	concurrency := flag.Int("c", 32, "worker count")
	duration := flag.Duration("d", 10*time.Second, "test duration")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout")
	flag.Parse()
	if *target == "" || *concurrency < 1 || *duration <= 0 {
		fmt.Fprintln(os.Stderr, "url, positive concurrency, and positive duration are required")
		os.Exit(2)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			MaxIdleConns:        *concurrency * 2,
			MaxIdleConnsPerHost: *concurrency,
			IdleConnTimeout:     30 * time.Second,
		},
		Timeout: *timeout,
	}
	token, err := fetchToken(client, *tokenURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	start := time.Now()
	var completed atomic.Int64
	var failures atomic.Int64
	var latencyMu sync.Mutex
	latencies := make([]time.Duration, 0, 10000)
	var resultMu sync.Mutex
	statusCounts := make(map[string]int64)
	errorSamples := make([]string, 0, 5)
	var workers sync.WaitGroup
	workers.Add(*concurrency)
	for range *concurrency {
		go func() {
			defer workers.Done()
			for ctx.Err() == nil {
				request, requestErr := http.NewRequestWithContext(ctx, *method, *target, bytes.NewBufferString(*body))
				if requestErr != nil {
					failures.Add(1)
					return
				}
				if *body != "" {
					request.Header.Set("Content-Type", "application/json")
				}
				if token != "" {
					request.Header.Set("Authorization", "Bearer "+token)
				}
				requestStart := time.Now()
				response, requestErr := client.Do(request)
				elapsed := time.Since(requestStart)
				if requestErr != nil {
					if ctx.Err() == nil {
						failures.Add(1)
					}
					continue
				}
				responseBody, copyErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
				response.Body.Close()
				resultMu.Lock()
				statusCounts[fmt.Sprint(response.StatusCode)]++
				resultMu.Unlock()
				if copyErr != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
					failures.Add(1)
					resultMu.Lock()
					if len(errorSamples) < cap(errorSamples) {
						errorSamples = append(errorSamples, fmt.Sprintf("status=%d body=%s", response.StatusCode, responseBody))
					}
					resultMu.Unlock()
					continue
				}
				completed.Add(1)
				latencyMu.Lock()
				latencies = append(latencies, elapsed)
				latencyMu.Unlock()
			}
		}()
	}
	workers.Wait()
	elapsed := time.Since(start)
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	result := report{
		Target: *target, Concurrency: *concurrency, DurationSeconds: elapsed.Seconds(),
		Completed: completed.Load(), Errors: failures.Load(),
		StatusCounts: statusCounts, ErrorSamples: errorSamples,
	}
	if elapsed > 0 {
		result.RequestsPerSecond = float64(result.Completed) / elapsed.Seconds()
	}
	result.LatencyMS = summarize(latencies)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fetchToken(client *http.Client, tokenURL string) (string, error) {
	if tokenURL == "" {
		return "", nil
	}
	response, err := client.Get(tokenURL)
	if err != nil {
		return "", fmt.Errorf("fetch token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch token: status %d", response.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode token: %w", err)
	}
	if payload.AccessToken == "" {
		return "", fmt.Errorf("fetch token: access_token is empty")
	}
	return payload.AccessToken, nil
}

func summarize(values []time.Duration) latencyReport {
	if len(values) == 0 {
		return latencyReport{}
	}
	var total time.Duration
	for _, value := range values {
		total += value
	}
	return latencyReport{
		Average: milliseconds(total / time.Duration(len(values))),
		P50:     milliseconds(percentile(values, 0.50)),
		P95:     milliseconds(percentile(values, 0.95)),
		P99:     milliseconds(percentile(values, 0.99)),
		Maximum: milliseconds(values[len(values)-1]),
	}
}

func percentile(values []time.Duration, fraction float64) time.Duration {
	index := int(float64(len(values)-1) * fraction)
	return values[index]
}

func milliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}
