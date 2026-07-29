// demoapi is an independent HTTP backend used for real cli-gateway integration tests.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type api struct {
	items       sync.Map
	requests    atomic.Int64
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18081", "listen address")
	flag.Parse()
	service := &api{}
	service.items.Store("seed", map[string]any{"id": "seed", "name": "initial", "value": 1})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", service.instrument(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	}))
	mux.HandleFunc("GET /v1/items/{id}", service.instrument(service.getItem))
	mux.HandleFunc("POST /v1/items", service.instrument(service.createItem))
	mux.HandleFunc("DELETE /v1/items/{id}", service.instrument(service.deleteItem))
	mux.HandleFunc("GET /v1/work", service.instrument(service.work))
	mux.HandleFunc("GET /v1/stats", service.instrument(service.stats))
	mux.HandleFunc("GET /v1/stream", service.instrument(service.stream))

	log.Printf("demo API listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func (a *api) instrument(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		a.requests.Add(1)
		current := a.inFlight.Add(1)
		for {
			maximum := a.maxInFlight.Load()
			if current <= maximum || a.maxInFlight.CompareAndSwap(maximum, current) {
				break
			}
		}
		defer a.inFlight.Add(-1)
		next(writer, request)
	}
}

func (a *api) getItem(writer http.ResponseWriter, request *http.Request) {
	item, ok := a.items.Load(request.PathValue("id"))
	if !ok {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"item": item, "identity_received": request.Header.Get("X-Cli-Gateway-Identity") != "", "trace_id": request.Header.Get("X-Cli-Gateway-Trace-Id")})
}

func (a *api) createItem(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Name == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	item := map[string]any{"id": id, "name": input.Name, "value": input.Value}
	a.items.Store(id, item)
	writeJSON(writer, http.StatusCreated, map[string]any{"item": item, "identity_received": request.Header.Get("X-Cli-Gateway-Identity") != ""})
}

func (a *api) deleteItem(writer http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if _, loaded := a.items.LoadAndDelete(id); !loaded {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"deleted": id})
}

func (a *api) work(writer http.ResponseWriter, request *http.Request) {
	delayMS, _ := strconv.Atoi(request.URL.Query().Get("delay_ms"))
	if delayMS < 0 || delayMS > 1000 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_delay"})
		return
	}
	if delayMS > 0 {
		time.Sleep(time.Duration(delayMS) * time.Millisecond)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"ok": true, "delay_ms": delayMS, "identity_received": request.Header.Get("X-Cli-Gateway-Identity") != ""})
}

func (a *api) stats(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]int64{"requests": a.requests.Load(), "in_flight": a.inFlight.Load(), "max_in_flight": a.maxInFlight.Load()})
}

func (a *api) stream(writer http.ResponseWriter, request *http.Request) {
	lines, _ := strconv.Atoi(request.URL.Query().Get("lines"))
	if lines == 0 {
		lines = 3
	}
	delayMS, _ := strconv.Atoi(request.URL.Query().Get("delay_ms"))
	if delayMS == 0 {
		delayMS = 100
	}
	if lines < 1 || lines > 100 || delayMS < 1 || delayMS > 1000 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_stream_options"})
		return
	}
	writer.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := writer.(http.Flusher)
	encoder := json.NewEncoder(writer)
	for index := 1; index <= lines; index++ {
		if err := encoder.Encode(map[string]any{"line": index, "identity_received": request.Header.Get("X-Cli-Gateway-Identity") != ""}); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		if index != lines {
			select {
			case <-request.Context().Done():
				return
			case <-time.After(time.Duration(delayMS) * time.Millisecond):
			}
		}
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
