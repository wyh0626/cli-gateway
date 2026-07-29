package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryExportsBoundedMetrics(t *testing.T) {
	t.Parallel()
	registry := &Registry{}
	registry.SetGeneration(7)
	handler := registry.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/items/user-value", nil))

	response := httptest.NewRecorder()
	registry.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	if !strings.Contains(body, "cli_gateway_requests_total 1") || !strings.Contains(body, "cli_gateway_runtime_generation 7") {
		t.Fatalf("metrics = %s", body)
	}
	if strings.Contains(body, "user-value") {
		t.Fatalf("metrics leaked raw path: %s", body)
	}
}
