package invoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/model"
)

func buildRequest(ctx context.Context, invocation model.Invocation, arguments map[string]any) (*http.Request, *httpx.APIError) {
	command := invocation.Command
	flags := make(map[string]model.CompiledFlag, len(command.Flags))
	for _, flag := range command.Flags {
		flags[flag.Name] = flag
	}

	segments := make([]string, 0, len(command.EndpointSegments))
	for _, segment := range command.EndpointSegments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
			segments = append(segments, url.PathEscape(fmt.Sprint(arguments[name])))
		} else {
			segments = append(segments, url.PathEscape(segment))
		}
	}
	rawPath := strings.TrimSuffix(command.Upstream.EscapedPath(), "/") + "/" + strings.Join(segments, "/")
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return nil, internalError("construct upstream path", err)
	}
	destination := *command.Upstream
	destination.Path = decodedPath
	destination.RawPath = rawPath

	query := destination.Query()
	body := make(map[string]any)
	headers := make(http.Header)
	for name, value := range arguments {
		flag := flags[name]
		switch flag.Location {
		case model.FlagInQuery:
			if values, ok := value.([]string); ok {
				for _, item := range values {
					query.Add(flag.QueryName, item)
				}
			} else {
				query.Set(flag.QueryName, fmt.Sprint(value))
			}
		case model.FlagInBody:
			body[name] = value
		case model.FlagInHeader:
			text := fmt.Sprint(value)
			if !safeHeaderValue(text) {
				return nil, argumentError(name, "contains forbidden control characters")
			}
			headers.Set(flag.HeaderName, text)
		}
	}
	destination.RawQuery = query.Encode()

	var bodyReader io.Reader
	if len(body) > 0 {
		encoded, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return nil, internalError("encode upstream body", marshalErr)
		}
		if len(encoded) > 1<<20 {
			return nil, argumentError("body", "exceeds 1 MiB")
		}
		bodyReader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, command.Method, destination.String(), bodyReader)
	if err != nil {
		return nil, internalError("construct upstream request", err)
	}
	request.Header = headers
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "cli-gateway/upstream")
	request.Header.Set("X-Cli-Gateway-Trace-Id", invocation.TraceID)
	request.Header.Set("traceparent", httpx.TraceParent(invocation.TraceID))
	if invocation.TraceState != "" {
		request.Header.Set("tracestate", invocation.TraceState)
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func safeHeaderValue(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == '\r' || character == '\n' || character == 0 || (character < 0x20 && character != '\t') || character == 0x7f {
			return false
		}
	}
	return true
}

func internalError(message string, cause error) *httpx.APIError {
	return &httpx.APIError{Status: http.StatusInternalServerError, Code: "E_INTERNAL", Message: "internal gateway error", Cause: fmt.Errorf("%s: %w", message, cause)}
}
