package auth

import (
	"net/http"
	"strings"
)

// BearerToken extracts one RFC 6750 bearer credential.
func BearerToken(request *http.Request) (string, error) {
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	if value == "" {
		return "", ErrMissingToken
	}
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrInvalidToken
	}
	return parts[1], nil
}
