package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationCodePKCEAndRefreshRotation(t *testing.T) {
	t.Parallel()
	issuer, err := newIssuerServer("http://issuer.example", "cli-gateway", "cg-cli", "http://127.0.0.1:18082")
	if err != nil {
		t.Fatal(err)
	}
	handler := issuer.routes()
	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	query := url.Values{
		"response_type": {"code"}, "client_id": {"cg-cli"},
		"redirect_uri":   {"http://127.0.0.1:49152/callback"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"scope": {"openid offline_access demo:read"}, "state": {"state-1"},
		"resource": {"http://127.0.0.1:18082"},
	}
	request := httptest.NewRequest(http.MethodGet, "/oauth2/auth?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("authorization status = %d, body=%s", response.Code, response.Body.String())
	}
	redirect, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := redirect.Query().Get("code")
	if code == "" || redirect.Query().Get("state") != "state-1" {
		t.Fatalf("redirect = %s", redirect)
	}

	first := postToken(t, handler, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"cg-cli"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:49152/callback"}, "code_verifier": {verifier},
		"resource": {"http://127.0.0.1:18082"},
	}, http.StatusOK)
	if first.AccessToken == "" || first.RefreshToken == "" {
		t.Fatalf("token response = %#v", first)
	}
	second := postToken(t, handler, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"cg-cli"}, "refresh_token": {first.RefreshToken},
		"resource": {"http://127.0.0.1:18082"},
	}, http.StatusOK)
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatalf("refresh token was not rotated: %#v", second)
	}
	postToken(t, handler, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"cg-cli"}, "refresh_token": {first.RefreshToken},
		"resource": {"http://127.0.0.1:18082"},
	}, http.StatusBadRequest)
}

func TestDeviceAuthorizationPendingThenApproved(t *testing.T) {
	t.Parallel()
	issuer, err := newIssuerServer("http://issuer.example", "cli-gateway", "cg-cli", "http://127.0.0.1:18082")
	if err != nil {
		t.Fatal(err)
	}
	handler := issuer.routes()
	deviceRequest := httptest.NewRequest(http.MethodPost, "/oauth2/device/auth", strings.NewReader(url.Values{
		"client_id": {"cg-cli"}, "scope": {"offline_access demo:read"},
		"resource": {"http://127.0.0.1:18082"},
	}.Encode()))
	deviceRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deviceResponse := httptest.NewRecorder()
	handler.ServeHTTP(deviceResponse, deviceRequest)
	if deviceResponse.Code != http.StatusOK {
		t.Fatalf("device status = %d, body=%s", deviceResponse.Code, deviceResponse.Body.String())
	}
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal(deviceResponse.Body.Bytes(), &device); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {"cg-cli"},
		"device_code": {device.DeviceCode},
	}
	postToken(t, handler, form, http.StatusBadRequest)

	activate := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(url.Values{"user_code": {device.UserCode}}.Encode()))
	activate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	activateResponse := httptest.NewRecorder()
	handler.ServeHTTP(activateResponse, activate)
	if activateResponse.Code != http.StatusOK {
		t.Fatalf("activation status = %d, body=%s", activateResponse.Code, activateResponse.Body.String())
	}
	token := postToken(t, handler, form, http.StatusOK)
	if token.AccessToken == "" || token.RefreshToken == "" {
		t.Fatalf("token response = %#v", token)
	}
}

type testTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

func postToken(t *testing.T, handler http.Handler, form url.Values, expectedStatus int) testTokenResponse {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != expectedStatus {
		t.Fatalf("token status = %d, want %d, body=%s", response.Code, expectedStatus, body)
	}
	var parsed testTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed
}
