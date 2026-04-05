package codex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRefreshTokensWithRetry_NonRetryableOnlyAttemptsOnce(t *testing.T) {
	var calls int32
	auth := &CodexAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				atomic.AddInt32(&calls, 1)
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant","code":"refresh_token_reused"}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}

	_, err := auth.RefreshTokensWithRetry(context.Background(), "dummy_refresh_token", 3)
	if err == nil {
		t.Fatalf("expected error for non-retryable refresh failure")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "refresh_token_reused") {
		t.Fatalf("expected refresh_token_reused in error, got: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 refresh attempt, got %d", got)
	}
}

func TestNewOpenAIHTTPClientWithoutProxyForcesIPv4DirectTransport(t *testing.T) {
	t.Parallel()

	client := NewOpenAIHTTPClient(&config.Config{})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("expected OpenAI client without proxy to bypass proxy function")
	}
	if transport.DialContext == nil {
		t.Fatal("expected OpenAI client without proxy to override DialContext for IPv4")
	}
}

func TestNewOpenAIHTTPClientWithProxyUsesProxyTransport(t *testing.T) {
	t.Parallel()

	client := NewOpenAIHTTPClient(&config.Config{
		SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://proxy.example.com:8080"},
	})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}

	req, err := http.NewRequest(http.MethodGet, "https://auth.openai.com/oauth/token", nil)
	if err != nil {
		t.Fatalf("http.NewRequest returned error: %v", err)
	}

	proxyURL, errProxy := transport.Proxy(req)
	if errProxy != nil {
		t.Fatalf("transport.Proxy returned error: %v", errProxy)
	}
	if proxyURL == nil || proxyURL.String() != "http://proxy.example.com:8080" {
		t.Fatalf("proxy URL = %v, want http://proxy.example.com:8080", proxyURL)
	}
}

func TestGenerateAuthURLMatchesOfficialAuthShape(t *testing.T) {
	t.Parallel()

	auth := NewCodexAuth(&config.Config{})
	pkce := &PKCECodes{
		CodeChallenge: "challenge",
	}

	rawURL, err := auth.GenerateAuthURL("state-123", pkce)
	if err != nil {
		t.Fatalf("GenerateAuthURL returned error: %v", err)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse returned error: %v", err)
	}
	query := parsed.Query()

	if got := query.Get("originator"); got != CodexAuthOriginator {
		t.Fatalf("originator = %q, want %q", got, CodexAuthOriginator)
	}
	if got := query.Get("scope"); got != CodexAuthorizeScope {
		t.Fatalf("scope = %q, want %q", got, CodexAuthorizeScope)
	}
	if got := query.Get("prompt"); got != "login" {
		t.Fatalf("prompt = %q, want %q", got, "login")
	}
}

func TestExchangeCodeForTokensUsesConfiguredCodexHeaders(t *testing.T) {
	t.Parallel()

	var seenUA, seenAccept, seenContentType, seenOriginator string
	auth := &CodexAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				seenUA = req.Header.Get("User-Agent")
				seenAccept = req.Header.Get("Accept")
				seenContentType = req.Header.Get("Content-Type")
				seenOriginator = req.Header.Get("originator")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"at","refresh_token":"rt","id_token":"header.payload.sig","token_type":"Bearer","expires_in":3600}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}

	_, err := auth.ExchangeCodeForTokens(context.Background(), "dummy_code", &PKCECodes{
		CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatalf("ExchangeCodeForTokens returned error: %v", err)
	}
	if seenUA != CodexAuthUserAgent {
		t.Fatalf("User-Agent = %q, want %q", seenUA, CodexAuthUserAgent)
	}
	if seenAccept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", seenAccept)
	}
	if seenContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q, want application/x-www-form-urlencoded", seenContentType)
	}
	if seenOriginator != CodexAuthOriginator {
		t.Fatalf("originator = %q, want %q", seenOriginator, CodexAuthOriginator)
	}
}

func TestRefreshTokensUsesConfiguredCodexHeaders(t *testing.T) {
	t.Parallel()

	var seenUA, seenAccept, seenContentType, seenOriginator string
	auth := &CodexAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				seenUA = req.Header.Get("User-Agent")
				seenAccept = req.Header.Get("Accept")
				seenContentType = req.Header.Get("Content-Type")
				seenOriginator = req.Header.Get("originator")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"at","refresh_token":"rt","id_token":"header.payload.sig","token_type":"Bearer","expires_in":3600}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}

	_, err := auth.RefreshTokens(context.Background(), "dummy_refresh_token")
	if err != nil {
		t.Fatalf("RefreshTokens returned error: %v", err)
	}
	if seenUA != CodexAuthUserAgent {
		t.Fatalf("User-Agent = %q, want %q", seenUA, CodexAuthUserAgent)
	}
	if seenAccept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", seenAccept)
	}
	if seenContentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", seenContentType)
	}
	if seenOriginator != CodexAuthOriginator {
		t.Fatalf("originator = %q, want %q", seenOriginator, CodexAuthOriginator)
	}
}

func TestRefreshTokensSendsExpectedPayloadAndParsesTokenData(t *testing.T) {
	t.Parallel()

	var seenMethod, seenPath, seenBody string
	idToken := mustMakeTestJWT(t, map[string]any{
		"email": "user@example.com",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct_123",
		},
	})
	auth := &CodexAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				seenMethod = req.Method
				seenPath = req.URL.Path
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("io.ReadAll(req.Body) returned error: %v", err)
				}
				seenBody = string(body)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"new_at","refresh_token":"new_rt","id_token":"` + idToken + `","token_type":"Bearer","expires_in":3600}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}

	tokenData, err := auth.RefreshTokens(context.Background(), "refresh_123")
	if err != nil {
		t.Fatalf("RefreshTokens returned error: %v", err)
	}

	if seenMethod != http.MethodPost {
		t.Fatalf("method = %q, want %q", seenMethod, http.MethodPost)
	}
	if seenPath != "/oauth/token" {
		t.Fatalf("path = %q, want %q", seenPath, "/oauth/token")
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(seenBody), &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if got, _ := payload["client_id"].(string); got != ClientID {
		t.Fatalf("client_id = %q, want %q", got, ClientID)
	}
	if got, _ := payload["grant_type"].(string); got != "refresh_token" {
		t.Fatalf("grant_type = %q, want %q", got, "refresh_token")
	}
	if got, _ := payload["refresh_token"].(string); got != "refresh_123" {
		t.Fatalf("refresh_token = %q, want %q", got, "refresh_123")
	}
	if got, ok := payload["scope"]; ok {
		t.Fatalf("unexpected scope in refresh payload: %#v", got)
	}

	if tokenData.AccessToken != "new_at" {
		t.Fatalf("AccessToken = %q, want %q", tokenData.AccessToken, "new_at")
	}
	if tokenData.RefreshToken != "new_rt" {
		t.Fatalf("RefreshToken = %q, want %q", tokenData.RefreshToken, "new_rt")
	}
	if tokenData.AccountID != "acct_123" {
		t.Fatalf("AccountID = %q, want %q", tokenData.AccountID, "acct_123")
	}
	if tokenData.Email != "user@example.com" {
		t.Fatalf("Email = %q, want %q", tokenData.Email, "user@example.com")
	}
	if _, err := time.Parse(time.RFC3339, tokenData.Expire); err != nil {
		t.Fatalf("Expire = %q, want valid RFC3339: %v", tokenData.Expire, err)
	}
}

func mustMakeTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]any{
		"alg": "none",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatalf("json.Marshal(header) returned error: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal(payload) returned error: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) +
		".sig"
}
