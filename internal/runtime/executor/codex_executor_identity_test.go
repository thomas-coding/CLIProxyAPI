package executor

import (
	"net/http"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestApplyCodexAuthIdentity_RewritesOAuthIdentityPerAuth(t *testing.T) {
	body := []byte(`{
		"prompt_cache_key":"client-cache",
		"client_metadata":{
			"x-codex-installation-id":"install-1",
			"x-codex-window-id":"window-1",
			"x-codex-turn-metadata":"{\"prompt_cache_key\":\"turn-cache\",\"turn_id\":\"turn-1\",\"window_id\":\"window-1\",\"unchanged\":\"keep\"}"
		}
	}`)
	authA := &cliproxyauth.Auth{ID: "auth-a", Provider: "codex", Metadata: map[string]any{"access_token": "oauth-a", "account_id": "acct-a"}}
	authB := &cliproxyauth.Auth{ID: "auth-b", Provider: "codex", Metadata: map[string]any{"access_token": "oauth-b", "account_id": "acct-b"}}

	reqA := newIdentityRewriteRequest(t)
	stateA := &codexAuthIdentityState{}
	rewrittenA, err := applyCodexAuthIdentity(reqA, body, authA, stateA)
	if err != nil {
		t.Fatalf("applyCodexAuthIdentity(auth-a) error = %v", err)
	}
	reqA2 := newIdentityRewriteRequest(t)
	stateA2 := &codexAuthIdentityState{}
	rewrittenA2, err := applyCodexAuthIdentity(reqA2, body, authA, stateA2)
	if err != nil {
		t.Fatalf("applyCodexAuthIdentity(auth-a second) error = %v", err)
	}
	reqB := newIdentityRewriteRequest(t)
	stateB := &codexAuthIdentityState{}
	rewrittenB, err := applyCodexAuthIdentity(reqB, body, authB, stateB)
	if err != nil {
		t.Fatalf("applyCodexAuthIdentity(auth-b) error = %v", err)
	}

	scopeA := codexAuthIdentityScope(authA)
	wantPromptA := codexAuthScopedIdentity(scopeA, "identity", "client-cache")
	if got := gjson.GetBytes(rewrittenA, "prompt_cache_key").String(); got != wantPromptA {
		t.Fatalf("prompt_cache_key auth-a = %q, want %q", got, wantPromptA)
	}
	if got := gjson.GetBytes(rewrittenA2, "prompt_cache_key").String(); got != wantPromptA {
		t.Fatalf("prompt_cache_key auth-a second = %q, want %q", got, wantPromptA)
	}
	if gotB := gjson.GetBytes(rewrittenB, "prompt_cache_key").String(); gotB == wantPromptA {
		t.Fatalf("prompt_cache_key should differ for auth-b, got %q", gotB)
	}

	if got := gjson.GetBytes(rewrittenA, "client_metadata.x-codex-installation-id").String(); got != codexAuthScopedIdentity(scopeA, "identity", "install-1") {
		t.Fatalf("installation id auth-a = %q", got)
	}
	if got := gjson.GetBytes(rewrittenA, "client_metadata.x-codex-window-id").String(); got != codexAuthScopedIdentity(scopeA, "identity", "window-1") {
		t.Fatalf("window id auth-a = %q", got)
	}

	turnMetadata := gjson.GetBytes(rewrittenA, "client_metadata.x-codex-turn-metadata").String()
	if got := gjson.Get(turnMetadata, "prompt_cache_key").String(); got != codexAuthScopedIdentity(scopeA, "identity", "turn-cache") {
		t.Fatalf("turn prompt_cache_key auth-a = %q", got)
	}
	if got := gjson.Get(turnMetadata, "turn_id").String(); got != codexAuthScopedIdentity(scopeA, "identity", "turn-1") {
		t.Fatalf("turn_id auth-a = %q", got)
	}
	if got := gjson.Get(turnMetadata, "window_id").String(); got != codexAuthScopedIdentity(scopeA, "identity", "window-1") {
		t.Fatalf("turn window_id auth-a = %q", got)
	}
	if got := gjson.Get(turnMetadata, "unchanged").String(); got != "keep" {
		t.Fatalf("turn unchanged = %q, want keep", got)
	}

	if got := reqA.Header.Get("Session_id"); got != codexAuthScopedIdentity(scopeA, "identity", "client-session") {
		t.Fatalf("Session_id auth-a = %q", got)
	}
	if got := reqA.Header.Get("Conversation_id"); got != codexAuthScopedIdentity(scopeA, "identity", "client-conversation") {
		t.Fatalf("Conversation_id auth-a = %q", got)
	}
	if got := reqA.Header.Get("X-Client-Request-Id"); got != codexAuthScopedIdentity(scopeA, "identity", "client-request") {
		t.Fatalf("X-Client-Request-Id auth-a = %q", got)
	}
	if got := reqA.Header.Get("Thread-Id"); got != codexAuthScopedIdentity(scopeA, "identity", "client-thread") {
		t.Fatalf("Thread-Id auth-a = %q", got)
	}
	if got := reqA.Header.Get("X-Codex-Window-Id"); got != codexAuthScopedIdentity(scopeA, "identity", "client-window") {
		t.Fatalf("X-Codex-Window-Id auth-a = %q", got)
	}
	if gotA, gotB := reqA.Header.Get("Session_id"), reqB.Header.Get("Session_id"); gotA == gotB {
		t.Fatalf("Session_id should differ across auths, both %q", gotA)
	}

	headerTurnMetadata := reqA.Header.Get("X-Codex-Turn-Metadata")
	if got := gjson.Get(headerTurnMetadata, "turn_id").String(); got != codexAuthScopedIdentity(scopeA, "identity", "header-turn") {
		t.Fatalf("header turn_id auth-a = %q", got)
	}
	clientPayload := exposeCodexAuthIdentityPayload([]byte(`{"prompt_cache_key":"`+wantPromptA+`"}`), stateA)
	if got := gjson.GetBytes(clientPayload, "prompt_cache_key").String(); got != "client-cache" {
		t.Fatalf("exposed prompt_cache_key = %q, want client-cache", got)
	}
}

func TestApplyCodexAuthIdentity_DoesNotRewriteAPIKeyAuth(t *testing.T) {
	body := []byte(`{"prompt_cache_key":"client-cache","client_metadata":{"x-codex-window-id":"window-1"}}`)
	auth := &cliproxyauth.Auth{
		ID:       "api-key-auth",
		Provider: "codex",
		Attributes: map[string]string{
			"api_key": "sk-test",
		},
	}
	req := newIdentityRewriteRequest(t)

	rewritten, err := applyCodexAuthIdentity(req, body, auth, &codexAuthIdentityState{})
	if err != nil {
		t.Fatalf("applyCodexAuthIdentity(api key) error = %v", err)
	}

	if got := gjson.GetBytes(rewritten, "prompt_cache_key").String(); got != "client-cache" {
		t.Fatalf("prompt_cache_key = %q, want client-cache", got)
	}
	if got := gjson.GetBytes(rewritten, "client_metadata.x-codex-window-id").String(); got != "window-1" {
		t.Fatalf("window id = %q, want window-1", got)
	}
	if got := req.Header.Get("Session_id"); got != "client-session" {
		t.Fatalf("Session_id = %q, want client-session", got)
	}
}

func newIdentityRewriteRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://example.com/backend-api/codex/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Session_id", "client-session")
	req.Header.Set("Conversation_id", "client-conversation")
	req.Header.Set("X-Client-Request-Id", "client-request")
	req.Header.Set("Thread-Id", "client-thread")
	req.Header.Set("X-Codex-Window-Id", "client-window")
	req.Header.Set("X-Codex-Turn-Metadata", `{"prompt_cache_key":"header-cache","turn_id":"header-turn","window_id":"header-window"}`)
	return req
}

func TestApplyCodexAuthIdentity_KeepsPromptCacheHeadersConsistent(t *testing.T) {
	auth := &cliproxyauth.Auth{ID: "auth-cache", Provider: "codex", Metadata: map[string]any{"access_token": "oauth"}}
	body := []byte(`{"prompt_cache_key":"cache-1","client_metadata":{"x-codex-turn-metadata":"{\"prompt_cache_key\":\"cache-1\"}"}}`)
	req, err := http.NewRequest(http.MethodPost, "https://example.com/backend-api/codex/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Session_id", "cache-1")
	req.Header.Set("Conversation_id", "cache-1")
	req.Header.Set("X-Codex-Turn-Metadata", `{"prompt_cache_key":"cache-1"}`)

	state := &codexAuthIdentityState{}
	rewritten, err := applyCodexAuthIdentity(req, body, auth, state)
	if err != nil {
		t.Fatalf("applyCodexAuthIdentity() error = %v", err)
	}
	promptCacheKey := gjson.GetBytes(rewritten, "prompt_cache_key").String()
	if promptCacheKey == "" || promptCacheKey == "cache-1" {
		t.Fatalf("prompt_cache_key was not rewritten: %q", promptCacheKey)
	}
	if got := req.Header.Get("Session_id"); got != promptCacheKey {
		t.Fatalf("Session_id = %q, want prompt_cache_key %q", got, promptCacheKey)
	}
	if got := req.Header.Get("Conversation_id"); got != promptCacheKey {
		t.Fatalf("Conversation_id = %q, want prompt_cache_key %q", got, promptCacheKey)
	}
	if got := gjson.Get(req.Header.Get("X-Codex-Turn-Metadata"), "prompt_cache_key").String(); got != promptCacheKey {
		t.Fatalf("header turn prompt_cache_key = %q, want %q", got, promptCacheKey)
	}
	if got := gjson.Get(gjson.GetBytes(rewritten, "client_metadata.x-codex-turn-metadata").String(), "prompt_cache_key").String(); got != promptCacheKey {
		t.Fatalf("body turn prompt_cache_key = %q, want %q", got, promptCacheKey)
	}
}
