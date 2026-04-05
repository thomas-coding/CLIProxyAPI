package executor

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	_ "github.com/router-for-me/CLIProxyAPI/v6/internal/translator/codex/openai/responses"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestCodexExecutorExecute_DefaultOffKeepsLegacyRequestShaping(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		seenBody = body
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"created_at\":1700000000,\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}}}\n\n")
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url":            server.URL,
			"header:X-Gateway-ID": "gw-1",
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
			"account_id":   "acct-123",
		},
	}
	body := []byte(`{"model":"alias-model","stream":false,"store":true,"previous_response_id":"resp-prev","prompt_cache_retention":{"policy":"keep"},"safety_identifier":"safe-1","user":"user-1","context_management":{"compaction":"auto"}}`)
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		codexAffinityKeyHeader: "user:legacy",
	})
	expectedUA := codexBoundFallbackUserAgent(ctx, auth)

	resp, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := gjson.GetBytes(seenBody, "model").String(); got != "gpt-5" {
		t.Fatalf("upstream model = %q, want %q", got, "gpt-5")
	}
	if !gjson.GetBytes(seenBody, "stream").Bool() {
		t.Fatalf("legacy upstream must force stream=true")
	}
	if gjson.GetBytes(seenBody, "store").Type != gjson.False {
		t.Fatalf("legacy upstream must force store=false, got %s body=%s", gjson.GetBytes(seenBody, "store").Raw, string(seenBody))
	}
	if gjson.GetBytes(seenBody, "parallel_tool_calls").Type != gjson.True {
		t.Fatalf("legacy upstream must force parallel_tool_calls=true")
	}
	include := gjson.GetBytes(seenBody, "include")
	if !include.IsArray() || len(include.Array()) != 1 || include.Array()[0].String() != "reasoning.encrypted_content" {
		t.Fatalf("legacy upstream include = %s, want [reasoning.encrypted_content]", include.Raw)
	}
	if gjson.GetBytes(seenBody, "previous_response_id").Exists() {
		t.Fatalf("legacy upstream must drop previous_response_id")
	}
	if gjson.GetBytes(seenBody, "prompt_cache_retention").Exists() {
		t.Fatalf("legacy upstream must drop prompt_cache_retention")
	}
	if gjson.GetBytes(seenBody, "safety_identifier").Exists() {
		t.Fatalf("legacy upstream must drop safety_identifier")
	}
	if gjson.GetBytes(seenBody, "user").Exists() {
		t.Fatalf("legacy upstream must drop user")
	}
	if gjson.GetBytes(seenBody, "context_management").Exists() {
		t.Fatalf("legacy upstream must drop context_management")
	}
	if !gjson.GetBytes(seenBody, "instructions").Exists() {
		t.Fatalf("legacy upstream must add instructions placeholder")
	}

	if got := seenHeaders.Get("Authorization"); got != "Bearer oauth-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer oauth-token")
	}
	if got := seenHeaders.Get("Chatgpt-Account-Id"); got != "acct-123" {
		t.Fatalf("Chatgpt-Account-Id = %q, want %q", got, "acct-123")
	}
	if got := seenHeaders.Get("Originator"); got != "" {
		t.Fatalf("Originator = %q, want empty", got)
	}
	if got := seenHeaders.Get("Version"); got != "" {
		t.Fatalf("Version = %q, want empty", got)
	}
	if got := seenHeaders.Get("User-Agent"); got != expectedUA {
		t.Fatalf("User-Agent = %q, want %q", got, expectedUA)
	}
	if got := seenHeaders.Get("Session_id"); got != "" {
		t.Fatalf("Session_id = %q, want empty", got)
	}
	if got := seenHeaders.Get("Connection"); got != "" {
		t.Fatalf("Connection = %q, want empty", got)
	}
	if got := seenHeaders.Get(codexAffinityKeyHeader); got != "" {
		t.Fatalf("%s = %q, want empty", codexAffinityKeyHeader, got)
	}

	if got := gjson.GetBytes(resp.Payload, "id").String(); got != "resp_1" {
		t.Fatalf("response id = %q, want %q", got, "resp_1")
	}
	if got := gjson.GetBytes(resp.Payload, "object").String(); got != "response" {
		t.Fatalf("response object = %q, want %q", got, "response")
	}
}

func TestCodexExecutorPrepareRequestDropsCustomHeaderAttrs(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	executor := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"header:X-Gateway-ID": "gw-1",
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
		},
	}

	if err := executor.PrepareRequest(req, auth); err != nil {
		t.Fatalf("PrepareRequest() error = %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer oauth-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer oauth-token")
	}
	if got := req.Header.Get("X-Gateway-Id"); got != "" {
		t.Fatalf("X-Gateway-Id = %q, want empty", got)
	}
}

func TestCodexExecutorExecute_DefaultOffPreservesDirectClientUserAgent(t *testing.T) {
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_direct_ua\",\"object\":\"response\",\"created_at\":1700000000,\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		"User-Agent": "direct-client-ua",
	})

	_, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := seenHeaders.Get("User-Agent"); got != "direct-client-ua" {
		t.Fatalf("User-Agent = %q, want %q", got, "direct-client-ua")
	}
}

func TestCodexExecutorExecute_TransparentOnPreservesClientShape(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		seenBody = body
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_2","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":2,"output_tokens":1,"total_tokens":3}}`)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url":            server.URL,
			"header:X-Gateway-ID": "gw-1",
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
			"account_id":   "acct-123",
		},
	}
	body := []byte(`{"model":"alias-model","stream":false,"store":true,"previous_response_id":"resp-prev","prompt_cache_retention":{"policy":"keep"},"safety_identifier":"safe-1","user":"user-1","context_management":{"compaction":"auto"}}`)
	ctx := contextWithGinHeaders(map[string]string{
		"User-Agent":             "client-ua",
		"Version":                "client-version",
		"Session_id":             "client-session",
		"Originator":             "client-originator",
		"Accept":                 "application/json",
		"Accept-Language":        "en-US,en;q=0.9",
		"OpenAI-Beta":            "responses=experimental",
		"X-Stainless-Lang":       "js",
		"X-Test-Keep":            "keep-me",
		"X-New-Api-Version":      "internal",
		"X-Trace-Id":             "trace-1",
		"Accept-Encoding":        "br",
		"Connection":             "keep-alive",
		"X-Forwarded-For":        "1.2.3.4",
		"X-Arroute-Affinity-Key": "user:shadow",
		"Chatgpt-Account-Id":     "client-account",
	})

	resp, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := gjson.GetBytes(seenBody, "model").String(); got != "gpt-5" {
		t.Fatalf("upstream model = %q, want %q", got, "gpt-5")
	}
	if gjson.GetBytes(seenBody, "stream").Type != gjson.False {
		t.Fatalf("transparent upstream must preserve stream=false, got %s", gjson.GetBytes(seenBody, "stream").Raw)
	}
	if gjson.GetBytes(seenBody, "store").Type != gjson.False {
		t.Fatalf("transparent upstream must still force store=false, got %s", gjson.GetBytes(seenBody, "store").Raw)
	}
	if got := gjson.GetBytes(seenBody, "previous_response_id").String(); got != "resp-prev" {
		t.Fatalf("previous_response_id = %q, want %q", got, "resp-prev")
	}
	if got := gjson.GetBytes(seenBody, "prompt_cache_retention.policy").String(); got != "keep" {
		t.Fatalf("prompt_cache_retention.policy = %q, want %q", got, "keep")
	}
	if got := gjson.GetBytes(seenBody, "safety_identifier").String(); got != "safe-1" {
		t.Fatalf("safety_identifier = %q, want %q", got, "safe-1")
	}
	if got := gjson.GetBytes(seenBody, "user").String(); got != "user-1" {
		t.Fatalf("user = %q, want %q", got, "user-1")
	}
	if got := gjson.GetBytes(seenBody, "context_management.compaction").String(); got != "auto" {
		t.Fatalf("context_management.compaction = %q, want %q", got, "auto")
	}
	if gjson.GetBytes(seenBody, "parallel_tool_calls").Exists() {
		t.Fatalf("transparent upstream must not inject parallel_tool_calls")
	}
	if gjson.GetBytes(seenBody, "include").Exists() {
		t.Fatalf("transparent upstream must not inject include")
	}
	if gjson.GetBytes(seenBody, "instructions").Exists() {
		t.Fatalf("transparent upstream must not inject instructions")
	}
	if gjson.GetBytes(seenBody, "prompt_cache_key").Exists() {
		t.Fatalf("transparent upstream must not inject prompt_cache_key")
	}

	if got := seenHeaders.Get("Authorization"); got != "Bearer oauth-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer oauth-token")
	}
	if got := seenHeaders.Get("Chatgpt-Account-Id"); got != "acct-123" {
		t.Fatalf("Chatgpt-Account-Id = %q, want %q", got, "acct-123")
	}
	if got := seenHeaders.Get("User-Agent"); got != "client-ua" {
		t.Fatalf("User-Agent = %q, want %q", got, "client-ua")
	}
	if got := seenHeaders.Get("Version"); got != "client-version" {
		t.Fatalf("Version = %q, want %q", got, "client-version")
	}
	if got := seenHeaders.Get("Session_id"); got != "client-session" {
		t.Fatalf("Session_id = %q, want %q", got, "client-session")
	}
	if got := seenHeaders.Get("Originator"); got != "client-originator" {
		t.Fatalf("Originator = %q, want %q", got, "client-originator")
	}
	if got := seenHeaders.Get("Accept-Language"); got != "en-US,en;q=0.9" {
		t.Fatalf("Accept-Language = %q, want %q", got, "en-US,en;q=0.9")
	}
	if got := seenHeaders.Get("Openai-Beta"); got != "responses=experimental" {
		t.Fatalf("Openai-Beta = %q, want %q", got, "responses=experimental")
	}
	if got := seenHeaders.Get("X-Stainless-Lang"); got != "js" {
		t.Fatalf("X-Stainless-Lang = %q, want %q", got, "js")
	}
	if got := seenHeaders.Get("X-Gateway-Id"); got != "" {
		t.Fatalf("X-Gateway-Id = %q, want empty", got)
	}
	if got := seenHeaders.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept = %q, want %q", got, "application/json")
	}
	if got := seenHeaders.Get("Accept-Encoding"); got != "br" {
		t.Fatalf("Accept-Encoding = %q, want %q from client snapshot", got, "br")
	}
	if got := seenHeaders.Get("Connection"); got != "" {
		t.Fatalf("Connection = %q, want empty", got)
	}
	if got := seenHeaders.Get("X-Forwarded-For"); got != "" {
		t.Fatalf("X-Forwarded-For = %q, want empty", got)
	}
	if got := seenHeaders.Get("X-Test-Keep"); got != "" {
		t.Fatalf("X-Test-Keep = %q, want empty", got)
	}
	if got := seenHeaders.Get("X-New-Api-Version"); got != "" {
		t.Fatalf("X-New-Api-Version = %q, want empty", got)
	}
	if got := seenHeaders.Get("X-Trace-Id"); got != "" {
		t.Fatalf("X-Trace-Id = %q, want empty", got)
	}
	if got := seenHeaders.Get("X-Arroute-Affinity-Key"); got != "" {
		t.Fatalf("X-Arroute-Affinity-Key = %q, want empty", got)
	}
	if got := seenHeaders.Get("Conversation_id"); got != "" {
		t.Fatalf("Conversation_id = %q, want empty", got)
	}

	if got := strings.TrimSpace(string(resp.Payload)); got != `{"id":"resp_2","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":2,"output_tokens":1,"total_tokens":3}}` {
		t.Fatalf("response payload = %s", got)
	}
}

func TestCodexExecutorExecute_TransparentOnInjectsStoreFalseWhenMissing(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		seenBody = body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_store_missing","object":"response","status":"completed","model":"gpt-5.4","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
			"account_id":   "acct-123",
		},
	}
	body := []byte(`{"model":"alias-model","stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}`)

	_, err := executor.Execute(
		contextWithGinRequest("/v1/responses", map[string]string{
			"Accept": "text/event-stream",
		}),
		auth,
		cliproxyexecutor.Request{Model: "gpt-5.4", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := gjson.GetBytes(seenBody, "store").Type; got != gjson.False {
		t.Fatalf("transparent upstream must inject store=false when missing, got %s body=%s", gjson.GetBytes(seenBody, "store").Raw, string(seenBody))
	}
}

func TestCodexExecutorExecute_TransparentOnPassthroughsArbitraryJSONSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"result":"ok","unexpected_shape":true}`)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)

	resp, err := executor.Execute(
		context.Background(),
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := strings.TrimSpace(string(resp.Payload)); got != `{"result":"ok","unexpected_shape":true}` {
		t.Fatalf("response payload = %s", got)
	}
}

func TestCodexExecutorExecute_TransparentOnPrefersClientSnapshotHeadersAndQuery(t *testing.T) {
	var seenHeaders http.Header
	var seenQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		if r.URL != nil {
			seenQuery = r.URL.RawQuery
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_snapshot","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
			"account_id":   "acct-123",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)
	ctx := contextWithGinRequest("/v1/responses?internal=true", map[string]string{
		"User-Agent": "new-api-ua",
		"Version":    "new-api-version",
		"Session_id": "new-api-session",
		"Originator": "new-api-originator",
		"Accept":     "application/json",
		codexTransparentClientHeadersHeader: encodeTransparentSnapshotHeadersForTest(map[string]string{
			"User-Agent":  "client-ua",
			"Version":     "client-version",
			"Session_id":  "client-session",
			"Originator":  "client-originator",
			"Openai-Beta": "responses=experimental",
		}),
		codexTransparentClientQueryHeader: base64.RawURLEncoding.EncodeToString([]byte("trace_id=req-1&include=reasoning.encrypted_content")),
	})

	resp, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := seenHeaders.Get("User-Agent"); got != "client-ua" {
		t.Fatalf("User-Agent = %q, want %q", got, "client-ua")
	}
	if got := seenHeaders.Get("Version"); got != "client-version" {
		t.Fatalf("Version = %q, want %q", got, "client-version")
	}
	if got := seenHeaders.Get("Session_id"); got != "client-session" {
		t.Fatalf("Session_id = %q, want %q", got, "client-session")
	}
	if got := seenHeaders.Get("Originator"); got != "client-originator" {
		t.Fatalf("Originator = %q, want %q", got, "client-originator")
	}
	if got := seenHeaders.Get("Openai-Beta"); got != "responses=experimental" {
		t.Fatalf("Openai-Beta = %q, want %q", got, "responses=experimental")
	}
	if got := seenQuery; got != "trace_id=req-1&include=reasoning.encrypted_content" {
		t.Fatalf("query = %q, want snapshot query", got)
	}
	if got := strings.TrimSpace(string(resp.Payload)); got != `{"id":"resp_snapshot","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}` {
		t.Fatalf("response payload = %s", got)
	}
}

func TestCodexExecutorExecute_TransparentOnFallsBackToConfiguredUserAgent(t *testing.T) {
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_ua","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		CodexHeaderDefaults: config.CodexHeaderDefaults{
			UserAgent: "config-ua",
		},
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)

	_, err := executor.Execute(
		contextWithGinRequest("/v1/responses", map[string]string{
			"Accept": "application/json",
		}),
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := seenHeaders.Get("User-Agent"); got != "config-ua" {
		t.Fatalf("User-Agent = %q, want %q", got, "config-ua")
	}
	if got := seenHeaders.Get("Version"); got != "" {
		t.Fatalf("Version = %q, want empty when client did not send it", got)
	}
	if got := seenHeaders.Get("Session_id"); got != "" {
		t.Fatalf("Session_id = %q, want empty when client did not send it", got)
	}
	if got := seenHeaders.Get("Originator"); got != "" {
		t.Fatalf("Originator = %q, want empty when client did not send it", got)
	}
}

func TestCodexExecutorExecute_TransparentOnFallsBackToBoundUserAgent(t *testing.T) {
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_bound_ua","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		"Accept":               "application/json",
		codexAffinityKeyHeader: "user:15",
	})

	_, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	expectedUA := codexBoundFallbackUserAgent(ctx, auth)
	if got := seenHeaders.Get("User-Agent"); got != expectedUA {
		t.Fatalf("User-Agent = %q, want %q", got, expectedUA)
	}
	if got := seenHeaders.Get("Version"); got != "" {
		t.Fatalf("Version = %q, want empty", got)
	}
	if got := seenHeaders.Get("Session_id"); got != "" {
		t.Fatalf("Session_id = %q, want empty", got)
	}
	if got := seenHeaders.Get("Originator"); got != "" {
		t.Fatalf("Originator = %q, want empty", got)
	}
	if got := seenHeaders.Get(codexAffinityKeyHeader); got != "" {
		t.Fatalf("%s = %q, want empty", codexAffinityKeyHeader, got)
	}
}

func TestCodexExecutorExecute_TransparentOnIgnoresInternalHopUserAgent(t *testing.T) {
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_internal_ua","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		"User-Agent": "Go-http-client/1.1",
		"Accept":     "application/json",
		codexTransparentClientHeadersHeader: encodeTransparentSnapshotHeadersForTest(map[string]string{
			"Accept": "application/json",
		}),
		codexAffinityKeyHeader: "user:internal-hop",
	})

	_, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	expectedUA := codexBoundFallbackUserAgent(ctx, auth)
	if got := seenHeaders.Get("User-Agent"); got != expectedUA {
		t.Fatalf("User-Agent = %q, want %q", got, expectedUA)
	}
	if got := seenHeaders.Get("User-Agent"); got == "Go-http-client/1.1" {
		t.Fatalf("User-Agent must not keep internal hop UA")
	}
}

func TestCodexExecutorExecute_TransparentOnMalformedSnapshotFallsBackToLegacyRequestShaping(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		seenBody = body
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fallback\",\"object\":\"response\",\"created_at\":1700000000,\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
			"account_id":   "acct-123",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false,"previous_response_id":"resp-prev"}`)
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		"User-Agent":                        "Go-http-client/1.1",
		"Accept":                            "application/json",
		codexTransparentClientHeadersHeader: "%%%not-base64%%%",
		codexAffinityKeyHeader:              "user:fallback",
	})

	_, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !gjson.GetBytes(seenBody, "stream").Bool() {
		t.Fatalf("legacy fallback must force stream=true")
	}
	if gjson.GetBytes(seenBody, "previous_response_id").Exists() {
		t.Fatalf("legacy fallback must drop previous_response_id")
	}
	if got := seenHeaders.Get("Version"); got != "" {
		t.Fatalf("Version = %q, want empty", got)
	}
	if got := seenHeaders.Get("Originator"); got != "" {
		t.Fatalf("Originator = %q, want empty", got)
	}
	if got := seenHeaders.Get("Session_id"); got != "" {
		t.Fatalf("Session_id = %q, want empty", got)
	}
	expectedUA := codexBoundFallbackUserAgent(ctx, auth)
	if got := seenHeaders.Get("User-Agent"); got != expectedUA {
		t.Fatalf("User-Agent = %q, want %q", got, expectedUA)
	}
}

func TestCodexExecutorExecute_TransparentOnSnapshotStatusFallsBackToLegacyRequestShaping(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		seenBody = body
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_status_fallback\",\"object\":\"response\",\"created_at\":1700000000,\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
			"account_id":   "acct-123",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		"User-Agent":                         "Go-http-client/1.1",
		"Accept":                             "application/json",
		codexTransparentSnapshotStatusHeader: "headers_oversize",
		codexAffinityKeyHeader:               "user:status-fallback",
	})

	_, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !gjson.GetBytes(seenBody, "stream").Bool() {
		t.Fatalf("legacy fallback must force stream=true")
	}
	if got := seenHeaders.Get("Version"); got != "" {
		t.Fatalf("Version = %q, want empty", got)
	}
	expectedUA := codexBoundFallbackUserAgent(ctx, auth)
	if got := seenHeaders.Get("User-Agent"); got != expectedUA {
		t.Fatalf("User-Agent = %q, want %q", got, expectedUA)
	}
}

func TestCodexExecutorExecute_TransparentOnDecodesCompressedResponse(t *testing.T) {
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, `{"id":"resp_gzip","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
		_ = gz.Close()
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "oauth-token",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		"Accept": "application/json",
		codexTransparentClientHeadersHeader: encodeTransparentSnapshotHeadersForTest(map[string]string{
			"Accept-Encoding": "gzip",
		}),
	})

	resp, err := executor.Execute(
		ctx,
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := seenHeaders.Get("Accept-Encoding"); got != "gzip" {
		t.Fatalf("Accept-Encoding = %q, want %q", got, "gzip")
	}
	if got := strings.TrimSpace(string(resp.Payload)); got != `{"id":"resp_gzip","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}` {
		t.Fatalf("response payload = %s", got)
	}
}

func TestCodexExecutorExecute_TransparentOnApiKeyDropsCustomHeaders(t *testing.T) {
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_api_key","object":"response","status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{
		SDKConfig: config.SDKConfig{
			CodexRelay: config.CodexRelayConfig{TransparentMode: "on"},
		},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"api_key":             "sk-test",
			"base_url":            server.URL,
			"header:X-Gateway-ID": "gw-api-key",
		},
	}
	body := []byte(`{"model":"gpt-5","stream":false}`)

	_, err := executor.Execute(
		contextWithGinRequest("/v1/responses", map[string]string{
			"Accept": "application/json",
		}),
		auth,
		cliproxyexecutor.Request{Model: "gpt-5", Payload: body},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: body,
		},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := seenHeaders.Get("Authorization"); got != "Bearer sk-test" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer sk-test")
	}
	if got := seenHeaders.Get("X-Gateway-Id"); got != "" {
		t.Fatalf("X-Gateway-Id = %q, want empty", got)
	}
	if got := seenHeaders.Get("Chatgpt-Account-Id"); got != "" {
		t.Fatalf("Chatgpt-Account-Id = %q, want empty for api_key auth", got)
	}
}

func TestSummarizeCodexTransparentDiff(t *testing.T) {
	legacyReq, err := http.NewRequest(http.MethodPost, "https://example.com/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest legacy error = %v", err)
	}
	legacyReq.Header.Set("Session_id", "generated-session")
	legacyReq.Header.Set("Originator", "codex_cli_rs")

	transparentReq, err := http.NewRequest(http.MethodPost, "https://example.com/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest transparent error = %v", err)
	}
	transparentReq.Header.Set("Session_id", "client-session")
	transparentReq.Header.Set("User-Agent", "client-ua")

	diff := summarizeCodexTransparentDiff(
		codexPreparedRequest{
			body:    []byte(`{"stream":true,"parallel_tool_calls":true}`),
			request: legacyReq,
		},
		codexPreparedRequest{
			body:        []byte(`{"stream":false,"previous_response_id":"resp-1"}`),
			request:     transparentReq,
			transparent: true,
		},
	)

	if !containsString(diff.headersOnlyLegacy, "Originator") {
		t.Fatalf("headersOnlyLegacy = %v, want Originator", diff.headersOnlyLegacy)
	}
	if !containsString(diff.headersOnlyTransparent, "User-Agent") {
		t.Fatalf("headersOnlyTransparent = %v, want User-Agent", diff.headersOnlyTransparent)
	}
	if !containsString(diff.headersChanged, "Session_id") {
		t.Fatalf("headersChanged = %v, want Session_id", diff.headersChanged)
	}
	if !containsString(diff.bodyChanged, "stream") {
		t.Fatalf("bodyChanged = %v, want stream", diff.bodyChanged)
	}
	if !containsString(diff.bodyOnlyLegacy, "parallel_tool_calls") {
		t.Fatalf("bodyOnlyLegacy = %v, want parallel_tool_calls", diff.bodyOnlyLegacy)
	}
	if !containsString(diff.bodyOnlyTransparent, "previous_response_id") {
		t.Fatalf("bodyOnlyTransparent = %v, want previous_response_id", diff.bodyOnlyTransparent)
	}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func contextWithGinRequest(rawURL string, headers map[string]string) context.Context {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodPost, rawURL, nil)
	ginCtx.Request.Header = make(http.Header, len(headers))
	for key, value := range headers {
		ginCtx.Request.Header.Set(key, value)
	}
	return context.WithValue(context.Background(), "gin", ginCtx)
}

func encodeTransparentSnapshotHeadersForTest(headers map[string]string) string {
	data, err := json.Marshal(headers)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}
