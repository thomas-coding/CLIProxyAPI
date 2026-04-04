package executor

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

func TestCodexExecutorExecuteStream_ReturnsErrorWhenResponseCompletedIsMissing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n")
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"api_key":  "test-api-key",
			"base_url": server.URL,
		},
	}

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5.3-codex",
		Payload: []byte(`{"model":"gpt-5.3-codex","messages":[]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	if result == nil {
		t.Fatalf("expected stream result")
	}

	var terminalErr error
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			terminalErr = chunk.Err
		}
	}
	if terminalErr == nil {
		t.Fatalf("expected terminal stream error")
	}

	statusProvider, ok := terminalErr.(interface{ StatusCode() int })
	if !ok {
		t.Fatalf("expected status-carrying error, got %T", terminalErr)
	}
	if statusProvider.StatusCode() != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d", statusProvider.StatusCode(), http.StatusRequestTimeout)
	}
	if !strings.Contains(terminalErr.Error(), "response.completed") {
		t.Fatalf("error = %q, want response.completed detail", terminalErr.Error())
	}
}

func TestCodexExecutorExecuteStream_TransparentOnDecodesCompressedStream(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"pong\"}\n\n")
		_, _ = io.WriteString(gz, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"created_at\":1700000000,\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
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

	result, err := executor.ExecuteStream(
		contextWithGinRequest("/v1/responses", map[string]string{
			"Accept": "text/event-stream",
			codexTransparentClientHeadersHeader: encodeTransparentSnapshotHeadersForTest(map[string]string{
				"Accept-Encoding": "gzip",
			}),
		}),
		auth,
		cliproxyexecutor.Request{
			Model:   "gpt-5",
			Payload: []byte(`{"model":"gpt-5","stream":true}`),
		},
		cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FromString("openai-response"),
			OriginalRequest: []byte(`{"model":"gpt-5","stream":true}`),
		},
	)
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	if result == nil {
		t.Fatalf("expected stream result")
	}

	var chunks [][]byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("unexpected stream error: %v", chunk.Err)
		}
		if len(chunk.Payload) > 0 {
			chunks = append(chunks, append([]byte(nil), chunk.Payload...))
		}
	}
	if len(chunks) == 0 {
		t.Fatal("expected decoded stream chunks")
	}
}
