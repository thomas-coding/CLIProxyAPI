package executor

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestCodexBoundFallbackUserAgentStableForAffinityKey(t *testing.T) {
	ctxA := contextWithGinRequest("/v1/responses", map[string]string{
		codexAffinityKeyHeader: "user:15",
	})
	ctxB := contextWithGinRequest("/v1/responses", map[string]string{
		codexAffinityKeyHeader: "user:15",
	})

	gotA := codexBoundFallbackUserAgent(ctxA, nil)
	gotB := codexBoundFallbackUserAgent(ctxB, nil)
	if gotA == "" {
		t.Fatal("bound fallback UA must not be empty")
	}
	if gotA != gotB {
		t.Fatalf("bound fallback UA mismatch for same affinity key: %q vs %q", gotA, gotB)
	}
	if !containsString(codexFallbackUserAgentPool, gotA) {
		t.Fatalf("bound fallback UA = %q, want one of configured pool entries", gotA)
	}
}

func TestCodexBoundFallbackUserAgentFallsBackToAuthSeed(t *testing.T) {
	auth := &cliproxyauth.Auth{
		ID:       "auth-1",
		Provider: "codex",
	}

	got := codexBoundFallbackUserAgent(nil, auth)
	if got == "" {
		t.Fatal("bound fallback UA must not be empty")
	}
	if !containsString(codexFallbackUserAgentPool, got) {
		t.Fatalf("bound fallback UA = %q, want one of configured pool entries", got)
	}
}

func TestEnsureCodexUserAgentTransparentSnapshotPreservesClientUAOverConfig(t *testing.T) {
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		codexTransparentClientHeadersHeader: encodeTransparentSnapshotHeadersForTest(map[string]string{
			"User-Agent": "client-ua",
		}),
	})
	target := http.Header{}
	target.Set("User-Agent", "Go-http-client/1.1")

	ensureCodexUserAgent(target, nil, ctx, &cliproxyauth.Auth{Provider: "codex"}, &config.Config{
		CodexHeaderDefaults: config.CodexHeaderDefaults{
			UserAgent: "config-ua",
		},
	})

	if got := target.Get("User-Agent"); got != "client-ua" {
		t.Fatalf("User-Agent = %q, want %q", got, "client-ua")
	}
}

func TestEnsureCodexUserAgentSnapshotWithoutUAKeepsNonInternalCurrentUA(t *testing.T) {
	ctx := contextWithGinRequest("/v1/responses", map[string]string{
		codexTransparentClientHeadersHeader: encodeTransparentSnapshotHeadersForTest(map[string]string{
			"Accept": "application/json",
		}),
	})
	target := http.Header{}
	target.Set("User-Agent", "custom-direct-ua")

	ensureCodexUserAgent(target, nil, ctx, &cliproxyauth.Auth{Provider: "codex"}, &config.Config{
		CodexHeaderDefaults: config.CodexHeaderDefaults{
			UserAgent: "config-ua",
		},
	})

	if got := target.Get("User-Agent"); got != "custom-direct-ua" {
		t.Fatalf("User-Agent = %q, want %q", got, "custom-direct-ua")
	}
}
