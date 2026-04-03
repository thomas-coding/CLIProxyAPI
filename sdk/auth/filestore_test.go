package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestExtractAccessToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata map[string]any
		expected string
	}{
		{
			"antigravity top-level access_token",
			map[string]any{"access_token": "tok-abc"},
			"tok-abc",
		},
		{
			"gemini nested token.access_token",
			map[string]any{
				"token": map[string]any{"access_token": "tok-nested"},
			},
			"tok-nested",
		},
		{
			"top-level takes precedence over nested",
			map[string]any{
				"access_token": "tok-top",
				"token":        map[string]any{"access_token": "tok-nested"},
			},
			"tok-top",
		},
		{
			"empty metadata",
			map[string]any{},
			"",
		},
		{
			"whitespace-only access_token",
			map[string]any{"access_token": "   "},
			"",
		},
		{
			"wrong type access_token",
			map[string]any{"access_token": 12345},
			"",
		},
		{
			"token is not a map",
			map[string]any{"token": "not-a-map"},
			"",
		},
		{
			"nested whitespace-only",
			map[string]any{
				"token": map[string]any{"access_token": "  "},
			},
			"",
		},
		{
			"fallback to nested when top-level empty",
			map[string]any{
				"access_token": "",
				"token":        map[string]any{"access_token": "tok-fallback"},
			},
			"tok-fallback",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractAccessToken(tt.metadata)
			if got != tt.expected {
				t.Errorf("extractAccessToken() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFileTokenStore_SaveAndListRestoresRuntimeState(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	auth := &cliproxyauth.Auth{
		ID:       "codex-auth.json",
		FileName: "codex-auth.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type":  "codex",
			"email": "cooling@example.com",
		},
		Unavailable:    true,
		NextRetryAfter: time.Now().Add(20 * time.Minute),
		Quota: cliproxyauth.QuotaState{
			Exceeded:      true,
			Reason:        "quota",
			NextRecoverAt: time.Now().Add(25 * time.Minute),
		},
	}

	if _, err := store.Save(context.Background(), auth); err != nil {
		t.Fatalf("Save: %v", err)
	}

	entries, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	got := entries[0]
	if got == nil {
		t.Fatalf("expected auth entry")
	}
	if !got.Unavailable {
		t.Fatalf("expected restored auth to remain unavailable")
	}
	if !got.NextRetryAfter.After(time.Now()) {
		t.Fatalf("expected future retry time, got %v", got.NextRetryAfter)
	}
	if !got.Quota.Exceeded {
		t.Fatalf("expected restored quota exceeded state")
	}
	if got.Attributes["path"] != filepath.Join(dir, "codex-auth.json") {
		t.Fatalf("path = %q, want %q", got.Attributes["path"], filepath.Join(dir, "codex-auth.json"))
	}
}

func TestFileTokenStore_ListIgnoresDeletedAuthBackup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	activePath := filepath.Join(dir, "active.json")
	if err := os.WriteFile(activePath, []byte(`{"type":"codex","email":"active@example.com"}`), 0o644); err != nil {
		t.Fatalf("write active auth: %v", err)
	}
	backupDir := filepath.Join(dir, "deleted-auth-backup", "20260401")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		t.Fatalf("mkdir backup dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "backup.json"), []byte(`{"type":"codex","email":"backup@example.com"}`), 0o644); err != nil {
		t.Fatalf("write backup auth: %v", err)
	}

	entries, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0] == nil || entries[0].ID != "active.json" {
		t.Fatalf("expected only active.json, got %+v", entries[0])
	}
}
