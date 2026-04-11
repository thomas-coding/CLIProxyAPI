package reserve2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestStatusDoesNotPersistFiles(t *testing.T) {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)
	writeAuthFixture(t, filepath.Join(env.PoolDir(), "cold-a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	summary, err := app.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if summary.Pool.TotalFiles != 1 {
		t.Fatalf("summary.Pool.TotalFiles = %d, want 1", summary.Pool.TotalFiles)
	}
	if _, err := os.Stat(env.StatePath()); !os.IsNotExist(err) {
		t.Fatalf("state file exists after status read: err=%v", err)
	}
	if _, err := os.Stat(env.SummaryPath()); !os.IsNotExist(err) {
		t.Fatalf("summary file exists after status read: err=%v", err)
	}
}

func TestStatusUsesUncheckedAuthModTimeForOldestUnchecked(t *testing.T) {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	oldPath := filepath.Join(env.PoolDir(), "cold-old.json")
	newPath := filepath.Join(env.PoolDir(), "cold-new.json")
	writeAuthFixture(t, oldPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-old",
	})
	writeAuthFixture(t, newPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-new",
	})

	oldMod := now.Add(-48 * time.Hour)
	newMod := now.Add(-2 * time.Hour)
	if err := os.Chtimes(oldPath, oldMod, oldMod); err != nil {
		t.Fatalf("Chtimes(oldPath) error = %v", err)
	}
	if err := os.Chtimes(newPath, newMod, newMod); err != nil {
		t.Fatalf("Chtimes(newPath) error = %v", err)
	}

	state := &StateFile{
		Files: map[string]*FileState{
			"cold-new.json": {
				LastCheckedAt: now.Add(-15 * time.Minute),
				LastResult:    resultHealthy200,
			},
		},
	}
	if err := app.saveState(state); err != nil {
		t.Fatalf("saveState() error = %v", err)
	}

	summary, err := app.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if summary.Pool.OldestUncheckedAt.IsZero() {
		t.Fatal("summary.Pool.OldestUncheckedAt = zero, want old file time")
	}
	if !summary.Pool.OldestUncheckedAt.Equal(oldMod) {
		t.Fatalf("summary.Pool.OldestUncheckedAt = %v, want %v", summary.Pool.OldestUncheckedAt, oldMod)
	}
}

func TestBuildRolling24hCountsAllSampleOutcomes(t *testing.T) {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)
	events := []eventRecord{
		{At: now.Add(-1 * time.Hour), Type: resultHealthy200},
		{At: now.Add(-2 * time.Hour), Type: resultRefreshRecovered},
		{At: now.Add(-3 * time.Hour), Type: resultInvalidMoved},
		{At: now.Add(-4 * time.Hour), Type: resultUsage429},
		{At: now.Add(-5 * time.Hour), Type: resultProbeError},
		{At: now.Add(-6 * time.Hour), Type: resultDuplicate},
		{At: now.Add(-7 * time.Hour), Type: "promoted_to_reserve1"},
	}
	if err := app.appendEvents(events); err != nil {
		t.Fatalf("appendEvents() error = %v", err)
	}

	summary, err := app.buildRolling24h(now)
	if err != nil {
		t.Fatalf("buildRolling24h() error = %v", err)
	}
	if summary.Sampled != 5 {
		t.Fatalf("summary.Sampled = %d, want 5", summary.Sampled)
	}
	if summary.SampleOK != 1 || summary.SampleRefreshOK != 1 || summary.InvalidMoved != 1 || summary.Usage429 != 1 || summary.ProbeError != 1 {
		t.Fatalf("unexpected rolling summary = %+v", summary)
	}
	if summary.DuplicateSkipped != 1 || summary.PromotedToReserve1 != 1 {
		t.Fatalf("unexpected duplicate/promoted summary = %+v", summary)
	}

	if _, err := os.Stat(env.EventsPath()); err != nil {
		t.Fatalf("events path missing after append: %v", err)
	}
}

func TestWithOptionalLockClearsStaleLock(t *testing.T) {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)
	if err := os.MkdirAll(env.StateDir(), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	staleRecord := lockRecord{
		PID: 12345,
		At:  now.Add(-3 * time.Hour),
	}
	raw, err := json.Marshal(staleRecord)
	if err != nil {
		t.Fatalf("Marshal(lockRecord) error = %v", err)
	}
	if err := os.WriteFile(env.LockPath(), raw, 0o600); err != nil {
		t.Fatalf("WriteFile(lock) error = %v", err)
	}

	called := false
	if err := app.withOptionalLock(true, func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("withOptionalLock() error = %v", err)
	}
	if !called {
		t.Fatal("withOptionalLock() did not execute callback")
	}
	if _, err := os.Stat(env.LockPath()); !os.IsNotExist(err) {
		t.Fatalf("lock file still exists after callback: err=%v", err)
	}
}

func TestInspectAuthPreviewSkipsRefresh(t *testing.T) {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	probeCalls := 0
	refreshCalls := 0
	app.usageProbeFunc = func(context.Context, *coreauth.Auth) (*usageProbeResponse, error) {
		probeCalls++
		return nil, fmt.Errorf("codex access_token is missing")
	}
	app.refreshAuthFunc = func(context.Context, *coreauth.Auth) (*coreauth.Auth, error) {
		refreshCalls++
		return nil, fmt.Errorf("refresh should not be called in preview")
	}

	result, err := app.inspectAuth(context.Background(), &coreauth.Auth{FileName: "cold-a.json"}, false)
	if err != nil {
		t.Fatalf("inspectAuth(preview) error = %v", err)
	}
	if probeCalls != 1 {
		t.Fatalf("probeCalls = %d, want 1", probeCalls)
	}
	if refreshCalls != 0 {
		t.Fatalf("refreshCalls = %d, want 0", refreshCalls)
	}
	if result.refreshed {
		t.Fatal("result.refreshed = true, want false")
	}
	if result.classification != classificationTransient {
		t.Fatalf("result.classification = %q, want %q", result.classification, classificationTransient)
	}
}

func TestInspectAuthApplyRefreshesRecoverableAuth(t *testing.T) {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	probeCalls := 0
	refreshCalls := 0
	app.usageProbeFunc = func(_ context.Context, authEntry *coreauth.Auth) (*usageProbeResponse, error) {
		probeCalls++
		if probeCalls == 1 {
			return nil, fmt.Errorf("codex access_token is missing")
		}
		if got := authEntry.Metadata["access_token"]; got != "fresh-token" {
			t.Fatalf("access_token after refresh = %v, want fresh-token", got)
		}
		return &usageProbeResponse{StatusCode: http.StatusOK, Body: "{}"}, nil
	}
	app.refreshAuthFunc = func(_ context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
		refreshCalls++
		updated := authEntry.Clone()
		if updated.Metadata == nil {
			updated.Metadata = map[string]any{}
		}
		updated.Metadata["access_token"] = "fresh-token"
		updated.Metadata["account_id"] = "acct-1"
		updated.Metadata["refresh_token"] = "refresh-1"
		return updated, nil
	}

	result, err := app.inspectAuth(context.Background(), &coreauth.Auth{
		FileName: "cold-a.json",
		Metadata: map[string]any{
			"refresh_token": "refresh-1",
		},
	}, true)
	if err != nil {
		t.Fatalf("inspectAuth(apply) error = %v", err)
	}
	if probeCalls != 2 {
		t.Fatalf("probeCalls = %d, want 2", probeCalls)
	}
	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want 1", refreshCalls)
	}
	if !result.refreshed {
		t.Fatal("result.refreshed = false, want true")
	}
	if result.classification != classificationSuccess {
		t.Fatalf("result.classification = %q, want %q", result.classification, classificationSuccess)
	}
	if result.statusCode != http.StatusOK {
		t.Fatalf("result.statusCode = %d, want %d", result.statusCode, http.StatusOK)
	}
}

func newTestApp(t *testing.T, now time.Time) (*App, *EnvConfig) {
	t.Helper()
	root := t.TempDir()
	env := &EnvConfig{
		ColdRoot:          filepath.Join(root, "cold"),
		ConfigPath:        filepath.Join(root, "config.yaml"),
		ProductionDir:     filepath.Join(root, "production"),
		Reserve1Dir:       filepath.Join(root, "reserve1"),
		LowWatermark:      300,
		Target:            600,
		MaxTransfer:       150,
		CandidateFactor:   1.6,
		SampleSize:        20,
		SampleCap:         30,
		Cooldown429:       24 * time.Hour,
		CooldownTransient: 30 * time.Minute,
		Timezone:          "UTC",
	}
	if err := env.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories() error = %v", err)
	}
	if err := os.WriteFile(env.ConfigPath, []byte("auth-dir: "+env.ProductionDir+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	app := NewApp(env, &config.Config{})
	app.now = func() time.Time { return now }
	return app, env
}

func writeAuthFixture(t *testing.T, path string, payload map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal(auth fixture) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(auth fixture) error = %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile(auth fixture) error = %v", err)
	}
}
