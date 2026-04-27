package maintpool

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestImportPreviewReturnsImportedNames(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	sourceDir := filepath.Join(t.TempDir(), "source")
	writeAuthFixture(t, filepath.Join(sourceDir, "a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})
	writeAuthFixture(t, filepath.Join(sourceDir, "b.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-b",
	})

	result, err := app.Import(context.Background(), sourceDir, false)
	if err != nil {
		t.Fatalf("Import(preview) error = %v", err)
	}
	if result.Summary.Imported != 2 {
		t.Fatalf("result.Summary.Imported = %d, want 2", result.Summary.Imported)
	}
	if len(result.Imported) != 2 {
		t.Fatalf("len(result.Imported) = %d, want 2", len(result.Imported))
	}
	if result.Imported[0] != "a.json" || result.Imported[1] != "b.json" {
		t.Fatalf("result.Imported = %v, want [a.json b.json]", result.Imported)
	}
	if _, err := os.Stat(filepath.Join(env.PoolDir(), "a.json")); !os.IsNotExist(err) {
		t.Fatalf("pool file exists after preview import: err=%v", err)
	}
}

func TestImportPreviewMarksTruncationWhenResultListOverflows(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	sourceDir := filepath.Join(t.TempDir(), "source")
	for i := 0; i < resultListLimit+5; i++ {
		writeAuthFixture(t, filepath.Join(sourceDir, fmt.Sprintf("a-%03d.json", i)), map[string]any{
			"type":          "codex",
			"refresh_token": fmt.Sprintf("refresh-%03d", i),
		})
	}

	result, err := app.Import(context.Background(), sourceDir, false)
	if err != nil {
		t.Fatalf("Import(preview) error = %v", err)
	}
	if !result.ImportedTruncated {
		t.Fatal("result.ImportedTruncated = false, want true")
	}
	if len(result.Imported) != resultListLimit {
		t.Fatalf("len(result.Imported) = %d, want %d", len(result.Imported), resultListLimit)
	}
	if result.ResultListLimit != resultListLimit {
		t.Fatalf("result.ResultListLimit = %d, want %d", result.ResultListLimit, resultListLimit)
	}
}

func TestImportApplyRecordsSourceAndTargetPaths(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	sourceDir := filepath.Join(t.TempDir(), "source")
	sourcePath := filepath.Join(sourceDir, "a.json")
	writeAuthFixture(t, sourcePath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	result, err := app.Import(context.Background(), sourceDir, true)
	if err != nil {
		t.Fatalf("Import(apply) error = %v", err)
	}
	if result.Summary.Imported != 1 {
		t.Fatalf("result.Summary.Imported = %d, want 1", result.Summary.Imported)
	}

	raw, err := os.ReadFile(env.EventsPath())
	if err != nil {
		t.Fatalf("ReadFile(events) error = %v", err)
	}
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("Unmarshal(event) error = %v", err)
	}
	wantTarget := filepath.Join(env.PoolDir(), "a.json")
	if event.SourcePath != sourcePath {
		t.Fatalf("event.SourcePath = %q, want %q", event.SourcePath, sourcePath)
	}
	if event.TargetPath != wantTarget {
		t.Fatalf("event.TargetPath = %q, want %q", event.TargetPath, wantTarget)
	}
}

func TestImportApplyRollsBackFilesWhenAppendEventsFails(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	sourceDir := filepath.Join(t.TempDir(), "source")
	sourcePath := filepath.Join(sourceDir, "a.json")
	writeAuthFixture(t, sourcePath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})
	if err := os.MkdirAll(env.EventsPath(), 0o700); err != nil {
		t.Fatalf("MkdirAll(eventsPath) error = %v", err)
	}

	_, err := app.Import(context.Background(), sourceDir, true)
	if err == nil {
		t.Fatal("Import(apply) error = nil, want append rollback failure")
	}
	if got := err.Error(); !strings.Contains(got, "append import events:") {
		t.Fatalf("Import(apply) error = %q, want append failure", got)
	}
	if _, err := os.Stat(filepath.Join(env.PoolDir(), "a.json")); !os.IsNotExist(err) {
		t.Fatalf("pool file still exists after rollback: err=%v", err)
	}
	state, err := app.loadState()
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	if len(state.Files) != 0 {
		t.Fatalf("len(state.Files) = %d, want 0", len(state.Files))
	}
}

func TestProcessDueAuthRefreshesWhenAccessTokenMissing(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
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
		updated.Metadata["type"] = "codex"
		updated.Metadata["access_token"] = "fresh-token"
		updated.Metadata["account_id"] = "acct-1"
		updated.Metadata["refresh_token"] = "refresh-1"
		return updated, nil
	}

	state := &StateFile{Files: map[string]*FileState{}}
	summary := &ScanSummary{}
	events := make([]Event, 0, 1)
	removed, err := app.processDueAuth(context.Background(), dueCandidate{
		auth: &coreauth.Auth{
			FileName: "pool-a.json",
			Provider: "codex",
			Metadata: map[string]any{
				"type":          "codex",
				"refresh_token": "refresh-1",
			},
		},
		dueProbe: true,
	}, state, summary, &events)
	if err != nil {
		t.Fatalf("processDueAuth() error = %v", err)
	}
	if removed {
		t.Fatal("removed = true, want false")
	}
	if probeCalls != 2 {
		t.Fatalf("probeCalls = %d, want 2", probeCalls)
	}
	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want 1", refreshCalls)
	}
	if summary.RecoveryRefreshOK != 1 {
		t.Fatalf("summary.RecoveryRefreshOK = %d, want 1", summary.RecoveryRefreshOK)
	}
	entry := state.Files["pool-a.json"]
	if entry == nil {
		t.Fatal("state entry missing for pool-a.json")
	}
	if entry.LastResult != resultRecoveryRefreshOK {
		t.Fatalf("entry.LastResult = %q, want %q", entry.LastResult, resultRecoveryRefreshOK)
	}
	if entry.LastHTTPStatus != http.StatusOK {
		t.Fatalf("entry.LastHTTPStatus = %d, want %d", entry.LastHTTPStatus, http.StatusOK)
	}
}

func TestProcessDueAuthRefreshesDirectlyWhenRefreshIsDue(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	probeCalls := 0
	refreshCalls := 0
	app.usageProbeFunc = func(_ context.Context, authEntry *coreauth.Auth) (*usageProbeResponse, error) {
		probeCalls++
		if got := authEntry.Metadata["access_token"]; got != "fresh-token" {
			t.Fatalf("usage probe saw access_token = %v, want fresh-token from post-refresh confirm only", got)
		}
		return &usageProbeResponse{StatusCode: http.StatusOK, Body: "{}"}, nil
	}
	app.refreshAuthFunc = func(_ context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
		refreshCalls++
		updated := authEntry.Clone()
		if updated.Metadata == nil {
			updated.Metadata = map[string]any{}
		}
		updated.Metadata["type"] = "codex"
		updated.Metadata["access_token"] = "fresh-token"
		updated.Metadata["account_id"] = "acct-1"
		updated.Metadata["refresh_token"] = "refresh-1"
		return updated, nil
	}

	state := &StateFile{Files: map[string]*FileState{}}
	summary := &ScanSummary{}
	events := make([]Event, 0, 1)
	removed, err := app.processDueAuth(context.Background(), dueCandidate{
		auth: &coreauth.Auth{
			FileName: "pool-a.json",
			Provider: "codex",
			Metadata: map[string]any{
				"type":          "codex",
				"refresh_token": "refresh-1",
			},
		},
		dueRefresh: true,
	}, state, summary, &events)
	if err != nil {
		t.Fatalf("processDueAuth() error = %v", err)
	}
	if removed {
		t.Fatal("removed = true, want false")
	}
	if probeCalls != 1 {
		t.Fatalf("probeCalls = %d, want 1 confirm probe after refresh", probeCalls)
	}
	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want 1", refreshCalls)
	}
	if summary.ScheduledRefreshOK != 1 {
		t.Fatalf("summary.ScheduledRefreshOK = %d, want 1", summary.ScheduledRefreshOK)
	}
	entry := state.Files["pool-a.json"]
	if entry == nil {
		t.Fatal("state entry missing for pool-a.json")
	}
	if entry.LastResult != resultScheduledRefreshOK {
		t.Fatalf("entry.LastResult = %q, want %q", entry.LastResult, resultScheduledRefreshOK)
	}
}

func TestScheduledRefreshPreservesFutureUsageAuditWindow(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	app.usageProbeFunc = func(_ context.Context, authEntry *coreauth.Auth) (*usageProbeResponse, error) {
		if got := authEntry.Metadata["access_token"]; got != "fresh-token" {
			t.Fatalf("usage probe saw access_token = %v, want fresh-token", got)
		}
		return &usageProbeResponse{StatusCode: http.StatusOK, Body: "{}"}, nil
	}
	app.refreshAuthFunc = func(_ context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
		updated := authEntry.Clone()
		if updated.Metadata == nil {
			updated.Metadata = map[string]any{}
		}
		updated.Metadata["type"] = "codex"
		updated.Metadata["access_token"] = "fresh-token"
		updated.Metadata["account_id"] = "acct-1"
		updated.Metadata["refresh_token"] = "refresh-1"
		return updated, nil
	}

	futureProbeAt := now.Add(80 * 24 * time.Hour)
	state := &StateFile{
		Files: map[string]*FileState{
			"pool-a.json": {
				ImportedAt:       now.Add(-40 * 24 * time.Hour),
				NextProbeAt:      futureProbeAt,
				NextRefreshDueAt: now.Add(-time.Hour),
			},
		},
	}
	summary := &ScanSummary{}
	events := make([]Event, 0, 1)
	removed, err := app.processDueAuth(context.Background(), dueCandidate{
		auth: &coreauth.Auth{
			FileName: "pool-a.json",
			Provider: "codex",
			Metadata: map[string]any{
				"type":          "codex",
				"refresh_token": "refresh-1",
			},
		},
		dueRefresh: true,
	}, state, summary, &events)
	if err != nil {
		t.Fatalf("processDueAuth() error = %v", err)
	}
	if removed {
		t.Fatal("removed = true, want false")
	}
	entry := state.Files["pool-a.json"]
	if entry == nil {
		t.Fatal("state entry missing for pool-a.json")
	}
	if !entry.NextProbeAt.Equal(futureProbeAt) {
		t.Fatalf("entry.NextProbeAt = %v, want preserved future audit window %v", entry.NextProbeAt, futureProbeAt)
	}
}

func TestSyntheticImportedStateForRecentMissingStateUsesRecoveryWindow(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	authEntry := &coreauth.Auth{
		FileName:  "recent.json",
		CreatedAt: now,
		UpdatedAt: now,
		Provider:  "codex",
		Metadata: map[string]any{
			"type":          "codex",
			"refresh_token": "refresh-recent",
		},
	}

	state := syntheticImportedState(authEntry, now)
	if !state.ImportedAt.IsZero() {
		t.Fatalf("state.ImportedAt = %v, want zero", state.ImportedAt)
	}
	wantProbeAt := now.Add(deterministicInitialDelay(authEntry, "recovery-probe", missingStateProbeMinDelay, missingStateProbeMaxDelay))
	wantRefreshAt := now.Add(deterministicInitialDelay(authEntry, "recovery-refresh", missingStateRefreshMinDelay, missingStateRefreshMaxDelay))
	if !state.NextProbeAt.Equal(wantProbeAt) {
		t.Fatalf("state.NextProbeAt = %v, want %v", state.NextProbeAt, wantProbeAt)
	}
	if !state.NextRefreshDueAt.Equal(wantRefreshAt) {
		t.Fatalf("state.NextRefreshDueAt = %v, want %v", state.NextRefreshDueAt, wantRefreshAt)
	}
}

func TestScanPreviewDoesNotTreatMissingStateAsImmediatelyDue(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	authPath := filepath.Join(env.PoolDir(), "fresh.json")
	writeAuthFixture(t, authPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-fresh",
	})
	if err := os.Chtimes(authPath, now, now); err != nil {
		t.Fatalf("Chtimes(authPath) error = %v", err)
	}

	result, err := app.Scan(context.Background(), false, 0)
	if err != nil {
		t.Fatalf("Scan(preview) error = %v", err)
	}
	if result.Summary.Selected != 0 {
		t.Fatalf("result.Summary.Selected = %d, want 0", result.Summary.Selected)
	}
	if len(result.Selected) != 0 {
		t.Fatalf("len(result.Selected) = %d, want 0", len(result.Selected))
	}
}

func TestScanPreviewSelectsOlderMissingStateAuthForRecovery(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	authPath := filepath.Join(env.PoolDir(), "old.json")
	writeAuthFixture(t, authPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-old",
	})
	oldMod := now.Add(-7 * 24 * time.Hour)
	if err := os.Chtimes(authPath, oldMod, oldMod); err != nil {
		t.Fatalf("Chtimes(authPath) error = %v", err)
	}

	result, err := app.Scan(context.Background(), false, 0)
	if err != nil {
		t.Fatalf("Scan(preview) error = %v", err)
	}
	if result.Summary.Selected != 1 {
		t.Fatalf("result.Summary.Selected = %d, want 1", result.Summary.Selected)
	}
	if len(result.Selected) != 1 || result.Selected[0] != "old.json" {
		t.Fatalf("result.Selected = %v, want [old.json]", result.Selected)
	}
}

func TestStatusReportsOldestKnownAuthAtWhenStateIsMissing(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	oldPath := filepath.Join(env.PoolDir(), "old.json")
	newPath := filepath.Join(env.PoolDir(), "new.json")
	writeAuthFixture(t, oldPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-old",
	})
	writeAuthFixture(t, newPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-new",
	})
	oldMod := now.Add(-9 * 24 * time.Hour)
	newMod := now.Add(-2 * 24 * time.Hour)
	if err := os.Chtimes(oldPath, oldMod, oldMod); err != nil {
		t.Fatalf("Chtimes(oldPath) error = %v", err)
	}
	if err := os.Chtimes(newPath, newMod, newMod); err != nil {
		t.Fatalf("Chtimes(newPath) error = %v", err)
	}

	result, err := app.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !result.Pool.OldestImportedAt.IsZero() {
		t.Fatalf("result.Pool.OldestImportedAt = %v, want zero without state", result.Pool.OldestImportedAt)
	}
	if !result.Pool.OldestKnownAuthAt.Equal(oldMod) {
		t.Fatalf("result.Pool.OldestKnownAuthAt = %v, want %v", result.Pool.OldestKnownAuthAt, oldMod)
	}
}

func TestTakeoutRejectsDestinationInsidePool(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	authPath := filepath.Join(env.PoolDir(), "pool-a.json")
	writeAuthFixture(t, authPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	_, err := app.Takeout(context.Background(), "pool-a.json", filepath.Join(env.PoolDir(), "subdir"), false)
	if err == nil {
		t.Fatal("Takeout(preview) error = nil, want overlap rejection")
	}
	if got := err.Error(); got != "takeout destination must not overlap pool dir" {
		t.Fatalf("Takeout(preview) error = %q, want pool overlap rejection", got)
	}
}

func TestTakeoutRejectsDestinationInsideLiveAuthDir(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	authPath := filepath.Join(env.PoolDir(), "pool-a.json")
	writeAuthFixture(t, authPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	liveAuthDir := filepath.Join(t.TempDir(), "live-auths")
	if err := os.MkdirAll(liveAuthDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(liveAuthDir) error = %v", err)
	}
	app.cfg = &config.Config{AuthDir: liveAuthDir}

	_, err := app.Takeout(context.Background(), "pool-a.json", filepath.Join(liveAuthDir, "exports"), false)
	if err == nil {
		t.Fatal("Takeout(preview) error = nil, want auth-dir overlap rejection")
	}
	if got := err.Error(); got != "takeout destination must not overlap auth-dir" {
		t.Fatalf("Takeout(preview) error = %q, want auth-dir overlap rejection", got)
	}
}

func TestTakeoutRejectsDuplicateAlreadyInExportedArea(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	writeAuthFixture(t, filepath.Join(env.PoolDir(), "pool-a.json"), map[string]any{
		"type":          "codex",
		"email":         "dup@example.com",
		"refresh_token": "refresh-a",
	})
	writeAuthFixture(t, filepath.Join(env.ExportedDir(), "dup.json"), map[string]any{
		"type":          "codex",
		"email":         "dup@example.com",
		"refresh_token": "refresh-exported",
	})

	_, err := app.Takeout(context.Background(), "pool-a.json", filepath.Join(env.ExportedDir(), "batch-a"), false)
	if err == nil {
		t.Fatal("Takeout(preview) error = nil, want duplicate rejection")
	}
	if got := err.Error(); got != "takeout uniqueness check failed: email already exists in maintenance root at "+filepath.Join(env.ExportedDir(), "dup.json") {
		t.Fatalf("Takeout(preview) error = %q, want exported duplicate rejection", got)
	}
}

func TestTakeoutRejectsDuplicateAlreadyInLiveAuthDir(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	liveAuthDir := filepath.Join(t.TempDir(), "live-auths")
	if err := os.MkdirAll(liveAuthDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(liveAuthDir) error = %v", err)
	}
	app.cfg = &config.Config{AuthDir: liveAuthDir}

	writeAuthFixture(t, filepath.Join(env.PoolDir(), "pool-a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})
	writeAuthFixture(t, filepath.Join(liveAuthDir, "pool-a-copy.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	_, err := app.Takeout(context.Background(), "pool-a.json", filepath.Join(env.ExportedDir(), "batch-a"), false)
	if err == nil {
		t.Fatal("Takeout(preview) error = nil, want duplicate rejection")
	}
	if got := err.Error(); got != "takeout uniqueness check failed: refresh_token already exists in auth-dir at "+filepath.Join(liveAuthDir, "pool-a-copy.json") {
		t.Fatalf("Takeout(preview) error = %q, want auth-dir duplicate rejection", got)
	}
}

func TestTakeoutAllowsDestinationUnderExportedDir(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	authPath := filepath.Join(env.PoolDir(), "pool-a.json")
	writeAuthFixture(t, authPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	result, err := app.Takeout(context.Background(), "pool-a.json", filepath.Join(env.ExportedDir(), "batch-a"), false)
	if err != nil {
		t.Fatalf("Takeout(preview) error = %v", err)
	}
	if !result.TakenOut {
		t.Fatal("result.TakenOut = false, want true")
	}
}

func TestTakeoutApplyRollsBackMoveWhenAppendEventsFails(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	authPath := filepath.Join(env.PoolDir(), "pool-a.json")
	writeAuthFixture(t, authPath, map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})
	state := &StateFile{
		Files: map[string]*FileState{
			"pool-a.json": {
				ImportedAt: now.Add(-24 * time.Hour),
				LastResult: resultImported,
			},
		},
	}
	if err := app.saveState(state); err != nil {
		t.Fatalf("saveState() error = %v", err)
	}
	if err := os.MkdirAll(env.EventsPath(), 0o700); err != nil {
		t.Fatalf("MkdirAll(eventsPath) error = %v", err)
	}

	destDir := filepath.Join(env.ExportedDir(), "batch-a")
	_, err := app.Takeout(context.Background(), "pool-a.json", destDir, true)
	if err == nil {
		t.Fatal("Takeout(apply) error = nil, want append rollback failure")
	}
	if got := err.Error(); !strings.Contains(got, "append takeout event:") {
		t.Fatalf("Takeout(apply) error = %q, want append failure", got)
	}
	if _, err := os.Stat(authPath); err != nil {
		t.Fatalf("source auth missing after rollback: %v", err)
	}
	targetPath := filepath.Join(destDir, "pool-a.json")
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("target auth still exists after rollback: err=%v", err)
	}
	restoredState, err := app.loadState()
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	if restoredState.Files["pool-a.json"] == nil {
		t.Fatal("state entry missing after rollback")
	}
}

func newTestApp(t *testing.T, now time.Time) (*App, *EnvConfig) {
	t.Helper()
	root := t.TempDir()
	env := &EnvConfig{
		Root:                   filepath.Join(root, "maintpool"),
		ConfigPath:             filepath.Join(root, "config.yaml"),
		Timezone:               "UTC",
		InitialProbeMinDelay:   24 * time.Hour,
		InitialProbeMaxDelay:   24 * time.Hour,
		InitialRefreshMinDelay: 20 * 24 * time.Hour,
		InitialRefreshMaxDelay: 20 * 24 * time.Hour,
		ProbeMinDelay:          10 * 24 * time.Hour,
		ProbeMaxDelay:          10 * 24 * time.Hour,
		RefreshMinDelay:        30 * 24 * time.Hour,
		RefreshMaxDelay:        30 * 24 * time.Hour,
		RefreshHardMax:         45 * 24 * time.Hour,
		Cooldown429:            24 * time.Hour,
		CooldownTransient:      30 * time.Minute,
		ActionDelayMin:         0,
		ActionDelayMax:         0,
		RefreshChainDelayMin:   0,
		RefreshChainDelayMax:   0,
		ConfirmChainDelayMin:   0,
		ConfirmChainDelayMax:   0,
	}
	if err := env.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories() error = %v", err)
	}
	if err := os.WriteFile(env.ConfigPath, []byte("auth-dir: "+filepath.Join(root, "active-auths")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	app := NewApp(env, &config.Config{})
	app.now = func() time.Time { return now }
	app.rng = rand.New(rand.NewSource(1))
	app.sleep = func(context.Context, time.Duration) error { return nil }
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
