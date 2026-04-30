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

	result, err := app.Import(context.Background(), sourceDir, ImportOptions{})
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

	result, err := app.Import(context.Background(), sourceDir, ImportOptions{})
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

	result, err := app.Import(context.Background(), sourceDir, ImportOptions{Apply: true})
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

	_, err := app.Import(context.Background(), sourceDir, ImportOptions{Apply: true})
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

func TestImportApplyStoresBaselinePendingMetadata(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	sourceDir := filepath.Join(t.TempDir(), "source")
	writeAuthFixture(t, filepath.Join(sourceDir, "a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	_, err := app.Import(context.Background(), sourceDir, ImportOptions{
		Apply:         true,
		CohortID:      "cohort-1",
		SourceBatchID: "batch-1",
		Lane:          laneBaselinePending,
	})
	if err != nil {
		t.Fatalf("Import(apply) error = %v", err)
	}

	state, err := app.loadState()
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	entry := state.Files["a.json"]
	if entry == nil {
		t.Fatal("state entry missing for a.json")
	}
	if entry.CohortID != "cohort-1" {
		t.Fatalf("entry.CohortID = %q, want cohort-1", entry.CohortID)
	}
	if entry.SourceBatchID != "batch-1" {
		t.Fatalf("entry.SourceBatchID = %q, want batch-1", entry.SourceBatchID)
	}
	if entry.Lane != laneBaselinePending {
		t.Fatalf("entry.Lane = %q, want %q", entry.Lane, laneBaselinePending)
	}
	if entry.BaselineState != baselineStatePending {
		t.Fatalf("entry.BaselineState = %q, want %q", entry.BaselineState, baselineStatePending)
	}
	if !entry.BaselineRefreshOKAt.IsZero() {
		t.Fatalf("entry.BaselineRefreshOKAt = %v, want zero", entry.BaselineRefreshOKAt)
	}
}

func TestImportApplyBaselinePendingIsImmediatelySelectableForRefresh(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	sourceDir := filepath.Join(t.TempDir(), "source")
	writeAuthFixture(t, filepath.Join(sourceDir, "a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	_, err := app.Import(context.Background(), sourceDir, ImportOptions{
		Apply:         true,
		CohortID:      "cohort-1",
		SourceBatchID: "batch-1",
		Lane:          laneBaselinePending,
	})
	if err != nil {
		t.Fatalf("Import(apply) error = %v", err)
	}

	preview, err := app.Scan(context.Background(), false, 1)
	if err != nil {
		t.Fatalf("Scan(preview) error = %v", err)
	}
	if preview.Summary.Selected != 1 {
		t.Fatalf("preview.Summary.Selected = %d, want 1", preview.Summary.Selected)
	}
	if len(preview.Selected) != 1 || preview.Selected[0] != "a.json" {
		t.Fatalf("preview.Selected = %v, want [a.json]", preview.Selected)
	}
}

func TestImportApplyRejectsBaselinePendingWithoutCohortID(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	sourceDir := filepath.Join(t.TempDir(), "source")
	writeAuthFixture(t, filepath.Join(sourceDir, "a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	_, err := app.Import(context.Background(), sourceDir, ImportOptions{
		Apply:         true,
		SourceBatchID: "batch-1",
		Lane:          laneBaselinePending,
	})
	if err == nil {
		t.Fatal("Import(apply) error = nil, want missing cohort id rejection")
	}
	if got := err.Error(); got != "cohort id is required when import lane is baseline_pending" {
		t.Fatalf("Import(apply) error = %q, want missing cohort id rejection", got)
	}
}

func TestImportApplyRejectsBaselinePendingWithoutSourceBatchID(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, _ := newTestApp(t, now)

	sourceDir := filepath.Join(t.TempDir(), "source")
	writeAuthFixture(t, filepath.Join(sourceDir, "a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})

	_, err := app.Import(context.Background(), sourceDir, ImportOptions{
		Apply:    true,
		CohortID: "cohort-1",
		Lane:     laneBaselinePending,
	})
	if err == nil {
		t.Fatal("Import(apply) error = nil, want missing source batch id rejection")
	}
	if got := err.Error(); got != "source batch id is required when import lane is baseline_pending" {
		t.Fatalf("Import(apply) error = %q, want missing source batch id rejection", got)
	}
}

func TestBaselinePendingRefreshSuccessMarksReadyForAssignment(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	writeAuthFixture(t, filepath.Join(env.PoolDir(), "a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})
	state := &StateFile{
		Files: map[string]*FileState{
			"a.json": {
				ImportedAt:       now.Add(-24 * time.Hour),
				NextRefreshDueAt: now.Add(-time.Hour),
				CohortID:         "cohort-1",
				SourceBatchID:    "batch-1",
				Lane:             laneBaselinePending,
				BaselineState:    baselineStatePending,
			},
		},
	}
	if err := app.saveState(state); err != nil {
		t.Fatalf("saveState() error = %v", err)
	}

	app.refreshAuthFunc = func(_ context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
		updated := authEntry.Clone()
		if updated.Metadata == nil {
			updated.Metadata = map[string]any{}
		}
		updated.Metadata["type"] = "codex"
		updated.Metadata["access_token"] = "fresh-token"
		updated.Metadata["account_id"] = "acct-1"
		updated.Metadata["refresh_token"] = "refresh-a"
		return updated, nil
	}
	app.usageProbeFunc = func(_ context.Context, _ *coreauth.Auth) (*usageProbeResponse, error) {
		return &usageProbeResponse{StatusCode: http.StatusOK, Body: "{}"}, nil
	}

	result, err := app.Scan(context.Background(), true, 1)
	if err != nil {
		t.Fatalf("Scan(apply) error = %v", err)
	}
	if result.Summary.ScheduledRefreshOK != 1 {
		t.Fatalf("result.Summary.ScheduledRefreshOK = %d, want 1", result.Summary.ScheduledRefreshOK)
	}

	updatedState, err := app.loadState()
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	entry := updatedState.Files["a.json"]
	if entry == nil {
		t.Fatal("state entry missing for a.json after scan")
	}
	if entry.Lane != laneBaselinePending {
		t.Fatalf("entry.Lane = %q, want %q", entry.Lane, laneBaselinePending)
	}
	if entry.BaselineState != baselineStateReadyForAssignment {
		t.Fatalf("entry.BaselineState = %q, want %q", entry.BaselineState, baselineStateReadyForAssignment)
	}
	if !entry.BaselineRefreshOKAt.Equal(now) {
		t.Fatalf("entry.BaselineRefreshOKAt = %v, want %v", entry.BaselineRefreshOKAt, now)
	}
	if !entry.NextRefreshDueAt.IsZero() {
		t.Fatalf("entry.NextRefreshDueAt = %v, want zero while waiting for lane assignment", entry.NextRefreshDueAt)
	}

	preview, err := app.Scan(context.Background(), false, 0)
	if err != nil {
		t.Fatalf("Scan(preview) error = %v", err)
	}
	if preview.Summary.Selected != 0 {
		t.Fatalf("preview.Summary.Selected = %d, want 0", preview.Summary.Selected)
	}
}

func TestAssignLanesApplyDistributesReadyCohort(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	state := &StateFile{Files: map[string]*FileState{}}
	for _, name := range []string{"a.json", "b.json", "c.json", "d.json"} {
		writeAuthFixture(t, filepath.Join(env.PoolDir(), name), map[string]any{
			"type":          "codex",
			"refresh_token": "refresh-" + name,
		})
		state.Files[name] = &FileState{
			ImportedAt:          now.Add(-24 * time.Hour),
			LastRefreshOKAt:     now.Add(-24 * time.Hour),
			BaselineRefreshOKAt: now.Add(-24 * time.Hour),
			CohortID:            "cohort-1",
			SourceBatchID:       "batch-1",
			Lane:                laneBaselinePending,
			BaselineState:       baselineStateReadyForAssignment,
		}
	}
	if err := app.saveState(state); err != nil {
		t.Fatalf("saveState() error = %v", err)
	}

	result, err := app.AssignLanes(context.Background(), AssignLanesOptions{
		Apply:    true,
		CohortID: "cohort-1",
		Guard0:   1,
		Guard1:   1,
		Guard2:   1,
	})
	if err != nil {
		t.Fatalf("AssignLanes(apply) error = %v", err)
	}
	if result.Summary.AssignedMain != 1 || result.Summary.AssignedGuard0 != 1 || result.Summary.AssignedGuard1 != 1 || result.Summary.AssignedGuard2 != 1 {
		t.Fatalf("unexpected assignment summary: %#v", result.Summary)
	}

	updatedState, err := app.loadState()
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	countByLane := map[string]int{}
	for _, entry := range updatedState.Files {
		countByLane[entry.Lane]++
		if entry.BaselineState != baselineStateAdmitted {
			t.Fatalf("entry.BaselineState = %q, want %q", entry.BaselineState, baselineStateAdmitted)
		}
		if entry.LaneAssignedAt.IsZero() {
			t.Fatal("entry.LaneAssignedAt is zero after assignment")
		}
		switch entry.Lane {
		case laneMain:
			minDue := entry.BaselineRefreshOKAt.Add(env.ManagedMainRefreshMinDelay())
			maxDue := entry.BaselineRefreshOKAt.Add(env.ManagedMainRefreshMaxDelay())
			if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
				t.Fatalf("main lane due = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
			}
		case laneGuard0:
			minDelay, maxDelay, _ := env.ManagedGuardDelay(laneGuard0)
			minDue := entry.BaselineRefreshOKAt.Add(minDelay)
			maxDue := entry.BaselineRefreshOKAt.Add(maxDelay)
			if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
				t.Fatalf("guard_0 due = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
			}
		case laneGuard1:
			minDelay, maxDelay, _ := env.ManagedGuardDelay(laneGuard1)
			minDue := entry.BaselineRefreshOKAt.Add(minDelay)
			maxDue := entry.BaselineRefreshOKAt.Add(maxDelay)
			if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
				t.Fatalf("guard_1 due = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
			}
		case laneGuard2:
			minDelay, maxDelay, _ := env.ManagedGuardDelay(laneGuard2)
			minDue := entry.BaselineRefreshOKAt.Add(minDelay)
			maxDue := entry.BaselineRefreshOKAt.Add(maxDelay)
			if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
				t.Fatalf("guard_2 due = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
			}
		default:
			t.Fatalf("unexpected lane %q", entry.Lane)
		}
	}
	if countByLane[laneMain] != 1 || countByLane[laneGuard0] != 1 || countByLane[laneGuard1] != 1 || countByLane[laneGuard2] != 1 {
		t.Fatalf("unexpected lane counts: %#v", countByLane)
	}
}

func TestAdoptLegacyApplyAssignsRecentLegacyEntries(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	state := &StateFile{Files: map[string]*FileState{}}
	for _, name := range []string{"a.json", "b.json", "c.json", "d.json"} {
		writeAuthFixture(t, filepath.Join(env.PoolDir(), name), map[string]any{
			"type":          "codex",
			"refresh_token": "refresh-" + name,
		})
		state.Files[name] = &FileState{
			ImportedAt:       now.Add(-48 * time.Hour),
			LastRefreshOKAt:  now.Add(-24 * time.Hour),
			NextProbeAt:      now.Add(50 * 24 * time.Hour),
			NextRefreshDueAt: now.Add(30 * 24 * time.Hour),
		}
	}
	if err := app.saveState(state); err != nil {
		t.Fatalf("saveState() error = %v", err)
	}

	result, err := app.AdoptLegacy(context.Background(), AdoptLegacyOptions{
		Apply:                    true,
		CohortID:                 "cohort-legacy-1",
		SourceBatchID:            "legacy-batch-1",
		Guard0:                   1,
		Guard1:                   1,
		Guard2:                   1,
		RequireLastRefreshWithin: 72 * time.Hour,
	})
	if err != nil {
		t.Fatalf("AdoptLegacy(apply) error = %v", err)
	}
	if result.Summary.LegacyMatched != 4 || result.Summary.Eligible != 4 {
		t.Fatalf("unexpected adoption eligibility summary: %#v", result.Summary)
	}
	if result.Summary.AssignedMain != 1 || result.Summary.AssignedGuard0 != 1 || result.Summary.AssignedGuard1 != 1 || result.Summary.AssignedGuard2 != 1 {
		t.Fatalf("unexpected adoption assignment summary: %#v", result.Summary)
	}

	updatedState, err := app.loadState()
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	countByLane := map[string]int{}
	for _, entry := range updatedState.Files {
		countByLane[entry.Lane]++
		if entry.CohortID != "cohort-legacy-1" {
			t.Fatalf("entry.CohortID = %q, want cohort-legacy-1", entry.CohortID)
		}
		if entry.SourceBatchID != "legacy-batch-1" {
			t.Fatalf("entry.SourceBatchID = %q, want legacy-batch-1", entry.SourceBatchID)
		}
		if entry.BaselineState != baselineStateAdmitted {
			t.Fatalf("entry.BaselineState = %q, want %q", entry.BaselineState, baselineStateAdmitted)
		}
		if !entry.BaselineRefreshOKAt.Equal(entry.LastRefreshOKAt) {
			t.Fatalf("entry.BaselineRefreshOKAt = %v, want same as LastRefreshOKAt %v", entry.BaselineRefreshOKAt, entry.LastRefreshOKAt)
		}
		if entry.LaneAssignedAt.IsZero() {
			t.Fatal("entry.LaneAssignedAt is zero after legacy adoption")
		}
		if !entry.NextProbeAt.After(now) {
			t.Fatalf("entry.NextProbeAt = %v, want future probe window after adoption", entry.NextProbeAt)
		}
		switch entry.Lane {
		case laneMain:
			minDue := entry.LastRefreshOKAt.Add(env.ManagedMainRefreshMinDelay())
			maxDue := entry.LastRefreshOKAt.Add(env.ManagedMainRefreshMaxDelay())
			if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
				t.Fatalf("main lane due = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
			}
		case laneGuard0:
			minDelay, maxDelay, _ := env.ManagedGuardDelay(laneGuard0)
			minDue := entry.LastRefreshOKAt.Add(minDelay)
			maxDue := entry.LastRefreshOKAt.Add(maxDelay)
			if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
				t.Fatalf("guard_0 due = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
			}
		case laneGuard1:
			minDelay, maxDelay, _ := env.ManagedGuardDelay(laneGuard1)
			minDue := entry.LastRefreshOKAt.Add(minDelay)
			maxDue := entry.LastRefreshOKAt.Add(maxDelay)
			if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
				t.Fatalf("guard_1 due = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
			}
		case laneGuard2:
			minDelay, maxDelay, _ := env.ManagedGuardDelay(laneGuard2)
			minDue := entry.LastRefreshOKAt.Add(minDelay)
			maxDue := entry.LastRefreshOKAt.Add(maxDelay)
			if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
				t.Fatalf("guard_2 due = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
			}
		default:
			t.Fatalf("unexpected adopted lane %q", entry.Lane)
		}
	}
	if countByLane[laneMain] != 1 || countByLane[laneGuard0] != 1 || countByLane[laneGuard1] != 1 || countByLane[laneGuard2] != 1 {
		t.Fatalf("unexpected adopted lane counts: %#v", countByLane)
	}
}

func TestAdoptLegacyPreviewSkipsLegacyEntriesWithoutRecentRefresh(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	writeAuthFixture(t, filepath.Join(env.PoolDir(), "recent.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-recent",
	})
	writeAuthFixture(t, filepath.Join(env.PoolDir(), "old.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-old",
	})
	writeAuthFixture(t, filepath.Join(env.PoolDir(), "missing.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-missing",
	})
	state := &StateFile{
		Files: map[string]*FileState{
			"recent.json": {
				ImportedAt:      now.Add(-72 * time.Hour),
				LastRefreshOKAt: now.Add(-24 * time.Hour),
			},
			"old.json": {
				ImportedAt:      now.Add(-10 * 24 * time.Hour),
				LastRefreshOKAt: now.Add(-6 * 24 * time.Hour),
			},
			"missing.json": {
				ImportedAt: now.Add(-10 * 24 * time.Hour),
			},
		},
	}
	if err := app.saveState(state); err != nil {
		t.Fatalf("saveState() error = %v", err)
	}

	result, err := app.AdoptLegacy(context.Background(), AdoptLegacyOptions{
		CohortID:                 "cohort-legacy-1",
		SourceBatchID:            "legacy-batch-1",
		RequireLastRefreshWithin: 72 * time.Hour,
	})
	if err != nil {
		t.Fatalf("AdoptLegacy(preview) error = %v", err)
	}
	if result.Summary.LegacyMatched != 3 {
		t.Fatalf("result.Summary.LegacyMatched = %d, want 3", result.Summary.LegacyMatched)
	}
	if result.Summary.Eligible != 1 {
		t.Fatalf("result.Summary.Eligible = %d, want 1", result.Summary.Eligible)
	}
	if result.Summary.AssignedMain != 1 {
		t.Fatalf("result.Summary.AssignedMain = %d, want 1", result.Summary.AssignedMain)
	}
	if result.Summary.SkippedTooOld != 1 {
		t.Fatalf("result.Summary.SkippedTooOld = %d, want 1", result.Summary.SkippedTooOld)
	}
	if result.Summary.SkippedMissingAnchor != 1 {
		t.Fatalf("result.Summary.SkippedMissingAnchor = %d, want 1", result.Summary.SkippedMissingAnchor)
	}
	if len(result.Main) != 1 || result.Main[0] != "recent.json" {
		t.Fatalf("result.Main = %v, want [recent.json]", result.Main)
	}
	if len(result.Skipped) != 2 {
		t.Fatalf("len(result.Skipped) = %d, want 2", len(result.Skipped))
	}

	updatedState, err := app.loadState()
	if err != nil {
		t.Fatalf("loadState() error = %v", err)
	}
	if updatedState.Files["recent.json"].CohortID != "" {
		t.Fatalf("preview mutated state unexpectedly: cohort_id=%q", updatedState.Files["recent.json"].CohortID)
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

func TestManagedGuardRefreshSuccessPromotesToMain(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	probeCalls := 0
	app.usageProbeFunc = func(_ context.Context, authEntry *coreauth.Auth) (*usageProbeResponse, error) {
		probeCalls++
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

	state := &StateFile{
		Files: map[string]*FileState{
			"pool-a.json": {
				ImportedAt:          now.Add(-20 * 24 * time.Hour),
				LastRefreshOKAt:     now.Add(-14 * 24 * time.Hour),
				BaselineRefreshOKAt: now.Add(-14 * 24 * time.Hour),
				NextRefreshDueAt:    now.Add(-time.Hour),
				CohortID:            "cohort-1",
				SourceBatchID:       "batch-1",
				Lane:                laneGuard0,
				BaselineState:       baselineStateAdmitted,
				LaneAssignedAt:      now.Add(-14 * 24 * time.Hour),
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
	if probeCalls != 1 {
		t.Fatalf("probeCalls = %d, want 1 confirm probe for guard lane", probeCalls)
	}
	entry := state.Files["pool-a.json"]
	if entry == nil {
		t.Fatal("state entry missing for pool-a.json")
	}
	if entry.Lane != laneMain {
		t.Fatalf("entry.Lane = %q, want %q", entry.Lane, laneMain)
	}
	if entry.BaselineState != baselineStateAdmitted {
		t.Fatalf("entry.BaselineState = %q, want %q", entry.BaselineState, baselineStateAdmitted)
	}
	if !entry.LaneAssignedAt.Equal(now) {
		t.Fatalf("entry.LaneAssignedAt = %v, want %v", entry.LaneAssignedAt, now)
	}
	minDue := now.Add(env.ManagedMainRefreshMinDelay())
	maxDue := now.Add(env.ManagedMainRefreshMaxDelay())
	if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
		t.Fatalf("entry.NextRefreshDueAt = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
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

func TestManagedMainScheduledRefreshSkipsImmediateConfirm(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	probeCalls := 0
	app.usageProbeFunc = func(_ context.Context, _ *coreauth.Auth) (*usageProbeResponse, error) {
		probeCalls++
		return &usageProbeResponse{StatusCode: http.StatusOK, Body: "{}"}, nil
	}
	refreshCalls := 0
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

	state := &StateFile{
		Files: map[string]*FileState{
			"pool-a.json": {
				ImportedAt:          now.Add(-20 * 24 * time.Hour),
				LastRefreshOKAt:     now.Add(-11 * 24 * time.Hour),
				BaselineRefreshOKAt: now.Add(-11 * 24 * time.Hour),
				NextProbeAt:         now.Add(-time.Hour),
				NextRefreshDueAt:    now.Add(-time.Hour),
				CohortID:            "cohort-1",
				SourceBatchID:       "batch-1",
				Lane:                laneMain,
				BaselineState:       baselineStateAdmitted,
				LaneAssignedAt:      now.Add(-11 * 24 * time.Hour),
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
	if probeCalls != 0 {
		t.Fatalf("probeCalls = %d, want 0 for scheduled main-lane refresh", probeCalls)
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
	if !entry.LastProbeAt.IsZero() {
		t.Fatalf("entry.LastProbeAt = %v, want zero without immediate confirm", entry.LastProbeAt)
	}
	if entry.LastHTTPStatus != 0 {
		t.Fatalf("entry.LastHTTPStatus = %d, want 0 without immediate confirm", entry.LastHTTPStatus)
	}
	wantProbeAt := now.Add(-time.Hour)
	if !entry.NextProbeAt.Equal(wantProbeAt) {
		t.Fatalf("entry.NextProbeAt = %v, want preserved overdue audit %v", entry.NextProbeAt, wantProbeAt)
	}
	minDue := now.Add(env.ManagedMainRefreshMinDelay())
	maxDue := now.Add(env.ManagedMainRefreshMaxDelay())
	if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
		t.Fatalf("entry.NextRefreshDueAt = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
	}
}

func TestManagedMainScheduledRefreshPreservesFutureAuditWindowWithoutConfirm(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	probeCalls := 0
	app.usageProbeFunc = func(_ context.Context, _ *coreauth.Auth) (*usageProbeResponse, error) {
		probeCalls++
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
				ImportedAt:          now.Add(-20 * 24 * time.Hour),
				LastRefreshOKAt:     now.Add(-11 * 24 * time.Hour),
				BaselineRefreshOKAt: now.Add(-11 * 24 * time.Hour),
				NextProbeAt:         futureProbeAt,
				NextRefreshDueAt:    now.Add(-time.Hour),
				CohortID:            "cohort-1",
				SourceBatchID:       "batch-1",
				Lane:                laneMain,
				BaselineState:       baselineStateAdmitted,
				LaneAssignedAt:      now.Add(-11 * 24 * time.Hour),
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
	if probeCalls != 0 {
		t.Fatalf("probeCalls = %d, want 0 for scheduled main-lane refresh", probeCalls)
	}
	entry := state.Files["pool-a.json"]
	if entry == nil {
		t.Fatal("state entry missing for pool-a.json")
	}
	if !entry.NextProbeAt.Equal(futureProbeAt) {
		t.Fatalf("entry.NextProbeAt = %v, want preserved future audit window %v", entry.NextProbeAt, futureProbeAt)
	}
	if entry.LastResult != resultScheduledRefreshOK {
		t.Fatalf("entry.LastResult = %q, want %q", entry.LastResult, resultScheduledRefreshOK)
	}
	minDue := now.Add(env.ManagedMainRefreshMinDelay())
	maxDue := now.Add(env.ManagedMainRefreshMaxDelay())
	if entry.NextRefreshDueAt.Before(minDue) || entry.NextRefreshDueAt.After(maxDue) {
		t.Fatalf("entry.NextRefreshDueAt = %v, want within [%v, %v]", entry.NextRefreshDueAt, minDue, maxDue)
	}
}

func TestManagedMainRecoveryRefreshStillConfirms(t *testing.T) {
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

	state := &StateFile{
		Files: map[string]*FileState{
			"pool-a.json": {
				ImportedAt:          now.Add(-20 * 24 * time.Hour),
				LastRefreshOKAt:     now.Add(-11 * 24 * time.Hour),
				BaselineRefreshOKAt: now.Add(-11 * 24 * time.Hour),
				NextProbeAt:         now.Add(-time.Hour),
				NextRefreshDueAt:    now.Add(10 * 24 * time.Hour),
				CohortID:            "cohort-1",
				SourceBatchID:       "batch-1",
				Lane:                laneMain,
				BaselineState:       baselineStateAdmitted,
				LaneAssignedAt:      now.Add(-11 * 24 * time.Hour),
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
		dueProbe: true,
	}, state, summary, &events)
	if err != nil {
		t.Fatalf("processDueAuth() error = %v", err)
	}
	if removed {
		t.Fatal("removed = true, want false")
	}
	if probeCalls != 2 {
		t.Fatalf("probeCalls = %d, want 2 for main-lane recovery refresh with confirm", probeCalls)
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
	if got := result.Pool.ByLane[laneLegacy]; got != 2 {
		t.Fatalf("result.Pool.ByLane[legacy] = %d, want 2", got)
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

func TestScanApplyTriggersEmergencyStopAfterConsecutiveInvalid401(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	for _, name := range []string{"a.json", "b.json", "c.json"} {
		writeAuthFixture(t, filepath.Join(env.PoolDir(), name), map[string]any{
			"type":          "codex",
			"refresh_token": "refresh-" + name,
		})
	}
	state := &StateFile{
		Files: map[string]*FileState{
			"a.json": {ImportedAt: now.Add(-48 * time.Hour), NextRefreshDueAt: now.Add(-time.Hour)},
			"b.json": {ImportedAt: now.Add(-48 * time.Hour), NextRefreshDueAt: now.Add(-time.Hour)},
			"c.json": {ImportedAt: now.Add(-48 * time.Hour), NextRefreshDueAt: now.Add(-time.Hour)},
		},
	}
	if err := app.saveState(state); err != nil {
		t.Fatalf("saveState() error = %v", err)
	}

	refreshCalls := 0
	app.refreshAuthFunc = func(_ context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
		refreshCalls++
		return nil, fmt.Errorf("status 401: authentication token has been invalidated for %s", authEntry.FileName)
	}

	result, err := app.Scan(context.Background(), true, 3)
	if err != nil {
		t.Fatalf("Scan(apply) error = %v", err)
	}
	if refreshCalls != 3 {
		t.Fatalf("refreshCalls = %d, want 3", refreshCalls)
	}
	if !result.Summary.EmergencyStopTriggered {
		t.Fatal("result.Summary.EmergencyStopTriggered = false, want true")
	}
	if !result.Summary.EmergencyStopActive {
		t.Fatal("result.Summary.EmergencyStopActive = false, want true")
	}
	if result.Summary.ConsecutiveInvalid401 != 3 {
		t.Fatalf("result.Summary.ConsecutiveInvalid401 = %d, want 3", result.Summary.ConsecutiveInvalid401)
	}
	if result.EmergencyStop == nil || !result.EmergencyStop.Active {
		t.Fatalf("result.EmergencyStop = %#v, want active stop", result.EmergencyStop)
	}
	if result.EmergencyStop.LastResult != resultInvalidMoved {
		t.Fatalf("result.EmergencyStop.LastResult = %q, want %q", result.EmergencyStop.LastResult, resultInvalidMoved)
	}
	if _, err := os.Stat(env.EmergencyStopPath()); err != nil {
		t.Fatalf("EmergencyStopPath stat error = %v", err)
	}
}

func TestScanApplySkipsProcessingWhenEmergencyStopIsActive(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	writeAuthFixture(t, filepath.Join(env.PoolDir(), "a.json"), map[string]any{
		"type":          "codex",
		"refresh_token": "refresh-a",
	})
	state := &StateFile{
		Files: map[string]*FileState{
			"a.json": {ImportedAt: now.Add(-48 * time.Hour), NextRefreshDueAt: now.Add(-time.Hour)},
		},
	}
	if err := app.saveState(state); err != nil {
		t.Fatalf("saveState() error = %v", err)
	}
	if err := app.saveEmergencyStop(&StatusEmergencyStop{
		Active:                true,
		TriggeredAt:           now,
		Reason:                "test stop",
		ConsecutiveInvalid401: 3,
		Threshold:             3,
	}); err != nil {
		t.Fatalf("saveEmergencyStop() error = %v", err)
	}

	refreshCalls := 0
	app.refreshAuthFunc = func(_ context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
		refreshCalls++
		return authEntry.Clone(), nil
	}

	result, err := app.Scan(context.Background(), true, 1)
	if err != nil {
		t.Fatalf("Scan(apply) error = %v", err)
	}
	if refreshCalls != 0 {
		t.Fatalf("refreshCalls = %d, want 0 while emergency stop is active", refreshCalls)
	}
	if !result.Summary.EmergencyStopActive {
		t.Fatal("result.Summary.EmergencyStopActive = false, want true")
	}
	if result.Summary.Processed != 0 {
		t.Fatalf("result.Summary.Processed = %d, want 0", result.Summary.Processed)
	}
	if result.EmergencyStop == nil || !result.EmergencyStop.Active {
		t.Fatalf("result.EmergencyStop = %#v, want active stop", result.EmergencyStop)
	}
}

func TestClearEmergencyStopApplyPersistsInactiveStopAndEvent(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	app, env := newTestApp(t, now)

	if err := app.saveEmergencyStop(&StatusEmergencyStop{
		Active:                true,
		TriggeredAt:           now.Add(-time.Hour),
		Reason:                "test stop",
		ConsecutiveInvalid401: 3,
		Threshold:             3,
	}); err != nil {
		t.Fatalf("saveEmergencyStop() error = %v", err)
	}

	result, err := app.ClearEmergencyStop(context.Background(), "reviewed and resumed", true)
	if err != nil {
		t.Fatalf("ClearEmergencyStop(apply) error = %v", err)
	}
	if !result.HadStop {
		t.Fatal("result.HadStop = false, want true")
	}
	if !result.Cleared {
		t.Fatal("result.Cleared = false, want true")
	}

	stop, err := app.loadEmergencyStop()
	if err != nil {
		t.Fatalf("loadEmergencyStop() error = %v", err)
	}
	if stop.Active {
		t.Fatalf("stop.Active = true, want false: %#v", stop)
	}
	if stop.Threshold != 3 {
		t.Fatalf("stop.Threshold = %d, want 3", stop.Threshold)
	}

	raw, err := os.ReadFile(env.EventsPath())
	if err != nil {
		t.Fatalf("ReadFile(events) error = %v", err)
	}
	if !strings.Contains(string(raw), resultEmergencyStopCleared) {
		t.Fatalf("events = %q, want %q entry", string(raw), resultEmergencyStopCleared)
	}
}

func newTestApp(t *testing.T, now time.Time) (*App, *EnvConfig) {
	t.Helper()
	root := t.TempDir()
	env := &EnvConfig{
		Root:                                 filepath.Join(root, "maintpool"),
		ConfigPath:                           filepath.Join(root, "config.yaml"),
		Timezone:                             "UTC",
		InitialProbeMinDelay:                 24 * time.Hour,
		InitialProbeMaxDelay:                 24 * time.Hour,
		InitialRefreshMinDelay:               20 * 24 * time.Hour,
		InitialRefreshMaxDelay:               20 * 24 * time.Hour,
		ProbeMinDelay:                        10 * 24 * time.Hour,
		ProbeMaxDelay:                        10 * 24 * time.Hour,
		RefreshMinDelay:                      30 * 24 * time.Hour,
		RefreshMaxDelay:                      30 * 24 * time.Hour,
		RefreshHardMax:                       45 * 24 * time.Hour,
		Cooldown429:                          24 * time.Hour,
		CooldownTransient:                    30 * time.Minute,
		ActionDelayMin:                       0,
		ActionDelayMax:                       0,
		RefreshChainDelayMin:                 0,
		RefreshChainDelayMax:                 0,
		ConfirmChainDelayMin:                 0,
		ConfirmChainDelayMax:                 0,
		ManagedUpstreamSafeRefreshDelay:      14 * 24 * time.Hour,
		ManagedMainBufferMin:                 3 * 24 * time.Hour,
		ManagedMainBufferMax:                 4 * 24 * time.Hour,
		ManagedGuard0Offset:                  0,
		ManagedGuard1Offset:                  24 * time.Hour,
		ManagedGuard2Offset:                  48 * time.Hour,
		ManagedGuardJitterMax:                6 * time.Hour,
		EmergencyConsecutiveInvalidThreshold: 3,
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
