package maintpool

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
)

const (
	maintPoolUsageURL       = "https://chatgpt.com/backend-api/wham/usage"
	maintPoolUsageUserAgent = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
	maintPoolLockStaleAfter = 2 * time.Hour
	resultListLimit         = 50

	missingStateProbeMinDelay   = 1 * time.Hour
	missingStateProbeMaxDelay   = 24 * time.Hour
	missingStateRefreshMinDelay = 12 * time.Hour
	missingStateRefreshMaxDelay = 48 * time.Hour

	resultImported               = "imported"
	resultLaneAssigned           = "lane_assigned"
	resultLegacyAdopted          = "legacy_adopted"
	resultTakenOut               = "taken_out"
	resultProbeOK                = "probe_ok"
	resultScheduledRefreshOK     = "scheduled_refresh_ok"
	resultRecoveryRefreshOK      = "recovery_refresh_ok"
	resultUsage429               = "usage_429"
	resultProbeError             = "probe_error"
	resultInvalidMoved           = "invalid_moved"
	resultScheduledRefresh429    = "scheduled_refresh_429"
	resultScheduledRefreshError  = "scheduled_refresh_error"
	resultRecoveryRefresh429     = "recovery_refresh_429"
	resultRecoveryRefreshError   = "recovery_refresh_error"
	resultScheduledConfirm429    = "scheduled_confirm_429"
	resultScheduledConfirmError  = "scheduled_confirm_error"
	resultRecoveryConfirm429     = "recovery_confirm_429"
	resultRecoveryConfirmError   = "recovery_confirm_error"
	resultEmergencyStopCleared   = "emergency_stop_cleared"
	resultEmergencyStopTriggered = "emergency_stop_triggered"

	laneLegacy          = "legacy"
	laneMain            = "main"
	laneGuard0          = "guard_0"
	laneGuard1          = "guard_1"
	laneGuard2          = "guard_2"
	laneBaselinePending = "baseline_pending"

	baselineStatePending            = "pending"
	baselineStateReadyForAssignment = "ready_for_assignment"
	baselineStateAdmitted           = "admitted"
)

type App struct {
	env             *EnvConfig
	cfg             *config.Config
	store           *auth.FileTokenStore
	now             func() time.Time
	rng             *rand.Rand
	sleep           func(context.Context, time.Duration) error
	usageProbeFunc  func(context.Context, *coreauth.Auth) (*usageProbeResponse, error)
	refreshAuthFunc func(context.Context, *coreauth.Auth) (*coreauth.Auth, error)
}

type usageProbeResponse struct {
	StatusCode int
	Body       string
}

type duplicateIndex struct {
	names         map[string]struct{}
	accountIDs    map[string]struct{}
	refreshHashes map[string]struct{}
	emails        map[string]struct{}
}

type lockRecord struct {
	PID int       `json:"pid"`
	At  time.Time `json:"at"`
}

type dueCandidate struct {
	auth       *coreauth.Auth
	state      *FileState
	dueAt      time.Time
	dueProbe   bool
	dueRefresh bool
}

func NewApp(env *EnvConfig, cfg *config.Config) *App {
	store := auth.NewFileTokenStore()
	store.SetBaseDir(env.PoolDir())
	return &App{
		env:   env,
		cfg:   cfg,
		store: store,
		now:   time.Now,
		rng:   rand.New(rand.NewSource(time.Now().UnixNano())),
		sleep: func(ctx context.Context, delay time.Duration) error {
			if delay <= 0 {
				return nil
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
}

func (a *App) Status(ctx context.Context) (*StatusResult, error) {
	state, err := a.loadState()
	if err != nil {
		return nil, err
	}
	auths, err := a.listPoolAuths(ctx)
	if err != nil {
		return nil, err
	}
	pruneMissingStateEntries(state, auths)

	now := a.now()
	result := &StatusResult{
		GeneratedAt: now,
		Root:        a.env.Root,
		Paths: StatusPaths{
			PoolDir:           a.env.PoolDir(),
			StatePath:         a.env.StatePath(),
			EventsPath:        a.env.EventsPath(),
			External401Dir:    a.env.External401Dir(),
			ExportedDir:       a.env.ExportedDir(),
			EmergencyStopPath: a.env.EmergencyStopPath(),
		},
		Cadence: StatusCadence{
			InitialProbeMinDelay:            a.env.InitialProbeMinDelay,
			InitialProbeMaxDelay:            a.env.InitialProbeMaxDelay,
			InitialRefreshMinDelay:          a.env.InitialRefreshMinDelay,
			InitialRefreshMaxDelay:          a.env.InitialRefreshMaxDelay,
			ProbeMinDelay:                   a.env.ProbeMinDelay,
			ProbeMaxDelay:                   a.env.ProbeMaxDelay,
			RefreshMinDelay:                 a.env.RefreshMinDelay,
			RefreshMaxDelay:                 a.env.RefreshMaxDelay,
			RefreshHardMax:                  a.env.RefreshHardMax,
			Cooldown429:                     a.env.Cooldown429,
			CooldownTransient:               a.env.CooldownTransient,
			ManagedUpstreamSafeRefreshDelay: a.env.ManagedUpstreamSafeRefreshDelay,
			ManagedMainBufferMin:            a.env.ManagedMainBufferMin,
			ManagedMainBufferMax:            a.env.ManagedMainBufferMax,
			ManagedGuard0Offset:             a.env.ManagedGuard0Offset,
			ManagedGuard1Offset:             a.env.ManagedGuard1Offset,
			ManagedGuard2Offset:             a.env.ManagedGuard2Offset,
			ManagedGuardJitterMax:           a.env.ManagedGuardJitterMax,
		},
		Guardrails: StatusGuardrails{
			EmergencyConsecutiveInvalidThreshold: a.env.EmergencyConsecutiveInvalidThreshold,
		},
	}
	result.Pool.ByLane = map[string]int{}
	result.Pool.ByBaselineState = map[string]int{}
	emergencyStop, err := a.loadEmergencyStop()
	if err != nil {
		return nil, err
	}
	result.EmergencyStop = *emergencyStop
	result.Pool.TotalFiles = len(auths)
	for _, authEntry := range auths {
		entry := effectiveStateForAuth(authEntry, state.Files[baseName(authEntry.FileName)], now)
		if lane := effectiveDisplayLane(entry); lane != "" {
			result.Pool.ByLane[lane]++
		}
		if baselineState := effectiveBaselineState(entry); baselineState != "" {
			result.Pool.ByBaselineState[baselineState]++
		}
		if observedAt := authObservedAt(authEntry); !observedAt.IsZero() {
			if result.Pool.OldestKnownAuthAt.IsZero() || observedAt.Before(result.Pool.OldestKnownAuthAt) {
				result.Pool.OldestKnownAuthAt = observedAt
			}
		}
		if entry != nil {
			if result.Pool.OldestImportedAt.IsZero() || (!entry.ImportedAt.IsZero() && entry.ImportedAt.Before(result.Pool.OldestImportedAt)) {
				result.Pool.OldestImportedAt = entry.ImportedAt
			}
		}
		if entryAwaitingLaneAssignment(entry) {
			continue
		}
		dueProbe := isProbeDue(entry, now)
		dueRefresh := isRefreshDue(entry, now, a.effectiveRefreshHardMax(entry))
		if entry != nil && entry.CooldownUntil.After(now) {
			result.Pool.Cooling++
			continue
		}
		if dueProbe || dueRefresh {
			result.Pool.DueNow++
		}
		if dueProbe {
			result.Pool.DueProbeNow++
		}
		if dueRefresh {
			result.Pool.DueRefreshNow++
		}
		dueAt := effectiveDueAt(entry, now, a.effectiveRefreshHardMax(entry))
		if !dueAt.IsZero() && (result.Pool.NextDueAt.IsZero() || dueAt.Before(result.Pool.NextDueAt)) {
			result.Pool.NextDueAt = dueAt
		}
	}
	result.Pool.External401Total, _ = countJSONFiles(a.env.External401Dir())
	result.Pool.ExportedTotal, _ = countJSONFiles(a.env.ExportedDir())
	return result, nil
}

func (a *App) Import(ctx context.Context, sourceDir string, options ImportOptions) (*ImportResult, error) {
	normalizedOptions, err := normalizeImportOptions(options)
	if err != nil {
		return nil, err
	}
	sourceDir = strings.TrimSpace(sourceDir)
	if sourceDir == "" {
		return nil, fmt.Errorf("source dir is required")
	}
	resolvedSource, err := filepath.Abs(sourceDir)
	if err != nil {
		return nil, err
	}
	result := &ImportResult{
		Mode:            modeLabel(normalizedOptions.Apply),
		SourceDir:       resolvedSource,
		CohortID:        normalizedOptions.CohortID,
		SourceBatchID:   normalizedOptions.SourceBatchID,
		Lane:            normalizedOptions.Lane,
		ResultListLimit: resultListLimit,
		Imported:        make([]string, 0, resultListLimit),
		Skipped:         make([]ImportSkip, 0, resultListLimit),
		Failed:          make([]ImportFailure, 0, resultListLimit),
	}

	sourceStore := auth.NewFileTokenStore()
	sourceStore.SetBaseDir(resolvedSource)
	sourceAuths, err := a.listStoreAuths(ctx, sourceStore)
	if err != nil {
		return nil, err
	}

	err = a.withOptionalLock(normalizedOptions.Apply, func() error {
		if normalizedOptions.Apply {
			if errEnsure := a.env.EnsureDirectories(); errEnsure != nil {
				return errEnsure
			}
		}
		state, errLoadState := a.loadState()
		if errLoadState != nil {
			return errLoadState
		}
		poolAuths, errList := a.listPoolAuths(ctx)
		if errList != nil {
			return errList
		}
		pruneMissingStateEntries(state, poolAuths)
		dupIndex := buildDuplicateIndex(poolAuths)
		previousState := cloneStateFile(state)
		now := a.now()
		events := make([]Event, 0)
		importedTargets := make([]string, 0)

		for _, authEntry := range sourceAuths {
			result.Summary.Scanned++
			name := baseName(authEntry.FileName)
			reason := duplicateReason(dupIndex, authEntry)
			if reason != "" {
				result.Summary.SkippedDuplicates++
				result.SkippedTruncated = appendImportSkip(result, ImportSkip{Name: name, Reason: reason}) || result.SkippedTruncated
				continue
			}

			if !normalizedOptions.Apply {
				result.Summary.Imported++
				var truncated bool
				result.Imported, truncated = appendName(result.Imported, name)
				result.ImportedTruncated = truncated || result.ImportedTruncated
				dupIndex.add(authEntry)
				continue
			}

			current := authEntry.Clone()
			if current == nil {
				result.Summary.Failed++
				result.FailedTruncated = appendImportFailure(result, ImportFailure{Name: name, Error: "source auth is nil"}) || result.FailedTruncated
				continue
			}
			current.FileName = name
			if current.Attributes == nil {
				current.Attributes = map[string]string{}
			}
			sourcePath := strings.TrimSpace(current.Attributes["path"])
			current.Attributes["path"] = filepath.Join(a.env.PoolDir(), name)
			savedPath, errSave := a.store.Save(ctx, current)
			if errSave != nil {
				result.Summary.Failed++
				result.FailedTruncated = appendImportFailure(result, ImportFailure{Name: name, Error: errSave.Error()}) || result.FailedTruncated
				continue
			}
			importedTargets = append(importedTargets, savedPath)

			entry := ensureStateEntry(state, name)
			initializeImportedState(a, entry, current, now, normalizedOptions)
			dupIndex.add(current)
			result.Summary.Imported++
			var truncated bool
			result.Imported, truncated = appendName(result.Imported, name)
			result.ImportedTruncated = truncated || result.ImportedTruncated
			events = append(events, Event{
				At:         now,
				Type:       resultImported,
				Name:       name,
				Email:      authEmail(current),
				AccountID:  authAccountID(current),
				SourcePath: sourcePath,
				TargetPath: strings.TrimSpace(current.Attributes["path"]),
			})
		}

		if !normalizedOptions.Apply {
			return nil
		}
		if errSaveState := a.saveState(state); errSaveState != nil {
			if rollbackErr := a.rollbackImportedFiles(importedTargets, nil); rollbackErr != nil {
				return fmt.Errorf("save import state: %w; rollback failed: %v", errSaveState, rollbackErr)
			}
			return fmt.Errorf("save import state: %w", errSaveState)
		}
		if errAppend := a.appendEvents(events); errAppend != nil {
			if rollbackErr := a.rollbackImportedFiles(importedTargets, func() error { return a.saveState(previousState) }); rollbackErr != nil {
				return fmt.Errorf("append import events: %w; rollback failed: %v", errAppend, rollbackErr)
			}
			return fmt.Errorf("append import events: %w", errAppend)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) AssignLanes(ctx context.Context, options AssignLanesOptions) (*AssignLanesResult, error) {
	normalizedOptions, err := normalizeAssignLanesOptions(options)
	if err != nil {
		return nil, err
	}
	result := &AssignLanesResult{
		Mode:            modeLabel(normalizedOptions.Apply),
		CohortID:        normalizedOptions.CohortID,
		ResultListLimit: resultListLimit,
		Main:            make([]string, 0, resultListLimit),
		Guard0:          make([]string, 0, resultListLimit),
		Guard1:          make([]string, 0, resultListLimit),
		Guard2:          make([]string, 0, resultListLimit),
		Skipped:         make([]AssignLaneSkip, 0, resultListLimit),
	}

	err = a.withOptionalLock(normalizedOptions.Apply, func() error {
		state, errLoadState := a.loadState()
		if errLoadState != nil {
			return errLoadState
		}
		auths, errList := a.listPoolAuths(ctx)
		if errList != nil {
			return errList
		}
		pruneMissingStateEntries(state, auths)

		type laneAssignmentTarget struct {
			auth  *coreauth.Auth
			entry *FileState
			name  string
		}

		ready := make([]laneAssignmentTarget, 0)
		for _, authEntry := range auths {
			name := baseName(authEntry.FileName)
			entry := state.Files[name]
			if entry == nil || !strings.EqualFold(strings.TrimSpace(entry.CohortID), normalizedOptions.CohortID) {
				continue
			}
			result.Summary.CohortMatched++
			if canonicalStoredLane(entry) != laneBaselinePending {
				result.Summary.SkippedNotReady++
				result.SkippedTruncated = appendAssignLaneSkip(result, AssignLaneSkip{Name: name, Reason: "lane_not_baseline_pending"}) || result.SkippedTruncated
				continue
			}
			if effectiveBaselineState(entry) != baselineStateReadyForAssignment {
				result.Summary.SkippedNotReady++
				result.SkippedTruncated = appendAssignLaneSkip(result, AssignLaneSkip{Name: name, Reason: "baseline_not_ready_for_assignment"}) || result.SkippedTruncated
				continue
			}
			if baselineAssignmentAnchor(entry).IsZero() {
				result.Summary.SkippedMissingAnchor++
				result.SkippedTruncated = appendAssignLaneSkip(result, AssignLaneSkip{Name: name, Reason: "missing_baseline_refresh_ok_at"}) || result.SkippedTruncated
				continue
			}
			result.Summary.ReadyForAssignment++
			ready = append(ready, laneAssignmentTarget{
				auth:  authEntry,
				entry: entry,
				name:  name,
			})
		}

		requestedSentinels := normalizedOptions.Guard0 + normalizedOptions.Guard1 + normalizedOptions.Guard2
		if requestedSentinels > len(ready) {
			return fmt.Errorf("cohort %q only has %d ready auths, but %d sentinel slots were requested", normalizedOptions.CohortID, len(ready), requestedSentinels)
		}

		sort.Slice(ready, func(i, j int) bool {
			leftKey := assignmentSortKey(normalizedOptions.CohortID, ready[i].auth)
			rightKey := assignmentSortKey(normalizedOptions.CohortID, ready[j].auth)
			if leftKey != rightKey {
				return leftKey < rightKey
			}
			return strings.ToLower(ready[i].name) < strings.ToLower(ready[j].name)
		})

		plannedEvents := make([]Event, 0, len(ready))
		nextIndex := 0
		appendTargets := func(targets []laneAssignmentTarget, lane string, list *[]string, truncated *bool, summaryCounter *int) {
			for _, target := range targets {
				*summaryCounter = *summaryCounter + 1
				var wasTruncated bool
				*list, wasTruncated = appendName(*list, target.name)
				*truncated = *truncated || wasTruncated
				if !normalizedOptions.Apply {
					continue
				}
				assignedAt := a.now()
				target.entry.Lane = lane
				target.entry.BaselineState = baselineStateAdmitted
				target.entry.LaneAssignedAt = assignedAt
				target.entry.NextRefreshDueAt = a.managedLaneDueAt(lane, baselineAssignmentAnchor(target.entry), target.auth)
				plannedEvents = append(plannedEvents, Event{
					At:        assignedAt,
					Type:      resultLaneAssigned,
					Name:      target.name,
					Email:     target.entry.Email,
					AccountID: target.entry.AccountID,
					Reason:    fmt.Sprintf("cohort_id=%s lane=%s", normalizedOptions.CohortID, lane),
				})
			}
		}

		assignRange := func(count int) []laneAssignmentTarget {
			if count <= 0 {
				return nil
			}
			start := nextIndex
			end := nextIndex + count
			nextIndex = end
			return ready[start:end]
		}

		appendTargets(assignRange(normalizedOptions.Guard0), laneGuard0, &result.Guard0, &result.Guard0Truncated, &result.Summary.AssignedGuard0)
		appendTargets(assignRange(normalizedOptions.Guard1), laneGuard1, &result.Guard1, &result.Guard1Truncated, &result.Summary.AssignedGuard1)
		appendTargets(assignRange(normalizedOptions.Guard2), laneGuard2, &result.Guard2, &result.Guard2Truncated, &result.Summary.AssignedGuard2)
		appendTargets(ready[nextIndex:], laneMain, &result.Main, &result.MainTruncated, &result.Summary.AssignedMain)

		if !normalizedOptions.Apply {
			return nil
		}
		if errSaveState := a.saveState(state); errSaveState != nil {
			return errSaveState
		}
		return a.appendEvents(plannedEvents)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) AdoptLegacy(ctx context.Context, options AdoptLegacyOptions) (*AdoptLegacyResult, error) {
	normalizedOptions, err := normalizeAdoptLegacyOptions(options)
	if err != nil {
		return nil, err
	}
	result := &AdoptLegacyResult{
		Mode:                     modeLabel(normalizedOptions.Apply),
		CohortID:                 normalizedOptions.CohortID,
		SourceBatchID:            normalizedOptions.SourceBatchID,
		RequireLastRefreshWithin: normalizedOptions.RequireLastRefreshWithin,
		ResultListLimit:          resultListLimit,
		Main:                     make([]string, 0, resultListLimit),
		Guard0:                   make([]string, 0, resultListLimit),
		Guard1:                   make([]string, 0, resultListLimit),
		Guard2:                   make([]string, 0, resultListLimit),
		Skipped:                  make([]AssignLaneSkip, 0, resultListLimit),
	}

	err = a.withOptionalLock(normalizedOptions.Apply, func() error {
		state, errLoadState := a.loadState()
		if errLoadState != nil {
			return errLoadState
		}
		auths, errList := a.listPoolAuths(ctx)
		if errList != nil {
			return errList
		}
		pruneMissingStateEntries(state, auths)

		type laneAssignmentTarget struct {
			auth  *coreauth.Auth
			entry *FileState
			name  string
		}

		now := a.now()
		cutoff := now.Add(-normalizedOptions.RequireLastRefreshWithin)
		eligible := make([]laneAssignmentTarget, 0)
		for _, authEntry := range auths {
			name := baseName(authEntry.FileName)
			entry := state.Files[name]
			if !isUnmanagedLegacyEntry(entry) {
				continue
			}
			result.Summary.LegacyMatched++
			if entry == nil || entry.LastRefreshOKAt.IsZero() {
				result.Summary.SkippedMissingAnchor++
				result.SkippedTruncated = appendAdoptLegacySkip(result, AssignLaneSkip{Name: name, Reason: "missing_last_refresh_ok_at"}) || result.SkippedTruncated
				continue
			}
			if entry.LastRefreshOKAt.Before(cutoff) {
				result.Summary.SkippedTooOld++
				result.SkippedTruncated = appendAdoptLegacySkip(result, AssignLaneSkip{Name: name, Reason: "last_refresh_ok_too_old"}) || result.SkippedTruncated
				continue
			}
			result.Summary.Eligible++
			eligible = append(eligible, laneAssignmentTarget{
				auth:  authEntry,
				entry: entry,
				name:  name,
			})
		}

		requestedSentinels := normalizedOptions.Guard0 + normalizedOptions.Guard1 + normalizedOptions.Guard2
		if requestedSentinels > len(eligible) {
			return fmt.Errorf("only %d eligible legacy auths matched, but %d sentinel slots were requested", len(eligible), requestedSentinels)
		}

		sort.Slice(eligible, func(i, j int) bool {
			leftKey := assignmentSortKey(normalizedOptions.CohortID, eligible[i].auth)
			rightKey := assignmentSortKey(normalizedOptions.CohortID, eligible[j].auth)
			if leftKey != rightKey {
				return leftKey < rightKey
			}
			return strings.ToLower(eligible[i].name) < strings.ToLower(eligible[j].name)
		})

		plannedEvents := make([]Event, 0, len(eligible))
		nextIndex := 0
		appendTargets := func(targets []laneAssignmentTarget, lane string, list *[]string, truncated *bool, summaryCounter *int) {
			for _, target := range targets {
				*summaryCounter = *summaryCounter + 1
				var wasTruncated bool
				*list, wasTruncated = appendName(*list, target.name)
				*truncated = *truncated || wasTruncated
				if !normalizedOptions.Apply {
					continue
				}
				adoptedAt := a.now()
				target.entry.CohortID = normalizedOptions.CohortID
				target.entry.SourceBatchID = normalizedOptions.SourceBatchID
				target.entry.Lane = lane
				target.entry.BaselineState = baselineStateAdmitted
				if target.entry.BaselineRefreshOKAt.IsZero() {
					target.entry.BaselineRefreshOKAt = target.entry.LastRefreshOKAt
				}
				target.entry.LaneAssignedAt = adoptedAt
				target.entry.NextRefreshDueAt = a.managedLaneDueAt(lane, baselineAssignmentAnchor(target.entry), target.auth)
				if target.entry.NextProbeAt.IsZero() || !target.entry.NextProbeAt.After(adoptedAt) {
					target.entry.NextProbeAt = target.entry.LastRefreshOKAt.Add(a.nextProbeDelay())
					if !target.entry.NextProbeAt.After(adoptedAt) {
						target.entry.NextProbeAt = adoptedAt.Add(a.nextProbeDelay())
					}
				}
				plannedEvents = append(plannedEvents, Event{
					At:        adoptedAt,
					Type:      resultLegacyAdopted,
					Name:      target.name,
					Email:     target.entry.Email,
					AccountID: target.entry.AccountID,
					Reason: fmt.Sprintf(
						"cohort_id=%s source_batch_id=%s lane=%s",
						normalizedOptions.CohortID,
						normalizedOptions.SourceBatchID,
						lane,
					),
				})
			}
		}

		assignRange := func(count int) []laneAssignmentTarget {
			if count <= 0 {
				return nil
			}
			start := nextIndex
			end := nextIndex + count
			nextIndex = end
			return eligible[start:end]
		}

		appendTargets(assignRange(normalizedOptions.Guard0), laneGuard0, &result.Guard0, &result.Guard0Truncated, &result.Summary.AssignedGuard0)
		appendTargets(assignRange(normalizedOptions.Guard1), laneGuard1, &result.Guard1, &result.Guard1Truncated, &result.Summary.AssignedGuard1)
		appendTargets(assignRange(normalizedOptions.Guard2), laneGuard2, &result.Guard2, &result.Guard2Truncated, &result.Summary.AssignedGuard2)
		appendTargets(eligible[nextIndex:], laneMain, &result.Main, &result.MainTruncated, &result.Summary.AssignedMain)

		if !normalizedOptions.Apply {
			return nil
		}
		if errSaveState := a.saveState(state); errSaveState != nil {
			return errSaveState
		}
		return a.appendEvents(plannedEvents)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) ClearEmergencyStop(_ context.Context, reason string, apply bool) (*ClearEmergencyStopResult, error) {
	result := &ClearEmergencyStopResult{
		Mode:   modeLabel(apply),
		Reason: trimReason(reason),
	}

	err := a.withOptionalLock(apply, func() error {
		previous, errLoad := a.loadEmergencyStop()
		if errLoad != nil {
			return errLoad
		}
		result.Previous = cloneEmergencyStop(previous)
		result.HadStop = previous.Active
		current := &StatusEmergencyStop{
			Active:    false,
			Threshold: a.env.EmergencyConsecutiveInvalidThreshold,
		}
		result.Current = cloneEmergencyStop(current)
		if !apply || !result.HadStop {
			return nil
		}
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("reason is required with --apply")
		}
		if errSave := a.saveEmergencyStop(current); errSave != nil {
			return errSave
		}
		if errAppend := a.appendEvents([]Event{{
			At:     a.now(),
			Type:   resultEmergencyStopCleared,
			Reason: trimReason(reason),
		}}); errAppend != nil {
			if rollbackErr := a.saveEmergencyStop(previous); rollbackErr != nil {
				return fmt.Errorf("append clear-emergency-stop event: %w; rollback failed: %v", errAppend, rollbackErr)
			}
			return fmt.Errorf("append clear-emergency-stop event: %w", errAppend)
		}
		result.Cleared = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) Takeout(ctx context.Context, name string, destDir string, apply bool) (*TakeoutResult, error) {
	trimmedName := baseName(name)
	if trimmedName == "" {
		return nil, fmt.Errorf("name is required")
	}
	if strings.TrimSpace(destDir) == "" {
		destDir = a.env.ExportedDir()
	}
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return nil, err
	}
	if err := a.validateTakeoutDestination(absDest); err != nil {
		return nil, err
	}
	result := &TakeoutResult{
		Mode: modeLabel(apply),
		Name: trimmedName,
	}

	err = a.withOptionalLock(apply, func() error {
		state, errLoadState := a.loadState()
		if errLoadState != nil {
			return errLoadState
		}
		sourcePath := filepath.Join(a.env.PoolDir(), trimmedName)
		if _, errStat := os.Stat(sourcePath); errStat != nil {
			if os.IsNotExist(errStat) {
				result.Reason = "not_found"
				return nil
			}
			return errStat
		}
		current, errLoadAuth := a.loadPoolAuthByName(ctx, trimmedName)
		if errLoadAuth != nil {
			return errLoadAuth
		}
		if errUnique := a.validateTakeoutUniqueness(ctx, current, sourcePath); errUnique != nil {
			return errUnique
		}

		targetPath := filepath.Join(absDest, trimmedName)
		if _, errStat := os.Stat(targetPath); errStat == nil {
			targetPath = uniquePath(targetPath, a.now())
		} else if !os.IsNotExist(errStat) {
			return errStat
		}

		if !apply {
			result.TakenOut = true
			result.DestinationPath = targetPath
			return nil
		}
		previousEntry, hadEntry := cloneStateEntry(state.Files[trimmedName]), state.Files[trimmedName] != nil

		if errEnsure := os.MkdirAll(absDest, 0o700); errEnsure != nil {
			return errEnsure
		}
		if errMove := moveFile(sourcePath, targetPath); errMove != nil {
			return errMove
		}
		delete(state.Files, trimmedName)
		if errSaveState := a.saveState(state); errSaveState != nil {
			if rollbackErr := a.rollbackTakeoutMove(sourcePath, targetPath, state, trimmedName, previousEntry, hadEntry, false); rollbackErr != nil {
				return fmt.Errorf("save takeout state: %w; rollback failed: %v", errSaveState, rollbackErr)
			}
			return fmt.Errorf("save takeout state: %w", errSaveState)
		}
		if errAppend := a.appendEvents([]Event{{
			At:         a.now(),
			Type:       resultTakenOut,
			Name:       trimmedName,
			TargetPath: targetPath,
		}}); errAppend != nil {
			if rollbackErr := a.rollbackTakeoutMove(sourcePath, targetPath, state, trimmedName, previousEntry, hadEntry, true); rollbackErr != nil {
				return fmt.Errorf("append takeout event: %w; rollback failed: %v", errAppend, rollbackErr)
			}
			return fmt.Errorf("append takeout event: %w", errAppend)
		}
		result.TakenOut = true
		result.DestinationPath = targetPath
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) Scan(ctx context.Context, apply bool, limit int) (*ScanResult, error) {
	result := &ScanResult{
		Mode:            modeLabel(apply),
		ResultListLimit: resultListLimit,
		Selected:        make([]string, 0, minPositive(limit, resultListLimit)),
	}
	err := a.withOptionalLock(apply, func() error {
		if apply {
			if errEnsure := a.env.EnsureDirectories(); errEnsure != nil {
				return errEnsure
			}
		}
		state, errLoadState := a.loadState()
		if errLoadState != nil {
			return errLoadState
		}
		auths, errList := a.listPoolAuths(ctx)
		if errList != nil {
			return errList
		}
		pruneMissingStateEntries(state, auths)
		emergencyStop, errEmergency := a.loadEmergencyStop()
		if errEmergency != nil {
			return errEmergency
		}
		if emergencyStop.Active || emergencyStop.Threshold > 0 {
			result.EmergencyStop = emergencyStop
		}

		candidates := a.selectDueCandidates(auths, state, limit)
		result.Summary.Selected = len(candidates)
		for _, candidate := range candidates {
			var truncated bool
			result.Selected, truncated = appendName(result.Selected, baseName(candidate.auth.FileName))
			result.SelectedTruncated = truncated || result.SelectedTruncated
		}
		if !apply {
			return nil
		}
		if emergencyStop.Active {
			result.Summary.EmergencyStopActive = true
			return nil
		}

		events := make([]Event, 0, len(candidates))
		consecutiveInvalid401 := 0
		for index, candidate := range candidates {
			if errWait := a.waitBetweenAuths(ctx, index); errWait != nil {
				return errWait
			}
			eventCountBefore := len(events)
			removed, errProcess := a.processDueAuth(ctx, candidate, state, &result.Summary, &events)
			if errProcess != nil {
				return errProcess
			}
			if removed {
				delete(state.Files, baseName(candidate.auth.FileName))
			}
			if len(events) <= eventCountBefore {
				consecutiveInvalid401 = 0
				continue
			}
			lastEvent := events[len(events)-1]
			if lastEvent.Type != resultInvalidMoved {
				consecutiveInvalid401 = 0
				continue
			}
			consecutiveInvalid401++
			if consecutiveInvalid401 > result.Summary.ConsecutiveInvalid401 {
				result.Summary.ConsecutiveInvalid401 = consecutiveInvalid401
			}
			if a.env.EmergencyConsecutiveInvalidThreshold > 0 && consecutiveInvalid401 >= a.env.EmergencyConsecutiveInvalidThreshold {
				stop := a.buildEmergencyStop(lastEvent, consecutiveInvalid401)
				if errSaveStop := a.saveEmergencyStop(stop); errSaveStop != nil {
					return errSaveStop
				}
				result.EmergencyStop = stop
				result.Summary.EmergencyStopTriggered = true
				result.Summary.EmergencyStopActive = true
				events = append(events, Event{
					At:         stop.TriggeredAt,
					Type:       resultEmergencyStopTriggered,
					Name:       stop.LastAuthName,
					Email:      stop.LastEmail,
					AccountID:  stop.LastAccountID,
					Reason:     stop.Reason,
					HTTPStatus: stop.LastHTTPStatus,
				})
				break
			}
		}

		if errSaveState := a.saveState(state); errSaveState != nil {
			return errSaveState
		}
		return a.appendEvents(events)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) processDueAuth(ctx context.Context, candidate dueCandidate, state *StateFile, summary *ScanSummary, events *[]Event) (bool, error) {
	current := candidate.auth.Clone()
	if current == nil {
		return false, fmt.Errorf("maintpool auth is nil")
	}
	name := baseName(current.FileName)
	existing := state.Files[name]
	entry := ensureStateEntry(state, name)
	if existing == nil {
		*entry = *effectiveStateForAuth(current, nil, a.now())
	}
	populateStateIdentity(entry, current)

	if candidate.dueRefresh {
		return a.handleRefreshPath(ctx, current, entry, true, summary, events)
	}
	return a.handleUsageAuditPath(ctx, current, entry, summary, events)
}

func (a *App) handleUsageAuditPath(ctx context.Context, current *coreauth.Auth, entry *FileState, summary *ScanSummary, events *[]Event) (bool, error) {
	resp, err := a.runUsageProbe(ctx, current.Clone())
	now := a.now()
	entry.LastProbeAt = now
	entry.LastHTTPStatus = responseHTTPStatus(resp, err)
	probeClass := classifyHTTPOrError(resp, err)

	switch probeClass {
	case classificationSuccess:
		entry.LastProbeOKAt = now
		entry.CooldownUntil = time.Time{}
		entry.LastResult = resultProbeOK
		entry.NextProbeAt = now.Add(a.nextProbeDelay())
		if entry.NextRefreshDueAt.IsZero() {
			entry.NextRefreshDueAt = now.Add(a.nextRefreshDelay())
		}
		summary.Processed++
		summary.HealthyProbeOnly++
		*events = append(*events, Event{
			At:         now,
			Type:       resultProbeOK,
			Name:       baseName(current.FileName),
			Email:      entry.Email,
			AccountID:  entry.AccountID,
			HTTPStatus: entry.LastHTTPStatus,
		})
		return false, nil
	case classificationInvalid:
		return a.handleRefreshPath(ctx, current, entry, false, summary, events)
	case classification429:
		entry.LastResult = resultUsage429
		entry.CooldownUntil = now.Add(a.env.Cooldown429)
		entry.NextProbeAt = entry.CooldownUntil
		summary.Processed++
		summary.Usage429++
		*events = append(*events, Event{
			At:         now,
			Type:       resultUsage429,
			Name:       baseName(current.FileName),
			Email:      entry.Email,
			AccountID:  entry.AccountID,
			Reason:     trimReason(responseMessage(resp, err)),
			HTTPStatus: entry.LastHTTPStatus,
		})
		return false, nil
	default:
		if shouldRefreshAfterProbeFailure(resp, err) {
			return a.handleRefreshPath(ctx, current, entry, false, summary, events)
		}
		entry.LastResult = resultProbeError
		entry.CooldownUntil = now.Add(a.env.CooldownTransient)
		entry.NextProbeAt = entry.CooldownUntil
		summary.Processed++
		summary.TransientError++
		*events = append(*events, Event{
			At:         now,
			Type:       resultProbeError,
			Name:       baseName(current.FileName),
			Email:      entry.Email,
			AccountID:  entry.AccountID,
			Reason:     trimReason(responseMessage(resp, err)),
			HTTPStatus: entry.LastHTTPStatus,
		})
		return false, nil
	}
}

func (a *App) handleRefreshPath(ctx context.Context, current *coreauth.Auth, entry *FileState, scheduled bool, summary *ScanSummary, events *[]Event) (bool, error) {
	if err := a.waitBetweenChainSteps(ctx, a.nextRefreshChainDelay()); err != nil {
		return false, err
	}

	entry.LastRefreshAttemptAt = a.now()
	updated, refreshErr := a.runRefreshAuth(ctx, current.Clone())
	refreshTime := a.now()
	if refreshErr != nil {
		entry.LastHTTPStatus = httpStatusFromText(refreshErr.Error())
		switch classifyErrorText(refreshErr.Error()) {
		case classificationInvalid:
			targetPath, errMove := a.movePoolAuthToExternal401(current, refreshTime)
			if errMove != nil {
				return false, errMove
			}
			entry.LastResult = resultInvalidMoved
			summary.Processed++
			summary.InvalidMoved++
			*events = append(*events, Event{
				At:         refreshTime,
				Type:       resultInvalidMoved,
				Name:       baseName(current.FileName),
				Email:      entry.Email,
				AccountID:  entry.AccountID,
				Reason:     trimReason(refreshErr.Error()),
				TargetPath: targetPath,
				HTTPStatus: entry.LastHTTPStatus,
			})
			return true, nil
		case classification429:
			entry.CooldownUntil = refreshTime.Add(a.env.Cooldown429)
			entry.NextProbeAt = entry.CooldownUntil
			entry.NextRefreshDueAt = entry.CooldownUntil
			if scheduled {
				entry.LastResult = resultScheduledRefresh429
			} else {
				entry.LastResult = resultRecoveryRefresh429
			}
			summary.Processed++
			summary.Usage429++
			*events = append(*events, Event{
				At:         refreshTime,
				Type:       entry.LastResult,
				Name:       baseName(current.FileName),
				Email:      entry.Email,
				AccountID:  entry.AccountID,
				Reason:     trimReason(refreshErr.Error()),
				HTTPStatus: entry.LastHTTPStatus,
			})
			return false, nil
		default:
			entry.CooldownUntil = refreshTime.Add(a.env.CooldownTransient)
			entry.NextProbeAt = entry.CooldownUntil
			entry.NextRefreshDueAt = entry.CooldownUntil
			if scheduled {
				entry.LastResult = resultScheduledRefreshError
			} else {
				entry.LastResult = resultRecoveryRefreshError
			}
			summary.Processed++
			summary.TransientError++
			*events = append(*events, Event{
				At:         refreshTime,
				Type:       entry.LastResult,
				Name:       baseName(current.FileName),
				Email:      entry.Email,
				AccountID:  entry.AccountID,
				Reason:     trimReason(refreshErr.Error()),
				HTTPStatus: entry.LastHTTPStatus,
			})
			return false, nil
		}
	}

	refreshed := mergeRecoveredAuth(current, updated)
	if refreshed == nil {
		return false, fmt.Errorf("refresh returned nil auth")
	}
	normalizeAuthSuccess(refreshed, refreshTime, true)
	if errSave := a.savePoolAuth(ctx, refreshed); errSave != nil {
		return false, errSave
	}
	entry.LastRefreshAttemptAt = refreshTime
	entry.LastRefreshOKAt = refreshTime
	populateStateIdentity(entry, refreshed)

	if !a.shouldConfirmAfterRefresh(entry, scheduled) {
		entry.LastHTTPStatus = 0
		entry.CooldownUntil = time.Time{}
		// Keep an overdue standalone audit due soon after a no-confirm main refresh
		// instead of silently pushing it out by another full 60d-90d window.
		if entry.NextProbeAt.IsZero() {
			entry.NextProbeAt = refreshTime
		}
		entry.NextRefreshDueAt = a.nextRefreshDueAfterConfirmedRefresh(entry, refreshed, refreshTime)
		if scheduled {
			entry.LastResult = resultScheduledRefreshOK
			summary.ScheduledRefreshOK++
		} else {
			entry.LastResult = resultRecoveryRefreshOK
			summary.RecoveryRefreshOK++
		}
		summary.Processed++
		*events = append(*events, Event{
			At:        refreshTime,
			Type:      entry.LastResult,
			Name:      baseName(refreshed.FileName),
			Email:     entry.Email,
			AccountID: entry.AccountID,
		})
		return false, nil
	}

	if err := a.waitBetweenChainSteps(ctx, a.nextConfirmChainDelay()); err != nil {
		return false, err
	}

	confirmResp, confirmErr := a.runUsageProbe(ctx, refreshed.Clone())
	confirmTime := a.now()
	entry.LastProbeAt = confirmTime
	entry.LastHTTPStatus = responseHTTPStatus(confirmResp, confirmErr)

	switch classifyHTTPOrError(confirmResp, confirmErr) {
	case classificationSuccess:
		entry.LastProbeOKAt = confirmTime
		entry.CooldownUntil = time.Time{}
		// A refresh confirm can satisfy an overdue audit, but it should not
		// keep pushing a still-future audit window out forever.
		if entry.NextProbeAt.IsZero() || !entry.NextProbeAt.After(confirmTime) {
			entry.NextProbeAt = confirmTime.Add(a.nextProbeDelay())
		}
		if baselineLanePending(entry) {
			entry.BaselineRefreshOKAt = refreshTime
			entry.BaselineState = baselineStateReadyForAssignment
			entry.NextRefreshDueAt = time.Time{}
		} else {
			if promoteManagedGuardLane(entry, confirmTime) {
				entry.BaselineState = baselineStateAdmitted
			}
			entry.NextRefreshDueAt = a.nextRefreshDueAfterConfirmedRefresh(entry, refreshed, refreshTime)
		}
		if scheduled {
			entry.LastResult = resultScheduledRefreshOK
			summary.ScheduledRefreshOK++
		} else {
			entry.LastResult = resultRecoveryRefreshOK
			summary.RecoveryRefreshOK++
		}
		summary.Processed++
		*events = append(*events, Event{
			At:         confirmTime,
			Type:       entry.LastResult,
			Name:       baseName(refreshed.FileName),
			Email:      entry.Email,
			AccountID:  entry.AccountID,
			HTTPStatus: entry.LastHTTPStatus,
		})
		return false, nil
	case classificationInvalid:
		targetPath, errMove := a.movePoolAuthToExternal401(refreshed, confirmTime)
		if errMove != nil {
			return false, errMove
		}
		entry.LastResult = resultInvalidMoved
		summary.Processed++
		summary.InvalidMoved++
		*events = append(*events, Event{
			At:         confirmTime,
			Type:       resultInvalidMoved,
			Name:       baseName(refreshed.FileName),
			Email:      entry.Email,
			AccountID:  entry.AccountID,
			Reason:     trimReason(responseMessage(confirmResp, confirmErr)),
			TargetPath: targetPath,
			HTTPStatus: entry.LastHTTPStatus,
		})
		return true, nil
	case classification429:
		entry.CooldownUntil = confirmTime.Add(a.env.Cooldown429)
		entry.NextProbeAt = entry.CooldownUntil
		entry.NextRefreshDueAt = a.nextRefreshDueAfterUnconfirmedRefresh(entry, refreshed, refreshTime)
		if scheduled {
			entry.LastResult = resultScheduledConfirm429
		} else {
			entry.LastResult = resultRecoveryConfirm429
		}
		summary.Processed++
		summary.Usage429++
		*events = append(*events, Event{
			At:         confirmTime,
			Type:       entry.LastResult,
			Name:       baseName(refreshed.FileName),
			Email:      entry.Email,
			AccountID:  entry.AccountID,
			Reason:     trimReason(responseMessage(confirmResp, confirmErr)),
			HTTPStatus: entry.LastHTTPStatus,
		})
		return false, nil
	default:
		entry.CooldownUntil = confirmTime.Add(a.env.CooldownTransient)
		entry.NextProbeAt = entry.CooldownUntil
		entry.NextRefreshDueAt = a.nextRefreshDueAfterUnconfirmedRefresh(entry, refreshed, refreshTime)
		if scheduled {
			entry.LastResult = resultScheduledConfirmError
		} else {
			entry.LastResult = resultRecoveryConfirmError
		}
		summary.Processed++
		summary.TransientError++
		*events = append(*events, Event{
			At:         confirmTime,
			Type:       entry.LastResult,
			Name:       baseName(refreshed.FileName),
			Email:      entry.Email,
			AccountID:  entry.AccountID,
			Reason:     trimReason(responseMessage(confirmResp, confirmErr)),
			HTTPStatus: entry.LastHTTPStatus,
		})
		return false, nil
	}
}

func (a *App) selectDueCandidates(auths []*coreauth.Auth, state *StateFile, limit int) []dueCandidate {
	now := a.now()
	candidates := make([]dueCandidate, 0, len(auths))
	for _, authEntry := range auths {
		entry := effectiveStateForAuth(authEntry, state.Files[baseName(authEntry.FileName)], now)
		if entryAwaitingLaneAssignment(entry) {
			continue
		}
		if entry != nil && entry.CooldownUntil.After(now) {
			continue
		}
		dueProbe := isProbeDue(entry, now)
		dueRefresh := isRefreshDue(entry, now, a.effectiveRefreshHardMax(entry))
		if !dueProbe && !dueRefresh {
			continue
		}
		candidates = append(candidates, dueCandidate{
			auth:       authEntry,
			state:      entry,
			dueAt:      effectiveDueAt(entry, now, a.effectiveRefreshHardMax(entry)),
			dueProbe:   dueProbe,
			dueRefresh: dueRefresh,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		leftBucket := dueBucketStart(candidates[i].dueAt)
		rightBucket := dueBucketStart(candidates[j].dueAt)
		if !leftBucket.Equal(rightBucket) {
			return leftBucket.Before(rightBucket)
		}
		if !candidates[i].dueAt.Equal(candidates[j].dueAt) {
			return candidates[i].dueAt.Before(candidates[j].dueAt)
		}
		return strings.ToLower(baseName(candidates[i].auth.FileName)) < strings.ToLower(baseName(candidates[j].auth.FileName))
	})
	if a != nil && a.rng != nil {
		for start := 0; start < len(candidates); {
			end := start + 1
			bucket := dueBucketStart(candidates[start].dueAt)
			for end < len(candidates) && dueBucketStart(candidates[end].dueAt).Equal(bucket) {
				end++
			}
			if end-start > 1 {
				a.rng.Shuffle(end-start, func(i, j int) {
					candidates[start+i], candidates[start+j] = candidates[start+j], candidates[start+i]
				})
			}
			start = end
		}
	}
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func (a *App) withOptionalLock(apply bool, fn func() error) error {
	if !apply {
		return fn()
	}
	lockPath := a.env.LockPath()
	lockFile, err := a.acquireLock(lockPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = lockFile.Close()
		_ = os.Remove(lockPath)
	}()
	return fn()
}

func (a *App) acquireLock(lockPath string) (*os.File, error) {
	for attempt := 0; attempt < 2; attempt++ {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			record := lockRecord{PID: os.Getpid(), At: a.now()}
			if writeErr := json.NewEncoder(lockFile).Encode(record); writeErr != nil {
				_ = lockFile.Close()
				_ = os.Remove(lockPath)
				return nil, writeErr
			}
			if _, seekErr := lockFile.Seek(0, io.SeekStart); seekErr != nil {
				_ = lockFile.Close()
				_ = os.Remove(lockPath)
				return nil, seekErr
			}
			return lockFile, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		cleared, clearErr := a.clearStaleLock(lockPath)
		if clearErr != nil {
			return nil, clearErr
		}
		if !cleared {
			return nil, fmt.Errorf("maintpool lock exists: %s", lockPath)
		}
	}
	return nil, fmt.Errorf("maintpool failed to acquire lock: %s", lockPath)
}

func (a *App) clearStaleLock(lockPath string) (bool, error) {
	lockAt, err := readLockTime(lockPath)
	if err != nil {
		return false, err
	}
	if a.now().Sub(lockAt) <= maintPoolLockStaleAfter {
		return false, nil
	}
	if err := os.Remove(lockPath); err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	return true, nil
}

func (a *App) listPoolAuths(ctx context.Context) ([]*coreauth.Auth, error) {
	return a.listStoreAuths(ctx, a.store)
}

func (a *App) listStoreAuths(ctx context.Context, store *auth.FileTokenStore) ([]*coreauth.Auth, error) {
	auths, err := store.List(ctx)
	if err != nil {
		if os.IsNotExist(err) {
			return []*coreauth.Auth{}, nil
		}
		return nil, err
	}
	filtered := make([]*coreauth.Auth, 0, len(auths))
	for _, authEntry := range auths {
		if authEntry == nil || !strings.EqualFold(strings.TrimSpace(authEntry.Provider), "codex") {
			continue
		}
		authEntry.FileName = baseName(authEntry.FileName)
		filtered = append(filtered, authEntry)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return strings.ToLower(baseName(filtered[i].FileName)) < strings.ToLower(baseName(filtered[j].FileName))
	})
	return filtered, nil
}

func (a *App) loadState() (*StateFile, error) {
	path := a.env.StatePath()
	state := &StateFile{Files: map[string]*FileState{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, err
	}
	if state.Files == nil {
		state.Files = map[string]*FileState{}
	}
	return state, nil
}

func (a *App) saveState(state *StateFile) error {
	if state == nil {
		state = &StateFile{Files: map[string]*FileState{}}
	}
	if state.Files == nil {
		state.Files = map[string]*FileState{}
	}
	return writeJSONAtomic(a.env.StatePath(), state)
}

func (a *App) loadEmergencyStop() (*StatusEmergencyStop, error) {
	stop := &StatusEmergencyStop{
		Active:    false,
		Threshold: a.env.EmergencyConsecutiveInvalidThreshold,
	}
	raw, err := os.ReadFile(a.env.EmergencyStopPath())
	if err != nil {
		if os.IsNotExist(err) {
			return stop, nil
		}
		return nil, err
	}
	if len(raw) == 0 {
		return stop, nil
	}
	if err := json.Unmarshal(raw, stop); err != nil {
		return nil, err
	}
	if stop.Threshold == 0 {
		stop.Threshold = a.env.EmergencyConsecutiveInvalidThreshold
	}
	return stop, nil
}

func (a *App) saveEmergencyStop(stop *StatusEmergencyStop) error {
	if stop == nil {
		stop = &StatusEmergencyStop{}
	}
	if stop.Threshold == 0 {
		stop.Threshold = a.env.EmergencyConsecutiveInvalidThreshold
	}
	return writeJSONAtomic(a.env.EmergencyStopPath(), stop)
}

func (a *App) buildEmergencyStop(lastEvent Event, consecutiveInvalid401 int) *StatusEmergencyStop {
	threshold := a.env.EmergencyConsecutiveInvalidThreshold
	return &StatusEmergencyStop{
		Active:                true,
		TriggeredAt:           lastEvent.At,
		Reason:                fmt.Sprintf("consecutive maintpool invalid_401 results reached %d (threshold=%d); possible host/IP-level block. Stop further OpenAI interactions and inspect the current egress/IP before resuming.", consecutiveInvalid401, threshold),
		ConsecutiveInvalid401: consecutiveInvalid401,
		Threshold:             threshold,
		TriggerEventType:      resultEmergencyStopTriggered,
		LastResult:            lastEvent.Type,
		LastHTTPStatus:        lastEvent.HTTPStatus,
		LastAuthName:          lastEvent.Name,
		LastEmail:             lastEvent.Email,
		LastAccountID:         lastEvent.AccountID,
		SuggestedAction:       "Review the host/IP-level 401 anomaly, confirm whether the latest invalid auths look correlated, then clear the stop with maintpoolctl clear-emergency-stop --reason <note> --apply after operator review.",
	}
}

func (a *App) appendEvents(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.env.EventsPath()), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(a.env.EventsPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	for _, event := range events {
		raw, errMarshal := json.Marshal(event)
		if errMarshal != nil {
			return errMarshal
		}
		if _, errWrite := file.Write(append(raw, '\n')); errWrite != nil {
			return errWrite
		}
	}
	return nil
}

func buildDuplicateIndex(auths []*coreauth.Auth) *duplicateIndex {
	index := &duplicateIndex{
		names:         map[string]struct{}{},
		accountIDs:    map[string]struct{}{},
		refreshHashes: map[string]struct{}{},
		emails:        map[string]struct{}{},
	}
	for _, authEntry := range auths {
		index.add(authEntry)
	}
	return index
}

func (i *duplicateIndex) add(authEntry *coreauth.Auth) {
	if i == nil || authEntry == nil {
		return
	}
	if name := strings.ToLower(baseName(authEntry.FileName)); name != "" {
		i.names[name] = struct{}{}
	}
	if accountID := strings.ToLower(strings.TrimSpace(authAccountID(authEntry))); accountID != "" {
		i.accountIDs[accountID] = struct{}{}
	}
	if hash := refreshTokenHash(authEntry); hash != "" {
		i.refreshHashes[hash] = struct{}{}
	}
	if email := strings.ToLower(strings.TrimSpace(authEmail(authEntry))); email != "" {
		i.emails[email] = struct{}{}
	}
}

func duplicateReason(index *duplicateIndex, authEntry *coreauth.Auth) string {
	if index == nil || authEntry == nil {
		return ""
	}
	if name := strings.ToLower(baseName(authEntry.FileName)); name != "" {
		if _, ok := index.names[name]; ok {
			return "name_exists_in_pool"
		}
	}
	if accountID := strings.ToLower(strings.TrimSpace(authAccountID(authEntry))); accountID != "" {
		if _, ok := index.accountIDs[accountID]; ok {
			return "account_id_exists_in_pool"
		}
	}
	if hash := refreshTokenHash(authEntry); hash != "" {
		if _, ok := index.refreshHashes[hash]; ok {
			return "refresh_token_exists_in_pool"
		}
	}
	if email := strings.ToLower(strings.TrimSpace(authEmail(authEntry))); email != "" {
		if _, ok := index.emails[email]; ok {
			return "email_exists_in_pool"
		}
	}
	return ""
}

func duplicateReasonBetween(left, right *coreauth.Auth) string {
	if left == nil || right == nil {
		return ""
	}
	if name := strings.ToLower(baseName(left.FileName)); name != "" && name == strings.ToLower(baseName(right.FileName)) {
		return "name"
	}
	if accountID := strings.ToLower(strings.TrimSpace(authAccountID(left))); accountID != "" && accountID == strings.ToLower(strings.TrimSpace(authAccountID(right))) {
		return "account_id"
	}
	if hash := refreshTokenHash(left); hash != "" && hash == refreshTokenHash(right) {
		return "refresh_token"
	}
	if email := strings.ToLower(strings.TrimSpace(authEmail(left))); email != "" && email == strings.ToLower(strings.TrimSpace(authEmail(right))) {
		return "email"
	}
	return ""
}

func normalizeImportOptions(options ImportOptions) (ImportOptions, error) {
	options.CohortID = strings.TrimSpace(options.CohortID)
	options.SourceBatchID = strings.TrimSpace(options.SourceBatchID)
	options.Lane = strings.ToLower(strings.TrimSpace(options.Lane))
	switch options.Lane {
	case "", laneBaselinePending:
		if options.Lane == laneBaselinePending {
			if options.CohortID == "" {
				return ImportOptions{}, fmt.Errorf("cohort id is required when import lane is baseline_pending")
			}
			if options.SourceBatchID == "" {
				return ImportOptions{}, fmt.Errorf("source batch id is required when import lane is baseline_pending")
			}
		}
		return options, nil
	default:
		return ImportOptions{}, fmt.Errorf("import lane %q is not supported; use baseline_pending or leave it empty", options.Lane)
	}
}

func normalizeAssignLanesOptions(options AssignLanesOptions) (AssignLanesOptions, error) {
	options.CohortID = strings.TrimSpace(options.CohortID)
	if options.CohortID == "" {
		return AssignLanesOptions{}, fmt.Errorf("cohort id is required")
	}
	for label, value := range map[string]int{
		"guard_0": options.Guard0,
		"guard_1": options.Guard1,
		"guard_2": options.Guard2,
	} {
		if value < 0 {
			return AssignLanesOptions{}, fmt.Errorf("%s must be >= 0", label)
		}
	}
	return options, nil
}

func normalizeAdoptLegacyOptions(options AdoptLegacyOptions) (AdoptLegacyOptions, error) {
	options.CohortID = strings.TrimSpace(options.CohortID)
	options.SourceBatchID = strings.TrimSpace(options.SourceBatchID)
	if options.CohortID == "" {
		return AdoptLegacyOptions{}, fmt.Errorf("cohort id is required")
	}
	if options.SourceBatchID == "" {
		return AdoptLegacyOptions{}, fmt.Errorf("source batch id is required")
	}
	for label, value := range map[string]int{
		"guard_0": options.Guard0,
		"guard_1": options.Guard1,
		"guard_2": options.Guard2,
	} {
		if value < 0 {
			return AdoptLegacyOptions{}, fmt.Errorf("%s must be >= 0", label)
		}
	}
	if options.RequireLastRefreshWithin <= 0 {
		return AdoptLegacyOptions{}, fmt.Errorf("require_last_refresh_within must be > 0")
	}
	return options, nil
}

func initializeImportedState(a *App, entry *FileState, authEntry *coreauth.Auth, now time.Time, options ImportOptions) {
	if entry == nil {
		return
	}
	entry.ImportedAt = now
	entry.LastProbeAt = time.Time{}
	entry.LastProbeOKAt = time.Time{}
	entry.LastRefreshAttemptAt = time.Time{}
	entry.LastRefreshOKAt = time.Time{}
	entry.BaselineRefreshOKAt = time.Time{}
	entry.NextProbeAt = now.Add(a.nextInitialProbeDelay())
	entry.NextRefreshDueAt = now.Add(a.nextInitialRefreshDelay())
	entry.LaneAssignedAt = time.Time{}
	entry.CooldownUntil = time.Time{}
	entry.LastResult = resultImported
	entry.LastHTTPStatus = 0
	entry.CohortID = options.CohortID
	entry.SourceBatchID = options.SourceBatchID
	entry.Lane = options.Lane
	entry.BaselineState = ""
	if entry.Lane == laneBaselinePending {
		entry.BaselineState = baselineStatePending
		// Baseline-pending imports are an explicit admission queue, not ordinary
		// passive imports. They should be eligible for immediate baseline refresh.
		entry.NextRefreshDueAt = now
	}
	populateStateIdentity(entry, authEntry)
}

func canonicalStoredLane(entry *FileState) string {
	if entry == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(entry.Lane))
}

func effectiveDisplayLane(entry *FileState) string {
	if lane := canonicalStoredLane(entry); lane != "" {
		return lane
	}
	return laneLegacy
}

func isUnmanagedLegacyEntry(entry *FileState) bool {
	if entry == nil {
		return true
	}
	return canonicalStoredLane(entry) == "" &&
		strings.TrimSpace(entry.CohortID) == "" &&
		strings.TrimSpace(entry.SourceBatchID) == "" &&
		strings.TrimSpace(entry.BaselineState) == ""
}

func effectiveBaselineState(entry *FileState) string {
	if entry == nil {
		return ""
	}
	if state := strings.ToLower(strings.TrimSpace(entry.BaselineState)); state != "" {
		return state
	}
	switch canonicalStoredLane(entry) {
	case laneBaselinePending:
		return baselineStatePending
	case laneMain, laneGuard0, laneGuard1, laneGuard2:
		return baselineStateAdmitted
	default:
		return ""
	}
}

func baselineLanePending(entry *FileState) bool {
	return canonicalStoredLane(entry) == laneBaselinePending
}

func isSentinelLane(entry *FileState) bool {
	switch canonicalStoredLane(entry) {
	case laneGuard0, laneGuard1, laneGuard2:
		return true
	default:
		return false
	}
}

func entryAwaitingLaneAssignment(entry *FileState) bool {
	return baselineLanePending(entry) && effectiveBaselineState(entry) == baselineStateReadyForAssignment
}

func baselineAssignmentAnchor(entry *FileState) time.Time {
	if entry == nil {
		return time.Time{}
	}
	if !entry.BaselineRefreshOKAt.IsZero() {
		return entry.BaselineRefreshOKAt
	}
	return entry.LastRefreshOKAt
}

func promoteManagedGuardLane(entry *FileState, promotedAt time.Time) bool {
	if !isSentinelLane(entry) {
		return false
	}
	entry.Lane = laneMain
	entry.LaneAssignedAt = promotedAt
	return true
}

func (a *App) shouldConfirmAfterRefresh(entry *FileState, scheduled bool) bool {
	if baselineLanePending(entry) || isSentinelLane(entry) {
		return true
	}
	if canonicalStoredLane(entry) == laneMain {
		return !scheduled
	}
	return true
}

func (a *App) managedLaneDueAt(lane string, anchor time.Time, authEntry *coreauth.Auth) time.Time {
	if anchor.IsZero() {
		return time.Time{}
	}
	switch strings.ToLower(strings.TrimSpace(lane)) {
	case laneMain:
		return anchor.Add(deterministicInitialDelay(authEntry, "managed-main-refresh", a.env.ManagedMainRefreshMinDelay(), a.env.ManagedMainRefreshMaxDelay()))
	case laneGuard0, laneGuard1, laneGuard2:
		minDelay, maxDelay, ok := a.env.ManagedGuardDelay(lane)
		if !ok {
			return time.Time{}
		}
		return anchor.Add(deterministicInitialDelay(authEntry, "managed-"+lane+"-refresh", minDelay, maxDelay))
	default:
		return time.Time{}
	}
}

func effectiveRefreshBaseTime(entry *FileState) time.Time {
	if entry == nil {
		return time.Time{}
	}
	if !entry.LastRefreshOKAt.IsZero() {
		return entry.LastRefreshOKAt
	}
	if !entry.BaselineRefreshOKAt.IsZero() {
		return entry.BaselineRefreshOKAt
	}
	return entry.ImportedAt
}

func (a *App) effectiveRefreshHardMax(entry *FileState) time.Duration {
	if a == nil || a.env == nil {
		return 0
	}
	switch canonicalStoredLane(entry) {
	case laneMain:
		return a.env.ManagedMainRefreshHardMax()
	case laneGuard0, laneGuard1, laneGuard2:
		return a.env.ManagedGuardHardMax(canonicalStoredLane(entry))
	default:
		return a.env.RefreshHardMax
	}
}

func (a *App) nextRefreshDueAfterConfirmedRefresh(entry *FileState, authEntry *coreauth.Auth, refreshTime time.Time) time.Time {
	if canonicalStoredLane(entry) == laneMain {
		if dueAt := a.managedLaneDueAt(laneMain, refreshTime, authEntry); !dueAt.IsZero() {
			return dueAt
		}
	}
	return refreshTime.Add(a.nextRefreshDelay())
}

func (a *App) nextRefreshDueAfterUnconfirmedRefresh(entry *FileState, authEntry *coreauth.Auth, refreshTime time.Time) time.Time {
	switch canonicalStoredLane(entry) {
	case laneBaselinePending, laneGuard0, laneGuard1, laneGuard2:
		if !entry.CooldownUntil.IsZero() {
			return entry.CooldownUntil
		}
	case laneMain:
		if dueAt := a.managedLaneDueAt(laneMain, refreshTime, authEntry); !dueAt.IsZero() {
			return dueAt
		}
	}
	return refreshTime.Add(a.nextRefreshDelay())
}

func assignmentSortKey(cohortID string, authEntry *coreauth.Auth) string {
	identity := strings.TrimSpace(cohortID) + "\x00" + baseName(authFileName(authEntry)) + "\x00" + refreshTokenHash(authEntry)
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

func appendAssignLaneSkip(result *AssignLanesResult, skip AssignLaneSkip) bool {
	if len(result.Skipped) < cap(result.Skipped) {
		result.Skipped = append(result.Skipped, skip)
		return false
	}
	return true
}

func appendAdoptLegacySkip(result *AdoptLegacyResult, skip AssignLaneSkip) bool {
	if len(result.Skipped) < cap(result.Skipped) {
		result.Skipped = append(result.Skipped, skip)
		return false
	}
	return true
}

func cloneEmergencyStop(stop *StatusEmergencyStop) *StatusEmergencyStop {
	if stop == nil {
		return nil
	}
	copyStop := *stop
	return &copyStop
}

func authFileName(authEntry *coreauth.Auth) string {
	if authEntry == nil {
		return ""
	}
	return authEntry.FileName
}

func ensureStateEntry(state *StateFile, name string) *FileState {
	if state.Files == nil {
		state.Files = map[string]*FileState{}
	}
	entry := state.Files[name]
	if entry == nil {
		entry = &FileState{}
		state.Files[name] = entry
	}
	return entry
}

func cloneStateEntry(entry *FileState) *FileState {
	if entry == nil {
		return nil
	}
	copyEntry := *entry
	return &copyEntry
}

func cloneStateFile(state *StateFile) *StateFile {
	if state == nil {
		return &StateFile{Files: map[string]*FileState{}}
	}
	cloned := &StateFile{Files: make(map[string]*FileState, len(state.Files))}
	for name, entry := range state.Files {
		cloned.Files[name] = cloneStateEntry(entry)
	}
	return cloned
}

func restoreStateEntry(state *StateFile, name string, entry *FileState, hadEntry bool) {
	if state == nil {
		return
	}
	if hadEntry {
		state.Files[name] = cloneStateEntry(entry)
		return
	}
	delete(state.Files, name)
}

func pruneMissingStateEntries(state *StateFile, auths []*coreauth.Auth) {
	if state == nil {
		return
	}
	seen := make(map[string]struct{}, len(auths))
	for _, authEntry := range auths {
		seen[baseName(authEntry.FileName)] = struct{}{}
	}
	for name := range state.Files {
		if _, ok := seen[name]; !ok {
			delete(state.Files, name)
		}
	}
}

func effectiveStateForAuth(authEntry *coreauth.Auth, entry *FileState, now time.Time) *FileState {
	if entry != nil {
		return entry
	}
	return syntheticImportedState(authEntry, now)
}

func syntheticImportedState(authEntry *coreauth.Auth, now time.Time) *FileState {
	anchor := missingStateAnchorTime(authEntry, now)
	return &FileState{
		ImportedAt:       time.Time{},
		NextProbeAt:      anchor.Add(deterministicInitialDelay(authEntry, "recovery-probe", missingStateProbeMinDelay, missingStateProbeMaxDelay)),
		NextRefreshDueAt: anchor.Add(deterministicInitialDelay(authEntry, "recovery-refresh", missingStateRefreshMinDelay, missingStateRefreshMaxDelay)),
		Email:            authEmail(authEntry),
		AccountID:        authAccountID(authEntry),
		RefreshTokenSHA:  refreshTokenHash(authEntry),
	}
}

func missingStateAnchorTime(authEntry *coreauth.Auth, now time.Time) time.Time {
	anchor := now
	if authEntry != nil {
		switch {
		case !authEntry.CreatedAt.IsZero():
			anchor = authEntry.CreatedAt
		case !authEntry.UpdatedAt.IsZero():
			anchor = authEntry.UpdatedAt
		}
	}
	if anchor.After(now) {
		return now
	}
	return anchor
}

func authObservedAt(authEntry *coreauth.Auth) time.Time {
	if authEntry == nil {
		return time.Time{}
	}
	switch {
	case !authEntry.CreatedAt.IsZero():
		return authEntry.CreatedAt
	case !authEntry.UpdatedAt.IsZero():
		return authEntry.UpdatedAt
	default:
		return time.Time{}
	}
}

func isProbeDue(entry *FileState, now time.Time) bool {
	if entryAwaitingLaneAssignment(entry) {
		return false
	}
	if entry == nil || entry.NextProbeAt.IsZero() {
		return true
	}
	return !entry.NextProbeAt.After(now)
}

func isRefreshDue(entry *FileState, now time.Time, hardMax time.Duration) bool {
	if entryAwaitingLaneAssignment(entry) {
		return false
	}
	if entry == nil {
		return false
	}
	if !entry.NextRefreshDueAt.IsZero() && !entry.NextRefreshDueAt.After(now) {
		return true
	}
	base := effectiveRefreshBaseTime(entry)
	return !base.IsZero() && !base.Add(hardMax).After(now)
}

func effectiveDueAt(entry *FileState, now time.Time, hardMax time.Duration) time.Time {
	if entryAwaitingLaneAssignment(entry) {
		return time.Time{}
	}
	if entry == nil {
		return now
	}
	candidates := make([]time.Time, 0, 3)
	if !entry.NextProbeAt.IsZero() {
		candidates = append(candidates, entry.NextProbeAt)
	}
	if !entry.NextRefreshDueAt.IsZero() {
		candidates = append(candidates, entry.NextRefreshDueAt)
	}
	base := effectiveRefreshBaseTime(entry)
	if !base.IsZero() {
		candidates = append(candidates, base.Add(hardMax))
	}
	if len(candidates) == 0 {
		return now
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Before(candidates[j]) })
	return candidates[0]
}

func dueBucketStart(dueAt time.Time) time.Time {
	if dueAt.IsZero() {
		return time.Time{}
	}
	return dueAt.UTC().Truncate(time.Hour)
}

func (a *App) nextInitialProbeDelay() time.Duration {
	return a.nextRandomDelay(a.env.InitialProbeMinDelay, a.env.InitialProbeMaxDelay)
}

func (a *App) nextInitialRefreshDelay() time.Duration {
	return a.nextRandomDelay(a.env.InitialRefreshMinDelay, a.env.InitialRefreshMaxDelay)
}

func (a *App) nextProbeDelay() time.Duration {
	return a.nextRandomDelay(a.env.ProbeMinDelay, a.env.ProbeMaxDelay)
}

func (a *App) nextRefreshDelay() time.Duration {
	return a.nextRandomDelay(a.env.RefreshMinDelay, a.env.RefreshMaxDelay)
}

func deterministicInitialDelay(authEntry *coreauth.Auth, salt string, minDelay, maxDelay time.Duration) time.Duration {
	if maxDelay <= minDelay {
		return minDelay
	}
	name := ""
	if authEntry != nil {
		name = baseName(authEntry.FileName)
	}
	identity := salt + "\x00" + name + "\x00" + refreshTokenHash(authEntry)
	sum := sha256.Sum256([]byte(identity))
	span := maxDelay - minDelay
	offset := time.Duration(binary.BigEndian.Uint64(sum[:8]) % uint64(span+1))
	return minDelay + offset
}

func (a *App) nextRandomDelay(minDelay, maxDelay time.Duration) time.Duration {
	if maxDelay <= minDelay {
		return minDelay
	}
	if a == nil || a.rng == nil {
		return minDelay
	}
	span := maxDelay - minDelay
	if span <= 0 {
		return minDelay
	}
	return minDelay + time.Duration(a.rng.Int63n(int64(span)+1))
}

func (a *App) nextRefreshChainDelay() time.Duration {
	return a.nextRandomDelay(a.env.RefreshChainDelayMin, a.env.RefreshChainDelayMax)
}

func (a *App) nextConfirmChainDelay() time.Duration {
	return a.nextRandomDelay(a.env.ConfirmChainDelayMin, a.env.ConfirmChainDelayMax)
}

func (a *App) waitBetweenAuths(ctx context.Context, index int) error {
	if index <= 0 || a.sleep == nil {
		return nil
	}
	return a.waitBetweenChainSteps(ctx, a.nextRandomDelay(a.env.ActionDelayMin, a.env.ActionDelayMax))
}

func (a *App) waitBetweenChainSteps(ctx context.Context, delay time.Duration) error {
	if delay <= 0 || a.sleep == nil {
		return nil
	}
	return a.sleep(ctx, delay)
}

func (a *App) runUsageProbe(ctx context.Context, authEntry *coreauth.Auth) (*usageProbeResponse, error) {
	if a.usageProbeFunc != nil {
		return a.usageProbeFunc(ctx, authEntry)
	}
	return a.probeUsage(ctx, authEntry)
}

func (a *App) runRefreshAuth(ctx context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
	if a.refreshAuthFunc != nil {
		return a.refreshAuthFunc(ctx, authEntry)
	}
	exec := runtimeexecutor.NewCodexExecutor(a.cfg)
	return exec.Refresh(ctx, authEntry)
}

func (a *App) probeUsage(ctx context.Context, authEntry *coreauth.Auth) (*usageProbeResponse, error) {
	if authEntry == nil {
		return nil, fmt.Errorf("maintpool probe auth is nil")
	}
	token := strings.TrimSpace(resolveAccessToken(authEntry))
	if token == "" {
		return nil, fmt.Errorf("codex access_token is missing")
	}
	accountID := strings.TrimSpace(resolveChatGPTAccountID(authEntry))
	if accountID == "" {
		return nil, fmt.Errorf("codex chatgpt account id is missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, maintPoolUsageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", maintPoolUsageUserAgent)
	req.Header.Set("Chatgpt-Account-Id", accountID)
	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: buildTransport(a.cfg, authEntry),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &usageProbeResponse{StatusCode: resp.StatusCode, Body: string(body)}, nil
}

func (a *App) savePoolAuth(ctx context.Context, authEntry *coreauth.Auth) error {
	if authEntry == nil {
		return fmt.Errorf("maintpool save auth is nil")
	}
	authEntry.FileName = baseName(authEntry.FileName)
	if authEntry.Attributes == nil {
		authEntry.Attributes = map[string]string{}
	}
	authEntry.Attributes["path"] = filepath.Join(a.env.PoolDir(), authEntry.FileName)
	_, err := a.store.Save(ctx, authEntry)
	return err
}

func (a *App) loadPoolAuthByName(ctx context.Context, name string) (*coreauth.Auth, error) {
	auths, err := a.listPoolAuths(ctx)
	if err != nil {
		return nil, err
	}
	for _, authEntry := range auths {
		if strings.EqualFold(baseName(authEntry.FileName), baseName(name)) {
			return authEntry.Clone(), nil
		}
	}
	return nil, fmt.Errorf("maintpool auth %q not found in pool metadata", name)
}

func (a *App) validateTakeoutDestination(destDir string) error {
	destNorm, err := normalizeComparablePath(destDir)
	if err != nil {
		return fmt.Errorf("normalize takeout destination: %w", err)
	}
	for _, protected := range []struct {
		label string
		path  string
	}{
		{label: "pool dir", path: a.env.PoolDir()},
		{label: "state dir", path: a.env.StateDir()},
		{label: "events dir", path: a.env.EventsDir()},
		{label: "external-401 dir", path: a.env.External401Dir()},
	} {
		protectedNorm, err := normalizeComparablePath(protected.path)
		if err != nil {
			return fmt.Errorf("normalize %s: %w", protected.label, err)
		}
		if pathsOverlap(destNorm, protectedNorm) {
			return fmt.Errorf("takeout destination must not overlap %s", protected.label)
		}
	}
	rootNorm, err := normalizeComparablePath(a.env.Root)
	if err != nil {
		return fmt.Errorf("normalize ROOT: %w", err)
	}
	exportedNorm, err := normalizeComparablePath(a.env.ExportedDir())
	if err != nil {
		return fmt.Errorf("normalize exported dir: %w", err)
	}
	if pathsOverlap(destNorm, rootNorm) && !pathContains(exportedNorm, destNorm) {
		return fmt.Errorf("takeout destination inside ROOT must stay under exported/")
	}
	if a.cfg != nil {
		if authDir := strings.TrimSpace(a.cfg.AuthDir); authDir != "" {
			authNorm, err := normalizeComparablePath(authDir)
			if err != nil {
				return fmt.Errorf("normalize auth-dir: %w", err)
			}
			if pathsOverlap(destNorm, authNorm) {
				return fmt.Errorf("takeout destination must not overlap auth-dir")
			}
		}
	}
	return nil
}

func (a *App) validateTakeoutUniqueness(ctx context.Context, current *coreauth.Auth, sourcePath string) error {
	if current == nil {
		return fmt.Errorf("takeout uniqueness check requires auth metadata")
	}
	rootStore := auth.NewFileTokenStore()
	rootStore.SetBaseDir(a.env.Root)
	if err := a.ensureNoDuplicateInStore(ctx, current, sourcePath, rootStore, "maintenance root"); err != nil {
		return err
	}
	if a.cfg != nil {
		authDir := strings.TrimSpace(a.cfg.AuthDir)
		if authDir != "" {
			liveStore := auth.NewFileTokenStore()
			liveStore.SetBaseDir(authDir)
			if err := a.ensureNoDuplicateInStore(ctx, current, sourcePath, liveStore, "auth-dir"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) ensureNoDuplicateInStore(ctx context.Context, current *coreauth.Auth, sourcePath string, store *auth.FileTokenStore, scope string) error {
	auths, err := a.listStoreAuths(ctx, store)
	if err != nil {
		return err
	}
	for _, other := range auths {
		if other == nil {
			continue
		}
		otherPath, err := normalizeComparablePath(strings.TrimSpace(other.Attributes["path"]))
		if err == nil {
			sourceNorm, sourceErr := normalizeComparablePath(sourcePath)
			if sourceErr == nil && otherPath == sourceNorm {
				continue
			}
		}
		if reason := duplicateReasonBetween(current, other); reason != "" {
			return fmt.Errorf("takeout uniqueness check failed: %s already exists in %s at %s", reason, scope, strings.TrimSpace(other.Attributes["path"]))
		}
	}
	return nil
}

func (a *App) rollbackTakeoutMove(sourcePath, targetPath string, state *StateFile, name string, previousEntry *FileState, hadEntry bool, persistState bool) error {
	if err := moveFile(targetPath, sourcePath); err != nil {
		return err
	}
	restoreStateEntry(state, name, previousEntry, hadEntry)
	if persistState {
		if err := a.saveState(state); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) rollbackImportedFiles(importedTargets []string, afterFiles func() error) error {
	var errs []string
	for index := len(importedTargets) - 1; index >= 0; index-- {
		targetPath := strings.TrimSpace(importedTargets[index])
		if targetPath == "" {
			continue
		}
		if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("remove %s: %v", targetPath, err))
		}
	}
	if afterFiles != nil {
		if err := afterFiles(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (a *App) movePoolAuthToExternal401(authEntry *coreauth.Auth, now time.Time) (string, error) {
	sourcePath := filepath.Join(a.env.PoolDir(), baseName(authEntry.FileName))
	targetPath := filepath.Join(a.env.External401Dir(), baseName(authEntry.FileName))
	if _, err := os.Stat(targetPath); err == nil {
		targetPath = uniquePath(targetPath, now)
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := moveFile(sourcePath, targetPath); err != nil {
		return "", err
	}
	return targetPath, nil
}

func classifyHTTPOrError(resp *usageProbeResponse, err error) string {
	if err != nil {
		return classifyErrorText(err.Error())
	}
	if resp == nil {
		return classificationTransient
	}
	return classifyHTTPResult(resp.StatusCode, resp.Body)
}

func classifyHTTPResult(statusCode int, body string) string {
	switch {
	case statusCode == http.StatusOK:
		return classificationSuccess
	case statusCode == http.StatusTooManyRequests:
		return classification429
	case statusCode == http.StatusUnauthorized || has401Signal(body):
		return classificationInvalid
	default:
		return classificationTransient
	}
}

func classifyErrorText(text string) string {
	lower := strings.ToLower(strings.TrimSpace(text))
	switch {
	case lower == "":
		return classificationTransient
	case strings.Contains(lower, "429"):
		return classification429
	case has401Signal(lower):
		return classificationInvalid
	default:
		return classificationTransient
	}
}

func shouldRefreshAfterProbeFailure(resp *usageProbeResponse, err error) bool {
	if resp != nil && classifyHTTPResult(resp.StatusCode, resp.Body) == classificationInvalid {
		return true
	}
	if err == nil {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	if lower == "" {
		return false
	}
	if classifyErrorText(lower) == classificationInvalid {
		return true
	}
	return strings.Contains(lower, "access_token is missing") || strings.Contains(lower, "chatgpt account id is missing")
}

func responseHTTPStatus(resp *usageProbeResponse, err error) int {
	if resp != nil && resp.StatusCode > 0 {
		return resp.StatusCode
	}
	if err != nil {
		return httpStatusFromText(err.Error())
	}
	return 0
}

func httpStatusFromText(text string) int {
	switch classifyErrorText(text) {
	case classificationInvalid:
		return http.StatusUnauthorized
	case classification429:
		return http.StatusTooManyRequests
	default:
		return 0
	}
}

func responseMessage(resp *usageProbeResponse, err error) string {
	if err != nil {
		return strings.TrimSpace(err.Error())
	}
	if resp == nil {
		return ""
	}
	return strings.TrimSpace(resp.Body)
}

func has401Signal(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	for _, marker := range []string{
		"authentication token has been invalidated",
		"token_invalidated",
		"account_deactivated",
		"refresh_token_reused",
		"refresh_token_invalidated",
		"status 401",
		"status: 401",
		"\"status\":401",
		"\"status\": 401",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Contains(lower, " 401 ") || strings.HasSuffix(lower, " 401")
}

func normalizeAuthSuccess(authEntry *coreauth.Auth, now time.Time, refreshed bool) {
	if authEntry == nil {
		return
	}
	authEntry.Disabled = false
	authEntry.Status = coreauth.StatusActive
	authEntry.Unavailable = false
	authEntry.StatusMessage = ""
	authEntry.LastError = nil
	authEntry.Quota = coreauth.QuotaState{}
	authEntry.NextRetryAfter = time.Time{}
	authEntry.NextRefreshAfter = time.Time{}
	authEntry.UpdatedAt = now
	if refreshed {
		authEntry.LastRefreshedAt = now
	}
	if authEntry.Metadata != nil {
		delete(authEntry.Metadata, "disabled")
		delete(authEntry.Metadata, "_cliproxy_runtime")
	}
}

func mergeRecoveredAuth(base, updated *coreauth.Auth) *coreauth.Auth {
	if updated == nil {
		updated = base.Clone()
	}
	if updated == nil {
		return nil
	}
	if base == nil {
		return updated
	}
	updated.FileName = base.FileName
	if updated.Attributes == nil {
		updated.Attributes = map[string]string{}
	}
	if base.Attributes != nil {
		if path := strings.TrimSpace(base.Attributes["path"]); path != "" {
			updated.Attributes["path"] = path
		}
	}
	return updated
}

func buildTransport(cfg *config.Config, authEntry *coreauth.Auth) http.RoundTripper {
	proxyURL := ""
	if authEntry != nil {
		proxyURL = strings.TrimSpace(authEntry.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	transport, mode, err := proxyutil.BuildHTTPTransport(proxyURL)
	if err == nil && transport != nil {
		switch mode {
		case proxyutil.ModeProxy, proxyutil.ModeDirect:
			return transport
		}
	}
	return codexauth.NewOpenAIHTTPClient(cfg).Transport
}

func resolveAccessToken(authEntry *coreauth.Auth) string {
	if authEntry == nil || authEntry.Metadata == nil {
		return ""
	}
	if value, ok := authEntry.Metadata["access_token"].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func resolveChatGPTAccountID(authEntry *coreauth.Auth) string {
	if authEntry == nil || authEntry.Metadata == nil {
		return ""
	}
	if rawID, ok := authEntry.Metadata["account_id"].(string); ok {
		if trimmed := strings.TrimSpace(rawID); trimmed != "" {
			return trimmed
		}
	}
	idToken, _ := authEntry.Metadata["id_token"].(string)
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return ""
	}
	claims, err := codexauth.ParseJWTToken(idToken)
	if err != nil || claims == nil {
		return ""
	}
	return strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
}

func authEmail(authEntry *coreauth.Auth) string {
	if authEntry == nil || authEntry.Metadata == nil {
		return ""
	}
	if value, ok := authEntry.Metadata["email"].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func authAccountID(authEntry *coreauth.Auth) string {
	return strings.TrimSpace(resolveChatGPTAccountID(authEntry))
}

func populateStateIdentity(entry *FileState, authEntry *coreauth.Auth) {
	if entry == nil {
		return
	}
	entry.Email = authEmail(authEntry)
	entry.AccountID = authAccountID(authEntry)
	entry.RefreshTokenSHA = refreshTokenHash(authEntry)
}

func refreshTokenHash(authEntry *coreauth.Auth) string {
	if authEntry == nil {
		return ""
	}
	value := strings.TrimSpace(authEntry.RefreshToken())
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func appendName(target []string, name string) ([]string, bool) {
	if len(target) >= cap(target) && cap(target) > 0 {
		return target, true
	}
	return append(target, name), false
}

func appendImportSkip(result *ImportResult, skip ImportSkip) bool {
	if len(result.Skipped) < cap(result.Skipped) {
		result.Skipped = append(result.Skipped, skip)
		return false
	}
	return true
}

func appendImportFailure(result *ImportResult, failure ImportFailure) bool {
	if len(result.Failed) < cap(result.Failed) {
		result.Failed = append(result.Failed, failure)
		return false
	}
	return true
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func countJSONFiles(root string) (int, error) {
	count := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
			count++
		}
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	return count, err
}

func moveFile(sourcePath, targetPath string) error {
	if err := os.Rename(sourcePath, targetPath); err == nil {
		return nil
	}
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer func() { _ = sourceFile.Close() }()
	targetFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(targetFile, sourceFile); err != nil {
		_ = targetFile.Close()
		return err
	}
	if err = targetFile.Close(); err != nil {
		return err
	}
	return os.Remove(sourcePath)
}

func uniquePath(path string, ts time.Time) string {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(filepath.Base(path), ext)
	stamp := ts.Format("20060102-150405.000000000")
	return filepath.Join(filepath.Dir(path), fmt.Sprintf("%s-%s%s", base, stamp, ext))
}

func baseName(name string) string {
	return filepath.Base(strings.TrimSpace(name))
}

func modeLabel(apply bool) string {
	if apply {
		return "apply"
	}
	return "preview"
}

func trimReason(text string) string {
	text = strings.TrimSpace(text)
	if len(text) <= 800 {
		return text
	}
	return text[:800]
}

func readLockTime(lockPath string) (time.Time, error) {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return time.Time{}, err
	}
	var record lockRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return time.Time{}, err
	}
	return record.At, nil
}

const (
	classificationSuccess   = "success"
	classificationInvalid   = "invalid_401"
	classification429       = "anomaly_429"
	classificationTransient = "transient_error"
)
