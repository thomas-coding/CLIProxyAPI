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

	resultImported              = "imported"
	resultTakenOut              = "taken_out"
	resultProbeOK               = "probe_ok"
	resultScheduledRefreshOK    = "scheduled_refresh_ok"
	resultRecoveryRefreshOK     = "recovery_refresh_ok"
	resultUsage429              = "usage_429"
	resultProbeError            = "probe_error"
	resultInvalidMoved          = "invalid_moved"
	resultScheduledRefresh429   = "scheduled_refresh_429"
	resultScheduledRefreshError = "scheduled_refresh_error"
	resultRecoveryRefresh429    = "recovery_refresh_429"
	resultRecoveryRefreshError  = "recovery_refresh_error"
	resultScheduledConfirm429   = "scheduled_confirm_429"
	resultScheduledConfirmError = "scheduled_confirm_error"
	resultRecoveryConfirm429    = "recovery_confirm_429"
	resultRecoveryConfirmError  = "recovery_confirm_error"
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
			PoolDir:        a.env.PoolDir(),
			StatePath:      a.env.StatePath(),
			EventsPath:     a.env.EventsPath(),
			External401Dir: a.env.External401Dir(),
			ExportedDir:    a.env.ExportedDir(),
		},
		Cadence: StatusCadence{
			InitialProbeMinDelay:   a.env.InitialProbeMinDelay,
			InitialProbeMaxDelay:   a.env.InitialProbeMaxDelay,
			InitialRefreshMinDelay: a.env.InitialRefreshMinDelay,
			InitialRefreshMaxDelay: a.env.InitialRefreshMaxDelay,
			ProbeMinDelay:          a.env.ProbeMinDelay,
			ProbeMaxDelay:          a.env.ProbeMaxDelay,
			RefreshMinDelay:        a.env.RefreshMinDelay,
			RefreshMaxDelay:        a.env.RefreshMaxDelay,
			RefreshHardMax:         a.env.RefreshHardMax,
			Cooldown429:            a.env.Cooldown429,
			CooldownTransient:      a.env.CooldownTransient,
		},
	}
	result.Pool.TotalFiles = len(auths)
	for _, authEntry := range auths {
		entry := effectiveStateForAuth(authEntry, state.Files[baseName(authEntry.FileName)], now)
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
		dueProbe := isProbeDue(entry, now)
		dueRefresh := isRefreshDue(entry, now, a.env.RefreshHardMax)
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
		dueAt := effectiveDueAt(entry, now, a.env.RefreshHardMax)
		if !dueAt.IsZero() && (result.Pool.NextDueAt.IsZero() || dueAt.Before(result.Pool.NextDueAt)) {
			result.Pool.NextDueAt = dueAt
		}
	}
	result.Pool.External401Total, _ = countJSONFiles(a.env.External401Dir())
	result.Pool.ExportedTotal, _ = countJSONFiles(a.env.ExportedDir())
	return result, nil
}

func (a *App) Import(ctx context.Context, sourceDir string, apply bool) (*ImportResult, error) {
	sourceDir = strings.TrimSpace(sourceDir)
	if sourceDir == "" {
		return nil, fmt.Errorf("source dir is required")
	}
	resolvedSource, err := filepath.Abs(sourceDir)
	if err != nil {
		return nil, err
	}
	result := &ImportResult{
		Mode:            modeLabel(apply),
		SourceDir:       resolvedSource,
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

	err = a.withOptionalLock(apply, func() error {
		if apply {
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

			if !apply {
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
			initializeImportedState(a, entry, current, now)
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

		if !apply {
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

		events := make([]Event, 0, len(candidates))
		for index, candidate := range candidates {
			if errWait := a.waitBetweenAuths(ctx, index); errWait != nil {
				return errWait
			}
			removed, errProcess := a.processDueAuth(ctx, candidate, state, &result.Summary, &events)
			if errProcess != nil {
				return errProcess
			}
			if removed {
				delete(state.Files, baseName(candidate.auth.FileName))
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
		entry.NextRefreshDueAt = refreshTime.Add(a.nextRefreshDelay())
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
		entry.NextRefreshDueAt = refreshTime.Add(a.nextRefreshDelay())
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
		entry.NextRefreshDueAt = refreshTime.Add(a.nextRefreshDelay())
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
		if entry != nil && entry.CooldownUntil.After(now) {
			continue
		}
		dueProbe := isProbeDue(entry, now)
		dueRefresh := isRefreshDue(entry, now, a.env.RefreshHardMax)
		if !dueProbe && !dueRefresh {
			continue
		}
		candidates = append(candidates, dueCandidate{
			auth:       authEntry,
			state:      entry,
			dueAt:      effectiveDueAt(entry, now, a.env.RefreshHardMax),
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

func initializeImportedState(a *App, entry *FileState, authEntry *coreauth.Auth, now time.Time) {
	if entry == nil {
		return
	}
	entry.ImportedAt = now
	entry.LastProbeAt = time.Time{}
	entry.LastProbeOKAt = time.Time{}
	entry.LastRefreshAttemptAt = time.Time{}
	entry.LastRefreshOKAt = time.Time{}
	entry.NextProbeAt = now.Add(a.nextInitialProbeDelay())
	entry.NextRefreshDueAt = now.Add(a.nextInitialRefreshDelay())
	entry.CooldownUntil = time.Time{}
	entry.LastResult = resultImported
	entry.LastHTTPStatus = 0
	populateStateIdentity(entry, authEntry)
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
	if entry == nil || entry.NextProbeAt.IsZero() {
		return true
	}
	return !entry.NextProbeAt.After(now)
}

func isRefreshDue(entry *FileState, now time.Time, hardMax time.Duration) bool {
	if entry == nil {
		return false
	}
	if !entry.NextRefreshDueAt.IsZero() && !entry.NextRefreshDueAt.After(now) {
		return true
	}
	base := entry.LastRefreshOKAt
	if base.IsZero() {
		base = entry.ImportedAt
	}
	return !base.IsZero() && !base.Add(hardMax).After(now)
}

func effectiveDueAt(entry *FileState, now time.Time, hardMax time.Duration) time.Time {
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
	base := entry.LastRefreshOKAt
	if base.IsZero() {
		base = entry.ImportedAt
	}
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
