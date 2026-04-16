package reserve2

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
	codexUsageURL       = "https://chatgpt.com/backend-api/wham/usage"
	codexUsageUserAgent = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
	lockStaleAfter      = 2 * time.Hour

	classificationSuccess   = "success"
	classificationInvalid   = "invalid_401"
	classification429       = "anomaly_429"
	classificationTransient = "transient_error"

	resultHealthy200       = "healthy_200"
	resultRefreshRecovered = "refresh_recovered"
	resultInvalidMoved     = "invalid_moved"
	resultUsage429         = "usage_429"
	resultProbeError       = "probe_error"
	resultDuplicate        = "duplicate_skipped"
)

var status401Pattern = regexp.MustCompile(`(^|[^0-9])401([^0-9]|$)`)

type App struct {
	env             *EnvConfig
	cfg             *config.Config
	coldStore       *auth.FileTokenStore
	reserve1Store   *auth.FileTokenStore
	productionStore *auth.FileTokenStore
	now             func() time.Time
	usageProbeFunc  func(context.Context, *coreauth.Auth) (*usageProbeResponse, error)
	refreshAuthFunc func(context.Context, *coreauth.Auth) (*coreauth.Auth, error)
	rng             *rand.Rand
	sleep           func(context.Context, time.Duration) error
}

type duplicateIndex struct {
	names         map[string]struct{}
	accountIDs    map[string]struct{}
	refreshHashes map[string]struct{}
	emails        map[string]struct{}
}

type inspectResult struct {
	auth           *coreauth.Auth
	refreshed      bool
	classification string
	statusCode     int
	message        string
}

type eventRecord struct {
	At         time.Time `json:"at"`
	Type       string    `json:"type"`
	Name       string    `json:"name,omitempty"`
	Email      string    `json:"email,omitempty"`
	AccountID  string    `json:"account_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	TargetPath string    `json:"target_path,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
}

type lockRecord struct {
	PID int       `json:"pid"`
	At  time.Time `json:"at"`
}

type usageProbeResponse struct {
	StatusCode int
	Body       string
}

type coldCandidate struct {
	auth        *coreauth.Auth
	lastChecked time.Time
	lastRefresh time.Time
}

func NewApp(env *EnvConfig, cfg *config.Config) *App {
	coldStore := auth.NewFileTokenStore()
	coldStore.SetBaseDir(env.PoolDir())
	reserve1Store := auth.NewFileTokenStore()
	reserve1Store.SetBaseDir(env.Reserve1Dir)
	productionStore := auth.NewFileTokenStore()
	productionStore.SetBaseDir(env.ProductionDir)
	return &App{
		env:             env,
		cfg:             cfg,
		coldStore:       coldStore,
		reserve1Store:   reserve1Store,
		productionStore: productionStore,
		now:             time.Now,
		rng:             rand.New(rand.NewSource(time.Now().UnixNano())),
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

func (a *App) Sample(ctx context.Context, apply bool) (*SampleResult, error) {
	result := &SampleResult{
		Mode:    modeLabel(apply),
		Summary: SampleSummary{StartedAt: a.now(), Mode: modeLabel(apply)},
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
		coldAuths, errList := a.listColdAuths(ctx)
		if errList != nil {
			return errList
		}
		if apply {
			pruneMissingStateEntries(state, coldAuths)
		}
		selected := a.selectColdCandidates(coldAuths, state, minInt(a.env.SampleSize, a.env.SampleCap))
		result.Selected = selectedNames(selected)
		result.Summary.Requested = len(selected)

		events := make([]eventRecord, 0)
		for index, authEntry := range selected {
			if errWait := a.waitBetweenInspects(ctx, apply, index); errWait != nil {
				return errWait
			}
			outcome, errInspect := a.inspectAuth(ctx, authEntry.Clone(), apply)
			if errInspect != nil {
				return errInspect
			}
			result.Summary.Processed++
			switch outcome.classification {
			case classificationSuccess:
				if outcome.refreshed {
					result.Summary.RefreshRecovered++
				} else {
					result.Summary.Healthy200++
				}
				if apply {
					now := a.now()
					normalizeAuthSuccess(outcome.auth, now, outcome.refreshed)
					if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
						return errSave
					}
					entry := ensureStateEntry(state, baseName(outcome.auth.FileName))
					updateStateEntryFromAuth(entry, outcome.auth, outcome.refreshed, now, resultForSuccess(outcome.refreshed), outcome.statusCode, time.Time{})
					events = append(events, eventRecord{At: now, Type: eventTypeForSuccess(outcome.refreshed), Name: baseName(outcome.auth.FileName), Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), HTTPStatus: outcome.statusCode})
				}
			case classificationInvalid:
				result.Summary.InvalidMoved++
				if apply {
					now := a.now()
					if outcome.refreshed {
						if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
							return errSave
						}
					}
					targetPath, errMove := a.moveColdAuthToExternal401(outcome.auth)
					if errMove != nil {
						return errMove
					}
					delete(state.Files, baseName(outcome.auth.FileName))
					events = append(events, eventRecord{At: now, Type: resultInvalidMoved, Name: baseName(outcome.auth.FileName), Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), Reason: trimReason(outcome.message), TargetPath: targetPath, HTTPStatus: outcome.statusCode})
				}
			case classification429:
				result.Summary.Usage429++
				if apply {
					now := a.now()
					if outcome.refreshed {
						if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
							return errSave
						}
					}
					entry := ensureStateEntry(state, baseName(outcome.auth.FileName))
					nextRetry := now.Add(a.env.Cooldown429)
					updateStateEntryFromAuth(entry, outcome.auth, outcome.refreshed, now, resultUsage429, outcome.statusCode, nextRetry)
					events = append(events, eventRecord{At: now, Type: resultUsage429, Name: baseName(outcome.auth.FileName), Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), Reason: trimReason(outcome.message), HTTPStatus: outcome.statusCode})
				}
			default:
				result.Summary.ProbeError++
				if apply {
					now := a.now()
					if outcome.refreshed {
						if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
							return errSave
						}
					}
					entry := ensureStateEntry(state, baseName(outcome.auth.FileName))
					nextRetry := now.Add(a.env.CooldownTransient)
					updateStateEntryFromAuth(entry, outcome.auth, outcome.refreshed, now, resultProbeError, outcome.statusCode, nextRetry)
					events = append(events, eventRecord{At: now, Type: resultProbeError, Name: baseName(outcome.auth.FileName), Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), Reason: trimReason(outcome.message), HTTPStatus: outcome.statusCode})
				}
			}
		}

		result.Summary.FinishedAt = a.now()
		if !apply {
			return nil
		}
		if errSaveState := a.saveState(state); errSaveState != nil {
			return errSaveState
		}
		if errAppend := a.appendEvents(events); errAppend != nil {
			return errAppend
		}
		_, errSummary := a.refreshSummary(ctx, func(s *Summary) {
			copySummary := result.Summary
			s.LastSample = &copySummary
		}, true)
		return errSummary
	})
	if err != nil {
		return nil, err
	}
	if result.Summary.FinishedAt.IsZero() {
		result.Summary.FinishedAt = a.now()
	}
	return result, nil
}

func (a *App) Sync(ctx context.Context, apply bool) (*SyncResult, error) {
	result := &SyncResult{
		Mode:    modeLabel(apply),
		Summary: SyncSummary{StartedAt: a.now(), Mode: modeLabel(apply), LowWatermark: a.env.LowWatermark, Target: a.env.Target, TransferCap: a.env.MaxTransfer},
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
		coldAuths, errListCold := a.listColdAuths(ctx)
		if errListCold != nil {
			return errListCold
		}
		if apply {
			pruneMissingStateEntries(state, coldAuths)
		}
		reserve1Auths, errListReserve1 := a.listStoreAuths(ctx, a.reserve1Store)
		if errListReserve1 != nil {
			return errListReserve1
		}
		result.Summary.Reserve1AvailableBefore = countAvailable(reserve1Auths)
		result.Summary.Needed = a.env.DesiredTransfer(result.Summary.Reserve1AvailableBefore)
		if result.Summary.Reserve1AvailableBefore >= a.env.LowWatermark || result.Summary.Needed == 0 {
			result.Summary.Reserve1AvailableAfter = result.Summary.Reserve1AvailableBefore
			result.Summary.FinishedAt = a.now()
			if apply {
				_, errSummary := a.refreshSummary(ctx, func(s *Summary) {
					copySummary := result.Summary
					s.LastSync = &copySummary
				}, true)
				return errSummary
			}
			return nil
		}

		desiredTransfer := result.Summary.Needed
		result.Summary.CandidateCount = a.env.CandidateCount(desiredTransfer)
		selected := a.selectColdCandidates(coldAuths, state, result.Summary.CandidateCount)
		result.Selected = selectedNames(selected)

		dupIndex, errDupIndex := a.buildDuplicateIndex(ctx)
		if errDupIndex != nil {
			return errDupIndex
		}
		events := make([]eventRecord, 0)
		for index, authEntry := range selected {
			if result.Summary.PromotedToReserve1 >= desiredTransfer {
				break
			}
			if errWait := a.waitBetweenInspects(ctx, apply, index); errWait != nil {
				return errWait
			}
			outcome, errInspect := a.inspectAuth(ctx, authEntry.Clone(), apply)
			if errInspect != nil {
				return errInspect
			}
			if errHandle := a.handleSyncOutcome(outcome, dupIndex, state, apply, &result.Summary, &events); errHandle != nil {
				return errHandle
			}
		}

		result.Summary.Reserve1AvailableAfter = result.Summary.Reserve1AvailableBefore + result.Summary.PromotedToReserve1
		result.Summary.FinishedAt = a.now()
		if !apply {
			return nil
		}
		if errSaveState := a.saveState(state); errSaveState != nil {
			return errSaveState
		}
		if errAppend := a.appendEvents(events); errAppend != nil {
			return errAppend
		}
		_, errSummary := a.refreshSummary(ctx, func(s *Summary) {
			copySummary := result.Summary
			s.LastSync = &copySummary
		}, true)
		return errSummary
	})
	if err != nil {
		return nil, err
	}
	if result.Summary.FinishedAt.IsZero() {
		result.Summary.FinishedAt = a.now()
	}
	return result, nil
}

func (a *App) Status(ctx context.Context) (*Summary, error) {
	return a.refreshSummary(ctx, nil, false)
}

func (a *App) handleSyncOutcome(outcome *inspectResult, dupIndex *duplicateIndex, state *StateFile, apply bool, summary *SyncSummary, events *[]eventRecord) error {
	switch outcome.classification {
	case classificationSuccess:
		name := baseName(outcome.auth.FileName)
		reason := duplicateReason(dupIndex, outcome.auth)
		if reason != "" {
			summary.DuplicateSkipped++
			if apply {
				now := a.now()
				normalizeAuthSuccess(outcome.auth, now, outcome.refreshed)
				if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
					return errSave
				}
				entry := ensureStateEntry(state, name)
				updateStateEntryFromAuth(entry, outcome.auth, outcome.refreshed, now, resultDuplicate, outcome.statusCode, time.Time{})
				*events = append(*events, eventRecord{At: now, Type: resultDuplicate, Name: name, Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), Reason: reason, HTTPStatus: outcome.statusCode})
			}
			return nil
		}
		summary.PromotedToReserve1++
		if apply {
			now := a.now()
			normalizeAuthSuccess(outcome.auth, now, outcome.refreshed)
			if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
				return errSave
			}
			targetPath, errMove := a.moveColdAuthToReserve1(outcome.auth)
			if errMove != nil {
				return errMove
			}
			delete(state.Files, name)
			dupIndex.add(outcome.auth)
			*events = append(*events, eventRecord{At: now, Type: "promoted_to_reserve1", Name: name, Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), TargetPath: targetPath, HTTPStatus: outcome.statusCode})
		}
	case classificationInvalid:
		summary.InvalidMoved++
		if apply {
			now := a.now()
			if outcome.refreshed {
				if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
					return errSave
				}
			}
			targetPath, errMove := a.moveColdAuthToExternal401(outcome.auth)
			if errMove != nil {
				return errMove
			}
			delete(state.Files, baseName(outcome.auth.FileName))
			*events = append(*events, eventRecord{At: now, Type: resultInvalidMoved, Name: baseName(outcome.auth.FileName), Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), Reason: trimReason(outcome.message), TargetPath: targetPath, HTTPStatus: outcome.statusCode})
		}
	case classification429:
		summary.Usage429++
		if apply {
			now := a.now()
			if outcome.refreshed {
				if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
					return errSave
				}
			}
			entry := ensureStateEntry(state, baseName(outcome.auth.FileName))
			nextRetry := now.Add(a.env.Cooldown429)
			updateStateEntryFromAuth(entry, outcome.auth, outcome.refreshed, now, resultUsage429, outcome.statusCode, nextRetry)
			*events = append(*events, eventRecord{At: now, Type: resultUsage429, Name: baseName(outcome.auth.FileName), Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), Reason: trimReason(outcome.message), HTTPStatus: outcome.statusCode})
		}
	default:
		summary.ProbeError++
		if apply {
			now := a.now()
			if outcome.refreshed {
				if errSave := a.saveColdAuth(outcome.auth); errSave != nil {
					return errSave
				}
			}
			entry := ensureStateEntry(state, baseName(outcome.auth.FileName))
			nextRetry := now.Add(a.env.CooldownTransient)
			updateStateEntryFromAuth(entry, outcome.auth, outcome.refreshed, now, resultProbeError, outcome.statusCode, nextRetry)
			*events = append(*events, eventRecord{At: now, Type: resultProbeError, Name: baseName(outcome.auth.FileName), Email: authEmail(outcome.auth), AccountID: authAccountID(outcome.auth), Reason: trimReason(outcome.message), HTTPStatus: outcome.statusCode})
		}
	}
	return nil
}

func (a *App) refreshSummary(ctx context.Context, mutate func(*Summary), persist bool) (*Summary, error) {
	summary, err := a.loadSummary()
	if err != nil {
		return nil, err
	}
	summary.GeneratedAt = a.now()
	summary.ColdRoot = a.env.ColdRoot

	state, errState := a.loadState()
	if errState != nil {
		return nil, errState
	}
	coldAuths, errList := a.listColdAuths(ctx)
	if errList != nil {
		return nil, errList
	}
	pruneMissingStateEntries(state, coldAuths)

	now := a.now()
	poolSummary := PoolSummary{TotalFiles: len(coldAuths)}
	for _, authEntry := range coldAuths {
		entry := state.Files[baseName(authEntry.FileName)]
		if isEligibleNow(authEntry, entry, now) {
			poolSummary.EligibleNow++
		}
		if entry != nil && entry.NextRetryAfter.After(now) {
			switch entry.LastResult {
			case resultUsage429:
				poolSummary.Cooling429++
			default:
				poolSummary.CoolingTransient++
			}
		}
		if entry == nil || entry.LastCheckedAt.IsZero() {
			candidateTime := authEntry.UpdatedAt
			if candidateTime.IsZero() {
				candidateTime = authEntry.CreatedAt
			}
			updateOldestUnchecked(&poolSummary, candidateTime, now)
		}
	}
	poolSummary.External401Total, _ = countJSONFiles(a.env.External401Dir())
	summary.Pool = poolSummary
	summary.Rolling24h, _ = a.buildRolling24h(now)

	if mutate != nil {
		mutate(summary)
	}
	if persist {
		if errSaveState := a.saveState(state); errSaveState != nil {
			return nil, errSaveState
		}
		if errSaveSummary := a.saveSummary(summary); errSaveSummary != nil {
			return nil, errSaveSummary
		}
	}
	return summary, nil
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
			return nil, fmt.Errorf("reserve2 lock exists: %s", lockPath)
		}
	}
	return nil, fmt.Errorf("reserve2 failed to acquire lock: %s", lockPath)
}

func (a *App) clearStaleLock(lockPath string) (bool, error) {
	lockAt, err := readLockTime(lockPath)
	if err != nil {
		return false, err
	}
	if a.now().Sub(lockAt) <= lockStaleAfter {
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

func (a *App) listColdAuths(ctx context.Context) ([]*coreauth.Auth, error) {
	return a.listStoreAuths(ctx, a.coldStore)
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

func (a *App) selectColdCandidates(auths []*coreauth.Auth, state *StateFile, limit int) []*coreauth.Auth {
	if limit <= 0 {
		return nil
	}
	now := a.now()
	candidates := make([]coldCandidate, 0, len(auths))
	for _, authEntry := range auths {
		entry := state.Files[baseName(authEntry.FileName)]
		if !isEligibleNow(authEntry, entry, now) {
			continue
		}
		candidates = append(candidates, coldCandidate{
			auth:        authEntry,
			lastChecked: zeroTime(entry, func(s *FileState) time.Time { return s.LastCheckedAt }),
			lastRefresh: zeroTime(entry, func(s *FileState) time.Time { return s.LastRefreshAt }),
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].lastChecked.Equal(candidates[j].lastChecked) {
			return candidates[i].lastChecked.Before(candidates[j].lastChecked)
		}
		if !candidates[i].lastRefresh.Equal(candidates[j].lastRefresh) {
			return candidates[i].lastRefresh.Before(candidates[j].lastRefresh)
		}
		return strings.ToLower(baseName(candidates[i].auth.FileName)) < strings.ToLower(baseName(candidates[j].auth.FileName))
	})
	if len(candidates) == 0 {
		return nil
	}
	windowCount := a.env.SelectionWindowCount(limit)
	if windowCount > len(candidates) {
		windowCount = len(candidates)
	}
	frontier := append([]coldCandidate(nil), candidates[:windowCount]...)
	a.shuffleCandidates(frontier)
	if limit > len(frontier) {
		limit = len(frontier)
	}
	selected := make([]*coreauth.Auth, 0, limit)
	for i := 0; i < limit; i++ {
		selected = append(selected, frontier[i].auth)
	}
	return selected
}

func (a *App) shuffleCandidates(candidates []coldCandidate) {
	if len(candidates) <= 1 {
		return
	}
	if a == nil || a.rng == nil {
		return
	}
	a.rng.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
}

func (a *App) waitBetweenInspects(ctx context.Context, apply bool, index int) error {
	if !apply || index <= 0 || a == nil || a.env == nil {
		return nil
	}
	delay := a.nextSerialDelay()
	if delay <= 0 {
		return nil
	}
	if a.sleep == nil {
		return nil
	}
	return a.sleep(ctx, delay)
}

func (a *App) nextSerialDelay() time.Duration {
	if a == nil || a.env == nil {
		return 0
	}
	minDelay := a.env.SerialDelayMin
	maxDelay := a.env.SerialDelayMax
	if maxDelay <= minDelay {
		return minDelay
	}
	if a.rng == nil {
		return minDelay
	}
	span := maxDelay - minDelay
	if span <= 0 {
		return minDelay
	}
	return minDelay + time.Duration(a.rng.Int63n(int64(span)+1))
}

func (a *App) inspectAuth(ctx context.Context, authEntry *coreauth.Auth, allowRefresh bool) (*inspectResult, error) {
	current := authEntry.Clone()
	if current == nil {
		return nil, fmt.Errorf("reserve2 auth is nil")
	}
	resp, err := a.runUsageProbe(ctx, current.Clone())
	refreshed := false
	if allowRefresh && shouldRetryUsageAfterRefresh(resp, err) {
		updated, refreshErr := a.runRefreshAuth(ctx, current.Clone())
		if refreshErr != nil {
			return &inspectResult{
				auth:           current,
				refreshed:      false,
				classification: classifyErrorText(refreshErr.Error()),
				statusCode:     httpStatusFromText(refreshErr.Error()),
				message:        strings.TrimSpace(refreshErr.Error()),
			}, nil
		}
		current = mergeRecoveredAuth(current, updated)
		refreshed = true
		resp, err = a.runUsageProbe(ctx, current.Clone())
	}
	if err != nil {
		return &inspectResult{
			auth:           current,
			refreshed:      refreshed,
			classification: classifyErrorText(err.Error()),
			statusCode:     httpStatusFromText(err.Error()),
			message:        strings.TrimSpace(err.Error()),
		}, nil
	}
	if resp == nil {
		return &inspectResult{
			auth:           current,
			refreshed:      refreshed,
			classification: classificationTransient,
			statusCode:     0,
			message:        "empty usage response",
		}, nil
	}
	return &inspectResult{
		auth:           current,
		refreshed:      refreshed,
		classification: classifyHTTPResult(resp.StatusCode, resp.Body),
		statusCode:     resp.StatusCode,
		message:        reserveErrorMessage(resp.StatusCode, resp.Body),
	}, nil
}

func (a *App) runUsageProbe(ctx context.Context, authEntry *coreauth.Auth) (*usageProbeResponse, error) {
	if a != nil && a.usageProbeFunc != nil {
		return a.usageProbeFunc(ctx, authEntry)
	}
	return a.probeUsage(ctx, authEntry)
}

func (a *App) runRefreshAuth(ctx context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
	if a != nil && a.refreshAuthFunc != nil {
		return a.refreshAuthFunc(ctx, authEntry)
	}
	return a.refreshAuth(ctx, authEntry)
}

func (a *App) probeUsage(ctx context.Context, authEntry *coreauth.Auth) (*usageProbeResponse, error) {
	if authEntry == nil {
		return nil, fmt.Errorf("reserve2 probe auth is nil")
	}
	token := strings.TrimSpace(resolveAccessToken(authEntry))
	if token == "" {
		return nil, fmt.Errorf("codex access_token is missing")
	}
	accountID := strings.TrimSpace(resolveChatGPTAccountID(authEntry))
	if accountID == "" {
		return nil, fmt.Errorf("codex chatgpt account id is missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codexUsageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", codexUsageUserAgent)
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

func (a *App) refreshAuth(ctx context.Context, authEntry *coreauth.Auth) (*coreauth.Auth, error) {
	exec := runtimeexecutor.NewCodexExecutor(a.cfg)
	return exec.Refresh(ctx, authEntry)
}

func (a *App) saveColdAuth(authEntry *coreauth.Auth) error {
	if authEntry == nil {
		return fmt.Errorf("reserve2 save auth is nil")
	}
	authEntry.FileName = baseName(authEntry.FileName)
	if authEntry.Attributes == nil {
		authEntry.Attributes = map[string]string{}
	}
	authEntry.Attributes["path"] = filepath.Join(a.env.PoolDir(), authEntry.FileName)
	_, err := a.coldStore.Save(context.Background(), authEntry)
	return err
}

func (a *App) moveColdAuthToExternal401(authEntry *coreauth.Auth) (string, error) {
	sourcePath := filepath.Join(a.env.PoolDir(), baseName(authEntry.FileName))
	targetPath := filepath.Join(a.env.External401Dir(), baseName(authEntry.FileName))
	if _, err := os.Stat(targetPath); err == nil {
		targetPath = uniquePath(targetPath, a.now())
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return targetPath, moveFile(sourcePath, targetPath)
}

func (a *App) moveColdAuthToReserve1(authEntry *coreauth.Auth) (string, error) {
	sourcePath := filepath.Join(a.env.PoolDir(), baseName(authEntry.FileName))
	targetPath := filepath.Join(a.env.Reserve1Dir, baseName(authEntry.FileName))
	if _, err := os.Stat(targetPath); err == nil {
		return "", fmt.Errorf("target already exists: %s", targetPath)
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return "", err
	}
	return targetPath, moveFile(sourcePath, targetPath)
}

func (a *App) buildDuplicateIndex(ctx context.Context) (*duplicateIndex, error) {
	index := &duplicateIndex{
		names:         make(map[string]struct{}),
		accountIDs:    make(map[string]struct{}),
		refreshHashes: make(map[string]struct{}),
		emails:        make(map[string]struct{}),
	}
	for _, store := range []*auth.FileTokenStore{a.productionStore, a.reserve1Store} {
		auths, err := a.listStoreAuths(ctx, store)
		if err != nil {
			return nil, err
		}
		for _, authEntry := range auths {
			index.add(authEntry)
		}
	}
	return index, nil
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
			return "name_exists_in_target"
		}
	}
	if accountID := strings.ToLower(strings.TrimSpace(authAccountID(authEntry))); accountID != "" {
		if _, ok := index.accountIDs[accountID]; ok {
			return "account_id_exists_in_target"
		}
	}
	if hash := refreshTokenHash(authEntry); hash != "" {
		if _, ok := index.refreshHashes[hash]; ok {
			return "refresh_token_exists_in_target"
		}
	}
	if email := strings.ToLower(strings.TrimSpace(authEmail(authEntry))); email != "" {
		if _, ok := index.emails[email]; ok {
			return "email_exists_in_target"
		}
	}
	return ""
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

func (a *App) loadSummary() (*Summary, error) {
	path := a.env.SummaryPath()
	summary := &Summary{ColdRoot: a.env.ColdRoot}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return summary, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return summary, nil
	}
	if err := json.Unmarshal(raw, summary); err != nil {
		return nil, err
	}
	return summary, nil
}

func (a *App) saveSummary(summary *Summary) error {
	return writeJSONAtomic(a.env.SummaryPath(), summary)
}

func (a *App) appendEvents(events []eventRecord) error {
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

func (a *App) buildRolling24h(now time.Time) (Rolling24hSummary, error) {
	var summary Rolling24hSummary
	file, err := os.Open(a.env.EventsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return summary, nil
		}
		return summary, err
	}
	defer func() { _ = file.Close() }()

	cutoff := now.Add(-24 * time.Hour)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event eventRecord
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.At.Before(cutoff) {
			continue
		}
		switch event.Type {
		case resultHealthy200, resultRefreshRecovered, resultInvalidMoved, resultUsage429, resultProbeError:
			summary.Sampled++
		}
		switch event.Type {
		case resultHealthy200:
			summary.SampleOK++
		case resultRefreshRecovered:
			summary.SampleRefreshOK++
		case "promoted_to_reserve1":
			summary.PromotedToReserve1++
		case resultInvalidMoved:
			summary.InvalidMoved++
		case resultUsage429:
			summary.Usage429++
		case resultProbeError:
			summary.ProbeError++
		case resultDuplicate:
			summary.DuplicateSkipped++
		}
	}
	return summary, scanner.Err()
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

func updateStateEntryFromAuth(entry *FileState, authEntry *coreauth.Auth, refreshed bool, now time.Time, result string, statusCode int, nextRetryAfter time.Time) {
	if entry == nil {
		return
	}
	entry.LastCheckedAt = now
	entry.LastResult = result
	entry.LastHTTPStatus = statusCode
	entry.NextRetryAfter = nextRetryAfter
	entry.Email = authEmail(authEntry)
	entry.AccountID = authAccountID(authEntry)
	entry.RefreshTokenSHA = refreshTokenHash(authEntry)
	if refreshed {
		entry.LastRefreshAt = now
	}
}

func updateOldestUnchecked(summary *PoolSummary, checkedAt, now time.Time) {
	if summary == nil || checkedAt.IsZero() {
		return
	}
	if summary.OldestUncheckedAt.IsZero() || checkedAt.Before(summary.OldestUncheckedAt) {
		summary.OldestUncheckedAt = checkedAt
		summary.OldestUncheckedAgeSecond = int64(now.Sub(checkedAt).Seconds())
	}
}

func countAvailable(auths []*coreauth.Auth) int {
	count := 0
	for _, authEntry := range auths {
		if authEntry == nil || authEntry.Disabled || authEntry.Status == coreauth.StatusDisabled {
			continue
		}
		if authEntry.Status == coreauth.StatusActive && !authEntry.Unavailable {
			count++
		}
	}
	return count
}

func isEligibleNow(authEntry *coreauth.Auth, state *FileState, now time.Time) bool {
	if authEntry == nil || authEntry.Disabled || authEntry.Status == coreauth.StatusDisabled {
		return false
	}
	if authEntry.Unavailable && authEntry.NextRetryAfter.After(now) {
		return false
	}
	if state != nil && state.NextRetryAfter.After(now) {
		return false
	}
	return true
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

func resultForSuccess(refreshed bool) string {
	if refreshed {
		return resultRefreshRecovered
	}
	return resultHealthy200
}

func eventTypeForSuccess(refreshed bool) string {
	if refreshed {
		return resultRefreshRecovered
	}
	return resultHealthy200
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

func selectedNames(auths []*coreauth.Auth) []string {
	names := make([]string, 0, len(auths))
	for _, authEntry := range auths {
		names = append(names, baseName(authEntry.FileName))
	}
	return names
}

func modeLabel(apply bool) string {
	if apply {
		return "apply"
	}
	return "preview"
}

func zeroTime(entry *FileState, getter func(*FileState) time.Time) time.Time {
	if entry == nil {
		return time.Time{}
	}
	return getter(entry)
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

func refreshTokenHash(authEntry *coreauth.Auth) string {
	if authEntry == nil || authEntry.Metadata == nil {
		return ""
	}
	value, _ := authEntry.Metadata["refresh_token"].(string)
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
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
		"status 401",
		"status: 401",
		"\"status\":401",
		"\"status\": 401",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return status401Pattern.MatchString(lower)
}

func shouldRetryUsageAfterRefresh(resp *usageProbeResponse, err error) bool {
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
	return strings.Contains(lower, "access_token is missing")
}

func reserveErrorMessage(statusCode int, body string) string {
	text := strings.TrimSpace(body)
	if text != "" {
		return text
	}
	if statusCode > 0 {
		return fmt.Sprintf("reserve2 request failed with status %d", statusCode)
	}
	return "reserve2 request failed"
}

func trimReason(text string) string {
	text = strings.TrimSpace(text)
	if len(text) <= 800 {
		return text
	}
	return text[:800]
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

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func readLockTime(lockPath string) (time.Time, error) {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return time.Time{}, err
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		var record lockRecord
		if err := json.Unmarshal(raw, &record); err == nil && !record.At.IsZero() {
			return record.At, nil
		}
	}
	info, err := os.Stat(lockPath)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}
