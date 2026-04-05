package reservepool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

const (
	reserveDirName                  = "reserve-pool"
	deletedAuthBackupDirName        = "deleted-auth-backup"
	external401DirName              = "external-401"
	eventLogFileName                = "events.jsonl"
	defaultKeepAliveInterval        = 30 * time.Minute
	defaultKeepAliveCoverageDivisor = 48
	defaultKeepAliveRoundBudget     = 5 * time.Minute
	defaultReplenishInterval        = time.Minute
	defaultOperationTimeout         = 60 * time.Second
	defaultTransientErrorBackoff    = 30 * time.Minute
	defaultAnomaly429Backoff        = 24 * time.Hour
	codexUsageURL                   = "https://chatgpt.com/backend-api/wham/usage"
	codexUsageUserAgent             = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
)

var status401Pattern = regexp.MustCompile(`(^|[^0-9])401([^0-9]|$)`)

type usageProbeResponse struct {
	StatusCode int
	Body       string
}

// UsageResult describes a reserve usage refresh result for one auth file.
type UsageResult struct {
	Name       string `json:"name"`
	StatusCode int    `json:"status_code,omitempty"`
	Body       string `json:"body,omitempty"`
	Removed    bool   `json:"removed,omitempty"`
	Error      string `json:"error,omitempty"`
}

type usageProbeFunc func(context.Context, *config.Config, *coreauth.Auth) (*usageProbeResponse, error)
type refreshAuthFunc func(context.Context, *config.Config, *coreauth.Auth) (*coreauth.Auth, error)

// Option customizes reserve pool manager behavior.
type Option func(*Manager)

// WithUsageProbe overrides the default Codex usage probe implementation.
func WithUsageProbe(fn usageProbeFunc) Option {
	return func(m *Manager) {
		if fn != nil {
			m.probeUsage = fn
		}
	}
}

// WithRefreshAuth overrides the default Codex keepalive refresh implementation.
func WithRefreshAuth(fn refreshAuthFunc) Option {
	return func(m *Manager) {
		if fn != nil {
			m.refreshAuth = fn
		}
	}
}

// WithNow overrides the manager clock, mainly for tests.
func WithNow(fn func() time.Time) Option {
	return func(m *Manager) {
		if fn != nil {
			m.now = fn
		}
	}
}

// Manager maintains the isolated reserve Codex auth pool.
type Manager struct {
	mu          sync.RWMutex
	cfg         *config.Config
	authManager *coreauth.Manager

	store *sdkauth.FileTokenStore

	reserveDir     string
	external401Dir string
	eventLogPath   string

	now         func() time.Time
	probeUsage  usageProbeFunc
	refreshAuth refreshAuthFunc

	startOnce sync.Once
	stopMu    sync.Mutex
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	eventMu sync.Mutex

	authLocksMu sync.Mutex
	authLocks   map[string]*sync.Mutex
}

// NewManager creates a reserve pool manager.
func NewManager(cfg *config.Config, authManager *coreauth.Manager, opts ...Option) *Manager {
	m := &Manager{
		cfg:         cfg,
		authManager: authManager,
		store:       sdkauth.NewFileTokenStore(),
		now:         time.Now,
		probeUsage:  defaultUsageProbe,
		refreshAuth: defaultRefreshAuth,
		authLocks:   make(map[string]*sync.Mutex),
	}
	for _, opt := range opts {
		opt(m)
	}
	m.recomputePathsLocked()
	return m
}

// Start launches the background keepalive and replenish loops.
func (m *Manager) Start() {
	if m == nil {
		return
	}
	m.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		m.stopMu.Lock()
		m.cancel = cancel
		m.stopMu.Unlock()

		if err := m.ensureDirectories(); err != nil {
			log.WithError(err).Warn("reserve pool: ensure directories failed")
		}

		m.wg.Add(2)
		go m.runKeepAliveLoop(ctx)
		go m.runReplenishLoop(ctx)
	})
}

// Stop terminates the background loop and waits for it to finish.
func (m *Manager) Stop(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.stopMu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.stopMu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.wg.Wait()
	}()

	if ctx == nil {
		<-done
		return nil
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// UpdateConfig swaps the current config/auth-manager snapshot used by background work.
func (m *Manager) UpdateConfig(cfg *config.Config, authManager *coreauth.Manager) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	m.authManager = authManager
	m.recomputePathsLocked()
}

// List returns the reserve Codex auth files currently on disk.
func (m *Manager) List(ctx context.Context) ([]*coreauth.Auth, error) {
	if m == nil {
		return nil, nil
	}
	_, reserveDir, _, _ := m.pathsSnapshot()
	if reserveDir == "" {
		return []*coreauth.Auth{}, nil
	}
	if _, err := os.Stat(reserveDir); err != nil {
		if os.IsNotExist(err) {
			return []*coreauth.Auth{}, nil
		}
		return nil, err
	}
	auths, err := m.store.List(ctx)
	if err != nil {
		if os.IsNotExist(err) {
			return []*coreauth.Auth{}, nil
		}
		return nil, err
	}
	filtered := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
			continue
		}
		auth.FileName = filepath.Base(strings.TrimSpace(auth.FileName))
		filtered = append(filtered, auth)
	}
	sort.Slice(filtered, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(filtered[i].FileName))
		right := strings.ToLower(strings.TrimSpace(filtered[j].FileName))
		if left == right {
			return filtered[i].UpdatedAt.Before(filtered[j].UpdatedAt)
		}
		return left < right
	})
	return filtered, nil
}

// Upload validates and writes one reserve auth JSON file.
func (m *Manager) Upload(name string, data []byte) error {
	if m == nil {
		return fmt.Errorf("reserve pool manager not initialized")
	}
	baseName := filepath.Base(strings.TrimSpace(name))
	if baseName == "" || baseName != strings.TrimSpace(name) {
		return fmt.Errorf("invalid file name")
	}
	if !strings.HasSuffix(strings.ToLower(baseName), ".json") {
		return fmt.Errorf("file must end with .json")
	}
	if err := validateReserveAuthPayload(data); err != nil {
		return err
	}
	unlock := m.lockAuth(baseName)
	defer unlock()
	if err := m.ensureDirectories(); err != nil {
		return err
	}
	_, reserveDir, _, _ := m.pathsSnapshot()
	targetPath := filepath.Join(reserveDir, baseName)
	return os.WriteFile(targetPath, data, 0o600)
}

// Download reads one reserve auth JSON file.
func (m *Manager) Download(name string) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("reserve pool manager not initialized")
	}
	baseName := filepath.Base(strings.TrimSpace(name))
	if baseName == "" || baseName != strings.TrimSpace(name) {
		return nil, fmt.Errorf("invalid file name")
	}
	_, reserveDir, _, _ := m.pathsSnapshot()
	if reserveDir == "" {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(filepath.Join(reserveDir, baseName))
}

// RefreshUsage runs a Codex usage probe for the selected reserve auth files.
func (m *Manager) RefreshUsage(ctx context.Context, names []string) ([]UsageResult, error) {
	if m == nil {
		return nil, fmt.Errorf("reserve pool manager not initialized")
	}
	cfg, _, _, _ := m.pathsSnapshot()
	_, order, err := m.authsForNames(ctx, names)
	if err != nil {
		return nil, err
	}

	results := make([]UsageResult, 0, len(order))
	for _, name := range order {
		unlock := m.lockAuth(name)
		currentAuth, loadErr := m.loadAuthByName(name)
		if loadErr != nil {
			unlock()
			results = append(results, UsageResult{Name: name, Error: "file not found"})
			continue
		}

		opCtx, cancel := m.operationContext(ctx)
		currentAuth, resp, refreshed, probeErr := m.probeUsageWithRefreshRetry(opCtx, cfg, currentAuth)
		cancel()
		if probeErr != nil {
			errText := strings.TrimSpace(probeErr.Error())
			switch classifyErrorText(errText) {
			case classificationInvalid401:
				if _, err = m.moveToExternal401(currentAuth, "manual_refresh", http.StatusUnauthorized, errText); err != nil {
					log.WithError(err).Warnf("reserve pool: move invalid auth %s failed", name)
					results = append(results, UsageResult{Name: name, Error: errText})
					unlock()
					continue
				}
				results = append(results, UsageResult{Name: name, Error: errText, Removed: true})
			case classificationAnomaly429:
				if saveErr := m.markTransient(currentAuth, http.StatusTooManyRequests, errText, defaultAnomaly429Backoff); saveErr != nil {
					log.WithError(saveErr).Warnf("reserve pool: persist 429 state for %s failed", name)
				}
				m.appendEvent("usage_429", map[string]any{
					"name":        name,
					"source":      "manual_refresh",
					"status_code": http.StatusTooManyRequests,
					"message":     trimForEvent(errText),
				})
				results = append(results, UsageResult{Name: name, StatusCode: http.StatusTooManyRequests, Error: errText})
			default:
				if saveErr := m.markTransient(currentAuth, 0, errText, defaultTransientErrorBackoff); saveErr != nil {
					log.WithError(saveErr).Warnf("reserve pool: persist usage error state for %s failed", name)
				}
				m.appendEvent("usage_error", map[string]any{
					"name":    name,
					"source":  "manual_refresh",
					"message": trimForEvent(errText),
				})
				results = append(results, UsageResult{Name: name, Error: errText})
			}
			unlock()
			continue
		}

		if resp == nil {
			unlock()
			results = append(results, UsageResult{Name: name, Error: "empty usage response"})
			continue
		}

		switch classifyHTTPResult(resp.StatusCode, resp.Body) {
		case classificationSuccess:
			if err = m.markActive(currentAuth, refreshed); err != nil {
				log.WithError(err).Warnf("reserve pool: persist active state for %s failed", name)
			}
			results = append(results, UsageResult{Name: name, StatusCode: resp.StatusCode, Body: resp.Body})
		case classificationInvalid401:
			if _, err = m.moveToExternal401(currentAuth, "manual_refresh", resp.StatusCode, resp.Body); err != nil {
				log.WithError(err).Warnf("reserve pool: move invalid auth %s failed", name)
				results = append(results, UsageResult{Name: name, StatusCode: resp.StatusCode, Body: resp.Body, Error: err.Error()})
				unlock()
				continue
			}
			results = append(results, UsageResult{Name: name, StatusCode: resp.StatusCode, Body: resp.Body, Removed: true})
		case classificationAnomaly429:
			if err = m.markTransient(currentAuth, resp.StatusCode, reserveErrorMessage(resp.StatusCode, resp.Body), defaultAnomaly429Backoff); err != nil {
				log.WithError(err).Warnf("reserve pool: persist 429 state for %s failed", name)
			}
			m.appendEvent("usage_429", map[string]any{
				"name":        name,
				"source":      "manual_refresh",
				"status_code": resp.StatusCode,
				"message":     trimForEvent(resp.Body),
			})
			results = append(results, UsageResult{Name: name, StatusCode: resp.StatusCode, Body: resp.Body})
		default:
			if err = m.markTransient(currentAuth, resp.StatusCode, reserveErrorMessage(resp.StatusCode, resp.Body), defaultTransientErrorBackoff); err != nil {
				log.WithError(err).Warnf("reserve pool: persist transient usage state for %s failed", name)
			}
			m.appendEvent("usage_error", map[string]any{
				"name":        name,
				"source":      "manual_refresh",
				"status_code": resp.StatusCode,
				"message":     trimForEvent(resp.Body),
			})
			results = append(results, UsageResult{Name: name, StatusCode: resp.StatusCode, Body: resp.Body})
		}
		unlock()
	}

	return results, nil
}

func (m *Manager) runKeepAliveLoop(ctx context.Context) {
	defer m.wg.Done()

	keepaliveTicker := time.NewTicker(defaultKeepAliveInterval)
	defer keepaliveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepaliveTicker.C:
			m.runKeepAlive(ctx)
		}
	}
}

func (m *Manager) runReplenishLoop(ctx context.Context) {
	defer m.wg.Done()

	m.runReplenishRound(ctx)

	replenishTicker := time.NewTicker(defaultReplenishInterval)
	defer replenishTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-replenishTicker.C:
			m.runReplenishRound(ctx)
		}
	}
}

func (m *Manager) runKeepAlive(ctx context.Context) {
	cfg, _, _, _ := m.pathsSnapshot()
	auths, err := m.List(ctx)
	if err != nil {
		log.WithError(err).Warn("reserve pool: keepalive list failed")
		return
	}
	candidates := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if auth == nil || auth.Disabled || m.shouldSkipKeepAlive(auth) {
			continue
		}
		candidates = append(candidates, auth)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].UpdatedAt.Equal(candidates[j].UpdatedAt) {
			return strings.ToLower(candidates[i].FileName) < strings.ToLower(candidates[j].FileName)
		}
		return candidates[i].UpdatedAt.Before(candidates[j].UpdatedAt)
	})

	limit := keepAliveBatchSize(len(candidates))
	if limit > len(candidates) {
		limit = len(candidates)
	}

	roundStartedAt := m.now().UTC()
	for i := 0; i < limit; i++ {
		if i > 0 && defaultKeepAliveRoundBudget > 0 && !m.now().UTC().Before(roundStartedAt.Add(defaultKeepAliveRoundBudget)) {
			break
		}
		name := filepath.Base(strings.TrimSpace(candidates[i].FileName))
		unlock := m.lockAuth(name)
		currentAuth, loadErr := m.loadAuthByName(name)
		if loadErr != nil {
			unlock()
			if !os.IsNotExist(loadErr) {
				log.WithError(loadErr).Warnf("reserve pool: load keepalive auth %s failed", name)
			}
			continue
		}
		if currentAuth == nil || currentAuth.Disabled || m.shouldSkipKeepAlive(currentAuth) {
			unlock()
			continue
		}

		opCtx, cancel := m.operationContext(ctx)
		updated, refreshErr := m.refreshAuth(opCtx, cfg, currentAuth.Clone())
		cancel()

		if refreshErr != nil {
			message := strings.TrimSpace(refreshErr.Error())
			if classifyErrorText(message) == classificationInvalid401 {
				if _, err = m.moveToExternal401(currentAuth, "keepalive_refresh", http.StatusUnauthorized, message); err != nil {
					log.WithError(err).Warnf("reserve pool: move keepalive-invalid auth %s failed", name)
				}
				unlock()
				continue
			}
			backoff := defaultTransientErrorBackoff
			eventType := "keepalive_error"
			statusCode := 0
			if classifyErrorText(message) == classificationAnomaly429 {
				backoff = defaultAnomaly429Backoff
				eventType = "refresh_429"
				statusCode = http.StatusTooManyRequests
			}
			if err = m.markTransient(currentAuth, statusCode, message, backoff); err != nil {
				log.WithError(err).Warnf("reserve pool: persist keepalive error for %s failed", name)
			}
			m.appendEvent(eventType, map[string]any{
				"name":        name,
				"source":      "keepalive_refresh",
				"status_code": statusCode,
				"message":     trimForEvent(message),
			})
			unlock()
			continue
		}

		updated = mergeRecoveredAuth(currentAuth, updated)
		if err = m.markActive(updated, true); err != nil {
			log.WithError(err).Warnf("reserve pool: persist keepalive success for %s failed", name)
		}
		unlock()
	}
}

func (m *Manager) runReplenishRound(ctx context.Context) {
	m.mu.RLock()
	cfg := m.cfg
	authManager := m.authManager
	m.mu.RUnlock()
	authDir := m.productionAuthDir()
	if cfg == nil || authManager == nil || authDir == "" {
		return
	}
	threshold := cfg.ReservePool.ProductionAvailableThreshold
	batchSize := cfg.ReservePool.ReplenishBatchSize
	if threshold <= 0 || batchSize <= 0 {
		return
	}

	currentAvailable := countProductionAvailable(authManager)
	if currentAvailable >= threshold {
		return
	}

	auths, err := m.List(ctx)
	if err != nil {
		log.WithError(err).Warn("reserve pool: replenish list failed")
		return
	}

	sort.Slice(auths, func(i, j int) bool {
		if auths[i].UpdatedAt.Equal(auths[j].UpdatedAt) {
			return strings.ToLower(auths[i].FileName) < strings.ToLower(auths[j].FileName)
		}
		return auths[i].UpdatedAt.Before(auths[j].UpdatedAt)
	})

	promoted := 0
	for _, auth := range auths {
		if auth == nil || promoted >= batchSize {
			break
		}
		name := filepath.Base(strings.TrimSpace(auth.FileName))
		unlock := m.lockAuth(name)
		currentAuth, loadErr := m.loadAuthByName(name)
		if loadErr != nil {
			unlock()
			if !os.IsNotExist(loadErr) {
				log.WithError(loadErr).Warnf("reserve pool: load replenish auth %s failed", name)
			}
			continue
		}
		if currentAuth == nil || currentAuth.Disabled || currentAuth.Unavailable || currentAuth.Status != coreauth.StatusActive {
			unlock()
			continue
		}
		if cfg.ReservePool.ValidateUsageBeforePromotion {
			opCtx, cancel := m.operationContext(ctx)
			currentAuth, resp, refreshed, probeErr := m.probeUsageWithRefreshRetry(opCtx, cfg, currentAuth)
			cancel()
			if probeErr != nil {
				message := strings.TrimSpace(probeErr.Error())
				switch classifyErrorText(message) {
				case classificationInvalid401:
					if _, err = m.moveToExternal401(currentAuth, "auto_replenish", http.StatusUnauthorized, message); err != nil {
						log.WithError(err).Warnf("reserve pool: move auto-replenish invalid auth %s failed", name)
					}
				case classificationAnomaly429:
					if err = m.markTransient(currentAuth, http.StatusTooManyRequests, message, defaultAnomaly429Backoff); err != nil {
						log.WithError(err).Warnf("reserve pool: persist 429 state for %s failed", name)
					}
					m.appendEvent("usage_429", map[string]any{
						"name":        name,
						"source":      "auto_replenish",
						"status_code": http.StatusTooManyRequests,
						"message":     trimForEvent(message),
					})
				default:
					if err = m.markTransient(currentAuth, 0, message, defaultTransientErrorBackoff); err != nil {
						log.WithError(err).Warnf("reserve pool: persist replenish usage error for %s failed", name)
					}
					m.appendEvent("usage_error", map[string]any{
						"name":    name,
						"source":  "auto_replenish",
						"message": trimForEvent(message),
					})
				}
				unlock()
				continue
			}
			if resp == nil {
				unlock()
				continue
			}
			switch classifyHTTPResult(resp.StatusCode, resp.Body) {
			case classificationSuccess:
				if err = m.markActive(currentAuth, refreshed); err != nil {
					log.WithError(err).Warnf("reserve pool: persist active state for %s failed", name)
					unlock()
					continue
				}
			case classificationInvalid401:
				if _, err = m.moveToExternal401(currentAuth, "auto_replenish", resp.StatusCode, resp.Body); err != nil {
					log.WithError(err).Warnf("reserve pool: move auto-replenish invalid auth %s failed", name)
				}
				unlock()
				continue
			case classificationAnomaly429:
				if err = m.markTransient(currentAuth, resp.StatusCode, reserveErrorMessage(resp.StatusCode, resp.Body), defaultAnomaly429Backoff); err != nil {
					log.WithError(err).Warnf("reserve pool: persist 429 state for %s failed", name)
				}
				m.appendEvent("usage_429", map[string]any{
					"name":        name,
					"source":      "auto_replenish",
					"status_code": resp.StatusCode,
					"message":     trimForEvent(resp.Body),
				})
				unlock()
				continue
			default:
				if err = m.markTransient(currentAuth, resp.StatusCode, reserveErrorMessage(resp.StatusCode, resp.Body), defaultTransientErrorBackoff); err != nil {
					log.WithError(err).Warnf("reserve pool: persist auto-replenish transient state for %s failed", name)
				}
				m.appendEvent("usage_error", map[string]any{
					"name":        name,
					"source":      "auto_replenish",
					"status_code": resp.StatusCode,
					"message":     trimForEvent(resp.Body),
				})
				unlock()
				continue
			}
		} else {
			opCtx, cancel := m.operationContext(ctx)
			updated, refreshErr := m.refreshAuth(opCtx, cfg, currentAuth.Clone())
			cancel()
			if refreshErr != nil {
				message := strings.TrimSpace(refreshErr.Error())
				switch classifyErrorText(message) {
				case classificationInvalid401:
					if _, err = m.moveToExternal401(currentAuth, "auto_replenish", http.StatusUnauthorized, message); err != nil {
						log.WithError(err).Warnf("reserve pool: move auto-replenish invalid auth %s failed", name)
					}
				case classificationAnomaly429:
					if err = m.markTransient(currentAuth, http.StatusTooManyRequests, message, defaultAnomaly429Backoff); err != nil {
						log.WithError(err).Warnf("reserve pool: persist auto-replenish 429 state for %s failed", name)
					}
					m.appendEvent("refresh_429", map[string]any{
						"name":        name,
						"source":      "auto_replenish",
						"status_code": http.StatusTooManyRequests,
						"message":     trimForEvent(message),
					})
				default:
					if err = m.markTransient(currentAuth, 0, message, defaultTransientErrorBackoff); err != nil {
						log.WithError(err).Warnf("reserve pool: persist auto-replenish refresh error for %s failed", name)
					}
					m.appendEvent("replenish_refresh_error", map[string]any{
						"name":    name,
						"source":  "auto_replenish",
						"message": trimForEvent(message),
					})
				}
				unlock()
				continue
			}
			currentAuth = mergeRecoveredAuth(currentAuth, updated)
			if err = m.markActive(currentAuth, true); err != nil {
				log.WithError(err).Warnf("reserve pool: persist refreshed auth state for %s failed", name)
				unlock()
				continue
			}
		}

		if _, err = m.promoteToProduction(currentAuth); err != nil {
			log.WithError(err).Warnf("reserve pool: promote auth %s failed", name)
			unlock()
			continue
		}
		promoted++
		unlock()
	}
}

func (m *Manager) probeUsageWithRefreshRetry(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*coreauth.Auth, *usageProbeResponse, bool, error) {
	currentAuth := auth.Clone()
	if currentAuth == nil {
		return nil, nil, false, fmt.Errorf("reserve auth is nil")
	}

	resp, probeErr := m.probeUsage(ctx, cfg, currentAuth.Clone())
	if !shouldRetryUsageAfterRefresh(resp, probeErr) {
		return currentAuth, resp, false, probeErr
	}

	updated, refreshErr := m.refreshAuth(ctx, cfg, currentAuth.Clone())
	if refreshErr != nil {
		return currentAuth, nil, false, refreshErr
	}
	currentAuth = mergeRecoveredAuth(currentAuth, updated)

	resp, probeErr = m.probeUsage(ctx, cfg, currentAuth.Clone())
	return currentAuth, resp, true, probeErr
}

func (m *Manager) authsForNames(ctx context.Context, names []string) (map[string]*coreauth.Auth, []string, error) {
	auths, err := m.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	byName := make(map[string]*coreauth.Auth, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		name := filepath.Base(strings.TrimSpace(auth.FileName))
		if name == "" {
			continue
		}
		auth.FileName = name
		byName[name] = auth
	}
	order := make([]string, 0)
	if len(names) == 0 {
		for name := range byName {
			order = append(order, name)
		}
		sort.Strings(order)
		return byName, order, nil
	}
	seen := make(map[string]struct{}, len(names))
	for _, rawName := range names {
		name := filepath.Base(strings.TrimSpace(rawName))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		order = append(order, name)
	}
	return byName, order, nil
}

func (m *Manager) shouldSkipKeepAlive(auth *coreauth.Auth) bool {
	if auth == nil {
		return true
	}
	now := m.now().UTC()
	return auth.Unavailable && auth.NextRetryAfter.After(now)
}

func (m *Manager) lockAuth(name string) func() {
	key := filepath.Base(strings.TrimSpace(name))
	if key == "" {
		return func() {}
	}
	m.authLocksMu.Lock()
	lock := m.authLocks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		m.authLocks[key] = lock
	}
	m.authLocksMu.Unlock()
	lock.Lock()
	return func() {
		lock.Unlock()
	}
}

func (m *Manager) markActive(auth *coreauth.Auth, updateLastRefresh bool) error {
	if auth == nil {
		return nil
	}
	now := m.now().UTC()
	auth.Disabled = false
	auth.Status = coreauth.StatusActive
	auth.Unavailable = false
	auth.StatusMessage = ""
	auth.LastError = nil
	auth.Quota = coreauth.QuotaState{}
	auth.NextRetryAfter = time.Time{}
	auth.NextRefreshAfter = time.Time{}
	auth.UpdatedAt = now
	if updateLastRefresh {
		auth.LastRefreshedAt = now
	}
	_, err := m.store.Save(context.Background(), auth)
	return err
}

func (m *Manager) markTransient(auth *coreauth.Auth, statusCode int, message string, backoff time.Duration) error {
	if auth == nil {
		return nil
	}
	now := m.now().UTC()
	msg := strings.TrimSpace(message)
	if msg == "" {
		msg = "reserve auth unavailable"
	}
	auth.Status = coreauth.StatusError
	auth.Unavailable = true
	auth.StatusMessage = msg
	auth.LastError = &coreauth.Error{
		Message:    msg,
		Retryable:  true,
		HTTPStatus: statusCode,
	}
	auth.Quota = coreauth.QuotaState{}
	auth.UpdatedAt = now
	auth.NextRefreshAfter = time.Time{}
	auth.NextRetryAfter = time.Time{}
	if backoff > 0 {
		auth.NextRetryAfter = now.Add(backoff)
	}
	_, err := m.store.Save(context.Background(), auth)
	return err
}

func (m *Manager) promoteToProduction(auth *coreauth.Auth) (string, error) {
	sourcePath := authPath(auth)
	if sourcePath == "" {
		return "", fmt.Errorf("reserve auth path is empty")
	}
	authDir := m.productionAuthDir()
	if authDir == "" {
		return "", fmt.Errorf("production auth dir is not configured")
	}
	targetPath := filepath.Join(authDir, filepath.Base(strings.TrimSpace(auth.FileName)))
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(targetPath); err == nil {
		if removeErr := os.Remove(targetPath); removeErr != nil {
			return "", removeErr
		}
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := moveFile(sourcePath, targetPath); err != nil {
		return "", err
	}
	m.appendEvent("promoted", map[string]any{
		"name":        filepath.Base(strings.TrimSpace(auth.FileName)),
		"source_path": sourcePath,
		"target_path": targetPath,
	})
	return targetPath, nil
}

func (m *Manager) moveToExternal401(auth *coreauth.Auth, source string, statusCode int, message string) (string, error) {
	sourcePath := authPath(auth)
	if sourcePath == "" {
		return "", fmt.Errorf("reserve auth path is empty")
	}
	if err := m.ensureDirectories(); err != nil {
		return "", err
	}
	_, _, external401Dir, _ := m.pathsSnapshot()
	targetPath := filepath.Join(external401Dir, filepath.Base(sourcePath))
	if _, err := os.Stat(targetPath); err == nil {
		targetPath = uniquePath(targetPath, m.now().UTC())
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := moveFile(sourcePath, targetPath); err != nil {
		return "", err
	}
	m.appendEvent("invalid_moved", map[string]any{
		"name":        filepath.Base(strings.TrimSpace(auth.FileName)),
		"source":      source,
		"status_code": statusCode,
		"message":     trimForEvent(message),
		"source_path": sourcePath,
		"target_path": targetPath,
	})
	return targetPath, nil
}

func (m *Manager) ensureDirectories() error {
	_, reserveDir, external401Dir, _ := m.pathsSnapshot()
	for _, dir := range []string{reserveDir, external401Dir} {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, defaultOperationTimeout)
}

func (m *Manager) recomputePathsLocked() {
	authDir := ""
	if m.cfg != nil {
		if resolved, err := util.ResolveAuthDir(m.cfg.AuthDir); err == nil {
			authDir = resolved
		} else {
			log.WithError(err).Warnf("reserve pool: resolve auth-dir %q failed", m.cfg.AuthDir)
			authDir = filepath.Clean(strings.TrimSpace(m.cfg.AuthDir))
		}
	}
	if authDir == "" {
		m.reserveDir = ""
		m.external401Dir = ""
		m.eventLogPath = ""
		m.store.SetBaseDir("")
		return
	}
	m.reserveDir = filepath.Join(authDir, reserveDirName)
	m.external401Dir = filepath.Join(authDir, deletedAuthBackupDirName, external401DirName)
	m.eventLogPath = filepath.Join(m.reserveDir, eventLogFileName)
	m.store.SetBaseDir(m.reserveDir)
}

func (m *Manager) pathsSnapshot() (*config.Config, string, string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg, m.reserveDir, m.external401Dir, m.eventLogPath
}

func (m *Manager) productionAuthDir() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return ""
	}
	resolved, err := util.ResolveAuthDir(m.cfg.AuthDir)
	if err != nil {
		return filepath.Clean(strings.TrimSpace(m.cfg.AuthDir))
	}
	return resolved
}

func (m *Manager) appendEvent(eventType string, fields map[string]any) {
	if m == nil {
		return
	}
	_, _, _, eventLogPath := m.pathsSnapshot()
	if eventLogPath == "" {
		return
	}
	entry := map[string]any{
		"at":   m.now().UTC().Format(time.RFC3339Nano),
		"type": eventType,
	}
	for key, value := range fields {
		if value == nil {
			continue
		}
		entry[key] = value
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		log.WithError(err).Warnf("reserve pool: marshal event %s failed", eventType)
		return
	}

	m.eventMu.Lock()
	defer m.eventMu.Unlock()

	if err = os.MkdirAll(filepath.Dir(eventLogPath), 0o700); err != nil {
		log.WithError(err).Warn("reserve pool: create event log directory failed")
		return
	}
	file, err := os.OpenFile(eventLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.WithError(err).Warn("reserve pool: open event log failed")
		return
	}
	defer func() {
		_ = file.Close()
	}()
	if _, err = file.Write(append(raw, '\n')); err != nil {
		log.WithError(err).Warn("reserve pool: append event log failed")
	}
}

type httpClassification int

const (
	classificationTransient httpClassification = iota
	classificationSuccess
	classificationInvalid401
	classificationAnomaly429
)

func classifyHTTPResult(statusCode int, body string) httpClassification {
	switch {
	case statusCode == http.StatusOK:
		return classificationSuccess
	case statusCode == http.StatusTooManyRequests:
		return classificationAnomaly429
	case statusCode == http.StatusUnauthorized || has401Signal(body):
		return classificationInvalid401
	default:
		return classificationTransient
	}
}

func classifyErrorText(text string) httpClassification {
	lower := strings.ToLower(strings.TrimSpace(text))
	switch {
	case lower == "":
		return classificationTransient
	case strings.Contains(lower, "429"):
		return classificationAnomaly429
	case has401Signal(lower):
		return classificationInvalid401
	default:
		return classificationTransient
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

func reserveErrorMessage(statusCode int, body string) string {
	text := strings.TrimSpace(body)
	if text != "" {
		return text
	}
	if statusCode > 0 {
		return fmt.Sprintf("reserve auth request failed with status %d", statusCode)
	}
	return "reserve auth request failed"
}

func trimForEvent(text string) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) <= 800 {
		return trimmed
	}
	return trimmed[:800]
}

func validateReserveAuthPayload(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("auth file is empty")
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("invalid json payload: %w", err)
	}
	provider, _ := payload["type"].(string)
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return fmt.Errorf("reserve pool only accepts codex auth files")
	}
	if stringValue(payload["refresh_token"]) == "" {
		return fmt.Errorf("reserve auth missing refresh_token")
	}
	return nil
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func moveFile(sourcePath, targetPath string) error {
	if err := os.Rename(sourcePath, targetPath); err == nil {
		return nil
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer func() {
		_ = sourceFile.Close()
	}()

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

func authPath(auth *coreauth.Auth) string {
	if auth == nil || auth.Attributes == nil {
		return ""
	}
	return strings.TrimSpace(auth.Attributes["path"])
}

func keepAliveBatchSize(total int) int {
	if total <= 0 {
		return 0
	}
	size := (total + defaultKeepAliveCoverageDivisor - 1) / defaultKeepAliveCoverageDivisor
	if size < 1 {
		return 1
	}
	return size
}

func (m *Manager) loadAuthByName(name string) (*coreauth.Auth, error) {
	baseName := filepath.Base(strings.TrimSpace(name))
	if baseName == "" || baseName != strings.TrimSpace(name) {
		return nil, fmt.Errorf("invalid file name")
	}
	_, reserveDir, _, _ := m.pathsSnapshot()
	if reserveDir == "" {
		return nil, os.ErrNotExist
	}
	path := filepath.Join(reserveDir, baseName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("reserve auth file is empty")
	}

	metadata := make(map[string]any)
	if err = json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("invalid reserve auth json: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	provider := stringValue(metadata["type"])
	if provider == "" {
		provider = "unknown"
	}
	disabled, _ := metadata["disabled"].(bool)
	status := coreauth.StatusActive
	if disabled {
		status = coreauth.StatusDisabled
	}
	auth := &coreauth.Auth{
		ID:               baseName,
		Provider:         provider,
		FileName:         baseName,
		Label:            reserveAuthLabel(metadata),
		Status:           status,
		Disabled:         disabled,
		Attributes:       map[string]string{"path": path},
		Metadata:         metadata,
		CreatedAt:        info.ModTime(),
		UpdatedAt:        info.ModTime(),
		LastRefreshedAt:  time.Time{},
		NextRefreshAfter: time.Time{},
	}
	if email := stringValue(metadata["email"]); email != "" {
		auth.Attributes["email"] = email
	}
	coreauth.RestoreRuntimeState(auth)
	return auth, nil
}

func reserveAuthLabel(metadata map[string]any) string {
	return stringValue(metadata["email"])
}

func shouldRetryUsageAfterRefresh(resp *usageProbeResponse, err error) bool {
	if resp != nil && classifyHTTPResult(resp.StatusCode, resp.Body) == classificationInvalid401 {
		return true
	}
	if err == nil {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	if lower == "" {
		return false
	}
	if classifyErrorText(lower) == classificationInvalid401 {
		return true
	}
	return strings.Contains(lower, "access_token is missing")
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
	if path := authPath(base); path != "" {
		updated.Attributes["path"] = path
	}
	return updated
}

func countProductionAvailable(manager *coreauth.Manager) int {
	if manager == nil {
		return 0
	}
	count := 0
	for _, auth := range manager.List() {
		if auth == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
			continue
		}
		if auth.Disabled || auth.Status == coreauth.StatusDisabled {
			continue
		}
		if auth.Status == coreauth.StatusActive && !auth.Unavailable {
			count++
		}
	}
	return count
}

func defaultRefreshAuth(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*coreauth.Auth, error) {
	exec := runtimeexecutor.NewCodexExecutor(cfg)
	return exec.Refresh(ctx, auth)
}

func defaultUsageProbe(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*usageProbeResponse, error) {
	if auth == nil {
		return nil, fmt.Errorf("reserve auth is nil")
	}
	token := resolveAccessToken(auth)
	if token == "" {
		return nil, fmt.Errorf("codex access_token is missing")
	}
	accountID := resolveChatGPTAccountID(auth)
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
		Timeout:   defaultOperationTimeout,
		Transport: buildTransport(cfg, auth),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &usageProbeResponse{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}, nil
}

func buildTransport(cfg *config.Config, auth *coreauth.Auth) http.RoundTripper {
	proxyURL := ""
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	transport, mode, err := proxyutil.BuildHTTPTransport(proxyURL)
	if err != nil {
		log.WithError(err).Warnf("reserve pool: build proxy transport for %q failed", proxyURL)
	}
	if mode == proxyutil.ModeProxy && transport != nil {
		return transport
	}
	if mode == proxyutil.ModeDirect && transport != nil {
		return transport
	}
	return codexauth.NewOpenAIHTTPClient(cfg).Transport
}

func resolveAccessToken(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if token, ok := auth.Metadata["access_token"].(string); ok {
		return strings.TrimSpace(token)
	}
	return ""
}

func resolveChatGPTAccountID(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if rawID, ok := auth.Metadata["account_id"].(string); ok {
		if trimmed := strings.TrimSpace(rawID); trimmed != "" {
			return trimmed
		}
	}
	idToken, _ := auth.Metadata["id_token"].(string)
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
