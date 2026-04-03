package auth

import (
	"sort"
	"strings"
	"sync"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

const (
	defaultAffinityIdleTTL               = 20 * time.Minute
	defaultAffinityTransientBreakStrikes = 3
	affinityGenerationMetadataKey        = "affinity_generation"
)

type affinityLease struct {
	ScopeKey        string
	AuthID          string
	Generation      uint64
	Confirmed       bool
	BoundAt         time.Time
	LastUsedAt      time.Time
	TransientBreaks int
}

type affinityManager struct {
	mu         sync.Mutex
	leaseByKey map[string]*affinityLease
	keyByAuth  map[string]string
	nextGen    uint64
}

func newAffinityManager() *affinityManager {
	return &affinityManager{
		leaseByKey: make(map[string]*affinityLease),
		keyByAuth:  make(map[string]string),
	}
}

func (m *Manager) currentConfig() *internalconfig.Config {
	if m == nil {
		return &internalconfig.Config{}
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return &internalconfig.Config{}
	}
	return cfg
}

func (m *Manager) affinityScopeKey(providers []string, opts cliproxyexecutor.Options) string {
	if m == nil || m.affinity == nil {
		return ""
	}
	return m.affinity.scopeKey(providers, opts.Metadata)
}

func affinityRawKeyFromMetadata(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	raw, ok := meta[cliproxyexecutor.AffinityKeyMetadataKey]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return ""
	}
}

func buildAffinityScopeKey(providers []string, rawKey string) string {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return ""
	}
	keys := normalizeProviderKeys(providers)
	if len(keys) == 0 {
		return rawKey
	}
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	return strings.Join(sorted, "+") + "|" + rawKey
}

func (m *affinityManager) scopeKey(providers []string, meta map[string]any) string {
	if m == nil {
		return ""
	}
	return buildAffinityScopeKey(providers, affinityRawKeyFromMetadata(meta))
}

func (m *affinityManager) preparePickOptions(cfg *internalconfig.Config, scopeKey string, opts cliproxyexecutor.Options) (cliproxyexecutor.Options, bool) {
	if m == nil || !affinitySelectionEnabled(cfg) || scopeKey == "" {
		return opts, false
	}
	if pinnedAuthIDFromMetadata(opts.Metadata) != "" {
		return opts, false
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpiredLocked(cfg, now)
	lease := m.leaseByKey[scopeKey]
	if lease == nil || strings.TrimSpace(lease.AuthID) == "" {
		return opts, false
	}
	return withAffinitySelectionMetadata(opts, lease.AuthID, lease.Generation), true
}

func withPinnedAuthMetadata(opts cliproxyexecutor.Options, authID string) cliproxyexecutor.Options {
	return withAffinitySelectionMetadata(opts, authID, 0)
}

func withAffinitySelectionMetadata(opts cliproxyexecutor.Options, authID string, generation uint64) cliproxyexecutor.Options {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return opts
	}
	if len(opts.Metadata) == 0 {
		meta := map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: authID}
		if generation > 0 {
			meta[affinityGenerationMetadataKey] = generation
		}
		opts.Metadata = meta
		return opts
	}
	meta := make(map[string]any, len(opts.Metadata)+2)
	for k, v := range opts.Metadata {
		meta[k] = v
	}
	meta[cliproxyexecutor.PinnedAuthMetadataKey] = authID
	if generation > 0 {
		meta[affinityGenerationMetadataKey] = generation
	}
	opts.Metadata = meta
	return opts
}

func affinityGenerationFromMetadata(meta map[string]any) uint64 {
	if len(meta) == 0 {
		return 0
	}
	raw, ok := meta[affinityGenerationMetadataKey]
	if !ok || raw == nil {
		return 0
	}
	switch val := raw.(type) {
	case uint64:
		return val
	case uint32:
		return uint64(val)
	case uint:
		return uint64(val)
	case int64:
		if val > 0 {
			return uint64(val)
		}
	case int:
		if val > 0 {
			return uint64(val)
		}
	case float64:
		if val > 0 {
			return uint64(val)
		}
	}
	return 0
}

func mergeTriedSets(base map[string]struct{}, extra map[string]struct{}) map[string]struct{} {
	switch {
	case len(base) == 0 && len(extra) == 0:
		return nil
	case len(extra) == 0:
		out := make(map[string]struct{}, len(base))
		for key := range base {
			out[key] = struct{}{}
		}
		return out
	case len(base) == 0:
		out := make(map[string]struct{}, len(extra))
		for key := range extra {
			out[key] = struct{}{}
		}
		return out
	default:
		out := make(map[string]struct{}, len(base)+len(extra))
		for key := range base {
			out[key] = struct{}{}
		}
		for key := range extra {
			out[key] = struct{}{}
		}
		return out
	}
}

func affinitySelectionEnabled(cfg *internalconfig.Config) bool {
	return affinityObservationEnabled(cfg) && !cfg.Affinity.ShadowMode
}

func affinityObservationEnabled(cfg *internalconfig.Config) bool {
	return cfg != nil && cfg.Affinity.Enabled
}

func affinityIdleTTL(cfg *internalconfig.Config) time.Duration {
	if cfg == nil || cfg.Affinity.IdleTTLSeconds <= 0 {
		return defaultAffinityIdleTTL
	}
	return time.Duration(cfg.Affinity.IdleTTLSeconds) * time.Second
}

func affinityTransientBreakStrikes(cfg *internalconfig.Config) int {
	if cfg == nil || cfg.Affinity.TransientBreakStrikes <= 0 {
		return defaultAffinityTransientBreakStrikes
	}
	return cfg.Affinity.TransientBreakStrikes
}

func shouldBreakAffinityLease(err *Error) bool {
	switch statusCodeFromResult(err) {
	case 401, 429:
		return true
	default:
		return false
	}
}

func shouldCountTransientAffinityFailure(err *Error) bool {
	if isStreamInterruptedError(err) {
		return true
	}
	switch statusCodeFromResult(err) {
	case 408, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func (m *affinityManager) canUseAuth(cfg *internalconfig.Config, scopeKey string, authID string) bool {
	if m == nil || scopeKey == "" || strings.TrimSpace(authID) == "" || !affinitySelectionEnabled(cfg) {
		return true
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpiredLocked(cfg, now)
	owner := strings.TrimSpace(m.keyByAuth[authID])
	return owner == "" || owner == scopeKey
}

func (m *affinityManager) claimSelection(cfg *internalconfig.Config, scopeKey string, authID string, opts cliproxyexecutor.Options) (cliproxyexecutor.Options, string, bool) {
	if m == nil || !affinitySelectionEnabled(cfg) || scopeKey == "" || strings.TrimSpace(authID) == "" {
		return opts, strings.TrimSpace(authID), true
	}
	now := time.Now()
	authID = strings.TrimSpace(authID)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpiredLocked(cfg, now)

	if lease := m.leaseByKey[scopeKey]; lease != nil && strings.TrimSpace(lease.AuthID) != "" {
		return withAffinitySelectionMetadata(opts, lease.AuthID, lease.Generation), lease.AuthID, lease.AuthID == authID
	}
	if owner := strings.TrimSpace(m.keyByAuth[authID]); owner != "" && owner != scopeKey {
		return opts, "", false
	}

	m.nextGen++
	lease := &affinityLease{
		ScopeKey:   scopeKey,
		AuthID:     authID,
		Generation: m.nextGen,
		Confirmed:  false,
		BoundAt:    now,
		LastUsedAt: now,
	}
	m.leaseByKey[scopeKey] = lease
	m.keyByAuth[authID] = scopeKey
	return withAffinitySelectionMetadata(opts, authID, lease.Generation), authID, true
}

func (m *affinityManager) acceptsSuccess(cfg *internalconfig.Config, result Result) bool {
	if m == nil || !affinitySelectionEnabled(cfg) {
		return true
	}
	scopeKey := strings.TrimSpace(result.AffinityKey)
	authID := strings.TrimSpace(result.AuthID)
	if scopeKey == "" || authID == "" {
		return true
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpiredLocked(cfg, now)
	lease := m.leaseByKey[scopeKey]
	if lease == nil || lease.AuthID != authID {
		return false
	}
	if result.AffinityGeneration > 0 && lease.Generation > 0 && result.AffinityGeneration != lease.Generation {
		return false
	}
	return true
}

func (m *affinityManager) observeResult(cfg *internalconfig.Config, result Result) {
	if m == nil || !affinityObservationEnabled(cfg) {
		return
	}
	scopeKey := strings.TrimSpace(result.AffinityKey)
	authID := strings.TrimSpace(result.AuthID)
	if scopeKey == "" || authID == "" {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpiredLocked(cfg, now)

	lease := m.leaseByKey[scopeKey]
	if lease == nil {
		if !result.Success || affinitySelectionEnabled(cfg) {
			return
		}
		m.bindLeaseLocked(scopeKey, authID, now)
		lease = m.leaseByKey[scopeKey]
	}
	if lease == nil || lease.AuthID != authID {
		return
	}
	if result.AffinityGeneration > 0 && lease.Generation > 0 && result.AffinityGeneration != lease.Generation {
		return
	}
	if result.Success {
		lease.Confirmed = true
		lease.LastUsedAt = now
		lease.TransientBreaks = 0
		if lease.BoundAt.IsZero() {
			lease.BoundAt = now
		}
		return
	}
	if !lease.Confirmed {
		m.releaseLeaseLocked(scopeKey, authID)
		return
	}
	if shouldBreakAffinityLease(result.Error) {
		m.releaseLeaseLocked(scopeKey, authID)
		return
	}
	if shouldCountTransientAffinityFailure(result.Error) {
		lease.TransientBreaks++
		lease.LastUsedAt = now
		if lease.TransientBreaks >= affinityTransientBreakStrikes(cfg) {
			m.releaseLeaseLocked(scopeKey, authID)
		}
	}
}

func (m *affinityManager) bindLeaseLocked(scopeKey string, authID string, now time.Time) {
	if m == nil || scopeKey == "" || authID == "" {
		return
	}
	if owner := strings.TrimSpace(m.keyByAuth[authID]); owner != "" && owner != scopeKey {
		return
	}
	boundAt := now
	if existing := m.leaseByKey[scopeKey]; existing != nil {
		if existing.AuthID != "" && existing.AuthID != authID {
			delete(m.keyByAuth, existing.AuthID)
		}
		if existing.AuthID == authID && !existing.BoundAt.IsZero() {
			boundAt = existing.BoundAt
		}
	}
	m.leaseByKey[scopeKey] = &affinityLease{
		ScopeKey:   scopeKey,
		AuthID:     authID,
		BoundAt:    boundAt,
		LastUsedAt: now,
	}
	m.keyByAuth[authID] = scopeKey
}

func (m *affinityManager) releaseLeaseLocked(scopeKey string, authID string) {
	if m == nil || scopeKey == "" {
		return
	}
	if lease := m.leaseByKey[scopeKey]; lease != nil {
		if authID == "" || lease.AuthID == authID {
			delete(m.keyByAuth, lease.AuthID)
			delete(m.leaseByKey, scopeKey)
		}
	}
}

func (m *affinityManager) releaseAuth(authID string) {
	if m == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	scopeKey := strings.TrimSpace(m.keyByAuth[authID])
	if scopeKey == "" {
		return
	}
	m.releaseLeaseLocked(scopeKey, authID)
}

func (m *affinityManager) currentLeaseAuthID(cfg *internalconfig.Config, scopeKey string) string {
	if m == nil || scopeKey == "" {
		return ""
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpiredLocked(cfg, now)
	lease := m.leaseByKey[scopeKey]
	if lease == nil {
		return ""
	}
	return strings.TrimSpace(lease.AuthID)
}

func (m *affinityManager) releaseLease(scopeKey string, authID string) bool {
	if m == nil || scopeKey == "" {
		return false
	}
	authID = strings.TrimSpace(authID)
	m.mu.Lock()
	defer m.mu.Unlock()
	before := m.leaseByKey[scopeKey]
	if before == nil {
		return false
	}
	if authID != "" && before.AuthID != authID {
		return false
	}
	m.releaseLeaseLocked(scopeKey, authID)
	return true
}

func (m *affinityManager) reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.leaseByKey)
	clear(m.keyByAuth)
}

func (m *affinityManager) evictExpiredLocked(cfg *internalconfig.Config, now time.Time) {
	if m == nil || len(m.leaseByKey) == 0 {
		return
	}
	ttl := affinityIdleTTL(cfg)
	if ttl <= 0 {
		return
	}
	for scopeKey, lease := range m.leaseByKey {
		if lease == nil {
			delete(m.leaseByKey, scopeKey)
			continue
		}
		lastUsedAt := lease.LastUsedAt
		if lastUsedAt.IsZero() {
			lastUsedAt = lease.BoundAt
		}
		if lastUsedAt.IsZero() || now.Sub(lastUsedAt) < ttl {
			continue
		}
		delete(m.keyByAuth, lease.AuthID)
		delete(m.leaseByKey, scopeKey)
	}
}
