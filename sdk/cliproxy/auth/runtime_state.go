package auth

import (
	"encoding/json"
	"strings"
	"time"
)

const runtimeStateMetadataKey = "_cliproxy_runtime"

type persistedRuntimeState struct {
	Auth *persistedAuthRuntime `json:"auth,omitempty"`
}

type persistedAuthRuntime struct {
	NextRetryAfter   time.Time   `json:"next_retry_after,omitempty"`
	NextRefreshAfter time.Time   `json:"next_refresh_after,omitempty"`
	Quota            *QuotaState `json:"quota,omitempty"`
	LastError        *Error      `json:"last_error,omitempty"`
	StatusMessage    string      `json:"status_message,omitempty"`
}

// MetadataForPersistence returns a metadata snapshot suitable for store persistence.
// It keeps operator-managed metadata intact while adding only the runtime state needed
// to preserve auth-wide runtime state across restarts.
func MetadataForPersistence(auth *Auth) map[string]any {
	if auth == nil {
		return nil
	}

	meta := cloneMetadataMap(auth.Metadata)
	if meta != nil {
		delete(meta, runtimeStateMetadataKey)
	}

	if runtime := buildPersistedRuntimeState(auth, time.Now()); runtime != nil {
		if meta == nil {
			meta = make(map[string]any, 1)
		}
		meta[runtimeStateMetadataKey] = runtime
	}

	if shouldPersistDisabledFlag(auth) {
		if meta == nil {
			meta = make(map[string]any, 1)
		}
		meta["disabled"] = auth.Disabled
	} else if meta != nil {
		delete(meta, "disabled")
	}

	if len(meta) == 0 {
		return nil
	}
	return meta
}

// RestoreRuntimeState rehydrates persisted auth-wide runtime state from metadata after loading an auth.
func RestoreRuntimeState(auth *Auth) {
	if auth == nil {
		return
	}

	if auth.Metadata != nil {
		if disabled, ok := parseBoolAny(auth.Metadata["disabled"]); ok {
			auth.Disabled = disabled
		}
	}

	persisted := decodePersistedRuntimeState(auth)
	if persisted != nil {
		applyPersistedAuthRuntime(auth, persisted.Auth, time.Now())
	}
	if auth.Metadata != nil {
		delete(auth.Metadata, runtimeStateMetadataKey)
	}

	normalizeRestoredAuthState(auth, time.Now())
}

func cloneMetadataMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func shouldPersistDisabledFlag(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if auth.Disabled {
		return true
	}
	if auth.Metadata == nil {
		return false
	}
	_, ok := auth.Metadata["disabled"]
	return ok
}

func buildPersistedRuntimeState(auth *Auth, now time.Time) *persistedRuntimeState {
	if auth == nil {
		return nil
	}

	state := &persistedRuntimeState{Auth: buildPersistedAuthRuntime(auth, now)}
	if state.Auth == nil {
		return nil
	}
	return state
}

func buildPersistedAuthRuntime(auth *Auth, now time.Time) *persistedAuthRuntime {
	if auth == nil || auth.Disabled {
		return nil
	}

	var (
		quota     *QuotaState
		nextRetry time.Time
	)
	if auth.Unavailable && auth.NextRetryAfter.After(now) {
		nextRetry = auth.NextRetryAfter
		quota = clonePersistableQuota(auth.Quota, now)
		if quota != nil && quota.NextRecoverAt.After(nextRetry) {
			nextRetry = quota.NextRecoverAt
		}
	}
	nextRefresh := auth.NextRefreshAfter
	quarantineKind := authWide401Quarantine(auth)
	if nextRetry.IsZero() && quota == nil && nextRefresh.IsZero() && quarantineKind == auth401KindNone {
		return nil
	}
	runtime := &persistedAuthRuntime{
		NextRetryAfter:   nextRetry,
		NextRefreshAfter: nextRefresh,
		Quota:            quota,
		LastError:        cloneError(auth.LastError),
		StatusMessage:    strings.TrimSpace(auth.StatusMessage),
	}
	if runtime.StatusMessage == "" && runtime.LastError != nil {
		runtime.StatusMessage = runtime.LastError.Message
	}
	return runtime
}

func clonePersistableQuota(quota QuotaState, now time.Time) *QuotaState {
	if !quota.Exceeded || quota.NextRecoverAt.IsZero() || !quota.NextRecoverAt.After(now) {
		return nil
	}
	copyQuota := quota
	return &copyQuota
}

func persistedRetryAfter(nextRetryAfter time.Time, quota *QuotaState, now time.Time) time.Time {
	if !nextRetryAfter.After(now) {
		nextRetryAfter = time.Time{}
	}
	if quota != nil && quota.NextRecoverAt.After(nextRetryAfter) {
		nextRetryAfter = quota.NextRecoverAt
	}
	return nextRetryAfter
}

func decodePersistedRuntimeState(auth *Auth) *persistedRuntimeState {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	raw, ok := auth.Metadata[runtimeStateMetadataKey]
	if !ok || raw == nil {
		return nil
	}
	switch typed := raw.(type) {
	case *persistedRuntimeState:
		return typed
	case persistedRuntimeState:
		return &typed
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var persisted persistedRuntimeState
	if err = json.Unmarshal(data, &persisted); err != nil {
		return nil
	}
	return &persisted
}

func applyPersistedAuthRuntime(auth *Auth, persisted *persistedAuthRuntime, now time.Time) {
	if auth == nil || persisted == nil {
		return
	}
	auth.NextRetryAfter = persistedRetryAfter(persisted.NextRetryAfter, persisted.Quota, now)
	auth.NextRefreshAfter = persisted.NextRefreshAfter
	if persisted.Quota != nil {
		auth.Quota = *persisted.Quota
	} else {
		auth.Quota = QuotaState{}
	}
	auth.Unavailable = auth.NextRetryAfter.After(now)
	auth.LastError = cloneError(persisted.LastError)
	auth.StatusMessage = strings.TrimSpace(persisted.StatusMessage)
	if auth.StatusMessage == "" && auth.LastError != nil {
		auth.StatusMessage = auth.LastError.Message
	}
}

func normalizeRestoredAuthState(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	if auth.Disabled {
		auth.Status = StatusDisabled
		if auth.StatusMessage == "" {
			auth.StatusMessage = "disabled"
		}
		return
	}
	if authWide401Quarantine(auth) != auth401KindNone {
		auth.Unavailable = true
		auth.Status = StatusError
		if auth.StatusMessage == "" && auth.LastError != nil {
			auth.StatusMessage = auth.LastError.Message
		}
		return
	}
	if auth.NextRefreshAfter.After(now) {
		auth.Status = StatusError
		if auth.StatusMessage == "" && auth.LastError != nil {
			auth.StatusMessage = auth.LastError.Message
		}
		return
	}
	if auth.Unavailable && !auth.NextRetryAfter.After(now) {
		auth.Unavailable = false
		auth.NextRetryAfter = time.Time{}
	}
	if auth.Quota.Exceeded && (!auth.Quota.NextRecoverAt.After(now) || auth.Quota.NextRecoverAt.IsZero()) {
		auth.Quota = QuotaState{}
	}
	if auth.Unavailable || hasModelError(auth, now) {
		auth.Status = StatusError
		if auth.StatusMessage == "" && auth.LastError != nil {
			auth.StatusMessage = auth.LastError.Message
		}
		return
	}
	auth.Status = StatusActive
	auth.LastError = nil
	auth.StatusMessage = ""
}
