package auth

import (
	"encoding/json"
	"strings"
	"time"
)

const runtimeStateMetadataKey = "_cliproxy_runtime"

type persistedRuntimeState struct {
	Auth       *persistedAuthRuntime             `json:"auth,omitempty"`
	ModelState map[string]*persistedModelRuntime `json:"model_states,omitempty"`
}

type persistedAuthRuntime struct {
	NextRetryAfter time.Time   `json:"next_retry_after,omitempty"`
	Quota          *QuotaState `json:"quota,omitempty"`
	LastError      *Error      `json:"last_error,omitempty"`
	StatusMessage  string      `json:"status_message,omitempty"`
}

type persistedModelRuntime struct {
	Status         Status      `json:"status,omitempty"`
	NextRetryAfter time.Time   `json:"next_retry_after,omitempty"`
	Quota          *QuotaState `json:"quota,omitempty"`
	LastError      *Error      `json:"last_error,omitempty"`
	StatusMessage  string      `json:"status_message,omitempty"`
	UpdatedAt      time.Time   `json:"updated_at,omitempty"`
}

// MetadataForPersistence returns a metadata snapshot suitable for store persistence.
// It keeps operator-managed metadata intact while adding only the runtime state needed
// to preserve auth/model cooldown decisions across restarts.
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

// RestoreRuntimeState rehydrates persisted cooldown state from metadata after loading an auth.
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
		applyPersistedModelRuntime(auth, persisted.ModelState, time.Now())
	}
	if auth.Metadata != nil {
		delete(auth.Metadata, runtimeStateMetadataKey)
	}

	now := time.Now()
	if len(auth.ModelStates) > 0 {
		updateAggregatedAvailability(auth, now)
	}
	mergePersistedAuthRuntime(auth, persisted, now)
	normalizeRestoredAuthState(auth, now)
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

	state := &persistedRuntimeState{
		Auth: buildPersistedAuthRuntime(auth, now),
	}
	if len(auth.ModelStates) > 0 {
		models := make(map[string]*persistedModelRuntime, len(auth.ModelStates))
		for model, modelState := range auth.ModelStates {
			if persisted := buildPersistedModelRuntime(modelState, now); persisted != nil {
				models[model] = persisted
			}
		}
		if len(models) > 0 {
			state.ModelState = models
		}
	}
	if state.Auth == nil && len(state.ModelState) == 0 {
		return nil
	}
	return state
}

func buildPersistedAuthRuntime(auth *Auth, now time.Time) *persistedAuthRuntime {
	if auth == nil || auth.Disabled {
		return nil
	}
	quota := clonePersistableQuota(auth.Quota, now)
	nextRetry := persistedRetryAfter(auth.NextRetryAfter, quota, now)
	if nextRetry.IsZero() && quota == nil {
		return nil
	}
	runtime := &persistedAuthRuntime{
		NextRetryAfter: nextRetry,
		Quota:          quota,
		LastError:      cloneError(auth.LastError),
		StatusMessage:  strings.TrimSpace(auth.StatusMessage),
	}
	if runtime.StatusMessage == "" && runtime.LastError != nil {
		runtime.StatusMessage = runtime.LastError.Message
	}
	return runtime
}

func buildPersistedModelRuntime(state *ModelState, now time.Time) *persistedModelRuntime {
	if state == nil {
		return nil
	}
	quota := clonePersistableQuota(state.Quota, now)
	nextRetry := persistedRetryAfter(state.NextRetryAfter, quota, now)
	persistStatus := state.Status == StatusDisabled
	if nextRetry.IsZero() && quota == nil && !persistStatus {
		return nil
	}
	runtime := &persistedModelRuntime{
		NextRetryAfter: nextRetry,
		Quota:          quota,
		LastError:      cloneError(state.LastError),
		StatusMessage:  strings.TrimSpace(state.StatusMessage),
		UpdatedAt:      state.UpdatedAt,
	}
	if persistStatus {
		runtime.Status = state.Status
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

func applyPersistedModelRuntime(auth *Auth, persisted map[string]*persistedModelRuntime, now time.Time) {
	if auth == nil || len(persisted) == 0 {
		return
	}
	auth.ModelStates = make(map[string]*ModelState, len(persisted))
	for model, runtime := range persisted {
		restored := restoreModelState(runtime, now)
		if restored != nil {
			auth.ModelStates[model] = restored
		}
	}
	if len(auth.ModelStates) == 0 {
		auth.ModelStates = nil
	}
}

func restoreModelState(runtime *persistedModelRuntime, now time.Time) *ModelState {
	if runtime == nil {
		return nil
	}
	state := &ModelState{
		Status:         runtime.Status,
		NextRetryAfter: persistedRetryAfter(runtime.NextRetryAfter, runtime.Quota, now),
		LastError:      cloneError(runtime.LastError),
		StatusMessage:  strings.TrimSpace(runtime.StatusMessage),
		UpdatedAt:      runtime.UpdatedAt,
	}
	if runtime.Quota != nil {
		state.Quota = *runtime.Quota
	}
	if state.StatusMessage == "" && state.LastError != nil {
		state.StatusMessage = state.LastError.Message
	}
	if state.Status == "" {
		if state.NextRetryAfter.After(now) || state.Quota.Exceeded || state.LastError != nil {
			state.Status = StatusError
		} else {
			state.Status = StatusActive
		}
	}
	if state.Status == StatusDisabled {
		state.Unavailable = true
		return state
	}
	state.Unavailable = state.NextRetryAfter.After(now)
	if !state.Unavailable && !state.Quota.Exceeded {
		return nil
	}
	return state
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

func mergePersistedAuthRuntime(auth *Auth, persisted *persistedRuntimeState, now time.Time) {
	if auth == nil || persisted == nil || persisted.Auth == nil {
		return
	}
	nextRetry := persistedRetryAfter(persisted.Auth.NextRetryAfter, persisted.Auth.Quota, now)
	if nextRetry.After(auth.NextRetryAfter) {
		auth.NextRetryAfter = nextRetry
		auth.Unavailable = true
	}
	if persisted.Auth.Quota != nil {
		if !auth.Quota.Exceeded || persisted.Auth.Quota.NextRecoverAt.After(auth.Quota.NextRecoverAt) {
			auth.Quota = *persisted.Auth.Quota
		}
	}
	if auth.LastError == nil && persisted.Auth.LastError != nil {
		auth.LastError = cloneError(persisted.Auth.LastError)
	}
	if auth.StatusMessage == "" {
		auth.StatusMessage = strings.TrimSpace(persisted.Auth.StatusMessage)
		if auth.StatusMessage == "" && auth.LastError != nil {
			auth.StatusMessage = auth.LastError.Message
		}
	}
}
