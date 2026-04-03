package auth

import (
	"testing"
	"time"
)

func TestMetadataForPersistence_OmitsRuntimeStateWhenAuthIsActive(t *testing.T) {
	t.Parallel()

	auth := &Auth{
		Metadata: map[string]any{"email": "active@example.com"},
	}

	got := MetadataForPersistence(auth)
	if got == nil {
		t.Fatalf("expected metadata copy, got nil")
	}
	if got["email"] != "active@example.com" {
		t.Fatalf("email = %v, want active@example.com", got["email"])
	}
	if _, ok := got[runtimeStateMetadataKey]; ok {
		t.Fatalf("unexpected runtime metadata: %#v", got[runtimeStateMetadataKey])
	}
	if _, ok := got["disabled"]; ok {
		t.Fatalf("unexpected disabled field for active auth")
	}
}

func TestRestoreRuntimeState_RestoresBlockedAuthAndModelCooldowns(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auth := &Auth{
		Metadata:       map[string]any{"email": "cooling@example.com"},
		Unavailable:    true,
		NextRetryAfter: now.Add(30 * time.Minute),
		Quota: QuotaState{
			Exceeded:      true,
			Reason:        "quota",
			NextRecoverAt: now.Add(45 * time.Minute),
			BackoffLevel:  3,
		},
		LastError: &Error{
			Message:    "quota reached",
			HTTPStatus: 429,
		},
		StatusMessage: "quota reached",
		ModelStates: map[string]*ModelState{
			"gpt-5-codex": {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: now.Add(20 * time.Minute),
				LastError: &Error{
					Message:    "stream incomplete",
					HTTPStatus: 408,
				},
				StatusMessage: "stream incomplete",
			},
			"healthy-model": {
				Status: StatusActive,
			},
		},
	}

	persisted := MetadataForPersistence(auth)
	if persisted == nil {
		t.Fatalf("expected persisted metadata, got nil")
	}
	if _, ok := persisted[runtimeStateMetadataKey]; !ok {
		t.Fatalf("expected runtime metadata key")
	}

	reloaded := &Auth{
		Metadata: persisted,
		Status:   StatusActive,
	}
	RestoreRuntimeState(reloaded)

	if !reloaded.Unavailable {
		t.Fatalf("expected auth to remain unavailable after restore")
	}
	if !reloaded.NextRetryAfter.After(now) {
		t.Fatalf("expected future next retry after, got %v", reloaded.NextRetryAfter)
	}
	if !reloaded.Quota.Exceeded {
		t.Fatalf("expected auth quota exceeded to be restored")
	}
	if reloaded.Status != StatusError {
		t.Fatalf("status = %q, want %q", reloaded.Status, StatusError)
	}
	if reloaded.StatusMessage != "quota reached" {
		t.Fatalf("status message = %q, want quota reached", reloaded.StatusMessage)
	}
	if len(reloaded.ModelStates) != 1 {
		t.Fatalf("expected only blocked model state to persist, got %d", len(reloaded.ModelStates))
	}
	modelState := reloaded.ModelStates["gpt-5-codex"]
	if modelState == nil {
		t.Fatalf("expected blocked model state to be restored")
	}
	if !modelState.Unavailable {
		t.Fatalf("expected restored model state to be unavailable")
	}
	if modelState.Status != StatusError {
		t.Fatalf("model status = %q, want %q", modelState.Status, StatusError)
	}
	if _, ok := reloaded.Metadata[runtimeStateMetadataKey]; ok {
		t.Fatalf("expected runtime metadata key to be removed from in-memory metadata")
	}
}

func TestRestoreRuntimeState_RestoresDisabledFlagFromMetadata(t *testing.T) {
	t.Parallel()

	auth := &Auth{
		Metadata: map[string]any{"disabled": true},
		Status:   StatusActive,
	}

	RestoreRuntimeState(auth)

	if !auth.Disabled {
		t.Fatalf("expected disabled flag to be restored")
	}
	if auth.Status != StatusDisabled {
		t.Fatalf("status = %q, want %q", auth.Status, StatusDisabled)
	}
}

func TestRestoreRuntimeState_RestoresTokenInvalidatedQuarantineAndProbeSchedule(t *testing.T) {
	t.Parallel()

	now := time.Now()
	probeAt := now.Add(24 * time.Hour)
	auth := &Auth{
		Metadata:         map[string]any{"email": "cooling@example.com"},
		Unavailable:      true,
		NextRetryAfter:   probeAt,
		NextRefreshAfter: probeAt,
		LastError: &Error{
			Code:       auth401KindTokenInvalidated,
			Message:    `{"error":{"code":"token_invalidated","message":"Your authentication token has been invalidated. Please try signing in again."},"status":401}`,
			HTTPStatus: 401,
		},
		Status:        StatusError,
		StatusMessage: "token invalidated",
	}

	persisted := MetadataForPersistence(auth)
	reloaded := &Auth{
		Metadata: persisted,
		Status:   StatusActive,
	}
	RestoreRuntimeState(reloaded)

	if authWide401Quarantine(reloaded) != auth401KindTokenInvalidated {
		t.Fatalf("quarantine kind = %q, want %q", authWide401Quarantine(reloaded), auth401KindTokenInvalidated)
	}
	if !reloaded.Unavailable {
		t.Fatalf("expected reloaded auth to remain unavailable")
	}
	if !reloaded.NextRefreshAfter.Equal(probeAt) {
		t.Fatalf("next refresh after = %v, want %v", reloaded.NextRefreshAfter, probeAt)
	}
}

func TestRestoreRuntimeState_RestoresAccountDeactivatedQuarantine(t *testing.T) {
	t.Parallel()

	auth := &Auth{
		Metadata:    map[string]any{"email": "disabled@example.com"},
		Unavailable: true,
		LastError: &Error{
			Code:       auth401KindAccountDeactivated,
			Message:    `{"error":{"code":"account_deactivated","message":"Your account has been deactivated."},"status":401}`,
			HTTPStatus: 401,
		},
		Status:        StatusError,
		StatusMessage: "account deactivated",
	}

	persisted := MetadataForPersistence(auth)
	if _, ok := persisted[runtimeStateMetadataKey]; !ok {
		t.Fatalf("expected runtime metadata for account_deactivated quarantine")
	}

	reloaded := &Auth{
		Metadata: persisted,
		Status:   StatusActive,
	}
	RestoreRuntimeState(reloaded)

	if authWide401Quarantine(reloaded) != auth401KindAccountDeactivated {
		t.Fatalf("quarantine kind = %q, want %q", authWide401Quarantine(reloaded), auth401KindAccountDeactivated)
	}
	if !reloaded.Unavailable {
		t.Fatalf("expected reloaded auth to remain unavailable")
	}
	if !reloaded.NextRefreshAfter.IsZero() {
		t.Fatalf("next refresh after = %v, want zero", reloaded.NextRefreshAfter)
	}
}
