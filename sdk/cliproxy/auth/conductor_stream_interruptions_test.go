package auth

import (
	"context"
	stderrors "errors"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestManager_WrapStreamResult_PostFirstChunkInterruptionStartsCooldown(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-1", Provider: "codex"}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	remaining := make(chan cliproxyexecutor.StreamChunk, 1)
	remaining <- cliproxyexecutor.StreamChunk{Err: stderrors.New("unexpected EOF")}
	close(remaining)

	start := time.Now()
	result := manager.wrapStreamResult(
		context.Background(),
		auth.Clone(),
		"codex",
		"gpt-5-codex",
		http.Header{},
		[]cliproxyexecutor.StreamChunk{{Payload: []byte("data: hello\n\n")}},
		remaining,
	)

	var chunks []cliproxyexecutor.StreamChunk
	for chunk := range result.Chunks {
		chunks = append(chunks, chunk)
	}
	if len(chunks) != 2 {
		t.Fatalf("len(chunks) = %d, want 2", len(chunks))
	}
	if string(chunks[0].Payload) != "data: hello\n\n" {
		t.Fatalf("first chunk payload = %q, want data chunk", string(chunks[0].Payload))
	}
	if chunks[1].Err == nil {
		t.Fatalf("expected terminal error chunk")
	}

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected updated auth")
	}
	state := updated.ModelStates["gpt-5-codex"]
	if state == nil {
		t.Fatalf("expected model state")
	}
	if state.LastError == nil || state.LastError.Code != streamInterruptedCode {
		t.Fatalf("last error = %#v, want %q", state.LastError, streamInterruptedCode)
	}
	assertCooldownWithin(t, state.NextRetryAfter, start, 9*time.Minute, 11*time.Minute)
}

func TestManager_MarkResult_StreamInterruptionCooldownEscalates(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-1", Provider: "codex"}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	model := "gpt-5-codex"
	errInterrupted := &Error{
		Code:       streamInterruptedCode,
		Message:    "stream error: stream disconnected before completion",
		Retryable:  true,
		HTTPStatus: http.StatusRequestTimeout,
	}

	start1 := time.Now()
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    model,
		Success:  false,
		Error:    errInterrupted,
	})
	state := mustModelState(t, manager, auth.ID, model)
	assertCooldownWithin(t, state.NextRetryAfter, start1, 9*time.Minute, 11*time.Minute)

	start2 := time.Now()
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    model,
		Success:  false,
		Error:    errInterrupted,
	})
	state = mustModelState(t, manager, auth.ID, model)
	assertCooldownWithin(t, state.NextRetryAfter, start2, 59*time.Minute, 61*time.Minute)

	start3 := time.Now()
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    model,
		Success:  false,
		Error:    errInterrupted,
	})
	state = mustModelState(t, manager, auth.ID, model)
	assertCooldownWithin(t, state.NextRetryAfter, start3, 5*time.Hour+59*time.Minute, 6*time.Hour+1*time.Minute)
}

func TestManager_MarkResult_SuccessClearsStreamInterruptionCooldown(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-1", Provider: "codex"}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	model := "gpt-5-codex"
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    model,
		Success:  false,
		Error: &Error{
			Code:       streamInterruptedCode,
			Message:    "stream error: stream disconnected before completion",
			Retryable:  true,
			HTTPStatus: http.StatusRequestTimeout,
		},
	})
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    model,
		Success:  true,
	})

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected updated auth")
	}
	state := updated.ModelStates[model]
	if state == nil {
		t.Fatalf("expected model state")
	}
	if state.Status != StatusActive {
		t.Fatalf("state.Status = %q, want %q", state.Status, StatusActive)
	}
	if !state.NextRetryAfter.IsZero() {
		t.Fatalf("state.NextRetryAfter = %v, want zero", state.NextRetryAfter)
	}
	if state.LastError != nil {
		t.Fatalf("state.LastError = %#v, want nil", state.LastError)
	}
	if updated.Status != StatusActive {
		t.Fatalf("auth.Status = %q, want %q", updated.Status, StatusActive)
	}
}

func TestManager_WrapStreamResult_UserCancellationDoesNotMarkInterruptionCooldown(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-1", Provider: "codex"}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	remaining := make(chan cliproxyexecutor.StreamChunk, 1)
	remaining <- cliproxyexecutor.StreamChunk{Err: stderrors.New("context canceled")}
	close(remaining)

	result := manager.wrapStreamResult(ctx, auth.Clone(), "codex", "gpt-5-codex", http.Header{}, nil, remaining)
	for range result.Chunks {
	}

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected updated auth")
	}
	if len(updated.ModelStates) != 0 {
		t.Fatalf("expected no model state updates on canceled context, got %#v", updated.ModelStates)
	}
	if updated.Status == StatusError {
		t.Fatalf("auth.Status = %q, want non-error", updated.Status)
	}
	if updated.Unavailable {
		t.Fatalf("auth.Unavailable = true, want false")
	}
}

func TestRestoreRuntimeState_PreservesStreamInterruptionEscalationWindow(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auth := &Auth{
		ID: "auth-1",
		ModelStates: map[string]*ModelState{
			"gpt-5-codex": {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: now.Add(streamInterruptedBaseCooldown),
				LastError: &Error{
					Code:       streamInterruptedCode,
					Message:    "unexpected EOF",
					Retryable:  true,
					HTTPStatus: http.StatusRequestTimeout,
				},
				StatusMessage: "unexpected EOF",
				UpdatedAt:     now,
			},
		},
	}

	persisted := MetadataForPersistence(auth)
	reloaded := &Auth{
		ID:       auth.ID,
		Provider: "codex",
		Metadata: persisted,
	}
	RestoreRuntimeState(reloaded)

	state := reloaded.ModelStates["gpt-5-codex"]
	if state == nil {
		t.Fatalf("expected restored model state")
	}
	if state.UpdatedAt.IsZero() {
		t.Fatalf("expected UpdatedAt to be restored")
	}

	manager := NewManager(nil, nil, nil)
	if _, errRegister := manager.Register(context.Background(), reloaded); errRegister != nil {
		t.Fatalf("register reloaded auth: %v", errRegister)
	}

	start := time.Now()
	manager.MarkResult(context.Background(), Result{
		AuthID:   reloaded.ID,
		Provider: "codex",
		Model:    "gpt-5-codex",
		Success:  false,
		Error: &Error{
			Code:       streamInterruptedCode,
			Message:    "stream error: stream disconnected before completion",
			Retryable:  true,
			HTTPStatus: http.StatusRequestTimeout,
		},
	})

	state = mustModelState(t, manager, reloaded.ID, "gpt-5-codex")
	assertCooldownWithin(t, state.NextRetryAfter, start, 59*time.Minute, 61*time.Minute)
}

func mustModelState(t *testing.T, manager *Manager, authID, model string) *ModelState {
	t.Helper()

	auth, ok := manager.GetByID(authID)
	if !ok || auth == nil {
		t.Fatalf("expected auth %q", authID)
	}
	state := auth.ModelStates[model]
	if state == nil {
		t.Fatalf("expected model state %q", model)
	}
	return state
}

func assertCooldownWithin(t *testing.T, nextRetryAfter, start time.Time, minWait, maxWait time.Duration) {
	t.Helper()

	wait := nextRetryAfter.Sub(start)
	if wait < minWait || wait > maxWait {
		t.Fatalf("cooldown = %v, want within [%v, %v]", wait, minWait, maxWait)
	}
}
