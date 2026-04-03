package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type quarantineTestExecutor struct {
	provider   string
	refreshFn  func(context.Context, *Auth) (*Auth, error)
	executeErr error
}

func (e quarantineTestExecutor) Identifier() string { return e.provider }

func (e quarantineTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, e.executeErr
}

func (e quarantineTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, e.executeErr
}

func (e quarantineTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	if e.refreshFn == nil {
		return auth, nil
	}
	return e.refreshFn(ctx, auth)
}

func (e quarantineTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e quarantineTestExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestManager_MarkResult_TokenInvalidatedQuarantinesAuthWide(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	auth := &Auth{ID: "token-invalidated", Provider: "codex"}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	start := time.Now()
	manager.MarkResult(ctx, Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5-codex",
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusUnauthorized,
			Message:    "{\n  \"error\": {\n    \"message\": \"Your authentication token has been invalidated. Please try signing in again.\",\n    \"type\": \"invalid_request_error\",\n    \"code\": \"token_invalidated\",\n    \"param\": null\n  },\n  \"status\": 401\n}",
		},
	})

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("GetByID(%q) returned no auth", auth.ID)
	}
	if authWide401Quarantine(updated) != auth401KindTokenInvalidated {
		t.Fatalf("quarantine kind = %q, want %q", authWide401Quarantine(updated), auth401KindTokenInvalidated)
	}
	if !updated.Unavailable {
		t.Fatalf("expected auth to be unavailable")
	}
	assertCooldownWithin(t, updated.NextRetryAfter, start, 23*time.Hour+59*time.Minute, 24*time.Hour+1*time.Minute)
	assertCooldownWithin(t, updated.NextRefreshAfter, start, 23*time.Hour+59*time.Minute, 24*time.Hour+1*time.Minute)
	if len(updated.ModelStates) != 0 {
		t.Fatalf("expected auth-wide quarantine without model cooldown state, got %#v", updated.ModelStates)
	}
}

func TestManager_MarkResult_AccountDeactivatedBlocksIndefinitely(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	auth := &Auth{ID: "account-deactivated", Provider: "codex"}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	manager.MarkResult(ctx, Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5-codex",
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusUnauthorized,
			Message:    `{"error":{"message":"Your account has been deactivated.","code":"account_deactivated"},"status":401}`,
		},
	})

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("GetByID(%q) returned no auth", auth.ID)
	}
	if authWide401Quarantine(updated) != auth401KindAccountDeactivated {
		t.Fatalf("quarantine kind = %q, want %q", authWide401Quarantine(updated), auth401KindAccountDeactivated)
	}
	if !updated.Unavailable {
		t.Fatalf("expected auth to be unavailable")
	}
	if !updated.NextRetryAfter.IsZero() {
		t.Fatalf("next retry after = %v, want zero", updated.NextRetryAfter)
	}
	if !updated.NextRefreshAfter.IsZero() {
		t.Fatalf("next refresh after = %v, want zero", updated.NextRefreshAfter)
	}
}

func TestManager_refreshAuth_TokenInvalidatedProbeSuccessClearsQuarantine(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(quarantineTestExecutor{
		provider: "codex",
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			cloned := auth.Clone()
			if cloned.Metadata == nil {
				cloned.Metadata = make(map[string]any)
			}
			cloned.Metadata["refreshed"] = true
			return cloned, nil
		},
	})

	auth := &Auth{
		ID:       "probe-success",
		Provider: "codex",
		LastError: &Error{
			Code:       auth401KindTokenInvalidated,
			Message:    "token invalidated",
			HTTPStatus: http.StatusUnauthorized,
		},
		Unavailable:      true,
		NextRetryAfter:   time.Now().Add(24 * time.Hour),
		NextRefreshAfter: time.Now().Add(24 * time.Hour),
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	manager.refreshAuth(ctx, auth.ID)

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("GetByID(%q) returned no auth", auth.ID)
	}
	if authWide401Quarantine(updated) != auth401KindNone {
		t.Fatalf("quarantine kind = %q, want none", authWide401Quarantine(updated))
	}
	if updated.Unavailable {
		t.Fatalf("expected auth to be available after successful probe")
	}
	if !updated.NextRefreshAfter.IsZero() {
		t.Fatalf("next refresh after = %v, want zero", updated.NextRefreshAfter)
	}
	if !updated.NextRetryAfter.IsZero() {
		t.Fatalf("next retry after = %v, want zero", updated.NextRetryAfter)
	}
}

func TestManager_refreshAuth_TokenInvalidatedProbeFailureReschedulesWithoutReflow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(quarantineTestExecutor{
		provider: "codex",
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			return nil, fmt.Errorf("dial tcp timeout")
		},
	})

	auth := &Auth{
		ID:       "probe-failure",
		Provider: "codex",
		LastError: &Error{
			Code:       auth401KindTokenInvalidated,
			Message:    "token invalidated",
			HTTPStatus: http.StatusUnauthorized,
		},
		Unavailable:      true,
		NextRetryAfter:   time.Now().Add(24 * time.Hour),
		NextRefreshAfter: time.Now().Add(24 * time.Hour),
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	start := time.Now()
	manager.refreshAuth(ctx, auth.ID)

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("GetByID(%q) returned no auth", auth.ID)
	}
	if authWide401Quarantine(updated) != auth401KindTokenInvalidated {
		t.Fatalf("quarantine kind = %q, want %q", authWide401Quarantine(updated), auth401KindTokenInvalidated)
	}
	if !updated.Unavailable {
		t.Fatalf("expected auth to remain unavailable after failed probe")
	}
	assertCooldownWithin(t, updated.NextRefreshAfter, start, 23*time.Hour+59*time.Minute, 24*time.Hour+1*time.Minute)
	assertCooldownWithin(t, updated.NextRetryAfter, start, 23*time.Hour+59*time.Minute, 24*time.Hour+1*time.Minute)
	if updated.LastError == nil || updated.LastError.Message == "" {
		t.Fatalf("expected last error to record the failed probe")
	}
}
