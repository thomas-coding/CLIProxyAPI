package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type codexRefreshV6TestExecutor struct {
	refreshFn func(context.Context, *Auth) (*Auth, error)
	executeFn func(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	countFn   func(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
}

func (e codexRefreshV6TestExecutor) Identifier() string { return "codex" }

func (e codexRefreshV6TestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e.executeFn != nil {
		return e.executeFn(ctx, auth, req, opts)
	}
	return cliproxyexecutor.Response{}, nil
}

func (e codexRefreshV6TestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e codexRefreshV6TestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	if e.refreshFn != nil {
		return e.refreshFn(ctx, auth)
	}
	return auth, nil
}

func (e codexRefreshV6TestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e.countFn != nil {
		return e.countFn(ctx, auth, req, opts)
	}
	return cliproxyexecutor.Response{}, nil
}

func (e codexRefreshV6TestExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

type firstAuthSelector struct{}

func (s *firstAuthSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	if len(auths) == 0 {
		return nil, nil
	}
	return auths[0], nil
}

func TestManager_shouldRefresh_CodexSkipsNormalBackgroundRefresh(t *testing.T) {
	t.Parallel()

	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	auth := &Auth{
		ID:              "codex-background-skip",
		Provider:        "codex",
		LastRefreshedAt: now.Add(-8 * 24 * time.Hour),
		Metadata: map[string]any{
			"expires_at": now.Add(time.Minute),
		},
	}

	if got := manager.shouldRefresh(auth, now); got {
		t.Fatalf("shouldRefresh() = true, want false")
	}
}

func TestManager_shouldRefresh_CodexTokenInvalidatedStillUsesBackgroundProbe(t *testing.T) {
	t.Parallel()

	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	auth := &Auth{
		ID:       "codex-token-invalidated",
		Provider: "codex",
		LastError: &Error{
			Code:       auth401KindTokenInvalidated,
			Message:    auth401KindTokenInvalidated,
			HTTPStatus: http.StatusUnauthorized,
		},
		Unavailable:      true,
		NextRefreshAfter: now.Add(-time.Minute),
		NextRetryAfter:   now.Add(-time.Minute),
	}

	if got := manager.shouldRefresh(auth, now); !got {
		t.Fatalf("shouldRefresh() = false, want true")
	}
}

func TestManager_prepareAuthForExecution_RefreshesCodexNearExpiry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	refreshCalls := 0
	manager.RegisterExecutor(codexRefreshV6TestExecutor{
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			refreshCalls++
			updated := auth.Clone()
			if updated.Metadata == nil {
				updated.Metadata = make(map[string]any)
			}
			updated.Metadata["expires_at"] = now.Add(time.Hour).Format(time.RFC3339)
			return updated, nil
		},
	})

	auth := &Auth{
		ID:       "codex-near-expiry",
		Provider: "codex",
		Metadata: map[string]any{
			"expires_at": now.Add(time.Minute).Format(time.RFC3339),
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	prepared, err := manager.prepareAuthForExecution(ctx, auth)
	if err != nil {
		t.Fatalf("prepareAuthForExecution() error = %v", err)
	}
	if prepared == nil {
		t.Fatal("prepareAuthForExecution() auth = nil")
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshCalls)
	}
	if prepared.LastRefreshedAt.IsZero() {
		t.Fatalf("LastRefreshedAt = zero, want updated timestamp")
	}
}

func TestManager_prepareAuthForExecution_RefreshesCodexWhenLastRefreshIsStale(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	refreshCalls := 0
	manager.RegisterExecutor(codexRefreshV6TestExecutor{
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			refreshCalls++
			return auth.Clone(), nil
		},
	})

	auth := &Auth{
		ID:              "codex-stale-refresh",
		Provider:        "codex",
		LastRefreshedAt: now.Add(-8 * 24 * time.Hour),
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	prepared, err := manager.prepareAuthForExecution(ctx, auth)
	if err != nil {
		t.Fatalf("prepareAuthForExecution() error = %v", err)
	}
	if prepared == nil {
		t.Fatal("prepareAuthForExecution() auth = nil")
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshCalls)
	}
}

func TestManager_selectCodexColdKeepaliveIDs_PicksOldestCoverageBatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(codexRefreshV6TestExecutor{})

	entries := []*Auth{
		{ID: "oldest-a", Provider: "codex", LastRefreshedAt: now.Add(-10 * 24 * time.Hour)},
		{ID: "oldest-b", Provider: "codex", LastRefreshedAt: now.Add(-9 * 24 * time.Hour)},
		{ID: "recent-skip", Provider: "codex", LastRefreshedAt: now.Add(-12 * time.Hour)},
	}
	for i := 0; i < 27; i++ {
		entries = append(entries, &Auth{
			ID:              "mid-" + time.Date(2000, 1, 1, 0, 0, i, 0, time.UTC).Format("150405"),
			Provider:        "codex",
			LastRefreshedAt: now.Add(-48 * time.Hour),
		})
	}
	for _, auth := range entries {
		if _, err := manager.Register(ctx, auth); err != nil {
			t.Fatalf("register auth %s: %v", auth.ID, err)
		}
	}

	got := manager.selectCodexColdKeepaliveIDs(now)
	if len(got) != 2 {
		t.Fatalf("len(selectCodexColdKeepaliveIDs()) = %d, want 2", len(got))
	}
	if got[0] != "oldest-a" || got[1] != "oldest-b" {
		t.Fatalf("selectCodexColdKeepaliveIDs() = %v, want [oldest-a oldest-b]", got)
	}
}

func TestManager_selectCodexColdKeepaliveIDs_UsesRecentAttemptActivity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(codexRefreshV6TestExecutor{})

	entries := []*Auth{
		{
			ID:              "attempted-recently",
			Provider:        "codex",
			LastRefreshedAt: now.Add(-10 * 24 * time.Hour),
			Metadata: map[string]any{
				"last_refresh_attempt_at": now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			},
		},
		{ID: "oldest-a", Provider: "codex", LastRefreshedAt: now.Add(-9 * 24 * time.Hour)},
		{ID: "oldest-b", Provider: "codex", LastRefreshedAt: now.Add(-8 * 24 * time.Hour)},
	}
	for i := 0; i < 27; i++ {
		entries = append(entries, &Auth{
			ID:              "mid-attempt-" + time.Date(2000, 1, 1, 0, 0, i, 0, time.UTC).Format("150405"),
			Provider:        "codex",
			LastRefreshedAt: now.Add(-48 * time.Hour),
		})
	}
	for _, auth := range entries {
		if _, err := manager.Register(ctx, auth); err != nil {
			t.Fatalf("register auth %s: %v", auth.ID, err)
		}
	}

	got := manager.selectCodexColdKeepaliveIDs(now)
	if len(got) != 2 {
		t.Fatalf("len(selectCodexColdKeepaliveIDs()) = %d, want 2", len(got))
	}
	if got[0] != "oldest-a" || got[1] != "oldest-b" {
		t.Fatalf("selectCodexColdKeepaliveIDs() = %v, want [oldest-a oldest-b]", got)
	}
}

func TestManager_executeMixedOnce_CodexSoftRefreshFailureFailsOpen(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &firstAuthSelector{}, nil)
	executedAuthIDs := make([]string, 0, 1)
	refreshCalls := 0
	manager.RegisterExecutor(codexRefreshV6TestExecutor{
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			refreshCalls++
			return nil, errors.New("refresh failed")
		},
		executeFn: func(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			executedAuthIDs = append(executedAuthIDs, auth.ID)
			return cliproxyexecutor.Response{}, nil
		},
	})

	authA := &Auth{
		ID:       "auth-a",
		Provider: "codex",
		Metadata: map[string]any{
			"expires_at": now.Add(time.Minute).Format(time.RFC3339),
		},
	}
	authB := &Auth{
		ID:       "auth-b",
		Provider: "codex",
		Metadata: map[string]any{
			"expires_at": now.Add(time.Hour).Format(time.RFC3339),
		},
	}
	if _, err := manager.Register(ctx, authA); err != nil {
		t.Fatalf("register auth-a: %v", err)
	}
	if _, err := manager.Register(ctx, authB); err != nil {
		t.Fatalf("register auth-b: %v", err)
	}

	if _, err := manager.executeMixedOnce(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}, 2); err != nil {
		t.Fatalf("executeMixedOnce() error = %v", err)
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshCalls)
	}
	if len(executedAuthIDs) != 1 || executedAuthIDs[0] != "auth-a" {
		t.Fatalf("executed auth ids = %v, want [auth-a]", executedAuthIDs)
	}

	updated, ok := manager.GetByID("auth-a")
	if !ok || updated == nil {
		t.Fatalf("GetByID(auth-a) returned no auth")
	}
	if updated.NextRefreshAfter.IsZero() || !updated.NextRefreshAfter.After(now) {
		t.Fatalf("auth-a NextRefreshAfter = %v, want future cooldown", updated.NextRefreshAfter)
	}
}

func TestManager_executeMixedOnce_CodexExpiredRefreshFailureFallsBackToNextAuth(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &firstAuthSelector{}, nil)
	executedAuthIDs := make([]string, 0, 1)
	manager.RegisterExecutor(codexRefreshV6TestExecutor{
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			if auth.ID == "auth-a" {
				return nil, errors.New("refresh failed")
			}
			return auth.Clone(), nil
		},
		executeFn: func(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			executedAuthIDs = append(executedAuthIDs, auth.ID)
			return cliproxyexecutor.Response{}, nil
		},
	})

	authA := &Auth{
		ID:       "auth-a",
		Provider: "codex",
		Metadata: map[string]any{
			"expires_at": now.Add(-time.Minute).Format(time.RFC3339),
		},
	}
	authB := &Auth{
		ID:       "auth-b",
		Provider: "codex",
		Metadata: map[string]any{
			"expires_at": now.Add(time.Hour).Format(time.RFC3339),
		},
	}
	if _, err := manager.Register(ctx, authA); err != nil {
		t.Fatalf("register auth-a: %v", err)
	}
	if _, err := manager.Register(ctx, authB); err != nil {
		t.Fatalf("register auth-b: %v", err)
	}

	if _, err := manager.executeMixedOnce(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}, 2); err != nil {
		t.Fatalf("executeMixedOnce() error = %v", err)
	}
	if len(executedAuthIDs) != 1 || executedAuthIDs[0] != "auth-b" {
		t.Fatalf("executed auth ids = %v, want [auth-b]", executedAuthIDs)
	}
}

func TestManager_prepareAuthForExecution_CodexHardRefreshWaitsForSemaphore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.refreshSemaphore = make(chan struct{}, 1)
	manager.refreshSemaphore <- struct{}{}
	refreshCalls := 0
	manager.RegisterExecutor(codexRefreshV6TestExecutor{
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			refreshCalls++
			updated := auth.Clone()
			if updated.Metadata == nil {
				updated.Metadata = make(map[string]any)
			}
			updated.Metadata["expires_at"] = now.Add(time.Hour).Format(time.RFC3339)
			return updated, nil
		},
	})

	auth := &Auth{
		ID:       "hard-wait-auth",
		Provider: "codex",
		Metadata: map[string]any{
			"expires_at": now.Add(-time.Minute).Format(time.RFC3339),
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	go func() {
		time.Sleep(150 * time.Millisecond)
		<-manager.refreshSemaphore
	}()

	start := time.Now()
	prepared, err := manager.prepareAuthForExecution(ctx, auth)
	if err != nil {
		t.Fatalf("prepareAuthForExecution() error = %v", err)
	}
	if prepared == nil {
		t.Fatal("prepareAuthForExecution() auth = nil")
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshCalls)
	}
	if prepared.LastRefreshedAt.IsZero() {
		t.Fatalf("LastRefreshedAt = zero, want updated timestamp")
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Fatalf("prepareAuthForExecution() returned too early, wait duration = %v", time.Since(start))
	}
}

func TestManager_prepareAuthForExecution_CodexHardRefreshWaitsForExistingPendingResult(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(codexRefreshV6TestExecutor{})

	auth := &Auth{
		ID:               "hard-pending-auth",
		Provider:         "codex",
		NextRefreshAfter: now.Add(30 * time.Second),
		Metadata: map[string]any{
			"expires_at": now.Add(-time.Minute).Format(time.RFC3339),
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	go func() {
		time.Sleep(150 * time.Millisecond)
		updated := auth.Clone()
		updated.NextRefreshAfter = time.Time{}
		if updated.Metadata == nil {
			updated.Metadata = make(map[string]any)
		}
		updated.Metadata["expires_at"] = now.Add(time.Hour).Format(time.RFC3339)
		updated.LastRefreshedAt = time.Now()
		_, _ = manager.Update(context.Background(), updated)
	}()

	start := time.Now()
	prepared, err := manager.prepareAuthForExecution(ctx, auth)
	if err != nil {
		t.Fatalf("prepareAuthForExecution() error = %v", err)
	}
	if prepared == nil {
		t.Fatal("prepareAuthForExecution() auth = nil")
	}
	if prepared.LastRefreshedAt.IsZero() {
		t.Fatalf("LastRefreshedAt = zero, want updated timestamp")
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Fatalf("prepareAuthForExecution() returned too early, wait duration = %v", time.Since(start))
	}
}

func TestManager_prepareAuthForExecution_CodexHardRefreshPropagatesContextCancelWhileWaiting(t *testing.T) {
	t.Parallel()

	now := time.Now()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.refreshSemaphore = make(chan struct{}, 1)
	manager.refreshSemaphore <- struct{}{}
	manager.RegisterExecutor(codexRefreshV6TestExecutor{
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			t.Fatal("refresh should not be called after context cancellation")
			return nil, nil
		},
	})

	auth := &Auth{
		ID:       "hard-cancel-auth",
		Provider: "codex",
		Metadata: map[string]any{
			"expires_at": now.Add(-time.Minute).Format(time.RFC3339),
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	prepared, err := manager.prepareAuthForExecution(ctx, auth)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("prepareAuthForExecution() error = %v, want context.Canceled", err)
	}
	if prepared != nil {
		t.Fatalf("prepareAuthForExecution() auth = %v, want nil", prepared)
	}
}

func TestManager_ExecuteCount_CodexDoesNotPreflightRefresh(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	manager := NewManager(nil, &firstAuthSelector{}, nil)
	refreshCalls := 0
	countCalls := 0
	manager.RegisterExecutor(codexRefreshV6TestExecutor{
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			refreshCalls++
			return auth.Clone(), nil
		},
		countFn: func(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			countCalls++
			return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
		},
	})

	auth := &Auth{
		ID:       "count-auth",
		Provider: "codex",
		Metadata: map[string]any{
			"expires_at": now.Add(time.Minute).Format(time.RFC3339),
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	resp, err := manager.ExecuteCount(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("ExecuteCount() error = %v", err)
	}
	if refreshCalls != 0 {
		t.Fatalf("refresh calls = %d, want 0", refreshCalls)
	}
	if countCalls != 1 {
		t.Fatalf("count calls = %d, want 1", countCalls)
	}
	if string(resp.Payload) != "count-auth" {
		t.Fatalf("ExecuteCount() payload = %q, want %q", string(resp.Payload), "count-auth")
	}
}
