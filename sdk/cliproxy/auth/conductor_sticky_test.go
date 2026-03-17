package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type stickyTestExecutor struct{}

func (stickyTestExecutor) Identifier() string { return "gemini" }

func (stickyTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (stickyTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (stickyTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (stickyTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (stickyTestExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestManagerPickNextMixed_StickyPrefersExistingAssignment(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(stickyTestExecutor{})
	registerSchedulerModels(t, "gemini", "gemini-2.5-pro", "auth-a", "auth-b")
	_, _ = manager.Register(context.Background(), &Auth{ID: "auth-a", Provider: "gemini"})
	_, _ = manager.Register(context.Background(), &Auth{ID: "auth-b", Provider: "gemini"})
	manager.assignStickyAuth("user-1", "auth-b", time.Now().Add(time.Minute))

	selected, _, _, err := manager.pickNextMixed(context.Background(), []string{"gemini"}, "gemini-2.5-pro", cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.StickyUserKeyMetadataKey: "user-1"},
	}, map[string]struct{}{})
	if err != nil {
		t.Fatalf("pickNextMixed() error = %v", err)
	}
	if selected == nil || selected.ID != "auth-b" {
		t.Fatalf("pickNextMixed() auth = %v, want auth-b", selected)
	}
}

func TestManagerPickNextMixed_StickyPrefersLeastBoundCandidate(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(stickyTestExecutor{})
	registerSchedulerModels(t, "gemini", "gemini-2.5-pro", "auth-a", "auth-b")
	_, _ = manager.Register(context.Background(), &Auth{ID: "auth-a", Provider: "gemini"})
	_, _ = manager.Register(context.Background(), &Auth{ID: "auth-b", Provider: "gemini"})
	manager.assignStickyAuth("user-existing", "auth-a", time.Now().Add(time.Minute))

	selected, _, _, err := manager.pickNextMixed(context.Background(), []string{"gemini"}, "gemini-2.5-pro", cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.StickyUserKeyMetadataKey: "user-new"},
	}, map[string]struct{}{})
	if err != nil {
		t.Fatalf("pickNextMixed() error = %v", err)
	}
	if selected == nil || selected.ID != "auth-b" {
		t.Fatalf("pickNextMixed() auth = %v, want auth-b", selected)
	}
}

func TestManagerMarkResult_ClearsStickyOnQuotaFailure(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.assignStickyAuth("user-1", "auth-a", time.Now().Add(time.Minute))

	manager.MarkResult(context.Background(), Result{
		AuthID:        "auth-a",
		StickyUserKey: "user-1",
		Success:       false,
		Error:         &Error{HTTPStatus: 429, Message: "rate limited"},
	})

	if got := manager.currentStickyAuthID("user-1", time.Now()); got != "" {
		t.Fatalf("currentStickyAuthID() = %q, want empty", got)
	}
	if got := manager.stickyCountForAuth("auth-a"); got != 0 {
		t.Fatalf("stickyCountForAuth() = %d, want 0", got)
	}
}

func TestManagerPickNextMixed_PrunesExpiredStickyCounts(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(stickyTestExecutor{})
	registerSchedulerModels(t, "gemini", "gemini-2.5-pro", "auth-a", "auth-b")
	_, _ = manager.Register(context.Background(), &Auth{ID: "auth-a", Provider: "gemini"})
	_, _ = manager.Register(context.Background(), &Auth{ID: "auth-b", Provider: "gemini"})
	manager.assignStickyAuth("user-expired", "auth-a", time.Now().Add(-time.Minute))
	manager.assignStickyAuth("user-active", "auth-b", time.Now().Add(time.Minute))

	selected, _, _, err := manager.pickNextMixed(context.Background(), []string{"gemini"}, "gemini-2.5-pro", cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.StickyUserKeyMetadataKey: "user-new"},
	}, map[string]struct{}{})
	if err != nil {
		t.Fatalf("pickNextMixed() error = %v", err)
	}
	if selected == nil || selected.ID != "auth-a" {
		t.Fatalf("pickNextMixed() auth = %v, want auth-a", selected)
	}
	if got := manager.stickyCountForAuth("auth-a"); got != 1 {
		t.Fatalf("stickyCountForAuth(auth-a) = %d, want 1", got)
	}
}
