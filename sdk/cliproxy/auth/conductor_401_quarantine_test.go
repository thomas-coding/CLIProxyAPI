package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
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

type quarantineWarehouseStore struct {
	root string
}

func (s *quarantineWarehouseStore) AuthDir() string {
	return s.root
}

func (s *quarantineWarehouseStore) List(context.Context) ([]*Auth, error) {
	return nil, nil
}

func (s *quarantineWarehouseStore) Save(_ context.Context, auth *Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	path, err := quarantineStorePath(s.root, auth)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	payload := auth.Metadata
	if payload == nil {
		payload = map[string]any{}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (s *quarantineWarehouseStore) Delete(_ context.Context, id string) error {
	path := strings.TrimSpace(id)
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.root, filepath.FromSlash(path))
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func quarantineStorePath(root string, auth *Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("auth is nil")
	}
	if auth.Attributes != nil {
		if path := strings.TrimSpace(auth.Attributes["path"]); path != "" {
			if filepath.IsAbs(path) {
				return path, nil
			}
			return filepath.Join(root, filepath.FromSlash(path)), nil
		}
	}
	name := strings.TrimSpace(auth.FileName)
	if name == "" {
		name = strings.TrimSpace(auth.ID)
	}
	if name == "" {
		return "", fmt.Errorf("auth path is empty")
	}
	if filepath.IsAbs(name) {
		return name, nil
	}
	return filepath.Join(root, filepath.FromSlash(name)), nil
}

func findArchivedWarehouseFile(t *testing.T, root string, fileName string) string {
	t.Helper()

	pattern := filepath.Join(root, deletedAuthBackupDirName, external401DirName, "*", fileName)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob archive path: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("archive matches = %v, want single match for %s", matches, fileName)
	}
	return matches[0]
}

type blockingArchiveStore struct {
	*quarantineWarehouseStore
	persistStarted chan struct{}
	releasePersist chan struct{}
	failPersist    error
}

func (s *blockingArchiveStore) PersistAuthFiles(context.Context, string, ...string) error {
	if s.persistStarted != nil {
		select {
		case <-s.persistStarted:
		default:
			close(s.persistStarted)
		}
	}
	if s.releasePersist != nil {
		<-s.releasePersist
	}
	return s.failPersist
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
	store := &quarantineWarehouseStore{root: t.TempDir()}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	auth := &Auth{
		ID:       "account-deactivated.json",
		FileName: "account-deactivated.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type":  "codex",
			"email": "account-deactivated@example.com",
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	sourcePath, err := quarantineStorePath(store.root, auth)
	if err != nil {
		t.Fatalf("quarantineStorePath: %v", err)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gpt-5-codex"}})
	defer reg.UnregisterClient(auth.ID)

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

	if updated, ok := manager.GetByID(auth.ID); ok || updated != nil {
		t.Fatalf("expected auth %q removed from manager after archive", auth.ID)
	}
	if _, err = os.Stat(sourcePath); !os.IsNotExist(err) {
		t.Fatalf("expected source auth removed, stat err = %v", err)
	}
	archivedPath := findArchivedWarehouseFile(t, store.root, "account-deactivated.json")
	if _, err = os.Stat(archivedPath); err != nil {
		t.Fatalf("expected archived auth file: %v", err)
	}
	if got := manager.List(); len(got) != 0 {
		t.Fatalf("manager.List() = %d auths, want 0", len(got))
	}
	if models := reg.GetModelsForClient(auth.ID); len(models) != 0 {
		t.Fatalf("expected registry models cleared after archive, got %d", len(models))
	}
}

func TestManager_MarkResult_HardExpiredCodexTokenExpiredArchivesAuth(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &quarantineWarehouseStore{root: t.TempDir()}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	auth := &Auth{
		ID:       "token-expired.json",
		FileName: "token-expired.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type":          "codex",
			"email":         "token-expired@example.com",
			"expired":       time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
			"refresh_token": "",
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	sourcePath, err := quarantineStorePath(store.root, auth)
	if err != nil {
		t.Fatalf("quarantineStorePath: %v", err)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gpt-5-codex"}})
	defer reg.UnregisterClient(auth.ID)

	manager.MarkResult(ctx, Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5-codex",
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusUnauthorized,
			Message:    `{"error":{"message":"Provided authentication token is expired. Please try signing in again.","code":"token_expired"},"status":401}`,
		},
	})

	if updated, ok := manager.GetByID(auth.ID); ok || updated != nil {
		t.Fatalf("expected auth %q removed from manager after archive", auth.ID)
	}
	if _, err = os.Stat(sourcePath); !os.IsNotExist(err) {
		t.Fatalf("expected source auth removed, stat err = %v", err)
	}
	archivedPath := findArchivedWarehouseFile(t, store.root, "token-expired.json")
	if _, err = os.Stat(archivedPath); err != nil {
		t.Fatalf("expected archived auth file: %v", err)
	}
	if got := manager.List(); len(got) != 0 {
		t.Fatalf("manager.List() = %d auths, want 0", len(got))
	}
	if models := reg.GetModelsForClient(auth.ID); len(models) != 0 {
		t.Fatalf("expected registry models cleared after archive, got %d", len(models))
	}
}

func TestManager_MarkResult_TokenExpiredWithRefreshTokenStaysModelScoped(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &quarantineWarehouseStore{root: t.TempDir()}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	auth := &Auth{
		ID:       "token-expired-refreshable.json",
		FileName: "token-expired-refreshable.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type":          "codex",
			"email":         "refreshable@example.com",
			"expired":       time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
			"refresh_token": "refresh-token",
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	sourcePath, err := quarantineStorePath(store.root, auth)
	if err != nil {
		t.Fatalf("quarantineStorePath: %v", err)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gpt-5-codex"}})
	defer reg.UnregisterClient(auth.ID)

	manager.MarkResult(ctx, Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5-codex",
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusUnauthorized,
			Message:    `{"error":{"message":"Provided authentication token is expired. Please try signing in again.","code":"token_expired"},"status":401}`,
		},
	})

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected auth %q to remain managed", auth.ID)
	}
	if got := authWide401Quarantine(updated); got != auth401KindNone {
		t.Fatalf("authWide401Quarantine() = %q, want none", got)
	}
	state := updated.ModelStates["gpt-5-codex"]
	if state == nil {
		t.Fatalf("expected model state recorded for gpt-5-codex")
	}
	if state.NextRetryAfter.IsZero() || !state.NextRetryAfter.After(time.Now()) {
		t.Fatalf("expected per-model retry cooldown, got %v", state.NextRetryAfter)
	}
	if _, err = os.Stat(sourcePath); err != nil {
		t.Fatalf("expected source auth to remain in place: %v", err)
	}
	pattern := filepath.Join(store.root, deletedAuthBackupDirName, external401DirName, "*", "token-expired-refreshable.json")
	if matches, err := filepath.Glob(pattern); err != nil {
		t.Fatalf("glob archive path: %v", err)
	} else if len(matches) != 0 {
		t.Fatalf("expected no archive file, got %v", matches)
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

func TestManager_refreshAuth_AccountDeactivatedMovesAuthToWarehouse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &quarantineWarehouseStore{root: t.TempDir()}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(quarantineTestExecutor{
		provider: "codex",
		refreshFn: func(ctx context.Context, auth *Auth) (*Auth, error) {
			return nil, &Error{
				HTTPStatus: http.StatusUnauthorized,
				Message:    `{"error":{"message":"Your account has been deactivated.","code":"account_deactivated"},"status":401}`,
			}
		},
	})

	auth := &Auth{
		ID:       "refresh-account-deactivated.json",
		FileName: "refresh-account-deactivated.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type":  "codex",
			"email": "refresh-account-deactivated@example.com",
		},
		LastError: &Error{
			Code:       auth401KindTokenInvalidated,
			Message:    auth401KindTokenInvalidated,
			HTTPStatus: http.StatusUnauthorized,
		},
		Unavailable:      true,
		NextRetryAfter:   time.Now().Add(24 * time.Hour),
		NextRefreshAfter: time.Now().Add(24 * time.Hour),
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	sourcePath, err := quarantineStorePath(store.root, auth)
	if err != nil {
		t.Fatalf("quarantineStorePath: %v", err)
	}

	manager.refreshAuth(ctx, auth.ID)

	if updated, ok := manager.GetByID(auth.ID); ok || updated != nil {
		t.Fatalf("expected auth %q removed from manager after refresh archive", auth.ID)
	}
	if _, err = os.Stat(sourcePath); !os.IsNotExist(err) {
		t.Fatalf("expected source auth removed, stat err = %v", err)
	}
	archivedPath := findArchivedWarehouseFile(t, store.root, "refresh-account-deactivated.json")
	if _, err = os.Stat(archivedPath); err != nil {
		t.Fatalf("expected archived refresh auth file: %v", err)
	}
}

func TestManager_MarkResult_AccountDeactivatedRemovesAuthBeforeArchiveSyncCompletes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &blockingArchiveStore{
		quarantineWarehouseStore: &quarantineWarehouseStore{root: t.TempDir()},
		persistStarted:           make(chan struct{}),
		releasePersist:           make(chan struct{}),
	}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(quarantineTestExecutor{provider: "codex"})

	auth := &Auth{
		ID:       "blocking-account-deactivated.json",
		FileName: "blocking-account-deactivated.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type":  "codex",
			"email": "blocking-account-deactivated@example.com",
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
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
	}()

	select {
	case <-store.persistStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for archive sync to start")
	}

	if updated, ok := manager.GetByID(auth.ID); ok || updated != nil {
		t.Fatalf("expected auth %q removed from manager before archive sync completed", auth.ID)
	}
	picked, _, errPick := manager.pickNext(ctx, "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick == nil || picked != nil {
		t.Fatalf("expected no auth available while archive sync is blocked, got auth=%v err=%v", picked, errPick)
	}

	close(store.releasePersist)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MarkResult to finish")
	}
}

func TestManager_MarkResult_AccountDeactivatedRestoreAuthWhenArchiveFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &blockingArchiveStore{
		quarantineWarehouseStore: &quarantineWarehouseStore{root: t.TempDir()},
		failPersist:              errors.New("archive sync failed"),
	}
	manager := NewManager(store, &RoundRobinSelector{}, nil)

	auth := &Auth{
		ID:       "restore-account-deactivated.json",
		FileName: "restore-account-deactivated.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type":  "codex",
			"email": "restore-account-deactivated@example.com",
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	sourcePath, err := quarantineStorePath(store.root, auth)
	if err != nil {
		t.Fatalf("quarantineStorePath: %v", err)
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
		t.Fatalf("expected auth restored after archive failure")
	}
	if authWide401Quarantine(updated) != auth401KindAccountDeactivated {
		t.Fatalf("quarantine kind = %q, want %q", authWide401Quarantine(updated), auth401KindAccountDeactivated)
	}
	if _, err = os.Stat(sourcePath); err != nil {
		t.Fatalf("expected source auth restored after archive failure: %v", err)
	}
}
