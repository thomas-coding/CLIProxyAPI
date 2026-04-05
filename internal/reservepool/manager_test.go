package reservepool

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestPromoteToProductionOverwritesExistingFile(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	reserveName := "replace-me.json"
	reservePayload := marshalReserveAuthFixture(t, map[string]any{
		"email":        "reserve@example.com",
		"access_token": "reserve-token",
	})
	productionPayload := []byte(`{"type":"codex","email":"old@example.com","access_token":"old-token"}`)

	if err := os.WriteFile(filepath.Join(reserveDir, reserveName), reservePayload, 0o600); err != nil {
		t.Fatalf("write reserve auth: %v", err)
	}
	if err := os.WriteFile(filepath.Join(authDir, reserveName), productionPayload, 0o600); err != nil {
		t.Fatalf("write production auth: %v", err)
	}

	manager := NewManager(&config.Config{AuthDir: authDir}, nil)
	auths, err := manager.List(context.Background())
	if err != nil {
		t.Fatalf("list reserve auths: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("reserve auth count = %d, want 1", len(auths))
	}

	targetPath, err := manager.promoteToProduction(auths[0])
	if err != nil {
		t.Fatalf("promoteToProduction: %v", err)
	}

	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read promoted auth: %v", err)
	}
	if string(got) != string(reservePayload) {
		t.Fatalf("promoted payload = %s, want %s", string(got), string(reservePayload))
	}
	if _, err = os.Stat(filepath.Join(reserveDir, reserveName)); !os.IsNotExist(err) {
		t.Fatalf("expected reserve auth to be removed, stat err = %v", err)
	}
}

func TestUploadRejectsReserveAuthWithoutRefreshToken(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	manager := NewManager(&config.Config{AuthDir: authDir}, nil)

	err := manager.Upload("broken.json", []byte(`{"type":"codex","access_token":"only-access-token"}`))
	if err == nil {
		t.Fatal("Upload returned nil error, want validation error")
	}
	if !strings.Contains(err.Error(), "refresh_token") {
		t.Fatalf("Upload error = %v, want refresh_token validation", err)
	}
}

func TestUploadWaitsForSameNameLock(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	manager := NewManager(&config.Config{AuthDir: authDir}, nil)
	name := "locked.json"
	payload := marshalReserveAuthFixture(t, map[string]any{
		"email":        "locked@example.com",
		"access_token": "locked-token",
	})

	unlock := manager.lockAuth(name)
	done := make(chan error, 1)
	go func() {
		done <- manager.Upload(name, payload)
	}()

	select {
	case err := <-done:
		t.Fatalf("Upload completed before lock release: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Upload returned error after lock release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Upload did not complete after lock release")
	}

	raw, err := os.ReadFile(filepath.Join(authDir, reserveDirName, name))
	if err != nil {
		t.Fatalf("read uploaded auth: %v", err)
	}
	if string(raw) != string(payload) {
		t.Fatalf("uploaded payload = %s, want %s", string(raw), string(payload))
	}
}

func TestRefreshUsageMoves401IntoExternalWarehouse(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	name := "invalid.json"
	payload := marshalReserveAuthFixture(t, map[string]any{
		"email":        "invalid@example.com",
		"access_token": "invalid-token",
	})
	if err := os.WriteFile(filepath.Join(reserveDir, name), payload, 0o600); err != nil {
		t.Fatalf("write reserve auth: %v", err)
	}

	manager := NewManager(
		&config.Config{AuthDir: authDir},
		nil,
		WithUsageProbe(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*usageProbeResponse, error) {
			return &usageProbeResponse{
				StatusCode: 401,
				Body:       `{"error":{"message":"Your authentication token has been invalidated.","code":"token_invalidated"},"status":401}`,
			}, nil
		}),
	)

	results, err := manager.RefreshUsage(context.Background(), []string{name})
	if err != nil {
		t.Fatalf("RefreshUsage: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if !results[0].Removed {
		t.Fatalf("Removed = false, want true")
	}

	if _, err = os.Stat(filepath.Join(reserveDir, name)); !os.IsNotExist(err) {
		t.Fatalf("expected reserve auth to be removed, stat err = %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(authDir, deletedAuthBackupDirName, external401DirName))
	if err != nil {
		t.Fatalf("read external 401 dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("external 401 file count = %d, want 1", len(entries))
	}
}

func TestRefreshUsageRefreshesStaleTokenBeforeRemovingAuth(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	name := "stale.json"
	payload := marshalReserveAuthFixture(t, map[string]any{
		"email":        "stale@example.com",
		"access_token": "stale-token",
	})
	if err := os.WriteFile(filepath.Join(reserveDir, name), payload, 0o600); err != nil {
		t.Fatalf("write reserve auth: %v", err)
	}

	manager := NewManager(
		&config.Config{AuthDir: authDir},
		nil,
		WithUsageProbe(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*usageProbeResponse, error) {
			token, _ := auth.Metadata["access_token"].(string)
			if token == "fresh-token" {
				return &usageProbeResponse{StatusCode: 200, Body: `{"plan_type":"plus"}`}, nil
			}
			return &usageProbeResponse{
				StatusCode: 401,
				Body:       `{"error":{"message":"expired access token"},"status":401}`,
			}, nil
		}),
		WithRefreshAuth(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*coreauth.Auth, error) {
			updated := auth.Clone()
			if updated.Metadata == nil {
				updated.Metadata = map[string]any{}
			}
			updated.Metadata["access_token"] = "fresh-token"
			return updated, nil
		}),
	)

	results, err := manager.RefreshUsage(context.Background(), []string{name})
	if err != nil {
		t.Fatalf("RefreshUsage: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if results[0].Removed {
		t.Fatal("Removed = true, want false")
	}
	if results[0].StatusCode != 200 {
		t.Fatalf("StatusCode = %d, want 200", results[0].StatusCode)
	}

	raw, err := os.ReadFile(filepath.Join(reserveDir, name))
	if err != nil {
		t.Fatalf("read refreshed reserve auth: %v", err)
	}
	var persisted map[string]any
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("unmarshal refreshed reserve auth: %v", err)
	}
	if got, _ := persisted["access_token"].(string); got != "fresh-token" {
		t.Fatalf("persisted access_token = %q, want fresh-token", got)
	}
}

func TestRunReplenishRoundUsageGatePromotesOnlyHTTP200(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	reserveName := "candidate.json"
	reservePayload := marshalReserveAuthFixture(t, map[string]any{
		"email":        "candidate@example.com",
		"access_token": "candidate-token",
	})
	if err := os.WriteFile(filepath.Join(reserveDir, reserveName), reservePayload, 0o600); err != nil {
		t.Fatalf("write reserve auth: %v", err)
	}

	productionName := "prod-1.json"
	productionPath := filepath.Join(authDir, productionName)
	if err := os.WriteFile(productionPath, marshalReserveAuthFixture(t, map[string]any{
		"email": "prod@example.com",
	}), 0o600); err != nil {
		t.Fatalf("write production auth: %v", err)
	}

	authManager := coreauth.NewManager(nil, nil, nil)
	if _, err := authManager.Register(context.Background(), &coreauth.Auth{
		ID:       productionName,
		FileName: productionName,
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": productionPath,
		},
	}); err != nil {
		t.Fatalf("register production auth: %v", err)
	}

	manager := NewManager(
		&config.Config{
			AuthDir: authDir,
			ReservePool: config.ReservePoolConfig{
				ProductionAvailableThreshold: 2,
				ReplenishBatchSize:           1,
				ValidateUsageBeforePromotion: true,
			},
		},
		authManager,
		WithUsageProbe(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*usageProbeResponse, error) {
			return &usageProbeResponse{StatusCode: 200, Body: `{"plan_type":"plus"}`}, nil
		}),
	)

	manager.runReplenishRound(context.Background())

	if _, err := os.Stat(filepath.Join(authDir, reserveName)); err != nil {
		t.Fatalf("expected promoted auth in production dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(reserveDir, reserveName)); !os.IsNotExist(err) {
		t.Fatalf("expected reserve auth removed after promotion, stat err = %v", err)
	}
}

func TestRunReplenishRoundUsageGateRefreshesStaleTokenBeforePromotion(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	reserveName := "candidate.json"
	reservePayload := marshalReserveAuthFixture(t, map[string]any{
		"email":        "candidate@example.com",
		"access_token": "stale-token",
	})
	if err := os.WriteFile(filepath.Join(reserveDir, reserveName), reservePayload, 0o600); err != nil {
		t.Fatalf("write reserve auth: %v", err)
	}

	productionName := "prod-1.json"
	productionPath := filepath.Join(authDir, productionName)
	if err := os.WriteFile(productionPath, marshalReserveAuthFixture(t, map[string]any{
		"email": "prod@example.com",
	}), 0o600); err != nil {
		t.Fatalf("write production auth: %v", err)
	}

	authManager := coreauth.NewManager(nil, nil, nil)
	if _, err := authManager.Register(context.Background(), &coreauth.Auth{
		ID:       productionName,
		FileName: productionName,
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": productionPath,
		},
	}); err != nil {
		t.Fatalf("register production auth: %v", err)
	}

	manager := NewManager(
		&config.Config{
			AuthDir: authDir,
			ReservePool: config.ReservePoolConfig{
				ProductionAvailableThreshold: 2,
				ReplenishBatchSize:           1,
				ValidateUsageBeforePromotion: true,
			},
		},
		authManager,
		WithUsageProbe(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*usageProbeResponse, error) {
			token, _ := auth.Metadata["access_token"].(string)
			if token == "fresh-token" {
				return &usageProbeResponse{StatusCode: 200, Body: `{"plan_type":"plus"}`}, nil
			}
			return &usageProbeResponse{
				StatusCode: 401,
				Body:       `{"error":{"message":"expired access token"},"status":401}`,
			}, nil
		}),
		WithRefreshAuth(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*coreauth.Auth, error) {
			updated := auth.Clone()
			if updated.Metadata == nil {
				updated.Metadata = map[string]any{}
			}
			updated.Metadata["access_token"] = "fresh-token"
			return updated, nil
		}),
	)

	manager.runReplenishRound(context.Background())

	raw, err := os.ReadFile(filepath.Join(authDir, reserveName))
	if err != nil {
		t.Fatalf("read promoted auth: %v", err)
	}
	var promoted map[string]any
	if err := json.Unmarshal(raw, &promoted); err != nil {
		t.Fatalf("unmarshal promoted auth: %v", err)
	}
	if got, _ := promoted["access_token"].(string); got != "fresh-token" {
		t.Fatalf("promoted access_token = %q, want fresh-token", got)
	}
	if _, err := os.Stat(filepath.Join(reserveDir, reserveName)); !os.IsNotExist(err) {
		t.Fatalf("expected reserve auth removed after promotion, stat err = %v", err)
	}
}

func TestRunReplenishRoundWithoutUsageGateRefreshesBeforePromotion(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	reserveName := "candidate.json"
	reservePayload := marshalReserveAuthFixture(t, map[string]any{
		"email": "candidate@example.com",
	})
	if err := os.WriteFile(filepath.Join(reserveDir, reserveName), reservePayload, 0o600); err != nil {
		t.Fatalf("write reserve auth: %v", err)
	}

	productionName := "prod-1.json"
	productionPath := filepath.Join(authDir, productionName)
	if err := os.WriteFile(productionPath, marshalReserveAuthFixture(t, map[string]any{
		"email": "prod@example.com",
	}), 0o600); err != nil {
		t.Fatalf("write production auth: %v", err)
	}

	authManager := coreauth.NewManager(nil, nil, nil)
	if _, err := authManager.Register(context.Background(), &coreauth.Auth{
		ID:       productionName,
		FileName: productionName,
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": productionPath,
		},
	}); err != nil {
		t.Fatalf("register production auth: %v", err)
	}

	refreshCalls := 0
	manager := NewManager(
		&config.Config{
			AuthDir: authDir,
			ReservePool: config.ReservePoolConfig{
				ProductionAvailableThreshold: 2,
				ReplenishBatchSize:           1,
				ValidateUsageBeforePromotion: false,
			},
		},
		authManager,
		WithRefreshAuth(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*coreauth.Auth, error) {
			refreshCalls++
			updated := auth.Clone()
			if updated.Metadata == nil {
				updated.Metadata = map[string]any{}
			}
			updated.Metadata["access_token"] = "fresh-token"
			return updated, nil
		}),
	)

	manager.runReplenishRound(context.Background())

	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want 1", refreshCalls)
	}

	raw, err := os.ReadFile(filepath.Join(authDir, reserveName))
	if err != nil {
		t.Fatalf("read promoted auth: %v", err)
	}
	var promoted map[string]any
	if err := json.Unmarshal(raw, &promoted); err != nil {
		t.Fatalf("unmarshal promoted auth: %v", err)
	}
	if got, _ := promoted["access_token"].(string); got != "fresh-token" {
		t.Fatalf("promoted access_token = %q, want fresh-token", got)
	}
	if _, err := os.Stat(filepath.Join(reserveDir, reserveName)); !os.IsNotExist(err) {
		t.Fatalf("expected reserve auth removed after promotion, stat err = %v", err)
	}
}

func TestCountProductionAvailableMatchesReportRule(t *testing.T) {
	t.Parallel()

	manager := coreauth.NewManager(nil, nil, nil)
	ctx := context.Background()

	cases := []*coreauth.Auth{
		{
			ID:       "count-me.json",
			FileName: "count-me.json",
			Provider: "codex",
			Status:   coreauth.StatusActive,
		},
		{
			ID:          "unavailable.json",
			FileName:    "unavailable.json",
			Provider:    "codex",
			Status:      coreauth.StatusActive,
			Unavailable: true,
		},
		{
			ID:       "disabled.json",
			FileName: "disabled.json",
			Provider: "codex",
			Status:   coreauth.StatusDisabled,
			Disabled: true,
		},
		{
			ID:       "other-provider.json",
			FileName: "other-provider.json",
			Provider: "gemini",
			Status:   coreauth.StatusActive,
		},
	}

	for _, auth := range cases {
		if _, err := manager.Register(ctx, auth); err != nil {
			t.Fatalf("register %s: %v", auth.ID, err)
		}
	}

	if got := countProductionAvailable(manager); got != 1 {
		t.Fatalf("countProductionAvailable = %d, want 1", got)
	}
}

func TestRunKeepAliveSkipsAuthStillInBackoff(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	name := "backoff.json"
	payload := marshalReserveAuthFixture(t, map[string]any{
		"email":        "backoff@example.com",
		"access_token": "access-token",
	})
	if err := os.WriteFile(filepath.Join(reserveDir, name), payload, 0o600); err != nil {
		t.Fatalf("write reserve auth: %v", err)
	}

	refreshCalls := 0
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	manager := NewManager(
		&config.Config{AuthDir: authDir},
		nil,
		WithNow(func() time.Time { return now }),
		WithRefreshAuth(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*coreauth.Auth, error) {
			refreshCalls++
			return auth, nil
		}),
	)

	auths, err := manager.List(context.Background())
	if err != nil {
		t.Fatalf("list reserve auths: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("reserve auth count = %d, want 1", len(auths))
	}
	if err := manager.markTransient(auths[0], http.StatusTooManyRequests, "too many requests", 24*time.Hour); err != nil {
		t.Fatalf("markTransient: %v", err)
	}

	manager.runKeepAlive(context.Background())

	if refreshCalls != 0 {
		t.Fatalf("refreshCalls = %d, want 0", refreshCalls)
	}
}

func TestRunKeepAliveRefreshesOnlyLimitedBatch(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	total := 50
	for i := 0; i < total; i++ {
		name := filepath.Join(reserveDir, fmt.Sprintf("auth-%02d.json", i))
		payload := marshalReserveAuthFixture(t, map[string]any{
			"email":        fmt.Sprintf("user-%02d@example.com", i),
			"access_token": fmt.Sprintf("token-%02d", i),
		})
		if err := os.WriteFile(name, payload, 0o600); err != nil {
			t.Fatalf("write reserve auth %d: %v", i, err)
		}
	}

	refreshCalls := 0
	manager := NewManager(
		&config.Config{AuthDir: authDir},
		nil,
		WithRefreshAuth(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*coreauth.Auth, error) {
			refreshCalls++
			return auth, nil
		}),
	)

	manager.runKeepAlive(context.Background())

	want := keepAliveBatchSize(total)
	if refreshCalls != want {
		t.Fatalf("refreshCalls = %d, want %d", refreshCalls, want)
	}
}

func TestRunKeepAliveStopsWhenRoundBudgetIsSpent(t *testing.T) {
	t.Parallel()

	authDir := t.TempDir()
	reserveDir := filepath.Join(authDir, reserveDirName)
	if err := os.MkdirAll(reserveDir, 0o700); err != nil {
		t.Fatalf("mkdir reserve dir: %v", err)
	}

	total := 200
	for i := 0; i < total; i++ {
		name := filepath.Join(reserveDir, fmt.Sprintf("auth-%03d.json", i))
		payload := marshalReserveAuthFixture(t, map[string]any{
			"email":        fmt.Sprintf("budget-%03d@example.com", i),
			"access_token": fmt.Sprintf("token-%03d", i),
		})
		if err := os.WriteFile(name, payload, 0o600); err != nil {
			t.Fatalf("write reserve auth %d: %v", i, err)
		}
	}

	refreshCalls := 0
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	manager := NewManager(
		&config.Config{AuthDir: authDir},
		nil,
		WithNow(func() time.Time { return now }),
		WithRefreshAuth(func(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) (*coreauth.Auth, error) {
			refreshCalls++
			now = now.Add(2 * time.Minute)
			return auth, nil
		}),
	)

	manager.runKeepAlive(context.Background())

	if refreshCalls != 3 {
		t.Fatalf("refreshCalls = %d, want 3", refreshCalls)
	}
}

func marshalReserveAuthFixture(t *testing.T, overrides map[string]any) []byte {
	t.Helper()

	payload := map[string]any{
		"type":          "codex",
		"email":         "fixture@example.com",
		"access_token":  "access-token",
		"refresh_token": "refresh-token",
		"id_token":      testCodexIDToken(),
	}
	for key, value := range overrides {
		payload[key] = value
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

func testCodexIDToken() string {
	header := `{"alg":"none","typ":"JWT"}`
	payload := map[string]any{
		"chatgpt_account_id": "acct-reserve",
		"chatgpt_plan_type":  "plus",
		"exp":                time.Now().Add(24 * time.Hour).Unix(),
	}
	rawPayload, _ := json.Marshal(payload)
	return base64URL(header) + "." + base64URL(string(rawPayload)) + "."
}

func base64URL(value string) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(value)), "=")
}
