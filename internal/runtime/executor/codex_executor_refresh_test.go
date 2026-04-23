package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestCodexExecutorRefreshUsesResolvedRefreshToken(t *testing.T) {
	t.Parallel()

	exec := NewCodexExecutor(&config.Config{})
	tests := []struct {
		name string
		auth *cliproxyauth.Auth
	}{
		{
			name: "nested metadata token",
			auth: &cliproxyauth.Auth{
				Provider: "codex",
				Metadata: map[string]any{
					"token": map[string]any{
						"refresh_token": "nested-refresh-token",
					},
				},
			},
		},
		{
			name: "attribute refresh token",
			auth: &cliproxyauth.Auth{
				Provider: "codex",
				Attributes: map[string]string{
					"refresh_token": "attribute-refresh-token",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			updated, err := exec.Refresh(ctx, tt.auth)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Refresh() error = %v, want context.Canceled", err)
			}
			if updated != nil {
				t.Fatalf("Refresh() updated auth = %v, want nil on canceled refresh", updated)
			}
		})
	}
}
