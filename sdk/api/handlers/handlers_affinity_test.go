package handlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestRequestExecutionMetadata_IncludesAffinityKey(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest("POST", "/v1/responses", nil)
	req.Header.Set("Idempotency-Key", "idem-1")
	req.Header.Set(affinityKeyHeader, "user:15")
	req.Header.Set("Authorization", "Bearer trusted-key")
	ginCtx.Request = req

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	meta := requestExecutionMetadata(ctx, &sdkconfig.SDKConfig{
		Affinity: sdkconfig.AffinityConfig{
			TrustedClientKeys: []string{"trusted-key"},
		},
	})

	if got := meta[idempotencyKeyMetadataKey]; got != "idem-1" {
		t.Fatalf("metadata[%q] = %v, want %q", idempotencyKeyMetadataKey, got, "idem-1")
	}
	if got := meta[coreexecutor.AffinityKeyMetadataKey]; got != "user:15" {
		t.Fatalf("metadata[%q] = %v, want %q", coreexecutor.AffinityKeyMetadataKey, got, "user:15")
	}
}

func TestRequestExecutionMetadata_IgnoresAffinityKeyFromUntrustedClient(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest("POST", "/v1/responses", nil)
	req.Header.Set("Idempotency-Key", "idem-1")
	req.Header.Set(affinityKeyHeader, "user:15")
	req.Header.Set("Authorization", "Bearer untrusted-key")
	ginCtx.Request = req

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	meta := requestExecutionMetadata(ctx, &sdkconfig.SDKConfig{
		Affinity: sdkconfig.AffinityConfig{
			TrustedClientKeys: []string{"trusted-key"},
		},
	})

	if got := meta[idempotencyKeyMetadataKey]; got != "idem-1" {
		t.Fatalf("metadata[%q] = %v, want %q", idempotencyKeyMetadataKey, got, "idem-1")
	}
	if got := meta[coreexecutor.AffinityKeyMetadataKey]; got != nil {
		t.Fatalf("metadata[%q] = %v, want nil", coreexecutor.AffinityKeyMetadataKey, got)
	}
}
