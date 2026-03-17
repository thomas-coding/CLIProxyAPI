package handlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestRequestExecutionMetadata_IncludesStickyUserKey(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/v1/models", nil)
	ctx.Request.Header.Set("X-NewAPI-User-ID", "42")

	meta := requestExecutionMetadata(context.WithValue(context.Background(), "gin", ctx))
	if got, ok := meta[coreexecutor.StickyUserKeyMetadataKey].(string); !ok || got != "42" {
		t.Fatalf("sticky metadata = %#v, want %q", meta[coreexecutor.StickyUserKeyMetadataKey], "42")
	}
}
