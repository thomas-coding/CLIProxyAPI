package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
)

func TestGetAvailableModelsReturnsRuntimeRegistry(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient("mgmt-models-test-client", "codex", []*registry.ModelInfo{
		{
			ID:      "gpt-5-codex",
			Object:  "model",
			Created: 1757894400,
			OwnedBy: "openai",
			Type:    "openai",
		},
	})
	defer reg.UnregisterClient("mgmt-models-test-client")

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/models", nil)

	h := &Handler{}
	h.GetAvailableModels(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(payload.Models) == 0 {
		t.Fatalf("expected at least one model in response")
	}

	found := false
	for _, model := range payload.Models {
		if id, _ := model["id"].(string); id == "gpt-5-codex" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected gpt-5-codex in response, got %#v", payload.Models)
	}
}
