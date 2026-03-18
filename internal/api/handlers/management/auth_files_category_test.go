package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestListAuthFiles_IncludesCategoryFields(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(nil, nil, nil)
	for _, auth := range []*coreauth.Auth{
		{
			ID:       "team-auth",
			FileName: "alpha-team.json",
			Provider: "codex",
			Attributes: map[string]string{
				"path":     "alpha-team.json",
				"priority": "10",
			},
			Metadata: map[string]any{"type": "codex", "auth_category": "team", "priority": 10},
		},
		{
			ID:       "free-auth",
			FileName: "beta-free.json",
			Provider: "codex",
			Attributes: map[string]string{
				"path":     "beta-free.json",
				"priority": "2",
			},
			Metadata: map[string]any{"type": "codex", "auth_category": "free", "priority": 2},
		},
	} {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, err)
		}
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)

	h.ListAuthFiles(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("ListAuthFiles() status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(payload.Files) != 2 {
		t.Fatalf("len(files) = %d, want 2", len(payload.Files))
	}
	if got := payload.Files[0]["auth_category"]; got != coreauth.AuthCategoryTeam {
		t.Fatalf("first auth_category = %v, want %s", got, coreauth.AuthCategoryTeam)
	}
	if got := payload.Files[0]["category_priority"]; got != float64(10) {
		t.Fatalf("first category_priority = %v, want 10", got)
	}
	if got := payload.Files[1]["auth_category"]; got != coreauth.AuthCategoryFree {
		t.Fatalf("second auth_category = %v, want %s", got, coreauth.AuthCategoryFree)
	}
	if got := payload.Files[1]["priority"]; got != float64(2) {
		t.Fatalf("second priority = %v, want 2", got)
	}
}

func TestPatchAuthFileFields_UpdatesCategoryPriority(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(nil, nil, nil)
	for _, auth := range []*coreauth.Auth{
		{
			ID:       "team-a",
			FileName: "team-a.json",
			Provider: "codex",
			Attributes: map[string]string{
				"path":          "team-a.json",
				"auth_category": "team",
				"priority":      "3",
			},
			Metadata: map[string]any{"type": "codex", "auth_category": "team", "priority": 3},
		},
		{
			ID:       "team-b",
			FileName: "team-b.json",
			Provider: "codex",
			Attributes: map[string]string{
				"path":          "team-b.json",
				"auth_category": "team",
				"priority":      "4",
			},
			Metadata: map[string]any{"type": "codex", "auth_category": "team", "priority": 4},
		},
		{
			ID:       "free-a",
			FileName: "free-a.json",
			Provider: "codex",
			Attributes: map[string]string{
				"path":          "free-a.json",
				"auth_category": "free",
				"priority":      "1",
			},
			Metadata: map[string]any{"type": "codex", "auth_category": "free", "priority": 1},
		},
	} {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, err)
		}
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	body := []byte(`{"name":"team-a.json","category_priority":9}`)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.PatchAuthFileFields(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("PatchAuthFileFields() status = %d, body = %s", rec.Code, rec.Body.String())
	}

	teamA, _ := manager.GetByID("team-a")
	teamB, _ := manager.GetByID("team-b")
	freeA, _ := manager.GetByID("free-a")
	if got := coreauth.AuthPriorityValue(teamA); got != 9 {
		t.Fatalf("team-a priority = %d, want 9", got)
	}
	if got := coreauth.AuthPriorityValue(teamB); got != 9 {
		t.Fatalf("team-b priority = %d, want 9", got)
	}
	if got := coreauth.AuthPriorityValue(freeA); got != 1 {
		t.Fatalf("free-a priority = %d, want 1", got)
	}
}
