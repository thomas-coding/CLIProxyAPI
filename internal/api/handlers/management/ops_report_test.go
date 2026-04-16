package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

func TestGetOpsReportReturnsRequestedDate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reportDir := t.TempDir()
	writeOpsReportFixture(t, reportDir, "2026-04-11")
	t.Setenv("ARROUTE_OPS_REPORT_DIR", reportDir)

	handler := NewHandler(&config.Config{}, "", nil)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/ops-report?date=2026-04-11", nil)
	ctx.Request = req

	handler.GetOpsReport(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload struct {
		RequestedDate    string         `json:"requested_date"`
		ResolvedDate     string         `json:"resolved_date"`
		Source           string         `json:"source"`
		FallbackToLatest bool           `json:"fallback_to_latest"`
		Markdown         string         `json:"markdown"`
		Report           map[string]any `json:"report"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if payload.RequestedDate != "2026-04-11" {
		t.Fatalf("requested_date = %q, want %q", payload.RequestedDate, "2026-04-11")
	}
	if payload.ResolvedDate != "2026-04-11" {
		t.Fatalf("resolved_date = %q, want %q", payload.ResolvedDate, "2026-04-11")
	}
	if payload.Source != "date" {
		t.Fatalf("source = %q, want %q", payload.Source, "date")
	}
	if payload.FallbackToLatest {
		t.Fatal("fallback_to_latest = true, want false")
	}
	if payload.Markdown == "" {
		t.Fatal("expected markdown payload")
	}
	if got, _ := payload.Report["date"].(string); got != "2026-04-11" {
		t.Fatalf("report.date = %q, want %q", got, "2026-04-11")
	}
}

func TestGetOpsReportFallsBackToLatestAvailableDate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reportDir := t.TempDir()
	writeOpsReportFixture(t, reportDir, "2026-04-10")
	t.Setenv("ARROUTE_OPS_REPORT_DIR", reportDir)

	oldNow := opsReportNow
	opsReportNow = func() time.Time {
		return time.Date(2026, 4, 12, 2, 30, 0, 0, opsReportLocation)
	}
	t.Cleanup(func() {
		opsReportNow = oldNow
	})

	handler := NewHandler(&config.Config{}, "", nil)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/ops-report", nil)
	ctx.Request = req

	handler.GetOpsReport(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload struct {
		RequestedDate    string `json:"requested_date"`
		ResolvedDate     string `json:"resolved_date"`
		Source           string `json:"source"`
		FallbackToLatest bool   `json:"fallback_to_latest"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if payload.RequestedDate != "2026-04-11" {
		t.Fatalf("requested_date = %q, want %q", payload.RequestedDate, "2026-04-11")
	}
	if payload.ResolvedDate != "2026-04-10" {
		t.Fatalf("resolved_date = %q, want %q", payload.ResolvedDate, "2026-04-10")
	}
	if payload.Source != "latest_fallback" {
		t.Fatalf("source = %q, want %q", payload.Source, "latest_fallback")
	}
	if !payload.FallbackToLatest {
		t.Fatal("fallback_to_latest = false, want true")
	}
}

func TestGetOpsReportRejectsInvalidDate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHandler(&config.Config{}, "", nil)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/ops-report?date=20260411", nil)
	ctx.Request = req

	handler.GetOpsReport(ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func writeOpsReportFixture(t *testing.T, dir string, date string) {
	t.Helper()

	jsonPath := filepath.Join(dir, date+".json")
	markdownPath := filepath.Join(dir, date+".md")

	jsonPayload := []byte(`{"date":"` + date + `","generated_at":"` + date + `T04:00:00+08:00","user_overview":{"active_users":31}}`)
	if err := os.WriteFile(jsonPath, jsonPayload, 0o644); err != nil {
		t.Fatalf("write json fixture: %v", err)
	}
	if err := os.WriteFile(markdownPath, []byte("# 运维日报 "+date+"\n"), 0o644); err != nil {
		t.Fatalf("write markdown fixture: %v", err)
	}
}
