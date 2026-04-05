package management

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/reservepool"
)

func TestUploadReserveAuthFileMissingRefreshTokenReturnsBadRequest(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	handler := NewHandler(&config.Config{AuthDir: authDir}, "", nil)
	handler.SetReservePool(reservepool.NewManager(&config.Config{AuthDir: authDir}, nil))

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "broken.json")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err = part.Write([]byte(`{"type":"codex","access_token":"only-access-token"}`)); err != nil {
		t.Fatalf("write multipart payload: %v", err)
	}
	if err = writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/reserve-auth-files", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx.Request = req

	handler.UploadReserveAuthFile(ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var payload map[string]any
	if err = json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got, _ := payload["error"].(string); got == "" {
		t.Fatal("expected error message in response")
	}
}
