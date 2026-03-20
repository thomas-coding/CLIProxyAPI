package executor

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	log "github.com/sirupsen/logrus"
)

func TestUpstreamPerfLogsIncludeAuthID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	start := time.Now().Add(-25 * time.Millisecond)
	logging.SetGinRequestStartTime(ginCtx, start)

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	ctx = logging.WithRequestID(ctx, "req-test")
	ctx = logging.WithRequestStartTime(ctx, start)

	logger := log.StandardLogger()
	prevOut := logger.Out
	prevFormatter := logger.Formatter
	prevLevel := logger.Level

	var buf bytes.Buffer
	logger.SetOutput(&buf)
	logger.SetFormatter(&log.TextFormatter{DisableTimestamp: true, DisableColors: true})
	logger.SetLevel(log.InfoLevel)
	defer func() {
		logger.SetOutput(prevOut)
		logger.SetFormatter(prevFormatter)
		logger.SetLevel(prevLevel)
	}()

	recordAPIRequest(ctx, &config.Config{}, upstreamRequestLog{
		URL:      "https://example.com/v1/chat/completions",
		Method:   http.MethodPost,
		Provider: "codex",
		AuthID:   "auth-123",
	})
	recordAPIResponseMetadata(ctx, &config.Config{}, http.StatusOK, http.Header{"Content-Type": {"text/event-stream"}})
	appendAPIResponseChunk(ctx, &config.Config{}, []byte("data: test"))
	recordAPIResponseError(ctx, &config.Config{}, errors.New("boom"))

	output := buf.String()
	for _, phase := range []string{"phase=dispatch", "phase=headers", "phase=first_chunk", "phase=error"} {
		if !strings.Contains(output, phase) {
			t.Fatalf("expected log output to contain %s, got %q", phase, output)
		}
	}
	if count := strings.Count(output, "auth_id=auth-123"); count != 4 {
		t.Fatalf("expected auth_id in 4 perf log lines, got %d in %q", count, output)
	}
}
