package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagerMarkResult_LogsQuotaReentryAvailable(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	logPath := filepath.Join(t.TempDir(), quotaReentryEventDirName, quotaReentryEventLogFileName)
	manager.SetQuotaReentryEventLogPath(logPath)

	expiredAt := time.Now().Add(-1 * time.Minute)
	auth := &Auth{
		ID:          "auth-a",
		Provider:    "codex",
		FileName:    "alpha.json",
		Status:      StatusError,
		Unavailable: true,
		Quota: QuotaState{
			Exceeded:      true,
			Reason:        "quota",
			NextRecoverAt: expiredAt,
		},
		ModelStates: map[string]*ModelState{
			"gpt-5.4": {
				Status:         StatusError,
				Unavailable:    true,
				StatusMessage:  "quota exhausted",
				NextRetryAfter: expiredAt,
				Quota: QuotaState{
					Exceeded:      true,
					Reason:        "quota",
					NextRecoverAt: expiredAt,
				},
			},
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5.4",
		Success:  true,
	})

	events := readQuotaReentryEvents(t, logPath)
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if got := events[0]["outcome"]; got != "available" {
		t.Fatalf("outcome = %#v, want available", got)
	}
	if got := events[0]["name"]; got != "alpha.json" {
		t.Fatalf("name = %#v, want alpha.json", got)
	}
}

func TestManagerMarkResult_LogsQuotaReentryInvalid401(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	logPath := filepath.Join(t.TempDir(), quotaReentryEventDirName, quotaReentryEventLogFileName)
	manager.SetQuotaReentryEventLogPath(logPath)

	expiredAt := time.Now().Add(-1 * time.Minute)
	auth := &Auth{
		ID:          "auth-a",
		Provider:    "codex",
		FileName:    "alpha.json",
		Status:      StatusError,
		Unavailable: true,
		Quota: QuotaState{
			Exceeded:      true,
			Reason:        "quota",
			NextRecoverAt: expiredAt,
		},
		ModelStates: map[string]*ModelState{
			"gpt-5.4": {
				Status:         StatusError,
				Unavailable:    true,
				StatusMessage:  "quota exhausted",
				NextRetryAfter: expiredAt,
				Quota: QuotaState{
					Exceeded:      true,
					Reason:        "quota",
					NextRecoverAt: expiredAt,
				},
			},
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5.4",
		Success:  false,
		Error: &Error{
			HTTPStatus: 401,
			Message:    `{"detail":"Unauthorized"}`,
		},
	})

	events := readQuotaReentryEvents(t, logPath)
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if got := events[0]["outcome"]; got != "invalid_401" {
		t.Fatalf("outcome = %#v, want invalid_401", got)
	}
	if got := events[0]["http_status"]; got != float64(401) {
		t.Fatalf("http_status = %#v, want 401", got)
	}
}

func TestManagerMarkResult_DoesNotLogQuotaReentryBeforeCooldownExpiry(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	logPath := filepath.Join(t.TempDir(), quotaReentryEventDirName, quotaReentryEventLogFileName)
	manager.SetQuotaReentryEventLogPath(logPath)

	futureAt := time.Now().Add(5 * time.Minute)
	auth := &Auth{
		ID:          "auth-a",
		Provider:    "codex",
		FileName:    "alpha.json",
		Status:      StatusError,
		Unavailable: true,
		Quota: QuotaState{
			Exceeded:      true,
			Reason:        "quota",
			NextRecoverAt: futureAt,
		},
		ModelStates: map[string]*ModelState{
			"gpt-5.4": {
				Status:         StatusError,
				Unavailable:    true,
				StatusMessage:  "quota exhausted",
				NextRetryAfter: futureAt,
				Quota: QuotaState{
					Exceeded:      true,
					Reason:        "quota",
					NextRecoverAt: futureAt,
				},
			},
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5.4",
		Success:  true,
	})

	events := readQuotaReentryEvents(t, logPath)
	if len(events) != 0 {
		t.Fatalf("event count = %d, want 0", len(events))
	}
}

func readQuotaReentryEvents(t *testing.T, path string) []map[string]any {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	lines := bytesToLines(data)
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var payload map[string]any
		if err = json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("Unmarshal(%q) error = %v", line, err)
		}
		events = append(events, payload)
	}
	return events
}

func bytesToLines(data []byte) []string {
	lines := make([]string, 0)
	for _, raw := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
