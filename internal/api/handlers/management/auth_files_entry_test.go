package management

import (
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestBuildAuthFileEntry_IncludesRuntimeErrorAndQuota(t *testing.T) {
	h := &Handler{}
	now := time.Now()

	entry := h.buildAuthFileEntry(&coreauth.Auth{
		ID:            "codex-user.json",
		FileName:      "codex-user.json",
		Provider:      "codex",
		Status:        coreauth.StatusError,
		StatusMessage: "quota exhausted",
		Unavailable:   true,
		Attributes: map[string]string{
			"path": "/tmp/codex-user.json",
		},
		Metadata: map[string]any{
			"type":  "codex",
			"email": "quota@example.com",
		},
		LastError: &coreauth.Error{
			Message:    "quota exhausted",
			HTTPStatus: 429,
			Retryable:  true,
		},
		Quota: coreauth.QuotaState{
			Exceeded:      true,
			Reason:        "quota",
			NextRecoverAt: now.Add(15 * time.Minute),
			BackoffLevel:  2,
		},
	})

	if entry == nil {
		t.Fatal("expected entry")
	}
	if _, ok := entry["last_error"]; !ok {
		t.Fatal("expected last_error to be included")
	}
	if _, ok := entry["quota"]; !ok {
		t.Fatal("expected quota to be included")
	}
}

func TestBuildAuthFileEntry_DerivesRuntimeErrorFromModelState(t *testing.T) {
	h := &Handler{}
	now := time.Now()

	entry := h.buildAuthFileEntry(&coreauth.Auth{
		ID:          "codex-user.json",
		FileName:    "codex-user.json",
		Provider:    "codex",
		Status:      coreauth.StatusError,
		Unavailable: true,
		Attributes: map[string]string{
			"path": "/tmp/codex-user.json",
		},
		Metadata: map[string]any{
			"type":  "codex",
			"email": "derived@example.com",
		},
		ModelStates: map[string]*coreauth.ModelState{
			"gpt-5-codex": {
				Status:         coreauth.StatusError,
				Unavailable:    true,
				NextRetryAfter: now.Add(10 * time.Minute),
				Quota: coreauth.QuotaState{
					Exceeded:      true,
					Reason:        "quota",
					NextRecoverAt: now.Add(10 * time.Minute),
				},
				LastError: &coreauth.Error{
					Message:    "quota exhausted",
					HTTPStatus: 429,
					Retryable:  true,
				},
				UpdatedAt: now,
			},
		},
	})

	if entry == nil {
		t.Fatal("expected entry")
	}
	if got := entry["status_message"]; got != "quota exhausted" {
		t.Fatalf("status_message = %#v, want quota exhausted", got)
	}
	lastError, ok := entry["last_error"].(*coreauth.Error)
	if !ok || lastError == nil {
		t.Fatalf("expected derived last_error, got %#v", entry["last_error"])
	}
	if lastError.HTTPStatus != 429 {
		t.Fatalf("last_error.http_status = %d, want 429", lastError.HTTPStatus)
	}
}

func TestBuildAuthFileEntry_DoesNotDeriveRuntimeErrorForActiveAuth(t *testing.T) {
	h := &Handler{}
	now := time.Now()

	entry := h.buildAuthFileEntry(&coreauth.Auth{
		ID:       "codex-user.json",
		FileName: "codex-user.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": "/tmp/codex-user.json",
		},
		Metadata: map[string]any{
			"type":  "codex",
			"email": "active@example.com",
		},
		ModelStates: map[string]*coreauth.ModelState{
			"gpt-5-codex": {
				Status:         coreauth.StatusError,
				Unavailable:    true,
				NextRetryAfter: now.Add(10 * time.Minute),
				Quota: coreauth.QuotaState{
					Exceeded:      true,
					Reason:        "quota",
					NextRecoverAt: now.Add(10 * time.Minute),
				},
				LastError: &coreauth.Error{
					Message:    "quota exhausted",
					HTTPStatus: 429,
					Retryable:  true,
				},
				UpdatedAt: now,
			},
		},
	})

	if entry == nil {
		t.Fatal("expected entry")
	}
	if got := entry["status_message"]; got != "" {
		t.Fatalf("status_message = %#v, want empty", got)
	}
	if _, ok := entry["last_error"]; ok {
		t.Fatalf("expected no derived last_error for active auth, got %#v", entry["last_error"])
	}
}
