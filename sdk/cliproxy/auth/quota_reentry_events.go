package auth

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	log "github.com/sirupsen/logrus"
)

const (
	quotaReentryEventDirName     = "quota-reentry"
	quotaReentryEventLogFileName = "events.jsonl"
	quotaReentryEventType        = "quota_reentry_result"
)

type quotaReentryAttempt struct {
	AuthID                 string
	Name                   string
	Provider               string
	Model                  string
	PreviousNextRetryAfter time.Time
	PreviousNextRecoverAt  time.Time
	PreviousStatusMessage  string
}

func defaultQuotaReentryEventLogPath(cfg *internalconfig.Config) string {
	if cfg == nil {
		return ""
	}
	authDir := strings.TrimSpace(cfg.AuthDir)
	if authDir == "" {
		return ""
	}
	return filepath.Join(authDir, quotaReentryEventDirName, quotaReentryEventLogFileName)
}

// SetQuotaReentryEventLogPath configures the production 429 reentry event log.
func (m *Manager) SetQuotaReentryEventLogPath(path string) {
	if m == nil {
		return
	}
	path = strings.TrimSpace(path)
	m.quotaReentryEventLogPath.Store(path)
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.WithError(err).Warn("quota reentry: create event log directory failed")
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		log.WithError(err).Warn("quota reentry: create event log file failed")
		return
	}
	_ = file.Close()
}

func (m *Manager) quotaReentryEventPath() string {
	if m == nil {
		return ""
	}
	value, _ := m.quotaReentryEventLogPath.Load().(string)
	return strings.TrimSpace(value)
}

func detectQuotaReentryAttempt(auth *Auth, model string, now time.Time) *quotaReentryAttempt {
	if auth == nil {
		return nil
	}
	if state := quotaReentryModelState(auth, model, now); state != nil {
		return &quotaReentryAttempt{
			AuthID:                 strings.TrimSpace(auth.ID),
			Name:                   quotaReentryAuthName(auth),
			Provider:               strings.TrimSpace(auth.Provider),
			Model:                  strings.TrimSpace(model),
			PreviousNextRetryAfter: state.NextRetryAfter,
			PreviousNextRecoverAt:  state.Quota.NextRecoverAt,
			PreviousStatusMessage:  strings.TrimSpace(state.StatusMessage),
		}
	}
	if quotaStateExpired(auth.Quota, auth.NextRetryAfter, now) {
		return &quotaReentryAttempt{
			AuthID:                 strings.TrimSpace(auth.ID),
			Name:                   quotaReentryAuthName(auth),
			Provider:               strings.TrimSpace(auth.Provider),
			Model:                  strings.TrimSpace(model),
			PreviousNextRetryAfter: auth.NextRetryAfter,
			PreviousNextRecoverAt:  auth.Quota.NextRecoverAt,
			PreviousStatusMessage:  strings.TrimSpace(auth.StatusMessage),
		}
	}
	return nil
}

func quotaReentryModelState(auth *Auth, model string, now time.Time) *ModelState {
	if auth == nil || strings.TrimSpace(model) == "" || len(auth.ModelStates) == 0 {
		return nil
	}
	state, ok := auth.ModelStates[model]
	if !ok || state == nil {
		return nil
	}
	if !quotaStateExpired(state.Quota, state.NextRetryAfter, now) {
		return nil
	}
	return state
}

func quotaStateExpired(quota QuotaState, nextRetry time.Time, now time.Time) bool {
	if !quota.Exceeded {
		return false
	}
	if quota.NextRecoverAt.After(now) {
		return false
	}
	if nextRetry.After(now) {
		return false
	}
	if quota.NextRecoverAt.IsZero() && nextRetry.IsZero() {
		return false
	}
	return true
}

func quotaReentryAuthName(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return filepath.Base(name)
	}
	return strings.TrimSpace(auth.ID)
}

func quotaReentryOutcome(auth *Auth, result Result) (string, int) {
	if result.Success {
		return "available", http.StatusOK
	}
	statusCode := statusCodeFromResult(result.Error)
	switch {
	case auth401QuarantineKind(result.Error) != auth401KindNone || statusCode == http.StatusUnauthorized:
		return "invalid_401", http.StatusUnauthorized
	case statusCode == http.StatusTooManyRequests:
		return "still_429", http.StatusTooManyRequests
	case statusCode == http.StatusRequestTimeout ||
		statusCode == http.StatusInternalServerError ||
		statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout:
		return "transient_error", statusCode
	default:
		if result.Success && auth != nil && !auth.Disabled && !auth.Unavailable {
			return "available", http.StatusOK
		}
		return "other_error", statusCode
	}
}

func (m *Manager) appendQuotaReentryEvent(attempt *quotaReentryAttempt, auth *Auth, result Result) {
	if m == nil || attempt == nil {
		return
	}
	eventLogPath := m.quotaReentryEventPath()
	if eventLogPath == "" {
		return
	}
	outcome, httpStatus := quotaReentryOutcome(auth, result)
	entry := map[string]any{
		"at":       time.Now().UTC().Format(time.RFC3339Nano),
		"type":     quotaReentryEventType,
		"name":     attempt.Name,
		"auth_id":  attempt.AuthID,
		"provider": attempt.Provider,
		"model":    attempt.Model,
		"outcome":  outcome,
	}
	if httpStatus > 0 {
		entry["http_status"] = httpStatus
	}
	if !attempt.PreviousNextRetryAfter.IsZero() {
		entry["previous_next_retry_after"] = attempt.PreviousNextRetryAfter.UTC().Format(time.RFC3339Nano)
	}
	if !attempt.PreviousNextRecoverAt.IsZero() {
		entry["previous_quota_next_recover_at"] = attempt.PreviousNextRecoverAt.UTC().Format(time.RFC3339Nano)
	}
	if attempt.PreviousStatusMessage != "" {
		entry["previous_status_message"] = attempt.PreviousStatusMessage
	}
	if auth != nil {
		if !auth.NextRetryAfter.IsZero() {
			entry["post_next_retry_after"] = auth.NextRetryAfter.UTC().Format(time.RFC3339Nano)
		}
		if message := strings.TrimSpace(auth.StatusMessage); message != "" {
			entry["post_status_message"] = message
		}
		if auth.Quota.Exceeded {
			entry["post_quota_exceeded"] = true
			if !auth.Quota.NextRecoverAt.IsZero() {
				entry["post_quota_next_recover_at"] = auth.Quota.NextRecoverAt.UTC().Format(time.RFC3339Nano)
			}
		}
	}
	if result.Error != nil {
		if code := strings.TrimSpace(result.Error.Code); code != "" {
			entry["error_code"] = code
		}
		if message := strings.TrimSpace(result.Error.Message); message != "" {
			entry["error_message"] = message
		}
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		log.WithError(err).Warn("quota reentry: marshal event failed")
		return
	}
	m.quotaReentryEventMu.Lock()
	defer m.quotaReentryEventMu.Unlock()

	if err = os.MkdirAll(filepath.Dir(eventLogPath), 0o700); err != nil {
		log.WithError(err).Warn("quota reentry: create event log directory failed")
		return
	}
	file, err := os.OpenFile(eventLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.WithError(err).Warn("quota reentry: open event log failed")
		return
	}
	defer func() {
		_ = file.Close()
	}()
	if _, err = file.Write(append(raw, '\n')); err != nil {
		log.WithError(err).Warn("quota reentry: append event log failed")
	}
}
