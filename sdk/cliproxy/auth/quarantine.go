package auth

import (
	"encoding/json"
	"strings"
	"time"
)

const (
	auth401KindNone               = ""
	auth401KindTokenInvalidated   = "token_invalidated"
	auth401KindAccountDeactivated = "account_deactivated"
	auth401ProbeInterval          = 24 * time.Hour
)

type upstreamErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
	Status int `json:"status"`
}

func auth401QuarantineKind(err *Error) string {
	if err == nil {
		return auth401KindNone
	}
	if kind := auth401QuarantineKindText(err.Code); kind != auth401KindNone {
		return kind
	}
	return auth401QuarantineKindFromMessage(err.Message)
}

func auth401QuarantineKindText(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case lower == auth401KindTokenInvalidated || strings.Contains(lower, auth401KindTokenInvalidated):
		return auth401KindTokenInvalidated
	case lower == auth401KindAccountDeactivated || strings.Contains(lower, auth401KindAccountDeactivated):
		return auth401KindAccountDeactivated
	default:
		return auth401KindNone
	}
}

func auth401QuarantineKindFromMessage(message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return auth401KindNone
	}
	if kind := auth401QuarantineKindText(trimmed); kind != auth401KindNone {
		return kind
	}

	var envelope upstreamErrorEnvelope
	if err := json.Unmarshal([]byte(trimmed), &envelope); err == nil {
		if kind := auth401QuarantineKindText(envelope.Error.Code); kind != auth401KindNone {
			return kind
		}
		if kind := auth401QuarantineKindText(envelope.Error.Message); kind != auth401KindNone {
			return kind
		}
	}

	lower := strings.ToLower(trimmed)
	switch {
	case strings.Contains(lower, "authentication token has been invalidated"),
		strings.Contains(lower, "token invalidated"):
		return auth401KindTokenInvalidated
	case strings.Contains(lower, "account has been deactivated"),
		strings.Contains(lower, "account deactivated"),
		strings.Contains(lower, "deactivated"):
		return auth401KindAccountDeactivated
	default:
		return auth401KindNone
	}
}

func normalize401Error(err *Error) *Error {
	if err == nil {
		return nil
	}
	cloned := cloneError(err)
	if kind := auth401QuarantineKind(cloned); kind != auth401KindNone {
		cloned.Code = kind
	}
	return cloned
}

func authWide401Quarantine(auth *Auth) string {
	if auth == nil {
		return auth401KindNone
	}
	return auth401QuarantineKind(auth.LastError)
}

func authWide401NextProbe(auth *Auth) time.Time {
	if auth == nil {
		return time.Time{}
	}
	if !auth.NextRefreshAfter.IsZero() {
		return auth.NextRefreshAfter
	}
	return auth.NextRetryAfter
}

func authWide401BlockState(auth *Auth, now time.Time) (bool, time.Time) {
	switch authWide401Quarantine(auth) {
	case auth401KindTokenInvalidated:
		next := authWide401NextProbe(auth)
		if !next.IsZero() && next.Before(now) {
			next = now
		}
		return true, next
	case auth401KindAccountDeactivated:
		return true, time.Time{}
	default:
		return false, time.Time{}
	}
}

func applyAuth401Quarantine(auth *Auth, resultErr *Error, now time.Time) {
	if auth == nil {
		return
	}
	normalizedErr := normalize401Error(resultErr)
	auth.Unavailable = true
	auth.Status = StatusError
	auth.UpdatedAt = now
	auth.Quota = QuotaState{}
	auth.LastError = normalizedErr
	auth.StatusMessage = ""
	if normalizedErr != nil && strings.TrimSpace(normalizedErr.Message) != "" {
		auth.StatusMessage = normalizedErr.Message
	}

	switch auth401QuarantineKind(normalizedErr) {
	case auth401KindTokenInvalidated:
		probeAt := now.Add(auth401ProbeInterval)
		auth.NextRetryAfter = probeAt
		auth.NextRefreshAfter = probeAt
		if auth.StatusMessage == "" {
			auth.StatusMessage = auth401KindTokenInvalidated
		}
	case auth401KindAccountDeactivated:
		auth.NextRetryAfter = time.Time{}
		auth.NextRefreshAfter = time.Time{}
		if auth.StatusMessage == "" {
			auth.StatusMessage = auth401KindAccountDeactivated
		}
	}
}

func clearAuthStateAfterSuccessfulRefresh(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	auth.Unavailable = false
	auth.StatusMessage = ""
	auth.Quota = QuotaState{}
	auth.LastError = nil
	auth.NextRetryAfter = time.Time{}
	auth.NextRefreshAfter = time.Time{}
	auth.UpdatedAt = now

	if len(auth.ModelStates) > 0 {
		updateAggregatedAvailability(auth, now)
		if hasModelError(auth, now) {
			auth.Status = StatusError
			return
		}
	}
	auth.Status = StatusActive
}
