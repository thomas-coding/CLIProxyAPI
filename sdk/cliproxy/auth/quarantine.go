package auth

import (
	"encoding/json"
	"strings"
	"time"
)

const (
	auth401KindNone               = ""
	auth401KindTokenInvalidated   = "token_invalidated"
	auth401KindTokenRevoked       = "token_revoked"
	auth401KindAccountDeactivated = "account_deactivated"
	auth401KindTokenExpired       = "token_expired"
	auth401KindUnknown            = "unknown_401"
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
	case lower == auth401KindUnknown || strings.Contains(lower, auth401KindUnknown):
		return auth401KindUnknown
	case lower == auth401KindTokenInvalidated || strings.Contains(lower, auth401KindTokenInvalidated):
		return auth401KindTokenInvalidated
	case lower == auth401KindTokenRevoked || strings.Contains(lower, auth401KindTokenRevoked):
		return auth401KindTokenRevoked
	case strings.Contains(lower, "refresh_token_reused"),
		strings.Contains(lower, "refresh_token_invalidated"):
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
	case strings.Contains(lower, "invalidated oauth token"),
		strings.Contains(lower, "token revoked"):
		return auth401KindTokenRevoked
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
	if isTerminalRefreshToken401(cloned) {
		return cloned
	}
	if kind := auth401QuarantineKind(cloned); kind != auth401KindNone {
		cloned.Code = kind
	}
	return cloned
}

func normalize401ErrorForAuth(auth *Auth, err *Error, now time.Time) *Error {
	if err == nil {
		return nil
	}
	cloned := cloneError(err)
	if isTerminalRefreshToken401(cloned) {
		return cloned
	}
	if kind := auth401QuarantineKindForAuth(auth, cloned, now); kind != auth401KindNone {
		cloned.Code = kind
	}
	return cloned
}

func authWide401Quarantine(auth *Auth) string {
	if auth == nil {
		return auth401KindNone
	}
	return auth401QuarantineKindForAuth(auth, auth.LastError, time.Now())
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
	case auth401KindTokenInvalidated, auth401KindTokenRevoked, auth401KindUnknown:
		next := authWide401NextProbe(auth)
		if !next.IsZero() && next.Before(now) {
			next = now
		}
		return true, next
	case auth401KindAccountDeactivated:
		return true, time.Time{}
	case auth401KindTokenExpired:
		return true, time.Time{}
	default:
		return false, time.Time{}
	}
}

func auth401QuarantineKindForAuth(auth *Auth, err *Error, now time.Time) string {
	if kind := auth401QuarantineKind(err); kind != auth401KindNone {
		return kind
	}
	if auth401TokenExpired(err) && isHardExpiredCodexAuthWithoutRefresh(auth, now) {
		return auth401KindTokenExpired
	}
	if auth != nil && err != nil && err.HTTPStatus == 401 && isCodexProvider(auth.Provider) && !auth401TokenExpired(err) {
		return auth401KindUnknown
	}
	return auth401KindNone
}

func auth401TokenExpired(err *Error) bool {
	if err == nil {
		return false
	}
	if auth401TokenExpiredText(err.Code) {
		return true
	}
	return auth401TokenExpiredFromMessage(err.Message)
}

func auth401TokenExpiredText(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return lower == auth401KindTokenExpired || strings.Contains(lower, auth401KindTokenExpired)
}

func auth401TokenExpiredFromMessage(message string) bool {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return false
	}
	if auth401TokenExpiredText(trimmed) {
		return true
	}

	var envelope upstreamErrorEnvelope
	if err := json.Unmarshal([]byte(trimmed), &envelope); err == nil {
		if auth401TokenExpiredText(envelope.Error.Code) {
			return true
		}
		if auth401TokenExpiredText(envelope.Error.Message) {
			return true
		}
	}

	lower := strings.ToLower(trimmed)
	switch {
	case strings.Contains(lower, "provided authentication token is expired"),
		strings.Contains(lower, "authentication token is expired"),
		strings.Contains(lower, "authentication has expired"),
		strings.Contains(lower, "token has expired"),
		strings.Contains(lower, "token expired"):
		return true
	default:
		return false
	}
}

func isHardExpiredCodexAuthWithoutRefresh(auth *Auth, now time.Time) bool {
	if auth == nil || !isCodexProvider(auth.Provider) {
		return false
	}
	expiry, hasExpiry := auth.ExpirationTime()
	if !hasExpiry || expiry.IsZero() || expiry.After(now) {
		return false
	}
	return !authHasRefreshToken(auth)
}

func authHasRefreshToken(auth *Auth) bool {
	return auth != nil && auth.RefreshToken() != ""
}

func isTerminalRefreshToken401(err *Error) bool {
	if err == nil {
		return false
	}
	return terminalRefreshToken401Text(err.Code) || terminalRefreshToken401Text(err.Message)
}

func terminalRefreshToken401Text(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(lower, "refresh_token_reused") ||
		strings.Contains(lower, "refresh_token_invalidated")
}

func stringValueFromMetadata(meta map[string]any, keys ...string) string {
	if meta == nil {
		return ""
	}
	for _, key := range keys {
		if val, ok := meta[key]; ok {
			switch typed := val.(type) {
			case string:
				if trimmed := strings.TrimSpace(typed); trimmed != "" {
					return trimmed
				}
			case map[string]any:
				if nested := stringValueFromMetadata(typed, key); nested != "" {
					return nested
				}
			case map[string]string:
				if nested := strings.TrimSpace(typed[key]); nested != "" {
					return nested
				}
			}
		}
	}
	for _, nestedKey := range []string{"token", "Token"} {
		if nested, ok := meta[nestedKey]; ok {
			switch typed := nested.(type) {
			case map[string]any:
				if val := stringValueFromMetadata(typed, keys...); val != "" {
					return val
				}
			case map[string]string:
				for _, key := range keys {
					if val := strings.TrimSpace(typed[key]); val != "" {
						return val
					}
				}
			}
		}
	}
	return ""
}

func applyAuth401Quarantine(auth *Auth, resultErr *Error, now time.Time) {
	if auth == nil {
		return
	}
	normalizedErr := normalize401ErrorForAuth(auth, resultErr, now)
	auth.Unavailable = true
	auth.Status = StatusError
	auth.UpdatedAt = now
	auth.Quota = QuotaState{}
	auth.LastError = normalizedErr
	auth.StatusMessage = ""
	if normalizedErr != nil && strings.TrimSpace(normalizedErr.Message) != "" {
		auth.StatusMessage = normalizedErr.Message
	}

	switch auth401QuarantineKindForAuth(auth, normalizedErr, now) {
	case auth401KindTokenInvalidated, auth401KindTokenRevoked, auth401KindUnknown:
		probeAt := now.Add(auth401ProbeInterval)
		auth.NextRetryAfter = probeAt
		auth.NextRefreshAfter = probeAt
		if auth.StatusMessage == "" {
			auth.StatusMessage = auth401QuarantineKindForAuth(auth, normalizedErr, now)
		}
	case auth401KindAccountDeactivated:
		auth.NextRetryAfter = time.Time{}
		auth.NextRefreshAfter = time.Time{}
		if auth.StatusMessage == "" {
			auth.StatusMessage = auth401KindAccountDeactivated
		}
	case auth401KindTokenExpired:
		auth.NextRetryAfter = time.Time{}
		auth.NextRefreshAfter = time.Time{}
		if auth.StatusMessage == "" {
			auth.StatusMessage = auth401KindTokenExpired
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
