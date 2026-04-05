package auth

import (
	"testing"
	"time"
)

func TestUpdateAggregatedAvailability_UnavailableWithoutNextRetryDoesNotBlockAuth(t *testing.T) {
	t.Parallel()

	now := time.Now()
	model := "test-model"
	auth := &Auth{
		ID: "a",
		ModelStates: map[string]*ModelState{
			model: {
				Status:      StatusError,
				Unavailable: true,
			},
		},
	}

	updateAggregatedAvailability(auth, now)

	if auth.Unavailable {
		t.Fatalf("auth.Unavailable = true, want false")
	}
	if !auth.NextRetryAfter.IsZero() {
		t.Fatalf("auth.NextRetryAfter = %v, want zero", auth.NextRetryAfter)
	}
}

func TestUpdateAggregatedAvailability_FutureNextRetryBlocksAuth(t *testing.T) {
	t.Parallel()

	now := time.Now()
	model := "test-model"
	next := now.Add(5 * time.Minute)
	auth := &Auth{
		ID: "a",
		ModelStates: map[string]*ModelState{
			model: {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: next,
			},
		},
	}

	updateAggregatedAvailability(auth, now)

	if !auth.Unavailable {
		t.Fatalf("auth.Unavailable = false, want true")
	}
	if auth.NextRetryAfter.IsZero() {
		t.Fatalf("auth.NextRetryAfter = zero, want %v", next)
	}
	if auth.NextRetryAfter.Sub(next) > time.Second || next.Sub(auth.NextRetryAfter) > time.Second {
		t.Fatalf("auth.NextRetryAfter = %v, want %v", auth.NextRetryAfter, next)
	}
}

func TestDerivedAuthErrorFromModelStates_PrefersQuotaReason(t *testing.T) {
	t.Parallel()

	now := time.Now()
	next := now.Add(5 * time.Minute)
	auth := &Auth{
		ID: "a",
		ModelStates: map[string]*ModelState{
			"test-model": {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: next,
				Quota: QuotaState{
					Exceeded:      true,
					Reason:        "quota",
					NextRecoverAt: next,
				},
				LastError: &Error{
					Message:    "quota exhausted",
					HTTPStatus: 429,
					Retryable:  true,
				},
				UpdatedAt: now,
			},
		},
	}

	errValue, message := DerivedAuthErrorFromModelStates(auth, now)

	if errValue == nil {
		t.Fatalf("expected derived auth last error to be populated")
	}
	if errValue.HTTPStatus != 429 {
		t.Fatalf("derived last error http_status = %d, want 429", errValue.HTTPStatus)
	}
	if message != "quota exhausted" {
		t.Fatalf("derived message = %q, want quota exhausted", message)
	}
}

func TestUpdateAggregatedAvailability_DoesNotClearAuthReasonWhenAuthRemainsAvailable(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auth := &Auth{
		ID:            "a",
		Status:        StatusError,
		StatusMessage: "stream incomplete",
		LastError:     &Error{Message: "stream incomplete", HTTPStatus: 408, Retryable: true},
		ModelStates: map[string]*ModelState{
			"healthy-model": {
				Status: StatusActive,
			},
			"cooling-model": {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: now.Add(5 * time.Minute),
				LastError:      &Error{Message: "stream incomplete", HTTPStatus: 408, Retryable: true},
				StatusMessage:  "stream incomplete",
			},
		},
	}

	updateAggregatedAvailability(auth, now)

	if auth.Unavailable {
		t.Fatalf("auth.Unavailable = true, want false")
	}
	if auth.LastError == nil || auth.LastError.Message != "stream incomplete" {
		t.Fatalf("auth.LastError = %#v, want stream incomplete", auth.LastError)
	}
	if auth.StatusMessage != "stream incomplete" {
		t.Fatalf("auth.StatusMessage = %q, want stream incomplete", auth.StatusMessage)
	}
}

func TestUpdateAggregatedAvailability_ClearsExpiredModelQuotaFromAggregates(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auth := &Auth{
		ID: "a",
		ModelStates: map[string]*ModelState{
			"quota-model": {
				Status: StatusError,
				Quota: QuotaState{
					Exceeded:      true,
					Reason:        "quota",
					NextRecoverAt: now.Add(-1 * time.Minute),
					BackoffLevel:  2,
				},
				LastError: &Error{
					Message:    "quota exhausted",
					HTTPStatus: 429,
					Retryable:  true,
				},
			},
		},
	}

	updateAggregatedAvailability(auth, now)

	if auth.Quota.Exceeded {
		t.Fatalf("auth.Quota.Exceeded = true, want false")
	}
	state := auth.ModelStates["quota-model"]
	if state == nil {
		t.Fatalf("expected model state")
	}
	if state.Quota.Exceeded {
		t.Fatalf("state.Quota.Exceeded = true, want false")
	}
	errValue, message := DerivedAuthErrorFromModelStates(auth, now)
	if errValue != nil || message != "" {
		t.Fatalf("derived error = %#v, message = %q, want no derived reason", errValue, message)
	}
}
