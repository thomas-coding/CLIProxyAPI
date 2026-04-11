package reserve2

import "time"

type FileState struct {
	LastCheckedAt   time.Time `json:"last_checked_at,omitempty"`
	LastRefreshAt   time.Time `json:"last_refresh_at,omitempty"`
	LastResult      string    `json:"last_result,omitempty"`
	LastHTTPStatus  int       `json:"last_http_status,omitempty"`
	NextRetryAfter  time.Time `json:"next_retry_after,omitempty"`
	Email           string    `json:"email,omitempty"`
	AccountID       string    `json:"account_id,omitempty"`
	RefreshTokenSHA string    `json:"refresh_token_sha256,omitempty"`
}

type StateFile struct {
	Files map[string]*FileState `json:"files"`
}

type PoolSummary struct {
	TotalFiles               int       `json:"total_files"`
	EligibleNow              int       `json:"eligible_now"`
	Cooling429               int       `json:"cooling_429"`
	CoolingTransient         int       `json:"cooling_transient"`
	External401Total         int       `json:"external_401_total"`
	OldestUncheckedAt        time.Time `json:"oldest_unchecked_at,omitempty"`
	OldestUncheckedAgeSecond int64     `json:"oldest_unchecked_age_seconds"`
}

type SampleSummary struct {
	StartedAt        time.Time `json:"started_at,omitempty"`
	FinishedAt       time.Time `json:"finished_at,omitempty"`
	Mode             string    `json:"mode,omitempty"`
	Requested        int       `json:"requested"`
	Processed        int       `json:"processed"`
	Healthy200       int       `json:"healthy_200"`
	RefreshRecovered int       `json:"refresh_recovered"`
	InvalidMoved     int       `json:"invalid_moved"`
	Usage429         int       `json:"usage_429"`
	ProbeError       int       `json:"probe_error"`
}

type SyncSummary struct {
	StartedAt               time.Time `json:"started_at,omitempty"`
	FinishedAt              time.Time `json:"finished_at,omitempty"`
	Mode                    string    `json:"mode,omitempty"`
	Reserve1AvailableBefore int       `json:"reserve1_available_before"`
	Reserve1AvailableAfter  int       `json:"reserve1_available_after_estimated"`
	LowWatermark            int       `json:"low_watermark"`
	Target                  int       `json:"target"`
	Needed                  int       `json:"needed"`
	TransferCap             int       `json:"transfer_cap"`
	CandidateCount          int       `json:"candidate_count"`
	PromotedToReserve1      int       `json:"promoted_to_reserve1"`
	DuplicateSkipped        int       `json:"duplicate_skipped"`
	InvalidMoved            int       `json:"invalid_moved"`
	Usage429                int       `json:"usage_429"`
	ProbeError              int       `json:"probe_error"`
}

type Rolling24hSummary struct {
	Sampled            int `json:"sampled"`
	SampleOK           int `json:"sample_ok"`
	SampleRefreshOK    int `json:"sample_refresh_ok"`
	PromotedToReserve1 int `json:"promoted_to_reserve1"`
	InvalidMoved       int `json:"invalid_moved"`
	Usage429           int `json:"usage_429"`
	ProbeError         int `json:"probe_error"`
	DuplicateSkipped   int `json:"duplicate_skipped"`
}

type Summary struct {
	GeneratedAt time.Time         `json:"generated_at,omitempty"`
	ColdRoot    string            `json:"cold_root,omitempty"`
	Pool        PoolSummary       `json:"pool"`
	LastSample  *SampleSummary    `json:"last_sample,omitempty"`
	LastSync    *SyncSummary      `json:"last_sync,omitempty"`
	Rolling24h  Rolling24hSummary `json:"rolling_24h"`
}

type Event struct {
	At         time.Time `json:"at"`
	Type       string    `json:"type"`
	Name       string    `json:"name,omitempty"`
	Email      string    `json:"email,omitempty"`
	AccountID  string    `json:"account_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	TargetPath string    `json:"target_path,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
}

type SampleResult struct {
	Mode     string        `json:"mode"`
	Summary  SampleSummary `json:"summary"`
	Selected []string      `json:"selected,omitempty"`
}

type SyncResult struct {
	Mode     string      `json:"mode"`
	Summary  SyncSummary `json:"summary"`
	Selected []string    `json:"selected,omitempty"`
}
