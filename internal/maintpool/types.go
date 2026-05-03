package maintpool

import "time"

type FileState struct {
	ImportedAt           time.Time `json:"imported_at,omitempty"`
	LastProbeAt          time.Time `json:"last_probe_at,omitempty"`
	LastProbeOKAt        time.Time `json:"last_probe_ok_at,omitempty"`
	LastRefreshAttemptAt time.Time `json:"last_refresh_attempt_at,omitempty"`
	LastRefreshOKAt      time.Time `json:"last_refresh_ok_at,omitempty"`
	BaselineRefreshOKAt  time.Time `json:"baseline_refresh_ok_at,omitempty"`
	NextProbeAt          time.Time `json:"next_probe_at,omitempty"`
	NextRefreshDueAt     time.Time `json:"next_refresh_due_at,omitempty"`
	LaneAssignedAt       time.Time `json:"lane_assigned_at,omitempty"`
	CooldownUntil        time.Time `json:"cooldown_until,omitempty"`
	LastResult           string    `json:"last_result,omitempty"`
	LastHTTPStatus       int       `json:"last_http_status,omitempty"`
	Email                string    `json:"email,omitempty"`
	AccountID            string    `json:"account_id,omitempty"`
	RefreshTokenSHA      string    `json:"refresh_token_sha256,omitempty"`
	CohortID             string    `json:"cohort_id,omitempty"`
	SourceBatchID        string    `json:"source_batch_id,omitempty"`
	Lane                 string    `json:"lane,omitempty"`
	BaselineState        string    `json:"baseline_state,omitempty"`
}

type StateFile struct {
	Files map[string]*FileState `json:"files"`
}

type Event struct {
	At         time.Time `json:"at"`
	Type       string    `json:"type"`
	Name       string    `json:"name,omitempty"`
	Email      string    `json:"email,omitempty"`
	AccountID  string    `json:"account_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	SourcePath string    `json:"source_path,omitempty"`
	TargetPath string    `json:"target_path,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
}

type StatusResult struct {
	GeneratedAt   time.Time           `json:"generated_at"`
	Root          string              `json:"root"`
	Paths         StatusPaths         `json:"paths"`
	Pool          StatusPool          `json:"pool"`
	Cadence       StatusCadence       `json:"cadence"`
	Guardrails    StatusGuardrails    `json:"guardrails"`
	EmergencyStop StatusEmergencyStop `json:"emergency_stop"`
}

type StatusPaths struct {
	PoolDir           string `json:"pool_dir"`
	StatePath         string `json:"state_path"`
	EventsPath        string `json:"events_path"`
	External401Dir    string `json:"external_401_dir"`
	ExportedDir       string `json:"exported_dir"`
	EmergencyStopPath string `json:"emergency_stop_path"`
}

type StatusPool struct {
	TotalFiles        int            `json:"total_files"`
	DueNow            int            `json:"due_now"`
	DueProbeNow       int            `json:"due_probe_now"`
	DueRefreshNow     int            `json:"due_refresh_now"`
	Cooling           int            `json:"cooling"`
	External401Total  int            `json:"external_401_total"`
	ExportedTotal     int            `json:"exported_total"`
	NextDueAt         time.Time      `json:"next_due_at,omitempty"`
	OldestImportedAt  time.Time      `json:"oldest_imported_at,omitempty"`
	OldestKnownAuthAt time.Time      `json:"oldest_known_auth_at,omitempty"`
	ByLane            map[string]int `json:"by_lane,omitempty"`
	ByBaselineState   map[string]int `json:"by_baseline_state,omitempty"`
}

type StatusCadence struct {
	InitialProbeMinDelay            time.Duration `json:"initial_probe_min_delay"`
	InitialProbeMaxDelay            time.Duration `json:"initial_probe_max_delay"`
	InitialRefreshMinDelay          time.Duration `json:"initial_refresh_min_delay"`
	InitialRefreshMaxDelay          time.Duration `json:"initial_refresh_max_delay"`
	ProbeMinDelay                   time.Duration `json:"probe_min_delay"`
	ProbeMaxDelay                   time.Duration `json:"probe_max_delay"`
	RefreshMinDelay                 time.Duration `json:"refresh_min_delay"`
	RefreshMaxDelay                 time.Duration `json:"refresh_max_delay"`
	RefreshHardMax                  time.Duration `json:"refresh_hard_max"`
	Cooldown429                     time.Duration `json:"cooldown_429"`
	CooldownTransient               time.Duration `json:"cooldown_transient"`
	ManagedUpstreamSafeRefreshDelay time.Duration `json:"managed_upstream_safe_refresh_delay"`
	ManagedMainBufferMin            time.Duration `json:"managed_main_buffer_min"`
	ManagedMainBufferMax            time.Duration `json:"managed_main_buffer_max"`
	ManagedGuard0Offset             time.Duration `json:"managed_guard_0_offset"`
	ManagedGuard1Offset             time.Duration `json:"managed_guard_1_offset"`
	ManagedGuard2Offset             time.Duration `json:"managed_guard_2_offset"`
	ManagedGuardJitterMax           time.Duration `json:"managed_guard_jitter_max"`
}

type StatusGuardrails struct {
	EmergencyConsecutiveInvalidThreshold int           `json:"emergency_consecutive_invalid_threshold"`
	EmergencyStopMaxAge                  time.Duration `json:"emergency_stop_max_age"`
}

type StatusEmergencyStop struct {
	Active                bool      `json:"active"`
	TriggeredAt           time.Time `json:"triggered_at,omitempty"`
	ExpiresAt             time.Time `json:"expires_at,omitempty"`
	Expired               bool      `json:"expired,omitempty"`
	Reason                string    `json:"reason,omitempty"`
	ConsecutiveInvalid401 int       `json:"consecutive_invalid_401,omitempty"`
	Threshold             int       `json:"threshold,omitempty"`
	TriggerEventType      string    `json:"trigger_event_type,omitempty"`
	LastResult            string    `json:"last_result,omitempty"`
	LastHTTPStatus        int       `json:"last_http_status,omitempty"`
	LastAuthName          string    `json:"last_auth_name,omitempty"`
	LastEmail             string    `json:"last_email,omitempty"`
	LastAccountID         string    `json:"last_account_id,omitempty"`
	SuggestedAction       string    `json:"suggested_action,omitempty"`
}

type ImportResult struct {
	Mode              string          `json:"mode"`
	SourceDir         string          `json:"source_dir"`
	CohortID          string          `json:"cohort_id,omitempty"`
	SourceBatchID     string          `json:"source_batch_id,omitempty"`
	Lane              string          `json:"lane,omitempty"`
	ResultListLimit   int             `json:"result_list_limit,omitempty"`
	ImportedTruncated bool            `json:"imported_truncated,omitempty"`
	SkippedTruncated  bool            `json:"skipped_truncated,omitempty"`
	FailedTruncated   bool            `json:"failed_truncated,omitempty"`
	Summary           ImportSummary   `json:"summary"`
	Imported          []string        `json:"imported,omitempty"`
	Skipped           []ImportSkip    `json:"skipped,omitempty"`
	Failed            []ImportFailure `json:"failed,omitempty"`
}

type ImportSummary struct {
	Scanned           int `json:"scanned"`
	Imported          int `json:"imported"`
	SkippedDuplicates int `json:"skipped_duplicates"`
	Failed            int `json:"failed"`
}

type ImportSkip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type ImportFailure struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

type ImportOptions struct {
	Apply         bool
	CohortID      string
	SourceBatchID string
	Lane          string
}

type ScanResult struct {
	Mode              string               `json:"mode"`
	ResultListLimit   int                  `json:"result_list_limit,omitempty"`
	SelectedTruncated bool                 `json:"selected_truncated,omitempty"`
	Summary           ScanSummary          `json:"summary"`
	Selected          []string             `json:"selected,omitempty"`
	EmergencyStop     *StatusEmergencyStop `json:"emergency_stop,omitempty"`
}

type ScanSummary struct {
	Selected               int  `json:"selected"`
	Processed              int  `json:"processed"`
	HealthyProbeOnly       int  `json:"healthy_probe_only"`
	ScheduledRefreshOK     int  `json:"scheduled_refresh_ok"`
	RecoveryRefreshOK      int  `json:"recovery_refresh_ok"`
	InvalidMoved           int  `json:"invalid_moved"`
	Usage429               int  `json:"usage_429"`
	TransientError         int  `json:"transient_error"`
	ConsecutiveInvalid401  int  `json:"consecutive_invalid_401,omitempty"`
	EmergencyStopActive    bool `json:"emergency_stop_active,omitempty"`
	EmergencyStopTriggered bool `json:"emergency_stop_triggered,omitempty"`
}

type TakeoutResult struct {
	Mode            string `json:"mode"`
	Name            string `json:"name"`
	TakenOut        bool   `json:"taken_out"`
	DestinationPath string `json:"destination_path,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type AssignLanesResult struct {
	Mode             string             `json:"mode"`
	CohortID         string             `json:"cohort_id"`
	ResultListLimit  int                `json:"result_list_limit,omitempty"`
	MainTruncated    bool               `json:"main_truncated,omitempty"`
	Guard0Truncated  bool               `json:"guard_0_truncated,omitempty"`
	Guard1Truncated  bool               `json:"guard_1_truncated,omitempty"`
	Guard2Truncated  bool               `json:"guard_2_truncated,omitempty"`
	SkippedTruncated bool               `json:"skipped_truncated,omitempty"`
	Summary          AssignLanesSummary `json:"summary"`
	Main             []string           `json:"main,omitempty"`
	Guard0           []string           `json:"guard_0,omitempty"`
	Guard1           []string           `json:"guard_1,omitempty"`
	Guard2           []string           `json:"guard_2,omitempty"`
	Skipped          []AssignLaneSkip   `json:"skipped,omitempty"`
}

type AssignLanesSummary struct {
	CohortMatched        int `json:"cohort_matched"`
	ReadyForAssignment   int `json:"ready_for_assignment"`
	AssignedMain         int `json:"assigned_main"`
	AssignedGuard0       int `json:"assigned_guard_0"`
	AssignedGuard1       int `json:"assigned_guard_1"`
	AssignedGuard2       int `json:"assigned_guard_2"`
	SkippedNotReady      int `json:"skipped_not_ready"`
	SkippedMissingAnchor int `json:"skipped_missing_anchor"`
}

type AssignLaneSkip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type AssignLanesOptions struct {
	Apply    bool
	CohortID string
	Guard0   int
	Guard1   int
	Guard2   int
}

type AdoptLegacyResult struct {
	Mode                     string             `json:"mode"`
	CohortID                 string             `json:"cohort_id"`
	SourceBatchID            string             `json:"source_batch_id"`
	RequireLastRefreshWithin time.Duration      `json:"require_last_refresh_within"`
	ResultListLimit          int                `json:"result_list_limit,omitempty"`
	MainTruncated            bool               `json:"main_truncated,omitempty"`
	Guard0Truncated          bool               `json:"guard_0_truncated,omitempty"`
	Guard1Truncated          bool               `json:"guard_1_truncated,omitempty"`
	Guard2Truncated          bool               `json:"guard_2_truncated,omitempty"`
	SkippedTruncated         bool               `json:"skipped_truncated,omitempty"`
	Summary                  AdoptLegacySummary `json:"summary"`
	Main                     []string           `json:"main,omitempty"`
	Guard0                   []string           `json:"guard_0,omitempty"`
	Guard1                   []string           `json:"guard_1,omitempty"`
	Guard2                   []string           `json:"guard_2,omitempty"`
	Skipped                  []AssignLaneSkip   `json:"skipped,omitempty"`
}

type AdoptLegacySummary struct {
	LegacyMatched        int `json:"legacy_matched"`
	Eligible             int `json:"eligible"`
	AssignedMain         int `json:"assigned_main"`
	AssignedGuard0       int `json:"assigned_guard_0"`
	AssignedGuard1       int `json:"assigned_guard_1"`
	AssignedGuard2       int `json:"assigned_guard_2"`
	SkippedMissingAnchor int `json:"skipped_missing_anchor"`
	SkippedTooOld        int `json:"skipped_too_old"`
}

type AdoptLegacyOptions struct {
	Apply                    bool
	CohortID                 string
	SourceBatchID            string
	Guard0                   int
	Guard1                   int
	Guard2                   int
	RequireLastRefreshWithin time.Duration
}

type ClearEmergencyStopResult struct {
	Mode     string               `json:"mode"`
	HadStop  bool                 `json:"had_stop"`
	Cleared  bool                 `json:"cleared"`
	Reason   string               `json:"reason,omitempty"`
	Previous *StatusEmergencyStop `json:"previous,omitempty"`
	Current  *StatusEmergencyStop `json:"current,omitempty"`
}
