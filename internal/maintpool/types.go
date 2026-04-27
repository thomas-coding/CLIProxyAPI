package maintpool

import "time"

type FileState struct {
	ImportedAt           time.Time `json:"imported_at,omitempty"`
	LastProbeAt          time.Time `json:"last_probe_at,omitempty"`
	LastProbeOKAt        time.Time `json:"last_probe_ok_at,omitempty"`
	LastRefreshAttemptAt time.Time `json:"last_refresh_attempt_at,omitempty"`
	LastRefreshOKAt      time.Time `json:"last_refresh_ok_at,omitempty"`
	NextProbeAt          time.Time `json:"next_probe_at,omitempty"`
	NextRefreshDueAt     time.Time `json:"next_refresh_due_at,omitempty"`
	CooldownUntil        time.Time `json:"cooldown_until,omitempty"`
	LastResult           string    `json:"last_result,omitempty"`
	LastHTTPStatus       int       `json:"last_http_status,omitempty"`
	Email                string    `json:"email,omitempty"`
	AccountID            string    `json:"account_id,omitempty"`
	RefreshTokenSHA      string    `json:"refresh_token_sha256,omitempty"`
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
	GeneratedAt time.Time     `json:"generated_at"`
	Root        string        `json:"root"`
	Paths       StatusPaths   `json:"paths"`
	Pool        StatusPool    `json:"pool"`
	Cadence     StatusCadence `json:"cadence"`
}

type StatusPaths struct {
	PoolDir        string `json:"pool_dir"`
	StatePath      string `json:"state_path"`
	EventsPath     string `json:"events_path"`
	External401Dir string `json:"external_401_dir"`
	ExportedDir    string `json:"exported_dir"`
}

type StatusPool struct {
	TotalFiles        int       `json:"total_files"`
	DueNow            int       `json:"due_now"`
	DueProbeNow       int       `json:"due_probe_now"`
	DueRefreshNow     int       `json:"due_refresh_now"`
	Cooling           int       `json:"cooling"`
	External401Total  int       `json:"external_401_total"`
	ExportedTotal     int       `json:"exported_total"`
	NextDueAt         time.Time `json:"next_due_at,omitempty"`
	OldestImportedAt  time.Time `json:"oldest_imported_at,omitempty"`
	OldestKnownAuthAt time.Time `json:"oldest_known_auth_at,omitempty"`
}

type StatusCadence struct {
	InitialProbeMinDelay   time.Duration `json:"initial_probe_min_delay"`
	InitialProbeMaxDelay   time.Duration `json:"initial_probe_max_delay"`
	InitialRefreshMinDelay time.Duration `json:"initial_refresh_min_delay"`
	InitialRefreshMaxDelay time.Duration `json:"initial_refresh_max_delay"`
	ProbeMinDelay          time.Duration `json:"probe_min_delay"`
	ProbeMaxDelay          time.Duration `json:"probe_max_delay"`
	RefreshMinDelay        time.Duration `json:"refresh_min_delay"`
	RefreshMaxDelay        time.Duration `json:"refresh_max_delay"`
	RefreshHardMax         time.Duration `json:"refresh_hard_max"`
	Cooldown429            time.Duration `json:"cooldown_429"`
	CooldownTransient      time.Duration `json:"cooldown_transient"`
}

type ImportResult struct {
	Mode              string          `json:"mode"`
	SourceDir         string          `json:"source_dir"`
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

type ScanResult struct {
	Mode              string      `json:"mode"`
	ResultListLimit   int         `json:"result_list_limit,omitempty"`
	SelectedTruncated bool        `json:"selected_truncated,omitempty"`
	Summary           ScanSummary `json:"summary"`
	Selected          []string    `json:"selected,omitempty"`
}

type ScanSummary struct {
	Selected           int `json:"selected"`
	Processed          int `json:"processed"`
	HealthyProbeOnly   int `json:"healthy_probe_only"`
	ScheduledRefreshOK int `json:"scheduled_refresh_ok"`
	RecoveryRefreshOK  int `json:"recovery_refresh_ok"`
	InvalidMoved       int `json:"invalid_moved"`
	Usage429           int `json:"usage_429"`
	TransientError     int `json:"transient_error"`
}

type TakeoutResult struct {
	Mode            string `json:"mode"`
	Name            string `json:"name"`
	TakenOut        bool   `json:"taken_out"`
	DestinationPath string `json:"destination_path,omitempty"`
	Reason          string `json:"reason,omitempty"`
}
