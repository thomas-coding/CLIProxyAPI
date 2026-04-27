package maintpool

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

var dayDurationToken = regexp.MustCompile(`([+-]?\d+(?:\.\d+)?)d`)

type EnvConfig struct {
	Root                   string
	ConfigPath             string
	Timezone               string
	InitialProbeMinDelay   time.Duration
	InitialProbeMaxDelay   time.Duration
	InitialRefreshMinDelay time.Duration
	InitialRefreshMaxDelay time.Duration
	ProbeMinDelay          time.Duration
	ProbeMaxDelay          time.Duration
	RefreshMinDelay        time.Duration
	RefreshMaxDelay        time.Duration
	RefreshHardMax         time.Duration
	Cooldown429            time.Duration
	CooldownTransient      time.Duration
	ActionDelayMin         time.Duration
	ActionDelayMax         time.Duration
	RefreshChainDelayMin   time.Duration
	RefreshChainDelayMax   time.Duration
	ConfirmChainDelayMin   time.Duration
	ConfirmChainDelayMax   time.Duration
}

func LoadEnvConfig(envPath string) (*EnvConfig, error) {
	values, err := godotenv.Read(envPath)
	if err != nil {
		return nil, fmt.Errorf("load maintpool env %q: %w", envPath, err)
	}
	cfg := &EnvConfig{
		Root:                   strings.TrimSpace(values["ROOT"]),
		ConfigPath:             strings.TrimSpace(values["CONFIG"]),
		Timezone:               strings.TrimSpace(values["TZ"]),
		InitialProbeMinDelay:   parseEnvDuration(values, "INITIAL_PROBE_MIN_DELAY", 24*time.Hour),
		InitialProbeMaxDelay:   parseEnvDuration(values, "INITIAL_PROBE_MAX_DELAY", 14*24*time.Hour),
		InitialRefreshMinDelay: parseEnvDuration(values, "INITIAL_REFRESH_MIN_DELAY", 20*24*time.Hour),
		InitialRefreshMaxDelay: parseEnvDuration(values, "INITIAL_REFRESH_MAX_DELAY", 35*24*time.Hour),
		ProbeMinDelay:          parseEnvDuration(values, "PROBE_MIN_DELAY", 10*24*time.Hour),
		ProbeMaxDelay:          parseEnvDuration(values, "PROBE_MAX_DELAY", 14*24*time.Hour),
		RefreshMinDelay:        parseEnvDuration(values, "REFRESH_MIN_DELAY", 30*24*time.Hour),
		RefreshMaxDelay:        parseEnvDuration(values, "REFRESH_MAX_DELAY", 34*24*time.Hour),
		RefreshHardMax:         parseEnvDuration(values, "REFRESH_HARD_MAX", 45*24*time.Hour),
		Cooldown429:            parseEnvDuration(values, "COOLDOWN_429", 24*time.Hour),
		CooldownTransient:      parseEnvDuration(values, "COOLDOWN_TRANSIENT", 6*time.Hour),
		ActionDelayMin:         parseEnvDuration(values, "ACTION_DELAY_MIN", 10*time.Second),
		ActionDelayMax:         parseEnvDuration(values, "ACTION_DELAY_MAX", 30*time.Second),
		RefreshChainDelayMin:   parseEnvDuration(values, "REFRESH_CHAIN_DELAY_MIN", 300*time.Millisecond),
		RefreshChainDelayMax:   parseEnvDuration(values, "REFRESH_CHAIN_DELAY_MAX", 1200*time.Millisecond),
		ConfirmChainDelayMin:   parseEnvDuration(values, "CONFIRM_CHAIN_DELAY_MIN", 500*time.Millisecond),
		ConfirmChainDelayMax:   parseEnvDuration(values, "CONFIRM_CHAIN_DELAY_MAX", 1500*time.Millisecond),
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "Asia/Shanghai"
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *EnvConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("maintpool env config is nil")
	}
	for key, value := range map[string]string{
		"ROOT":   c.Root,
		"CONFIG": c.ConfigPath,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("maintpool env missing %s", key)
		}
	}
	if err := ensurePositiveWindow("INITIAL_PROBE", c.InitialProbeMinDelay, c.InitialProbeMaxDelay); err != nil {
		return err
	}
	if err := ensurePositiveWindow("INITIAL_REFRESH", c.InitialRefreshMinDelay, c.InitialRefreshMaxDelay); err != nil {
		return err
	}
	if err := ensurePositiveWindow("PROBE", c.ProbeMinDelay, c.ProbeMaxDelay); err != nil {
		return err
	}
	if err := ensurePositiveWindow("REFRESH", c.RefreshMinDelay, c.RefreshMaxDelay); err != nil {
		return err
	}
	if c.RefreshHardMax <= 0 {
		return fmt.Errorf("REFRESH_HARD_MAX must be > 0")
	}
	if c.RefreshHardMax < c.RefreshMinDelay {
		return fmt.Errorf("REFRESH_HARD_MAX must be >= REFRESH_MIN_DELAY")
	}
	if c.Cooldown429 <= 0 {
		return fmt.Errorf("COOLDOWN_429 must be > 0")
	}
	if c.CooldownTransient <= 0 {
		return fmt.Errorf("COOLDOWN_TRANSIENT must be > 0")
	}
	if err := ensurePositiveWindow("ACTION_DELAY", c.ActionDelayMin, c.ActionDelayMax); err != nil {
		return err
	}
	if err := ensureNonNegativeWindow("REFRESH_CHAIN_DELAY", c.RefreshChainDelayMin, c.RefreshChainDelayMax); err != nil {
		return err
	}
	if err := ensureNonNegativeWindow("CONFIRM_CHAIN_DELAY", c.ConfirmChainDelayMin, c.ConfirmChainDelayMax); err != nil {
		return err
	}
	return nil
}

func ensurePositiveWindow(prefix string, minDelay, maxDelay time.Duration) error {
	if minDelay <= 0 {
		return fmt.Errorf("%s_MIN_DELAY must be > 0", prefix)
	}
	if maxDelay < minDelay {
		return fmt.Errorf("%s_MAX_DELAY must be >= %s_MIN_DELAY", prefix, prefix)
	}
	return nil
}

func ensureNonNegativeWindow(prefix string, minDelay, maxDelay time.Duration) error {
	if minDelay < 0 {
		return fmt.Errorf("%s_MIN must be >= 0", prefix)
	}
	if maxDelay < minDelay {
		return fmt.Errorf("%s_MAX must be >= %s_MIN", prefix, prefix)
	}
	return nil
}

func (c *EnvConfig) ValidateAgainstConfig(cfg *config.Config) error {
	if c == nil || cfg == nil {
		return nil
	}
	authDir := strings.TrimSpace(cfg.AuthDir)
	if authDir == "" {
		return nil
	}
	return validateRootIsolation(c.Root, authDir, "auth-dir")
}

func (c *EnvConfig) EnsureDirectories() error {
	if c == nil {
		return fmt.Errorf("maintpool env config is nil")
	}
	for _, dir := range []string{
		c.Root,
		c.PoolDir(),
		c.StateDir(),
		c.EventsDir(),
		c.External401Dir(),
		c.ExportedDir(),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func (c *EnvConfig) PoolDir() string {
	return filepath.Join(c.Root, "pool")
}

func (c *EnvConfig) StateDir() string {
	return filepath.Join(c.Root, "state")
}

func (c *EnvConfig) EventsDir() string {
	return filepath.Join(c.Root, "events")
}

func (c *EnvConfig) External401Dir() string {
	return filepath.Join(c.Root, "external-401")
}

func (c *EnvConfig) ExportedDir() string {
	return filepath.Join(c.Root, "exported")
}

func (c *EnvConfig) StatePath() string {
	return filepath.Join(c.StateDir(), "maintpool-state.json")
}

func (c *EnvConfig) EventsPath() string {
	return filepath.Join(c.EventsDir(), "events.jsonl")
}

func (c *EnvConfig) LockPath() string {
	return filepath.Join(c.StateDir(), "maintpool.lock")
}

func (c *EnvConfig) StatusTimeout() time.Duration {
	return 2 * time.Minute
}

func (c *EnvConfig) ImportTimeout(fileCount int, apply bool) time.Duration {
	if !apply {
		return 10 * time.Minute
	}
	if fileCount < 1 {
		fileCount = 1
	}
	total := time.Duration(fileCount)*2*time.Second + 10*time.Minute
	if total < 15*time.Minute {
		total = 15 * time.Minute
	}
	if total > 4*time.Hour {
		total = 4 * time.Hour
	}
	return total
}

func (c *EnvConfig) TakeoutTimeout() time.Duration {
	return 10 * time.Minute
}

func (c *EnvConfig) ScanTimeout(limit int, apply bool) time.Duration {
	if !apply {
		return 10 * time.Minute
	}
	if limit <= 0 {
		limit = 1000
	}
	perAuthBudget := 3*time.Minute + c.ActionDelayMax + c.ConfirmChainDelayMax
	total := time.Duration(limit)*perAuthBudget + 10*time.Minute
	if total < 20*time.Minute {
		total = 20 * time.Minute
	}
	return total
}

func parseEnvDuration(values map[string]string, key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(values[key])
	if raw == "" {
		return fallback
	}
	parsed, err := parseFlexibleDuration(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseFlexibleDuration(raw string) (time.Duration, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, fmt.Errorf("empty duration")
	}
	converted := dayDurationToken.ReplaceAllStringFunc(text, func(token string) string {
		match := dayDurationToken.FindStringSubmatch(token)
		if len(match) != 2 {
			return token
		}
		value, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			return token
		}
		hours := value * 24
		return strconv.FormatFloat(hours, 'f', -1, 64) + "h"
	})
	return time.ParseDuration(converted)
}

func validateRootIsolation(root, otherPath, otherKey string) error {
	rootNorm, err := normalizeComparablePath(root)
	if err != nil {
		return fmt.Errorf("normalize ROOT: %w", err)
	}
	otherNorm, err := normalizeComparablePath(otherPath)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", otherKey, err)
	}
	if pathsOverlap(rootNorm, otherNorm) {
		return fmt.Errorf("ROOT must not overlap %s", otherKey)
	}
	return nil
}

func normalizeComparablePath(path string) (string, error) {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	absPath, err := filepath.Abs(cleaned)
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		absPath = strings.ToLower(absPath)
	}
	return absPath, nil
}

func pathsOverlap(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	return pathContains(left, right) || pathContains(right, left)
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	if rel == "." {
		return true
	}
	return !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".."
}

func minPositive(left, right int) int {
	switch {
	case left <= 0:
		return right
	case right <= 0:
		return left
	case left < right:
		return left
	default:
		return right
	}
}

func randomDurationBetween(minDelay, maxDelay time.Duration, fraction float64) time.Duration {
	if maxDelay <= minDelay {
		return minDelay
	}
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	span := maxDelay - minDelay
	value := float64(span) * fraction
	return minDelay + time.Duration(math.Round(value))
}
