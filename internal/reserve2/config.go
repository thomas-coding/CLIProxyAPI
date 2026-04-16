package reserve2

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type EnvConfig struct {
	ColdRoot          string
	ConfigPath        string
	ProductionDir     string
	Reserve1Dir       string
	LowWatermark      int
	Target            int
	MaxTransfer       int
	CandidateFactor   float64
	SampleSize        int
	SampleCap         int
	SelectionWindow   float64
	Cooldown429       time.Duration
	CooldownTransient time.Duration
	SerialDelayMin    time.Duration
	SerialDelayMax    time.Duration
	Timezone          string
}

func LoadEnvConfig(envPath string) (*EnvConfig, error) {
	values, err := godotenv.Read(envPath)
	if err != nil {
		return nil, fmt.Errorf("load reserve2 env %q: %w", envPath, err)
	}
	cfg := &EnvConfig{
		ColdRoot:          strings.TrimSpace(values["COLD_ROOT"]),
		ConfigPath:        strings.TrimSpace(values["CONFIG"]),
		ProductionDir:     strings.TrimSpace(values["PRODUCTION_DIR"]),
		Reserve1Dir:       strings.TrimSpace(values["RESERVE1_DIR"]),
		LowWatermark:      parseEnvInt(values, "LOW_WATERMARK", 300),
		Target:            parseEnvInt(values, "TARGET", 600),
		MaxTransfer:       parseEnvInt(values, "MAX_TRANSFER", 150),
		CandidateFactor:   parseEnvFloat(values, "CANDIDATE_FACTOR", 1.6),
		SampleSize:        parseEnvInt(values, "SAMPLE_SIZE", 20),
		SampleCap:         parseEnvInt(values, "SAMPLE_CAP", 30),
		SelectionWindow:   parseEnvFloat(values, "SELECTION_WINDOW_FACTOR", 1),
		Cooldown429:       parseEnvDuration(values, "COOLDOWN_429", 24*time.Hour),
		CooldownTransient: parseEnvDuration(values, "COOLDOWN_TRANSIENT", 30*time.Minute),
		SerialDelayMin:    parseEnvDuration(values, "SERIAL_DELAY_MIN", 0),
		SerialDelayMax:    parseEnvDuration(values, "SERIAL_DELAY_MAX", 0),
		Timezone:          strings.TrimSpace(values["TZ"]),
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
		return fmt.Errorf("reserve2 env config is nil")
	}
	for key, value := range map[string]string{
		"COLD_ROOT":      c.ColdRoot,
		"CONFIG":         c.ConfigPath,
		"PRODUCTION_DIR": c.ProductionDir,
		"RESERVE1_DIR":   c.Reserve1Dir,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("reserve2 env missing %s", key)
		}
	}
	if c.LowWatermark <= 0 {
		return fmt.Errorf("LOW_WATERMARK must be > 0")
	}
	if c.Target < c.LowWatermark {
		return fmt.Errorf("TARGET must be >= LOW_WATERMARK")
	}
	if c.MaxTransfer <= 0 {
		return fmt.Errorf("MAX_TRANSFER must be > 0")
	}
	if c.CandidateFactor < 1 {
		return fmt.Errorf("CANDIDATE_FACTOR must be >= 1")
	}
	if c.SampleSize <= 0 {
		return fmt.Errorf("SAMPLE_SIZE must be > 0")
	}
	if c.SampleCap <= 0 {
		return fmt.Errorf("SAMPLE_CAP must be > 0")
	}
	if c.SelectionWindow < 1 {
		return fmt.Errorf("SELECTION_WINDOW_FACTOR must be >= 1")
	}
	if c.Cooldown429 <= 0 {
		return fmt.Errorf("COOLDOWN_429 must be > 0")
	}
	if c.CooldownTransient <= 0 {
		return fmt.Errorf("COOLDOWN_TRANSIENT must be > 0")
	}
	if c.SerialDelayMin < 0 {
		return fmt.Errorf("SERIAL_DELAY_MIN must be >= 0")
	}
	if c.SerialDelayMax < c.SerialDelayMin {
		return fmt.Errorf("SERIAL_DELAY_MAX must be >= SERIAL_DELAY_MIN")
	}
	if err := validateColdRootIsolation(c.ColdRoot, c.ProductionDir, "PRODUCTION_DIR"); err != nil {
		return err
	}
	if err := validateColdRootIsolation(c.ColdRoot, c.Reserve1Dir, "RESERVE1_DIR"); err != nil {
		return err
	}
	return nil
}

func (c *EnvConfig) EnsureDirectories() error {
	if c == nil {
		return fmt.Errorf("reserve2 env config is nil")
	}
	for _, dir := range []string{
		c.ColdRoot,
		c.PoolDir(),
		c.External401Dir(),
		c.StateDir(),
		c.EventsDir(),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func (c *EnvConfig) PoolDir() string {
	return filepath.Join(c.ColdRoot, "pool")
}

func (c *EnvConfig) External401Dir() string {
	return filepath.Join(c.ColdRoot, "external-401")
}

func (c *EnvConfig) StateDir() string {
	return filepath.Join(c.ColdRoot, "state")
}

func (c *EnvConfig) EventsDir() string {
	return filepath.Join(c.ColdRoot, "events")
}

func (c *EnvConfig) StatePath() string {
	return filepath.Join(c.StateDir(), "reserve2-state.json")
}

func (c *EnvConfig) SummaryPath() string {
	return filepath.Join(c.StateDir(), "summary.json")
}

func (c *EnvConfig) EventsPath() string {
	return filepath.Join(c.EventsDir(), "events.jsonl")
}

func (c *EnvConfig) LockPath() string {
	return filepath.Join(c.StateDir(), "reserve2.lock")
}

func (c *EnvConfig) DesiredTransfer(currentReserve1Available int) int {
	if currentReserve1Available >= c.Target {
		return 0
	}
	need := c.Target - currentReserve1Available
	if need > c.MaxTransfer {
		need = c.MaxTransfer
	}
	if need < 0 {
		return 0
	}
	return need
}

func (c *EnvConfig) CandidateCount(desiredTransfer int) int {
	if desiredTransfer <= 0 {
		return 0
	}
	count := int(math.Ceil(float64(desiredTransfer) * c.CandidateFactor))
	if count < desiredTransfer {
		count = desiredTransfer
	}
	if count > 300 {
		count = 300
	}
	return count
}

func (c *EnvConfig) SelectionWindowCount(limit int) int {
	if limit <= 0 {
		return 0
	}
	count := int(math.Ceil(float64(limit) * c.SelectionWindow))
	if count < limit {
		count = limit
	}
	return count
}

func (c *EnvConfig) SampleTimeout(apply bool) time.Duration {
	if !apply {
		return 10 * time.Minute
	}
	sampleCount := minPositive(c.SampleSize, c.SampleCap)
	if sampleCount <= 0 {
		sampleCount = c.SampleSize
	}
	return boundedReserveTimeout(sampleCount, c.SerialDelayMax, 20*time.Minute, 4*time.Hour)
}

func (c *EnvConfig) SyncTimeout(apply bool) time.Duration {
	if !apply {
		return 20 * time.Minute
	}
	candidateCount := c.CandidateCount(c.MaxTransfer)
	return boundedReserveTimeout(candidateCount, c.SerialDelayMax, 30*time.Minute, 6*time.Hour)
}

func boundedReserveTimeout(count int, serialDelayMax, minimum, maximum time.Duration) time.Duration {
	if count <= 0 {
		return minimum
	}
	perAuthBudget := 30*time.Second + serialDelayMax
	if perAuthBudget < 30*time.Second {
		perAuthBudget = 30 * time.Second
	}
	total := time.Duration(count)*perAuthBudget + 10*time.Minute
	if total < minimum {
		total = minimum
	}
	if total > maximum {
		total = maximum
	}
	return total
}

func parseEnvInt(values map[string]string, key string, fallback int) int {
	raw := strings.TrimSpace(values[key])
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseEnvFloat(values map[string]string, key string, fallback float64) float64 {
	raw := strings.TrimSpace(values[key])
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseEnvDuration(values map[string]string, key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(values[key])
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return parsed
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

func validateColdRootIsolation(coldRoot, otherPath, otherKey string) error {
	coldNorm, err := normalizeComparablePath(coldRoot)
	if err != nil {
		return fmt.Errorf("normalize COLD_ROOT: %w", err)
	}
	otherNorm, err := normalizeComparablePath(otherPath)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", otherKey, err)
	}
	if pathsOverlap(coldNorm, otherNorm) {
		return fmt.Errorf("COLD_ROOT must not overlap %s", otherKey)
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
