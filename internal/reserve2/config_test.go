package reserve2

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEnvConfigValidateRejectsColdRootInsideProductionDir(t *testing.T) {
	root := t.TempDir()
	cfg := newValidEnvConfigForTest(root)
	cfg.ColdRoot = filepath.Join(cfg.ProductionDir, "reserve2-cold")

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want overlap rejection")
	}
	if got := err.Error(); got != "COLD_ROOT must not overlap PRODUCTION_DIR" {
		t.Fatalf("Validate() error = %q, want %q", got, "COLD_ROOT must not overlap PRODUCTION_DIR")
	}
}

func TestEnvConfigValidateRejectsReserve1InsideColdRoot(t *testing.T) {
	root := t.TempDir()
	cfg := newValidEnvConfigForTest(root)
	cfg.Reserve1Dir = filepath.Join(cfg.ColdRoot, "reserve1")

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want overlap rejection")
	}
	if got := err.Error(); got != "COLD_ROOT must not overlap RESERVE1_DIR" {
		t.Fatalf("Validate() error = %q, want %q", got, "COLD_ROOT must not overlap RESERVE1_DIR")
	}
}

func TestEnvConfigValidateAllowsReserve1UnderProductionDir(t *testing.T) {
	root := t.TempDir()
	cfg := newValidEnvConfigForTest(root)
	cfg.Reserve1Dir = filepath.Join(cfg.ProductionDir, "reserve-pool")

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestSampleTimeoutExpandsForSerialApply(t *testing.T) {
	cfg := newValidEnvConfigForTest(t.TempDir())
	cfg.SampleSize = 60
	cfg.SampleCap = 80
	cfg.SerialDelayMax = 15 * time.Second

	got := cfg.SampleTimeout(true)
	if got <= 10*time.Minute {
		t.Fatalf("SampleTimeout(apply) = %s, want > 10m", got)
	}
}

func TestSyncTimeoutExpandsForSerialApply(t *testing.T) {
	cfg := newValidEnvConfigForTest(t.TempDir())
	cfg.MaxTransfer = 150
	cfg.CandidateFactor = 1.6
	cfg.SerialDelayMax = 15 * time.Second

	got := cfg.SyncTimeout(true)
	if got <= 20*time.Minute {
		t.Fatalf("SyncTimeout(apply) = %s, want > 20m", got)
	}
}

func newValidEnvConfigForTest(root string) *EnvConfig {
	return &EnvConfig{
		ColdRoot:          filepath.Join(root, "cold"),
		ConfigPath:        filepath.Join(root, "config.yaml"),
		ProductionDir:     filepath.Join(root, "auths"),
		Reserve1Dir:       filepath.Join(root, "auths", "reserve-pool"),
		LowWatermark:      300,
		Target:            600,
		MaxTransfer:       150,
		CandidateFactor:   1.6,
		SampleSize:        20,
		SampleCap:         30,
		SelectionWindow:   1,
		Cooldown429:       24 * time.Hour,
		CooldownTransient: 30 * time.Minute,
		SerialDelayMin:    0,
		SerialDelayMax:    0,
		Timezone:          "UTC",
	}
}
