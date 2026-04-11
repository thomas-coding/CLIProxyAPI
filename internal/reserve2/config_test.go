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
		Cooldown429:       24 * time.Hour,
		CooldownTransient: 30 * time.Minute,
		Timezone:          "UTC",
	}
}
