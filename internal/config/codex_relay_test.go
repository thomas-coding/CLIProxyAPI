package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigOptional_CodexRelayTransparentMode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
codex-relay:
  transparent-mode: "  SHADOW  "
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if got := cfg.CodexRelay.TransparentMode; got != "shadow" {
		t.Fatalf("TransparentMode = %q, want %q", got, "shadow")
	}
}

func TestSanitizeCodexRelayDefaultsInvalidModeToOff(t *testing.T) {
	cfg := &Config{}
	cfg.CodexRelay.TransparentMode = "unsupported"

	cfg.SanitizeCodexRelay()

	if got := cfg.CodexRelay.TransparentMode; got != "off" {
		t.Fatalf("TransparentMode = %q, want %q", got, "off")
	}
}
