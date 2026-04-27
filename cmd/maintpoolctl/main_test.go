package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateScanLimit(t *testing.T) {
	if err := validateScanLimit(false, 0); err != nil {
		t.Fatalf("validateScanLimit(preview, 0) error = %v", err)
	}
	if err := validateScanLimit(true, 1); err != nil {
		t.Fatalf("validateScanLimit(apply, 1) error = %v", err)
	}
	if err := validateScanLimit(true, 0); err == nil {
		t.Fatal("validateScanLimit(apply, 0) error = nil, want failure")
	}
}

func TestCountJSONFilesOrZeroCountsRecursively(t *testing.T) {
	root := t.TempDir()
	files := []string{
		filepath.Join(root, "top.json"),
		filepath.Join(root, "nested", "child.json"),
		filepath.Join(root, "nested", "deep", "grandchild.json"),
		filepath.Join(root, "nested", "ignore.txt"),
	}
	for _, path := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", path, err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}

	if got := countJSONFilesOrZero(root); got != 3 {
		t.Fatalf("countJSONFilesOrZero() = %d, want 3", got)
	}
}
