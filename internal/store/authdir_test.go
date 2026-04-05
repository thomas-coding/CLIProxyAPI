package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestWalkManagedAuthFilesSkipsIgnoredDirs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStoreAuthFixture(t, filepath.Join(root, "main.json"), "main@example.com")
	mustWriteStoreAuthFixture(t, filepath.Join(root, "nested", "child.json"), "child@example.com")
	mustWriteStoreAuthFixture(t, filepath.Join(root, "reserve-pool", "reserve.json"), "reserve@example.com")
	mustWriteStoreAuthFixture(t, filepath.Join(root, "deleted-auth-backup", "external-401", "invalid.json"), "invalid@example.com")

	var got []string
	err := walkManagedAuthFiles(root, func(path string, _ os.DirEntry) error {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walkManagedAuthFiles: %v", err)
	}

	sort.Strings(got)
	want := []string{"main.json", "nested/child.json"}
	if len(got) != len(want) {
		t.Fatalf("walked files = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("walked files = %v, want %v", got, want)
		}
	}
}

func TestClearManagedAuthMirrorDirPreservesIgnoredDirs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStoreAuthFixture(t, filepath.Join(root, "main.json"), "main@example.com")
	mustWriteStoreAuthFixture(t, filepath.Join(root, "nested", "child.json"), "child@example.com")
	reservePath := filepath.Join(root, "reserve-pool", "reserve.json")
	warehousePath := filepath.Join(root, "deleted-auth-backup", "external-401", "invalid.json")
	mustWriteStoreAuthFixture(t, reservePath, "reserve@example.com")
	mustWriteStoreAuthFixture(t, warehousePath, "invalid@example.com")

	if err := clearManagedAuthMirrorDir(root); err != nil {
		t.Fatalf("clearManagedAuthMirrorDir: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "main.json")); !os.IsNotExist(err) {
		t.Fatalf("expected managed root auth removed, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "nested")); !os.IsNotExist(err) {
		t.Fatalf("expected managed nested dir removed, stat err = %v", err)
	}
	if _, err := os.Stat(reservePath); err != nil {
		t.Fatalf("expected reserve auth preserved: %v", err)
	}
	if _, err := os.Stat(warehousePath); err != nil {
		t.Fatalf("expected external-401 auth preserved: %v", err)
	}
}

func TestObjectTokenStoreListIgnoresIgnoredDirs(t *testing.T) {
	t.Parallel()

	store, err := NewObjectTokenStore(ObjectStoreConfig{
		Endpoint:  "example.com",
		Bucket:    "bucket",
		AccessKey: "access",
		SecretKey: "secret",
		LocalRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewObjectTokenStore: %v", err)
	}

	mustWriteStoreAuthFixture(t, filepath.Join(store.AuthDir(), "main.json"), "main@example.com")
	mustWriteStoreAuthFixture(t, filepath.Join(store.AuthDir(), "reserve-pool", "reserve.json"), "reserve@example.com")
	mustWriteStoreAuthFixture(t, filepath.Join(store.AuthDir(), "deleted-auth-backup", "external-401", "invalid.json"), "invalid@example.com")

	auths, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("ObjectTokenStore.List: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("auth count = %d, want 1", len(auths))
	}
	if auths[0].FileName != "main.json" {
		t.Fatalf("FileName = %q, want main.json", auths[0].FileName)
	}
}

func mustWriteStoreAuthFixture(t *testing.T, path string, email string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	payload := map[string]any{
		"type":  "codex",
		"email": email,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}
