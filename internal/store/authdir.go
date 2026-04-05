package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
)

func walkManagedAuthFiles(dir string, visit func(path string, d fs.DirEntry) error) error {
	root := strings.TrimSpace(dir)
	if root == "" {
		return nil
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && util.IsIgnoredAuthDirName(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if util.IsIgnoredAuthPath(path, root) {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		return visit(path, d)
	})
}

func clearManagedAuthMirrorDir(dir string) error {
	root := strings.TrimSpace(dir)
	if root == "" {
		return nil
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(root, name)
		if entry.IsDir() {
			if util.IsIgnoredAuthDirName(name) {
				continue
			}
			if err := os.RemoveAll(path); err != nil {
				return err
			}
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func isIgnoredManagedAuthPath(path, authDir string) bool {
	trimmedPath := strings.TrimSpace(path)
	root := strings.TrimSpace(authDir)
	if trimmedPath == "" || root == "" {
		return false
	}
	if !filepath.IsAbs(trimmedPath) {
		trimmedPath = filepath.Join(root, trimmedPath)
	}
	return util.IsIgnoredAuthPath(trimmedPath, root)
}
