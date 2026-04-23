package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
)

const (
	deletedAuthBackupDirName      = "deleted-auth-backup"
	external401DirName            = "external-401"
	external401ArchiveTimeLayout  = "20060102-150405"
	external401ArchiveUniqueStamp = "150405.000000000"
)

type managedAuthDirStore interface {
	AuthDir() string
}

type authFilePersistStore interface {
	PersistAuthFiles(ctx context.Context, message string, paths ...string) error
}

type authFileArchiveStore interface {
	ArchiveAuthFile(ctx context.Context, sourcePath, targetPath, message string) error
}

type external401ArchiveResult struct {
	SourcePath string
	TargetPath string
}

func (m *Manager) shouldArchiveExternal401Auth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	switch authWide401Quarantine(auth) {
	case auth401KindAccountDeactivated, auth401KindTokenExpired:
		return true
	default:
		return false
	}
}

func (m *Manager) archiveExternal401Auth(ctx context.Context, auth *Auth) (*external401ArchiveResult, error) {
	if auth == nil {
		return nil, fmt.Errorf("auth is nil")
	}
	sourcePath, authDir, err := resolveArchiveSource(auth, m.store)
	if err != nil {
		return nil, err
	}
	if util.IsIgnoredAuthPath(sourcePath, authDir) {
		return nil, fmt.Errorf("auth path already outside managed pool: %s", sourcePath)
	}

	now := time.Now().UTC()
	batchDir := filepath.Join(authDir, deletedAuthBackupDirName, external401DirName, now.Format(external401ArchiveTimeLayout))
	if err = os.MkdirAll(batchDir, 0o700); err != nil {
		return nil, fmt.Errorf("create external-401 batch dir: %w", err)
	}

	targetPath, err := uniqueArchivePath(batchDir, filepath.Base(sourcePath), now)
	if err != nil {
		return nil, err
	}
	if err = moveAuthFile(sourcePath, targetPath); err != nil {
		return nil, err
	}

	if err = m.syncArchivedAuthDeletion(ctx, auth, sourcePath, targetPath); err != nil {
		rollbackErr := moveAuthFile(targetPath, sourcePath)
		if rollbackErr != nil {
			return nil, fmt.Errorf("sync archived auth deletion: %w (rollback failed: %v)", err, rollbackErr)
		}
		return nil, err
	}

	return &external401ArchiveResult{
		SourcePath: sourcePath,
		TargetPath: targetPath,
	}, nil
}

func (m *Manager) syncArchivedAuthDeletion(ctx context.Context, auth *Auth, sourcePath string, targetPath string) error {
	if m == nil || m.store == nil {
		return nil
	}
	messageID := strings.TrimSpace(auth.ID)
	if messageID == "" {
		messageID = filepath.Base(sourcePath)
	}
	reason := authWide401Quarantine(auth)
	if reason == "" {
		reason = "terminal_401"
	}
	message := "Archive " + reason + " auth " + messageID
	if archiver, ok := m.store.(authFileArchiveStore); ok {
		return archiver.ArchiveAuthFile(ctx, sourcePath, targetPath, message)
	}
	if syncer, ok := m.store.(authFilePersistStore); ok {
		return syncer.PersistAuthFiles(ctx, message, sourcePath)
	}
	return m.store.Delete(ctx, sourcePath)
}

func (m *Manager) stageArchivedAuthRemovalLocked(auth *Auth) *Auth {
	if m == nil || auth == nil {
		return nil
	}
	authSnapshot := auth.Clone()
	delete(m.auths, auth.ID)
	if m.scheduler != nil {
		m.scheduler.removeAuth(auth.ID)
	}
	return authSnapshot
}

func (m *Manager) restoreArchivedAuth(auth *Auth) {
	if m == nil || auth == nil {
		return
	}
	authSnapshot := auth.Clone()
	m.mu.Lock()
	m.auths[authSnapshot.ID] = authSnapshot
	m.mu.Unlock()
	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	m.reconcileAffinityAuthState(authSnapshot)
	if m.scheduler != nil {
		m.scheduler.upsertAuth(authSnapshot)
	}
}

func (m *Manager) removeArchivedAuth(authID string) {
	if m == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}

	m.mu.Lock()
	delete(m.auths, authID)
	m.mu.Unlock()

	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	if m.affinity != nil {
		m.affinity.releaseAuth(authID)
	}
	if m.scheduler != nil {
		m.scheduler.removeAuth(authID)
	}
	registry.GetGlobalRegistry().UnregisterClient(authID)
}

func resolveArchiveSource(auth *Auth, store Store) (string, string, error) {
	if auth == nil {
		return "", "", fmt.Errorf("auth is nil")
	}
	authDir := ""
	if dirStore, ok := store.(managedAuthDirStore); ok {
		authDir = strings.TrimSpace(dirStore.AuthDir())
	}

	sourcePath, err := resolveManagedAuthPath(auth, authDir)
	if err != nil {
		return "", "", err
	}
	if authDir == "" {
		authDir = deriveManagedAuthDir(sourcePath, auth)
	}
	if strings.TrimSpace(authDir) == "" {
		return "", "", fmt.Errorf("managed auth dir is empty for %s", auth.ID)
	}
	return filepath.Clean(sourcePath), filepath.Clean(authDir), nil
}

func resolveManagedAuthPath(auth *Auth, authDir string) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("auth is nil")
	}
	if auth.Attributes != nil {
		if path := strings.TrimSpace(auth.Attributes["path"]); path != "" {
			if filepath.IsAbs(path) {
				return filepath.Clean(path), nil
			}
			if authDir != "" {
				return filepath.Join(authDir, filepath.FromSlash(path)), nil
			}
		}
	}

	for _, candidate := range []string{strings.TrimSpace(auth.FileName), strings.TrimSpace(auth.ID)} {
		if candidate == "" {
			continue
		}
		if filepath.IsAbs(candidate) {
			return filepath.Clean(candidate), nil
		}
		if authDir != "" {
			return filepath.Join(authDir, filepath.FromSlash(candidate)), nil
		}
	}

	return "", fmt.Errorf("auth %s does not expose a managed file path", auth.ID)
}

func deriveManagedAuthDir(sourcePath string, auth *Auth) string {
	cleanSource := filepath.Clean(strings.TrimSpace(sourcePath))
	if cleanSource == "" {
		return ""
	}

	relativeName := strings.TrimSpace(auth.FileName)
	if relativeName == "" {
		relativeName = strings.TrimSpace(auth.ID)
	}
	if relativeName == "" || filepath.IsAbs(relativeName) {
		return filepath.Dir(cleanSource)
	}

	cleanRelative := filepath.Clean(filepath.FromSlash(relativeName))
	if cleanRelative == "." || cleanRelative == string(os.PathSeparator) {
		return filepath.Dir(cleanSource)
	}

	dir := filepath.Dir(cleanSource)
	segments := strings.Split(cleanRelative, string(os.PathSeparator))
	for i := 1; i < len(segments); i++ {
		dir = filepath.Dir(dir)
	}
	return dir
}

func uniqueArchivePath(batchDir, fileName string, now time.Time) (string, error) {
	base := strings.TrimSpace(fileName)
	if base == "" {
		return "", fmt.Errorf("archive file name is empty")
	}

	targetPath := filepath.Join(batchDir, base)
	if _, err := os.Stat(targetPath); err == nil {
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		targetPath = filepath.Join(batchDir, fmt.Sprintf("%s-%s%s", stem, now.Format(external401ArchiveUniqueStamp), ext))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return targetPath, nil
}

func moveAuthFile(sourcePath, targetPath string) error {
	if strings.TrimSpace(sourcePath) == "" || strings.TrimSpace(targetPath) == "" {
		return fmt.Errorf("source or target path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return fmt.Errorf("prepare archive dir: %w", err)
	}
	if err := os.Rename(sourcePath, targetPath); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		sourceFile, openErr := os.Open(sourcePath)
		if openErr != nil {
			return fmt.Errorf("open source auth file: %w", openErr)
		}
		defer sourceFile.Close()

		targetFile, createErr := os.Create(targetPath)
		if createErr != nil {
			return fmt.Errorf("create archive auth file: %w", createErr)
		}
		copyErr := copyAndClose(targetFile, sourceFile)
		if copyErr != nil {
			_ = os.Remove(targetPath)
			return copyErr
		}
		if removeErr := os.Remove(sourcePath); removeErr != nil {
			_ = os.Remove(targetPath)
			return fmt.Errorf("remove source auth file: %w", removeErr)
		}
		return nil
	} else {
		return fmt.Errorf("source auth file missing: %w", err)
	}
}

func copyAndClose(target io.WriteCloser, source io.Reader) error {
	defer target.Close()
	if _, err := io.Copy(target, source); err != nil {
		return fmt.Errorf("copy auth file into archive: %w", err)
	}
	return nil
}
