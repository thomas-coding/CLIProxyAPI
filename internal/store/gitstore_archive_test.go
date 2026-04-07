package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/object"
)

func TestGitTokenStore_ArchiveAuthFileStagesArchiveTarget(t *testing.T) {
	t.Parallel()

	remoteDir := t.TempDir()
	if _, err := git.PlainInit(remoteDir, true); err != nil {
		t.Fatalf("init bare remote: %v", err)
	}

	workRoot := t.TempDir()
	authDir := filepath.Join(workRoot, "auths")
	store := NewGitTokenStore(remoteDir, "", "")
	store.SetBaseDir(authDir)
	if err := store.EnsureRepository(); err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}

	sourcePath := filepath.Join(authDir, "archived.json")
	if err := os.WriteFile(sourcePath, []byte(`{"type":"codex","email":"archived@example.com"}`), 0o600); err != nil {
		t.Fatalf("write source auth: %v", err)
	}
	if err := store.PersistAuthFiles(context.Background(), "seed auth", sourcePath); err != nil {
		t.Fatalf("PersistAuthFiles(seed): %v", err)
	}

	targetPath := filepath.Join(authDir, "deleted-auth-backup", "external-401", "20260406-120000", "archived.json")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatalf("mkdir archive dir: %v", err)
	}
	if err := os.Rename(sourcePath, targetPath); err != nil {
		t.Fatalf("move source to target: %v", err)
	}

	if err := store.ArchiveAuthFile(context.Background(), sourcePath, targetPath, "archive auth"); err != nil {
		t.Fatalf("ArchiveAuthFile: %v", err)
	}

	localRepo, err := git.PlainOpen(workRoot)
	if err != nil {
		t.Fatalf("open local repo: %v", err)
	}
	assertGitTreeContains(t, localRepo, "auths/deleted-auth-backup/external-401/20260406-120000/archived.json")
	assertGitTreeMissing(t, localRepo, "auths/archived.json")

	remoteRepo, err := git.PlainOpen(remoteDir)
	if err != nil {
		t.Fatalf("open remote repo: %v", err)
	}
	assertGitTreeContains(t, remoteRepo, "auths/deleted-auth-backup/external-401/20260406-120000/archived.json")
	assertGitTreeMissing(t, remoteRepo, "auths/archived.json")
}

func assertGitTreeContains(t *testing.T, repo *git.Repository, relPath string) {
	t.Helper()

	tree := gitHeadTree(t, repo)
	if _, err := tree.File(relPath); err != nil {
		t.Fatalf("expected git tree to contain %s: %v", relPath, err)
	}
}

func assertGitTreeMissing(t *testing.T, repo *git.Repository, relPath string) {
	t.Helper()

	tree := gitHeadTree(t, repo)
	if _, err := tree.File(relPath); err == nil {
		t.Fatalf("expected git tree to omit %s", relPath)
	}
}

func gitHeadTree(t *testing.T, repo *git.Repository) *object.Tree {
	t.Helper()

	head, err := repo.Head()
	if err != nil {
		t.Fatalf("repo.Head: %v", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		t.Fatalf("repo.CommitObject: %v", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("commit.Tree: %v", err)
	}
	return tree
}
