package util

import (
	"path/filepath"
	"testing"
)

func TestIsIgnoredAuthDirName(t *testing.T) {
	if !IsIgnoredAuthDirName(" deleted-auth-backup ") {
		t.Fatal("expected deleted-auth-backup to be ignored")
	}
	if IsIgnoredAuthDirName("active") {
		t.Fatal("did not expect active to be ignored")
	}
}

func TestIsIgnoredAuthPath(t *testing.T) {
	authDir := filepath.Join("root", "auths")

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "active top level file",
			path: filepath.Join(authDir, "active.json"),
			want: false,
		},
		{
			name: "backup subdirectory file",
			path: filepath.Join(authDir, "deleted-auth-backup", "20260401", "active.json"),
			want: true,
		},
		{
			name: "nested backup subdirectory file",
			path: filepath.Join(authDir, "nested", "deleted-auth-backup", "active.json"),
			want: true,
		},
		{
			name: "top level file that only shares the prefix",
			path: filepath.Join(authDir, "deleted-auth-backup.json"),
			want: false,
		},
		{
			name: "outside auth dir",
			path: filepath.Join("root", "other", "deleted-auth-backup", "active.json"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIgnoredAuthPath(tt.path, authDir); got != tt.want {
				t.Fatalf("IsIgnoredAuthPath(%q, %q) = %t, want %t", tt.path, authDir, got, tt.want)
			}
		})
	}
}
