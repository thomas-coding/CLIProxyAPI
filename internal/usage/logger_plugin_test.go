package usage

import (
	"context"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	coreusage "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/usage"
)

func TestRequestStatistics_SnapshotIncludesAuthCategories(t *testing.T) {
	stats := NewRequestStatistics()
	requestedAt := time.Date(2026, 3, 18, 8, 0, 0, 0, time.UTC)

	stats.Record(context.Background(), coreusage.Record{
		Provider:     "codex",
		Model:        "gpt-5",
		APIKey:       "POST /v1/chat/completions",
		AuthIndex:    "auth-team",
		AuthCategory: coreauth.AuthCategoryTeam,
		RequestedAt:  requestedAt,
		Detail:       coreusage.Detail{InputTokens: 10, OutputTokens: 5, TotalTokens: 15},
	})
	stats.Record(context.Background(), coreusage.Record{
		Provider:     "codex",
		Model:        "gpt-5",
		APIKey:       "POST /v1/chat/completions",
		AuthIndex:    "auth-free",
		AuthCategory: coreauth.AuthCategoryFree,
		RequestedAt:  requestedAt.Add(time.Minute),
		Failed:       true,
		Detail:       coreusage.Detail{InputTokens: 3, OutputTokens: 2, TotalTokens: 5},
	})

	snapshot := stats.Snapshot()
	if len(snapshot.Categories) != 2 {
		t.Fatalf("len(snapshot.Categories) = %d, want 2", len(snapshot.Categories))
	}
	team := snapshot.Categories[coreauth.AuthCategoryTeam]
	if team.TotalRequests != 1 || team.SuccessCount != 1 || team.TotalTokens != 15 {
		t.Fatalf("team snapshot = %+v", team)
	}
	free := snapshot.Categories[coreauth.AuthCategoryFree]
	if free.TotalRequests != 1 || free.FailureCount != 1 || free.TotalTokens != 5 {
		t.Fatalf("free snapshot = %+v", free)
	}
	if got := free.Models["gpt-5"].Details[0].AuthCategory; got != coreauth.AuthCategoryFree {
		t.Fatalf("detail auth_category = %q, want %q", got, coreauth.AuthCategoryFree)
	}
}

func TestRequestStatistics_MergeSnapshotPreservesAuthCategory(t *testing.T) {
	stats := NewRequestStatistics()
	requestedAt := time.Date(2026, 3, 18, 9, 0, 0, 0, time.UTC)
	result := stats.MergeSnapshot(StatisticsSnapshot{
		APIs: map[string]APISnapshot{
			"POST /v1/responses": {
				Models: map[string]ModelSnapshot{
					"gpt-5": {
						Details: []RequestDetail{{
							Timestamp:    requestedAt,
							AuthIndex:    "auth-team",
							AuthCategory: coreauth.AuthCategoryTeam,
							Tokens:       TokenStats{TotalTokens: 11},
						}},
					},
				},
			},
		},
	})
	if result.Added != 1 {
		t.Fatalf("result.Added = %d, want 1", result.Added)
	}
	snapshot := stats.Snapshot()
	team := snapshot.Categories[coreauth.AuthCategoryTeam]
	if team.TotalRequests != 1 || team.TotalTokens != 11 {
		t.Fatalf("team snapshot = %+v", team)
	}
}
