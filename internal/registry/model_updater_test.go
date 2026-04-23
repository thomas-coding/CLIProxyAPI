package registry

import (
	"slices"
	"testing"
)

func TestPreserveEmptyModelSectionsKeepsCurrentDefinitionsForEmptyProviders(t *testing.T) {
	current := &staticModelsJSON{
		Claude:      []*ModelInfo{{ID: "claude-current"}},
		Gemini:      []*ModelInfo{{ID: "gemini-current"}},
		Vertex:      []*ModelInfo{{ID: "vertex-current"}},
		GeminiCLI:   []*ModelInfo{{ID: "gemini-cli-current"}},
		AIStudio:    []*ModelInfo{{ID: "aistudio-current"}},
		CodexFree:   []*ModelInfo{{ID: "gpt-5"}},
		CodexTeam:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexPlus:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexPro:    []*ModelInfo{{ID: "gpt-5.4"}},
		Qwen:        []*ModelInfo{{ID: "qwen-current"}},
		IFlow:       []*ModelInfo{{ID: "iflow-current"}},
		Kimi:        []*ModelInfo{{ID: "kimi-current"}},
		Antigravity: []*ModelInfo{{ID: "antigravity-current"}},
	}
	incoming := &staticModelsJSON{
		Claude:      []*ModelInfo{{ID: "claude-new"}},
		Gemini:      []*ModelInfo{{ID: "gemini-new"}},
		Vertex:      []*ModelInfo{{ID: "vertex-new"}},
		GeminiCLI:   []*ModelInfo{{ID: "gemini-cli-new"}},
		AIStudio:    []*ModelInfo{{ID: "aistudio-new"}},
		CodexFree:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexTeam:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexPlus:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexPro:    []*ModelInfo{{ID: "gpt-5.4"}},
		Qwen:        nil,
		IFlow:       []*ModelInfo{},
		Kimi:        []*ModelInfo{{ID: "kimi-new"}},
		Antigravity: []*ModelInfo{{ID: "antigravity-new"}},
	}

	preserved := preserveEmptyModelSections(incoming, current)

	if !slices.Equal(preserved, []string{"qwen", "iflow"}) {
		t.Fatalf("unexpected preserved sections: %v", preserved)
	}
	if got := incoming.Qwen[0].ID; got != "qwen-current" {
		t.Fatalf("expected qwen fallback to be preserved, got %q", got)
	}
	if got := incoming.IFlow[0].ID; got != "iflow-current" {
		t.Fatalf("expected iflow fallback to be preserved, got %q", got)
	}
	if got := incoming.CodexFree[0].ID; got != "gpt-5.4" {
		t.Fatalf("expected codex-free to keep incoming value, got %q", got)
	}
}

func TestValidateModelsCatalogPassesAfterPreservingEmptySections(t *testing.T) {
	current := &staticModelsJSON{
		Claude:      []*ModelInfo{{ID: "claude-current"}},
		Gemini:      []*ModelInfo{{ID: "gemini-current"}},
		Vertex:      []*ModelInfo{{ID: "vertex-current"}},
		GeminiCLI:   []*ModelInfo{{ID: "gemini-cli-current"}},
		AIStudio:    []*ModelInfo{{ID: "aistudio-current"}},
		CodexFree:   []*ModelInfo{{ID: "gpt-5"}},
		CodexTeam:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexPlus:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexPro:    []*ModelInfo{{ID: "gpt-5.4"}},
		Qwen:        []*ModelInfo{{ID: "qwen-current"}},
		IFlow:       []*ModelInfo{{ID: "iflow-current"}},
		Kimi:        []*ModelInfo{{ID: "kimi-current"}},
		Antigravity: []*ModelInfo{{ID: "antigravity-current"}},
	}
	incoming := &staticModelsJSON{
		Claude:      []*ModelInfo{{ID: "claude-new"}},
		Gemini:      []*ModelInfo{{ID: "gemini-new"}},
		Vertex:      []*ModelInfo{{ID: "vertex-new"}},
		GeminiCLI:   []*ModelInfo{{ID: "gemini-cli-new"}},
		AIStudio:    []*ModelInfo{{ID: "aistudio-new"}},
		CodexFree:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexTeam:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexPlus:   []*ModelInfo{{ID: "gpt-5.4"}},
		CodexPro:    []*ModelInfo{{ID: "gpt-5.4"}},
		Qwen:        nil,
		IFlow:       []*ModelInfo{},
		Kimi:        []*ModelInfo{{ID: "kimi-new"}},
		Antigravity: []*ModelInfo{{ID: "antigravity-new"}},
	}

	if err := validateModelsCatalog(incoming); err == nil {
		t.Fatal("expected validation to fail before preserving empty sections")
	}

	preserveEmptyModelSections(incoming, current)

	if err := validateModelsCatalog(incoming); err != nil {
		t.Fatalf("expected validation to pass after preserving empty sections: %v", err)
	}
}
