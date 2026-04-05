package executor

import (
	"context"
	"hash/fnv"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const codexAffinityKeyHeader = "X-Arroute-Affinity-Key"

var codexFallbackUserAgentPool = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.165 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.154 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.7632.160 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.164 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.153 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.7632.159 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0",
}

func ensureCodexUserAgent(target, source http.Header, ctx context.Context, auth *cliproxyauth.Auth, cfg *config.Config) {
	if target == nil {
		return
	}
	currentUA := strings.TrimSpace(target.Get("User-Agent"))
	if looksLikeInternalHopUserAgent(currentUA) {
		target.Del("User-Agent")
		currentUA = ""
	}
	snapshotUA, snapshotPresent := codexSnapshotUserAgentFromContext(ctx)
	if snapshotPresent {
		if snapshotUA != "" {
			target.Set("User-Agent", snapshotUA)
			return
		}
		if looksLikeInternalHopUserAgent(currentUA) {
			target.Del("User-Agent")
			currentUA = ""
		}
	}
	if currentUA != "" {
		return
	}
	if sourceUA := codexSourceUserAgent(ctx, source); sourceUA != "" {
		target.Set("User-Agent", sourceUA)
		return
	}
	if strings.TrimSpace(target.Get("User-Agent")) != "" {
		return
	}
	if fallback := codexBoundFallbackUserAgent(ctx, auth); fallback != "" {
		target.Set("User-Agent", fallback)
	}
}

func codexSourceUserAgent(ctx context.Context, source http.Header) string {
	if snapshotUA, snapshotPresent := codexSnapshotUserAgentFromContext(ctx); snapshotPresent {
		return snapshotUA
	}
	if source == nil {
		return ""
	}
	sourceUA := strings.TrimSpace(source.Get("User-Agent"))
	if looksLikeInternalHopUserAgent(sourceUA) {
		return ""
	}
	return sourceUA
}

func codexSnapshotUserAgentFromContext(ctx context.Context) (string, bool) {
	ginCtx := ginContextFrom(ctx)
	if ginCtx == nil || ginCtx.Request == nil {
		return "", false
	}
	headers := ginCtx.Request.Header
	if headers == nil {
		return "", false
	}
	if strings.TrimSpace(headers.Get(codexTransparentClientHeadersHeader)) != "" {
		snapshotHeaders, err := decodeTransparentCodexSnapshotHeaders(headers)
		if err != nil || snapshotHeaders == nil {
			return "", true
		}
		return strings.TrimSpace(snapshotHeaders.Get("User-Agent")), true
	}
	if strings.TrimSpace(headers.Get(codexTransparentSnapshotStatusHeader)) != "" {
		return "", true
	}
	return "", false
}

func looksLikeInternalHopUserAgent(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.EqualFold(value, "Go-http-client/1.1") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(value), "go-http-client/")
}

func codexBoundFallbackUserAgent(ctx context.Context, auth *cliproxyauth.Auth) string {
	if len(codexFallbackUserAgentPool) == 0 {
		return ""
	}
	seed := codexFingerprintSeed(ctx, auth)
	if seed == "" {
		return codexFallbackUserAgentPool[0]
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(seed))
	idx := int(hash.Sum64() % uint64(len(codexFallbackUserAgentPool)))
	return codexFallbackUserAgentPool[idx]
}

func codexFingerprintSeed(ctx context.Context, auth *cliproxyauth.Auth) string {
	if ginCtx := ginContextFrom(ctx); ginCtx != nil && ginCtx.Request != nil {
		if affinityKey := strings.TrimSpace(ginCtx.Request.Header.Get(codexAffinityKeyHeader)); affinityKey != "" {
			return "affinity:" + affinityKey
		}
		if clientKey := requestClientAPIKeyFromRequest(ginCtx.Request); clientKey != "" {
			return "client_api_key:" + clientKey
		}
	}
	if auth != nil {
		if auth.Attributes != nil {
			if apiKey := strings.TrimSpace(auth.Attributes["api_key"]); apiKey != "" {
				return "auth_api_key:" + apiKey
			}
		}
		if authIndex := strings.TrimSpace(auth.EnsureIndex()); authIndex != "" {
			return "auth_index:" + authIndex
		}
		if authID := strings.TrimSpace(auth.ID); authID != "" {
			return "auth_id:" + authID
		}
	}
	return ""
}

func requestClientAPIKeyFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		return extractBearerToken(authHeader)
	}
	if key := strings.TrimSpace(r.Header.Get("X-Goog-Api-Key")); key != "" {
		return key
	}
	if key := strings.TrimSpace(r.Header.Get("X-Api-Key")); key != "" {
		return key
	}
	if r.URL == nil {
		return ""
	}
	if key := strings.TrimSpace(r.URL.Query().Get("key")); key != "" {
		return key
	}
	return strings.TrimSpace(r.URL.Query().Get("auth_token"))
}

func extractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return header
	}
	if !strings.EqualFold(strings.TrimSpace(parts[0]), "bearer") {
		return header
	}
	return strings.TrimSpace(parts[1])
}
