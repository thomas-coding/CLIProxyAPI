package cliproxy

import (
	"net/http"
	"strings"
	"sync"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// defaultRoundTripperProvider returns a per-auth HTTP RoundTripper based on
// the Auth.ProxyURL value. It caches transports per proxy URL string.
type defaultRoundTripperProvider struct {
	mu    sync.RWMutex
	cache map[string]http.RoundTripper
}

func newDefaultRoundTripperProvider() *defaultRoundTripperProvider {
	return &defaultRoundTripperProvider{cache: make(map[string]http.RoundTripper)}
}

// RoundTripperFor implements coreauth.RoundTripperProvider.
func (p *defaultRoundTripperProvider) RoundTripperFor(auth *coreauth.Auth) http.RoundTripper {
	if auth == nil {
		return nil
	}
	proxyStr := strings.TrimSpace(auth.ProxyURL)
	if shouldForceCodexIPv4(auth, proxyStr) {
		return p.cachedTransport("codex:ipv4-direct", newIPv4DirectTransport)
	}
	if proxyStr == "" {
		return nil
	}
	return p.cachedTransport(proxyStr, func() http.RoundTripper {
		transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyStr)
		if errBuild != nil {
			log.Errorf("%v", errBuild)
			return nil
		}
		return transport
	})
}

func (p *defaultRoundTripperProvider) cachedTransport(key string, build func() http.RoundTripper) http.RoundTripper {
	p.mu.RLock()
	rt := p.cache[key]
	p.mu.RUnlock()
	if rt != nil {
		return rt
	}
	rt = build()
	if rt == nil {
		return nil
	}
	p.mu.Lock()
	p.cache[key] = rt
	p.mu.Unlock()
	return rt
}

func shouldForceCodexIPv4(auth *coreauth.Auth, proxyStr string) bool {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	return proxyStr == "" || strings.EqualFold(proxyStr, "direct") || strings.EqualFold(proxyStr, "none")
}

func newIPv4DirectTransport() http.RoundTripper {
	return proxyutil.NewIPv4DirectTransport()
}
