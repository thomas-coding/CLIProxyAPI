package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type affinityTestExecutor struct {
	mu                sync.Mutex
	calls             []string
	failByAuth        map[string]error
	countFailByAuth   map[string]error
	refreshFailByAuth map[string]error
}

func (e *affinityTestExecutor) Identifier() string { return "codex" }

func (e *affinityTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	_ = ctx
	_ = req
	_ = opts
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	e.mu.Lock()
	e.calls = append(e.calls, authID)
	err := e.failByAuth[authID]
	e.mu.Unlock()
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	return cliproxyexecutor.Response{Payload: []byte(authID)}, nil
}

func (e *affinityTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, &Error{Code: "not_implemented", Message: "ExecuteStream not implemented", HTTPStatus: http.StatusNotImplemented}
}

func (e *affinityTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	e.mu.Lock()
	err := e.refreshFailByAuth[authID]
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return auth, nil
}

func (e *affinityTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	_ = ctx
	_ = req
	_ = opts
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	e.mu.Lock()
	e.calls = append(e.calls, "count:"+authID)
	err := e.countFailByAuth[authID]
	e.mu.Unlock()
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	return cliproxyexecutor.Response{Payload: []byte(authID)}, nil
}

func (e *affinityTestExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *affinityTestExecutor) setFailure(authID string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failByAuth == nil {
		e.failByAuth = make(map[string]error)
	}
	e.failByAuth[authID] = err
}

func (e *affinityTestExecutor) callsSnapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.calls))
	copy(out, e.calls)
	return out
}

type affinityContextAwareFillFirstSelector struct{}

func (s *affinityContextAwareFillFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	available, err := getAvailableAuths(auths, provider, model, time.Now())
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	return available[0], nil
}

type affinitySimpleStreamExecutor struct {
	mu    sync.Mutex
	calls []string
}

func (e *affinitySimpleStreamExecutor) Identifier() string { return "codex" }

func (e *affinitySimpleStreamExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	_ = ctx
	_ = req
	_ = opts
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	e.mu.Lock()
	e.calls = append(e.calls, authID)
	e.mu.Unlock()
	return cliproxyexecutor.Response{Payload: []byte(authID)}, nil
}

func (e *affinitySimpleStreamExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	_ = ctx
	_ = req
	_ = opts
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	e.mu.Lock()
	e.calls = append(e.calls, "stream:"+authID)
	e.mu.Unlock()
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Payload: []byte(authID)}
	close(ch)
	return &cliproxyexecutor.StreamResult{Headers: http.Header{}, Chunks: ch}, nil
}

func (e *affinitySimpleStreamExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *affinitySimpleStreamExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	return cliproxyexecutor.Response{Payload: []byte(authID)}, nil
}

func (e *affinitySimpleStreamExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

type affinityScriptedCall struct {
	wait <-chan struct{}
	err  error
}

type affinityScriptedExecutor struct {
	mu                sync.Mutex
	calls             []string
	scripts           map[string][]affinityScriptedCall
	refreshFailByAuth map[string]error
	started           chan string
}

func (e *affinityScriptedExecutor) Identifier() string { return "codex" }

func (e *affinityScriptedExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	_ = req
	_ = opts
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	var call affinityScriptedCall
	e.mu.Lock()
	e.calls = append(e.calls, authID)
	if len(e.scripts[authID]) > 0 {
		call = e.scripts[authID][0]
		e.scripts[authID] = e.scripts[authID][1:]
	}
	started := e.started
	e.mu.Unlock()
	if started != nil {
		started <- authID
	}
	if call.wait != nil {
		select {
		case <-ctx.Done():
			return cliproxyexecutor.Response{}, ctx.Err()
		case <-call.wait:
		}
	}
	if call.err != nil {
		return cliproxyexecutor.Response{}, call.err
	}
	return cliproxyexecutor.Response{Payload: []byte(authID)}, nil
}

func (e *affinityScriptedExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, &Error{Code: "not_implemented", Message: "ExecuteStream not implemented", HTTPStatus: http.StatusNotImplemented}
}

func (e *affinityScriptedExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	e.mu.Lock()
	err := e.refreshFailByAuth[authID]
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return auth, nil
}

func (e *affinityScriptedExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	return cliproxyexecutor.Response{Payload: []byte(authID)}, nil
}

func (e *affinityScriptedExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *affinityScriptedExecutor) setScripts(authID string, calls ...affinityScriptedCall) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.scripts == nil {
		e.scripts = make(map[string][]affinityScriptedCall)
	}
	e.scripts[authID] = append([]affinityScriptedCall(nil), calls...)
}

func (e *affinityScriptedExecutor) callsSnapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.calls))
	copy(out, e.calls)
	return out
}

type affinityCancelingStreamExecutor struct {
	started chan string
}

func (e *affinityCancelingStreamExecutor) Identifier() string { return "codex" }

func (e *affinityCancelingStreamExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, &Error{Code: "not_implemented", Message: "Execute not implemented", HTTPStatus: http.StatusNotImplemented}
}

func (e *affinityCancelingStreamExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	_ = req
	_ = opts
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	if e.started != nil {
		e.started <- authID
	}
	ch := make(chan cliproxyexecutor.StreamChunk, 2)
	ch <- cliproxyexecutor.StreamChunk{Payload: []byte("data: hello\n\n")}
	go func() {
		defer close(ch)
		<-ctx.Done()
		ch <- cliproxyexecutor.StreamChunk{Err: ctx.Err()}
	}()
	return &cliproxyexecutor.StreamResult{Headers: http.Header{}, Chunks: ch}, nil
}

func (e *affinityCancelingStreamExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *affinityCancelingStreamExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	return cliproxyexecutor.Response{Payload: []byte(authID)}, nil
}

func (e *affinityCancelingStreamExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

func configureAffinityTestManager(t *testing.T, selector Selector, model string) (*Manager, *affinityTestExecutor, string, string) {
	t.Helper()

	manager := NewManager(nil, selector, nil)
	executor := &affinityTestExecutor{failByAuth: make(map[string]error), countFailByAuth: make(map[string]error), refreshFailByAuth: make(map[string]error)}
	manager.RegisterExecutor(executor)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				IdleTTLSeconds: 600,
			},
		},
	})

	authAID := model + "-auth-a"
	authBID := model + "-auth-b"
	auths := []*Auth{
		{ID: authAID, Provider: "codex", Metadata: map[string]any{"email": "a@example.com"}},
		{ID: authBID, Provider: "codex", Metadata: map[string]any{"email": "b@example.com"}},
	}
	for _, auth := range auths {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, err)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
	}
	t.Cleanup(func() {
		for _, auth := range auths {
			registry.GetGlobalRegistry().UnregisterClient(auth.ID)
		}
	})

	return manager, executor, authAID, authBID
}

func configureScriptedAffinityTestManager(t *testing.T, selector Selector, model string) (*Manager, *affinityScriptedExecutor, string, string) {
	t.Helper()

	manager := NewManager(nil, selector, nil)
	executor := &affinityScriptedExecutor{
		scripts:           make(map[string][]affinityScriptedCall),
		refreshFailByAuth: make(map[string]error),
		started:           make(chan string, 16),
	}
	manager.RegisterExecutor(executor)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				IdleTTLSeconds: 600,
			},
		},
	})

	authAID := model + "-auth-a"
	authBID := model + "-auth-b"
	auths := []*Auth{
		{ID: authAID, Provider: "codex", Metadata: map[string]any{"email": "a@example.com"}},
		{ID: authBID, Provider: "codex", Metadata: map[string]any{"email": "b@example.com"}},
	}
	for _, auth := range auths {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, err)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
	}
	t.Cleanup(func() {
		for _, auth := range auths {
			registry.GetGlobalRegistry().UnregisterClient(auth.ID)
		}
	})

	return manager, executor, authAID, authBID
}

func waitForAffinityExecutorStart(t *testing.T, started <-chan string) string {
	t.Helper()
	select {
	case authID := <-started:
		return authID
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for executor start")
		return ""
	}
}

func affinityLeaseAuthID(manager *Manager, scopeKey string) string {
	if manager == nil || manager.affinity == nil {
		return ""
	}
	manager.affinity.mu.Lock()
	defer manager.affinity.mu.Unlock()
	lease := manager.affinity.leaseByKey[scopeKey]
	if lease == nil {
		return ""
	}
	return lease.AuthID
}

func affinityLeaseConfirmed(manager *Manager, scopeKey string) bool {
	if manager == nil || manager.affinity == nil {
		return false
	}
	manager.affinity.mu.Lock()
	defer manager.affinity.mu.Unlock()
	lease := manager.affinity.leaseByKey[scopeKey]
	if lease == nil {
		return false
	}
	return lease.Confirmed
}

func registerAffinityAuthsForModels(t *testing.T, manager *Manager, authModels map[string][]string) []string {
	t.Helper()
	ids := make([]string, 0, len(authModels))
	for authID, models := range authModels {
		auth := &Auth{ID: authID, Provider: "codex", Metadata: map[string]any{"email": authID + "@example.com"}}
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, err)
		}
		ids = append(ids, authID)
		modelInfos := make([]*registry.ModelInfo, 0, len(models))
		for _, model := range models {
			modelInfos = append(modelInfos, &registry.ModelInfo{ID: model})
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, modelInfos)
	}
	t.Cleanup(func() {
		for _, authID := range ids {
			registry.GetGlobalRegistry().UnregisterClient(authID)
		}
	})
	return ids
}

func TestManagerExecute_AffinitySkipsAuthOwnedByAnotherUser(t *testing.T) {
	model := "affinity-share-test-model"
	manager, executor, authAID, authBID := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}

	respOne, err := manager.Execute(context.Background(), []string{"codex"}, req, cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:1"},
	})
	if err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	if string(respOne.Payload) != authAID {
		t.Fatalf("first Execute() payload = %q, want %q", string(respOne.Payload), authAID)
	}

	respTwo, err := manager.Execute(context.Background(), []string{"codex"}, req, cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:2"},
	})
	if err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if string(respTwo.Payload) != authBID {
		t.Fatalf("second Execute() payload = %q, want %q", string(respTwo.Payload), authBID)
	}

	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:1")); got != authAID {
		t.Fatalf("lease(user:1) = %q, want %q", got, authAID)
	}
	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:2")); got != authBID {
		t.Fatalf("lease(user:2) = %q, want %q", got, authBID)
	}

	if got := executor.callsSnapshot(); len(got) != 2 || got[0] != authAID || got[1] != authBID {
		t.Fatalf("executor calls = %v, want [%s %s]", got, authAID, authBID)
	}
}

func TestManagerExecute_AffinityBreaksLeaseAndRebindsAfter429(t *testing.T) {
	model := "affinity-rebind-test-model"
	manager, executor, authAID, authBID := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	respOne, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	if string(respOne.Payload) != authAID {
		t.Fatalf("first Execute() payload = %q, want %q", string(respOne.Payload), authAID)
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authAID {
		t.Fatalf("lease after first success = %q, want %q", got, authAID)
	}

	executor.setFailure(authAID, &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"})

	respTwo, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if string(respTwo.Payload) != authBID {
		t.Fatalf("second Execute() payload = %q, want %q", string(respTwo.Payload), authBID)
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authBID {
		t.Fatalf("lease after rebind = %q, want %q", got, authBID)
	}

	if got := executor.callsSnapshot(); len(got) != 3 || got[0] != authAID || got[1] != authAID || got[2] != authBID {
		t.Fatalf("executor calls = %v, want [%s %s %s]", got, authAID, authAID, authBID)
	}
}

func TestManagerExecute_AffinityBreaksLeaseAndRebindsAfter401(t *testing.T) {
	model := "affinity-401-rebind-test-model"
	manager, executor, authAID, authBID := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	respOne, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	if string(respOne.Payload) != authAID {
		t.Fatalf("first Execute() payload = %q, want %q", string(respOne.Payload), authAID)
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authAID {
		t.Fatalf("lease after first success = %q, want %q", got, authAID)
	}

	executor.setFailure(authAID, &Error{
		HTTPStatus: http.StatusUnauthorized,
		Code:       auth401KindAccountDeactivated,
		Message:    auth401KindAccountDeactivated,
	})

	respTwo, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if string(respTwo.Payload) != authBID {
		t.Fatalf("second Execute() payload = %q, want %q", string(respTwo.Payload), authBID)
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authBID {
		t.Fatalf("lease after rebind = %q, want %q", got, authBID)
	}

	if got := executor.callsSnapshot(); len(got) != 3 || got[0] != authAID || got[1] != authAID || got[2] != authBID {
		t.Fatalf("executor calls = %v, want [%s %s %s]", got, authAID, authAID, authBID)
	}
}

func TestManagerExecute_AffinityKeepsSameUserStickyUnderRoundRobin(t *testing.T) {
	model := "affinity-round-robin-stickiness-test-model"
	manager, executor, authAID, authBID := configureAffinityTestManager(t, &RoundRobinSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	optsUser15 := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	optsUser16 := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:16"},
	}

	for i := 0; i < 3; i++ {
		resp, err := manager.Execute(context.Background(), []string{"codex"}, req, optsUser15)
		if err != nil {
			t.Fatalf("user:15 Execute() #%d error = %v", i+1, err)
		}
		if string(resp.Payload) != authAID {
			t.Fatalf("user:15 Execute() #%d payload = %q, want %q", i+1, string(resp.Payload), authAID)
		}
	}

	respOther, err := manager.Execute(context.Background(), []string{"codex"}, req, optsUser16)
	if err != nil {
		t.Fatalf("user:16 Execute() error = %v", err)
	}
	if string(respOther.Payload) != authBID {
		t.Fatalf("user:16 Execute() payload = %q, want %q", string(respOther.Payload), authBID)
	}

	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:15")); got != authAID {
		t.Fatalf("lease(user:15) = %q, want %q", got, authAID)
	}
	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:16")); got != authBID {
		t.Fatalf("lease(user:16) = %q, want %q", got, authBID)
	}

	if got := executor.callsSnapshot(); len(got) != 4 || got[0] != authAID || got[1] != authAID || got[2] != authAID || got[3] != authBID {
		t.Fatalf("executor calls = %v, want [%s %s %s %s]", got, authAID, authAID, authAID, authBID)
	}
}

func TestManagerExecute_AffinityColdStartConcurrentSameUserClaimsSingleAuth(t *testing.T) {
	model := "affinity-concurrent-cold-start-test-model"
	manager, executor, authAID, _ := configureScriptedAffinityTestManager(t, &RoundRobinSelector{}, model)
	release := make(chan struct{})
	executor.setScripts(
		authAID,
		affinityScriptedCall{wait: release},
		affinityScriptedCall{wait: release},
	)

	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}

	type execResult struct {
		payload string
		err     error
	}
	done := make(chan execResult, 2)
	run := func() {
		resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
		done <- execResult{payload: string(resp.Payload), err: err}
	}

	go run()
	if got := waitForAffinityExecutorStart(t, executor.started); got != authAID {
		t.Fatalf("first concurrent auth = %q, want %q", got, authAID)
	}
	go run()
	if got := waitForAffinityExecutorStart(t, executor.started); got != authAID {
		t.Fatalf("second concurrent auth = %q, want %q", got, authAID)
	}

	close(release)

	for i := 0; i < 2; i++ {
		result := <-done
		if result.err != nil {
			t.Fatalf("Execute() #%d error = %v", i+1, result.err)
		}
		if result.payload != authAID {
			t.Fatalf("Execute() #%d payload = %q, want %q", i+1, result.payload, authAID)
		}
	}

	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:15")); got != authAID {
		t.Fatalf("lease(user:15) = %q, want %q", got, authAID)
	}
	if got := executor.callsSnapshot(); len(got) != 2 || got[0] != authAID || got[1] != authAID {
		t.Fatalf("executor calls = %v, want [%s %s]", got, authAID, authAID)
	}
}

func TestManagerExecute_AffinityLateSuccessDoesNotStealLeaseAfter429Rebind(t *testing.T) {
	model := "affinity-late-success-rebind-test-model"
	manager, executor, authAID, authBID := configureScriptedAffinityTestManager(t, &FillFirstSelector{}, model)
	manager.SetRetryConfig(0, 0, 2)

	release := make(chan struct{})
	executor.setScripts(
		authAID,
		affinityScriptedCall{wait: release},
		affinityScriptedCall{err: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"}},
	)

	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}

	type execResult struct {
		payload string
		err     error
	}
	firstDone := make(chan execResult, 1)
	secondDone := make(chan execResult, 1)

	go func() {
		resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
		firstDone <- execResult{payload: string(resp.Payload), err: err}
	}()
	if got := waitForAffinityExecutorStart(t, executor.started); got != authAID {
		t.Fatalf("first auth = %q, want %q", got, authAID)
	}

	go func() {
		resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
		secondDone <- execResult{payload: string(resp.Payload), err: err}
	}()
	if got := waitForAffinityExecutorStart(t, executor.started); got != authAID {
		t.Fatalf("second auth = %q, want %q", got, authAID)
	}

	second := <-secondDone
	if second.err != nil {
		t.Fatalf("second Execute() error = %v", second.err)
	}
	if second.payload != authBID {
		t.Fatalf("second Execute() payload = %q, want %q", second.payload, authBID)
	}
	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:15")); got != authBID {
		t.Fatalf("lease after 429 rebind = %q, want %q", got, authBID)
	}

	close(release)

	first := <-firstDone
	if first.err != nil {
		t.Fatalf("first Execute() error = %v", first.err)
	}
	if first.payload != authAID {
		t.Fatalf("first Execute() payload = %q, want %q", first.payload, authAID)
	}
	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:15")); got != authBID {
		t.Fatalf("lease after late success = %q, want %q", got, authBID)
	}

	authA, ok := manager.GetByID(authAID)
	if !ok || authA == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	state := authA.ModelStates[model]
	if state == nil {
		t.Fatalf("authA.ModelStates[%q] = nil, want quota cooldown state", model)
	}
	if !state.Unavailable {
		t.Fatalf("state.Unavailable = false, want true")
	}
	if !state.Quota.Exceeded {
		t.Fatalf("state.Quota.Exceeded = false, want true")
	}

	if got := executor.callsSnapshot(); len(got) != 3 || got[0] != authAID || got[1] != authAID || got[2] != authBID {
		t.Fatalf("executor calls = %v, want [%s %s %s]", got, authAID, authAID, authBID)
	}
}

func TestManagerExecute_AffinityFallsBackToSharedAuthWhenNoExclusiveAuthRemains(t *testing.T) {
	model := "affinity-shared-fallback-test-model"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	executor := &affinityTestExecutor{failByAuth: make(map[string]error), countFailByAuth: make(map[string]error), refreshFailByAuth: make(map[string]error)}
	manager.RegisterExecutor(executor)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				IdleTTLSeconds: 600,
			},
		},
	})

	auth := &Auth{ID: model + "-auth-a", Provider: "codex", Metadata: map[string]any{"email": "a@example.com"}}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register(%s) error = %v", auth.ID, err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() {
		registry.GetGlobalRegistry().UnregisterClient(auth.ID)
	})

	req := cliproxyexecutor.Request{Model: model}
	optsUser1 := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:1"},
	}
	optsUser2 := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:2"},
	}

	respOne, err := manager.Execute(context.Background(), []string{"codex"}, req, optsUser1)
	if err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	if string(respOne.Payload) != auth.ID {
		t.Fatalf("first Execute() payload = %q, want %q", string(respOne.Payload), auth.ID)
	}

	respTwo, err := manager.Execute(context.Background(), []string{"codex"}, req, optsUser2)
	if err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if string(respTwo.Payload) != auth.ID {
		t.Fatalf("second Execute() payload = %q, want %q", string(respTwo.Payload), auth.ID)
	}

	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:1")); got != auth.ID {
		t.Fatalf("lease(user:1) = %q, want %q", got, auth.ID)
	}
	if got := affinityLeaseAuthID(manager, buildAffinityScopeKey([]string{"codex"}, "user:2")); got != "" {
		t.Fatalf("lease(user:2) = %q, want empty because shared fallback should not steal existing lease", got)
	}
}

func TestManagerExecuteCount_AffinityDoesNotBreakLeaseOnCountFailure(t *testing.T) {
	model := "affinity-count-test-model"
	manager, executor, authAID, authBID := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if string(resp.Payload) != authAID {
		t.Fatalf("Execute() payload = %q, want %q", string(resp.Payload), authAID)
	}

	executor.countFailByAuth[authAID] = &Error{HTTPStatus: http.StatusTooManyRequests, Message: "count quota"}
	resp, err = manager.ExecuteCount(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("ExecuteCount() error = %v", err)
	}
	if string(resp.Payload) != authBID {
		t.Fatalf("ExecuteCount() payload = %q, want %q", string(resp.Payload), authBID)
	}

	if got := affinityLeaseAuthID(manager, scopeKey); got != authAID {
		t.Fatalf("lease after count failure = %q, want %q", got, authAID)
	}
	auth, ok := manager.GetByID(authAID)
	if !ok || auth == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	if auth.Unavailable {
		t.Fatalf("auth.Unavailable = true, want false")
	}
	state := auth.ModelStates[model]
	if state == nil {
		t.Fatalf("auth.ModelStates[%q] = nil, want active state", model)
	}
	if state.Unavailable {
		t.Fatalf("state.Unavailable = true, want false")
	}
	if !state.NextRetryAfter.IsZero() {
		t.Fatalf("state.NextRetryAfter = %v, want zero", state.NextRetryAfter)
	}
	if state.Quota.Exceeded {
		t.Fatalf("state.Quota.Exceeded = true, want false")
	}
	if state.LastError != nil {
		t.Fatalf("state.LastError = %#v, want nil", state.LastError)
	}
	if got := executor.callsSnapshot(); len(got) != 3 || got[0] != authAID || got[1] != "count:"+authAID || got[2] != "count:"+authBID {
		t.Fatalf("executor calls = %v, want [%s count:%s count:%s]", got, authAID, authAID, authBID)
	}
}

func TestManagerExecute_AffinityRebindsWhenBoundAuthModelIsUnavailable(t *testing.T) {
	model := "affinity-model-unavailable-rebind-test-model"
	manager := NewManager(nil, &affinityContextAwareFillFirstSelector{}, nil)
	executor := &affinityTestExecutor{failByAuth: make(map[string]error), countFailByAuth: make(map[string]error), refreshFailByAuth: make(map[string]error)}
	manager.RegisterExecutor(executor)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				IdleTTLSeconds: 600,
			},
		},
	})

	authAID := model + "-auth-a"
	authBID := model + "-auth-b"
	registerAffinityAuthsForModels(t, manager, map[string][]string{
		authAID: {model},
		authBID: {model},
	})

	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	if string(resp.Payload) != authAID {
		t.Fatalf("first Execute() payload = %q, want %q", string(resp.Payload), authAID)
	}

	authA, ok := manager.GetByID(authAID)
	if !ok || authA == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	authA.ModelStates = map[string]*ModelState{
		model: {
			Status:         StatusError,
			Unavailable:    true,
			NextRetryAfter: time.Now().Add(5 * time.Minute),
			LastError:      &Error{HTTPStatus: http.StatusNotFound, Message: "model unavailable"},
		},
	}
	authA.Status = StatusError
	if _, err := manager.Update(context.Background(), authA); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	resp, err = manager.Execute(ctx, []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if string(resp.Payload) != authBID {
		t.Fatalf("second Execute() payload = %q, want %q", string(resp.Payload), authBID)
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authBID {
		t.Fatalf("lease after unavailable rebind = %q, want %q", got, authBID)
	}
}

func TestManagerExecute_AffinityRebindsWhenBoundAuthDoesNotSupportRequestedModel(t *testing.T) {
	modelA := "affinity-supported-model-a"
	modelB := "affinity-supported-model-b"
	manager := NewManager(nil, &affinityContextAwareFillFirstSelector{}, nil)
	executor := &affinityTestExecutor{failByAuth: make(map[string]error), countFailByAuth: make(map[string]error), refreshFailByAuth: make(map[string]error)}
	manager.RegisterExecutor(executor)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				IdleTTLSeconds: 600,
			},
		},
	})

	authAID := "affinity-unsupported-auth-a"
	authBID := "affinity-unsupported-auth-b"
	registerAffinityAuthsForModels(t, manager, map[string][]string{
		authAID: {modelA},
		authBID: {modelB},
	})

	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	resp, err := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: modelA}, opts)
	if err != nil {
		t.Fatalf("Execute(modelA) error = %v", err)
	}
	if string(resp.Payload) != authAID {
		t.Fatalf("Execute(modelA) payload = %q, want %q", string(resp.Payload), authAID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	resp, err = manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: modelB}, opts)
	if err != nil {
		t.Fatalf("Execute(modelB) error = %v", err)
	}
	if string(resp.Payload) != authBID {
		t.Fatalf("Execute(modelB) payload = %q, want %q", string(resp.Payload), authBID)
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authBID {
		t.Fatalf("lease after unsupported-model rebind = %q, want %q", got, authBID)
	}
}

func TestManagerExecute_AffinityRebindsAfterSameRequestModelError(t *testing.T) {
	model := "affinity-same-request-model-error-test-model"
	manager := NewManager(nil, &affinityContextAwareFillFirstSelector{}, nil)
	executor := &affinityTestExecutor{failByAuth: make(map[string]error), countFailByAuth: make(map[string]error), refreshFailByAuth: make(map[string]error)}
	manager.RegisterExecutor(executor)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				IdleTTLSeconds: 600,
			},
		},
	})

	authAID := model + "-auth-a"
	authBID := model + "-auth-b"
	registerAffinityAuthsForModels(t, manager, map[string][]string{
		authAID: {model},
		authBID: {model},
	})

	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	if string(resp.Payload) != authAID {
		t.Fatalf("first Execute() payload = %q, want %q", string(resp.Payload), authAID)
	}

	executor.setFailure(authAID, &Error{HTTPStatus: http.StatusNotFound, Message: "model not found"})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	resp, err = manager.Execute(ctx, []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if string(resp.Payload) != authBID {
		t.Fatalf("second Execute() payload = %q, want %q", string(resp.Payload), authBID)
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authBID {
		t.Fatalf("lease after same-request model error = %q, want %q", got, authBID)
	}
}

func TestManagerExecuteStream_AffinityRebindsWhenBoundAuthModelIsUnavailable(t *testing.T) {
	model := "affinity-stream-unavailable-rebind-test-model"
	manager := NewManager(nil, &affinityContextAwareFillFirstSelector{}, nil)
	executor := &affinitySimpleStreamExecutor{}
	manager.RegisterExecutor(executor)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				IdleTTLSeconds: 600,
			},
		},
	})

	authAID := model + "-auth-a"
	authBID := model + "-auth-b"
	registerAffinityAuthsForModels(t, manager, map[string][]string{
		authAID: {model},
		authBID: {model},
	})

	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	streamResult, err := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts)
	if err != nil {
		t.Fatalf("first ExecuteStream() error = %v", err)
	}
	first := <-streamResult.Chunks
	if string(first.Payload) != authAID {
		t.Fatalf("first stream payload = %q, want %q", string(first.Payload), authAID)
	}
	for range streamResult.Chunks {
	}

	authA, ok := manager.GetByID(authAID)
	if !ok || authA == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	authA.ModelStates = map[string]*ModelState{
		model: {
			Status:         StatusError,
			Unavailable:    true,
			NextRetryAfter: time.Now().Add(5 * time.Minute),
			LastError:      &Error{HTTPStatus: http.StatusNotFound, Message: "model unavailable"},
		},
	}
	authA.Status = StatusError
	if _, err := manager.Update(context.Background(), authA); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	streamResult, err = manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts)
	if err != nil {
		t.Fatalf("second ExecuteStream() error = %v", err)
	}
	second := <-streamResult.Chunks
	if string(second.Payload) != authBID {
		t.Fatalf("second stream payload = %q, want %q", string(second.Payload), authBID)
	}
	for range streamResult.Chunks {
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authBID {
		t.Fatalf("stream lease after unavailable rebind = %q, want %q", got, authBID)
	}
}

func TestManagerMarkResult_ShadowAffinitySuccessClearsStateAndRecordsLease(t *testing.T) {
	model := "affinity-shadow-success-test-model"
	manager, _, authAID, _ := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				ShadowMode:     true,
				IdleTTLSeconds: 600,
			},
		},
	})
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	auth, ok := manager.GetByID(authAID)
	if !ok || auth == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	auth.Status = StatusError
	auth.Unavailable = true
	auth.LastError = &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"}
	auth.ModelStates = map[string]*ModelState{
		model: {
			Status:         StatusError,
			Unavailable:    true,
			NextRetryAfter: time.Now().Add(5 * time.Minute),
			LastError:      &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
			Quota: QuotaState{
				Exceeded:      true,
				NextRecoverAt: time.Now().Add(5 * time.Minute),
			},
		},
	}
	if _, err := manager.Update(context.Background(), auth); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	manager.MarkResult(context.Background(), Result{
		AuthID:      authAID,
		Provider:    "codex",
		Model:       model,
		AffinityKey: scopeKey,
		Success:     true,
	})

	updated, ok := manager.GetByID(authAID)
	if !ok || updated == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	state := updated.ModelStates[model]
	if state == nil {
		t.Fatalf("updated.ModelStates[%q] = nil", model)
	}
	if state.Status != StatusActive {
		t.Fatalf("state.Status = %q, want %q", state.Status, StatusActive)
	}
	if state.Unavailable {
		t.Fatalf("state.Unavailable = true, want false")
	}
	if !state.NextRetryAfter.IsZero() {
		t.Fatalf("state.NextRetryAfter = %v, want zero", state.NextRetryAfter)
	}
	if state.LastError != nil {
		t.Fatalf("state.LastError = %#v, want nil", state.LastError)
	}
	if state.Quota.Exceeded {
		t.Fatalf("state.Quota.Exceeded = true, want false")
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authAID {
		t.Fatalf("shadow lease auth = %q, want %q", got, authAID)
	}
	if !affinityLeaseConfirmed(manager, scopeKey) {
		t.Fatalf("shadow lease confirmed = false, want true")
	}
}

func TestManagerSetConfig_AffinityModeChangeClearsLeases(t *testing.T) {
	model := "affinity-config-reset-test-model"
	manager, _, authAID, _ := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if string(resp.Payload) != authAID {
		t.Fatalf("Execute() payload = %q, want %q", string(resp.Payload), authAID)
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != authAID {
		t.Fatalf("lease before config change = %q, want %q", got, authAID)
	}

	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				ShadowMode:     true,
				IdleTTLSeconds: 600,
			},
		},
	})

	if got := affinityLeaseAuthID(manager, scopeKey); got != "" {
		t.Fatalf("lease after config change = %q, want empty", got)
	}
}

func TestManagerExecute_AffinityInvalidRequestReleasesUnconfirmedReservation(t *testing.T) {
	model := "affinity-invalid-request-release-test-model"
	manager, executor, authAID, _ := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")
	executor.setFailure(authAID, &Error{HTTPStatus: http.StatusBadRequest, Message: "invalid_request_error: bad request"})

	_, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err == nil {
		t.Fatal("Execute() error = nil, want invalid_request_error")
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != "" {
		t.Fatalf("lease after invalid request = %q, want empty", got)
	}
}

func TestManagerExecute_AffinityCanceledColdStartReleasesReservation(t *testing.T) {
	model := "affinity-cancel-release-test-model"
	manager, executor, authAID, _ := configureScriptedAffinityTestManager(t, &FillFirstSelector{}, model)
	release := make(chan struct{})
	executor.setScripts(authAID, affinityScriptedCall{wait: release})

	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := manager.Execute(ctx, []string{"codex"}, req, opts)
		done <- err
	}()

	if got := waitForAffinityExecutorStart(t, executor.started); got != authAID {
		t.Fatalf("started auth = %q, want %q", got, authAID)
	}
	cancel()
	err := <-done
	close(release)
	if err == nil {
		t.Fatal("Execute() error = nil, want context canceled")
	}
	if got := affinityLeaseAuthID(manager, scopeKey); got != "" {
		t.Fatalf("lease after cancellation = %q, want empty", got)
	}
}

func TestManagerExecuteStream_AffinityCancellationAfterFirstChunkKeepsConfirmedLease(t *testing.T) {
	model := "affinity-stream-cancel-test-model"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	executor := &affinityCancelingStreamExecutor{started: make(chan string, 1)}
	manager.RegisterExecutor(executor)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			Affinity: internalconfig.AffinityConfig{
				Enabled:        true,
				IdleTTLSeconds: 600,
			},
		},
	})

	authAID := model + "-auth-a"
	auth := &Auth{ID: authAID, Provider: "codex", Metadata: map[string]any{"email": "a@example.com"}}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register(%s) error = %v", auth.ID, err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() {
		registry.GetGlobalRegistry().UnregisterClient(auth.ID)
	})

	ctx, cancel := context.WithCancel(context.Background())
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	streamResult, err := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	if got := waitForAffinityExecutorStart(t, executor.started); got != authAID {
		t.Fatalf("started auth = %q, want %q", got, authAID)
	}
	first, ok := <-streamResult.Chunks
	if !ok {
		t.Fatal("stream closed before first chunk")
	}
	if first.Err != nil {
		t.Fatalf("first chunk err = %v, want nil", first.Err)
	}
	if string(first.Payload) != "data: hello\n\n" {
		t.Fatalf("first chunk payload = %q, want data chunk", string(first.Payload))
	}

	cancel()
	for range streamResult.Chunks {
	}

	if got := affinityLeaseAuthID(manager, scopeKey); got != authAID {
		t.Fatalf("lease after stream cancellation = %q, want %q", got, authAID)
	}
	if !affinityLeaseConfirmed(manager, scopeKey) {
		t.Fatalf("lease confirmed after stream cancellation = false, want true")
	}
}

func TestManagerUpdate_DisablingLeasedAuthClearsAffinityLease(t *testing.T) {
	model := "affinity-disable-test-model"
	manager, _, authAID, _ := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if string(resp.Payload) != authAID {
		t.Fatalf("Execute() payload = %q, want %q", string(resp.Payload), authAID)
	}

	auth, ok := manager.GetByID(authAID)
	if !ok || auth == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	auth.Disabled = true
	auth.Status = StatusDisabled
	if _, err := manager.Update(context.Background(), auth); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if got := affinityLeaseAuthID(manager, scopeKey); got != "" {
		t.Fatalf("lease after disable = %q, want empty", got)
	}
}

func TestManagerRefreshAuth_ClearsAffinityLeaseOn401Quarantine(t *testing.T) {
	model := "affinity-refresh-test-model"
	manager, executor, authAID, _ := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if string(resp.Payload) != authAID {
		t.Fatalf("Execute() payload = %q, want %q", string(resp.Payload), authAID)
	}

	executor.refreshFailByAuth[authAID] = &Error{
		Code:       auth401KindTokenInvalidated,
		Message:    auth401KindTokenInvalidated,
		HTTPStatus: http.StatusUnauthorized,
	}
	manager.refreshAuth(context.Background(), authAID)

	if got := affinityLeaseAuthID(manager, scopeKey); got != "" {
		t.Fatalf("lease after refresh quarantine = %q, want empty", got)
	}
	auth, ok := manager.GetByID(authAID)
	if !ok || auth == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	now := time.Now()
	blocked, _ := authWide401BlockState(auth, now)
	if !blocked {
		t.Fatalf("authWide401BlockState() = false, want true")
	}
}

func TestManagerMarkResult_SuccessDoesNotRebindLeaseAfterDisable(t *testing.T) {
	model := "affinity-markresult-disable-test-model"
	manager, _, authAID, _ := configureAffinityTestManager(t, &FillFirstSelector{}, model)
	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AffinityKeyMetadataKey: "user:15"},
	}
	scopeKey := buildAffinityScopeKey([]string{"codex"}, "user:15")

	resp, err := manager.Execute(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if string(resp.Payload) != authAID {
		t.Fatalf("Execute() payload = %q, want %q", string(resp.Payload), authAID)
	}

	auth, ok := manager.GetByID(authAID)
	if !ok || auth == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	auth.Disabled = true
	auth.Status = StatusDisabled
	if _, err := manager.Update(context.Background(), auth); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	manager.MarkResult(context.Background(), Result{
		AuthID:      authAID,
		Provider:    "codex",
		Model:       model,
		AffinityKey: scopeKey,
		Success:     true,
	})

	if got := affinityLeaseAuthID(manager, scopeKey); got != "" {
		t.Fatalf("lease after disabled success mark = %q, want empty", got)
	}
	auth, ok = manager.GetByID(authAID)
	if !ok || auth == nil {
		t.Fatalf("GetByID(%q) returned no auth", authAID)
	}
	if !auth.Disabled {
		t.Fatalf("auth.Disabled = false, want true")
	}
	if auth.Status != StatusDisabled {
		t.Fatalf("auth.Status = %q, want %q", auth.Status, StatusDisabled)
	}
}
