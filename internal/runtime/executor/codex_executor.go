package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/tiktoken-go/tokenizer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	codexTransparentClientHeadersHeader  = "X-Arroute-Client-Headers"
	codexTransparentClientQueryHeader    = "X-Arroute-Client-Query"
	codexTransparentSnapshotStatusHeader = "X-Arroute-Transparent-Snapshot-Status"
)

type codexTransparentMode string

const (
	codexTransparentModeOff    codexTransparentMode = "off"
	codexTransparentModeShadow codexTransparentMode = "shadow"
	codexTransparentModeOn     codexTransparentMode = "on"
)

type codexRequestKind int

const (
	codexRequestKindResponsesNonStream codexRequestKind = iota
	codexRequestKindResponsesCompact
	codexRequestKindResponsesStream
)

type codexPreparedRequest struct {
	body            []byte
	request         *http.Request
	originalPayload []byte
	transparent     bool
}

type codexTransparentSnapshot struct {
	headers  http.Header
	rawQuery string
}

type codexTransparentDiff struct {
	headersOnlyLegacy      []string
	headersOnlyTransparent []string
	headersChanged         []string
	bodyOnlyLegacy         []string
	bodyOnlyTransparent    []string
	bodyChanged            []string
}

var dataTag = []byte("data:")

var codexTransparentAllowedRequestHeaders = map[string]struct{}{
	textproto.CanonicalMIMEHeaderKey("Accept"):              {},
	textproto.CanonicalMIMEHeaderKey("Accept-Encoding"):     {},
	textproto.CanonicalMIMEHeaderKey("Accept-Language"):     {},
	textproto.CanonicalMIMEHeaderKey("Content-Type"):        {},
	textproto.CanonicalMIMEHeaderKey("Idempotency-Key"):     {},
	textproto.CanonicalMIMEHeaderKey("OpenAI-Beta"):         {},
	textproto.CanonicalMIMEHeaderKey("OpenAI-Organization"): {},
	textproto.CanonicalMIMEHeaderKey("OpenAI-Project"):      {},
	textproto.CanonicalMIMEHeaderKey("Originator"):          {},
	"Session_id": {},
	textproto.CanonicalMIMEHeaderKey("Traceparent"):                           {},
	textproto.CanonicalMIMEHeaderKey("Tracestate"):                            {},
	textproto.CanonicalMIMEHeaderKey("User-Agent"):                            {},
	textproto.CanonicalMIMEHeaderKey("Version"):                               {},
	textproto.CanonicalMIMEHeaderKey("X-Codex-Beta-Features"):                 {},
	textproto.CanonicalMIMEHeaderKey("X-Codex-Turn-Metadata"):                 {},
	textproto.CanonicalMIMEHeaderKey("X-Codex-Turn-State"):                    {},
	textproto.CanonicalMIMEHeaderKey("X-ResponsesAPI-Include-Timing-Metrics"): {},
	textproto.CanonicalMIMEHeaderKey("X-Stainless-Arch"):                      {},
	textproto.CanonicalMIMEHeaderKey("X-Stainless-Lang"):                      {},
	textproto.CanonicalMIMEHeaderKey("X-Stainless-Os"):                        {},
	textproto.CanonicalMIMEHeaderKey("X-Stainless-Package-Version"):           {},
	textproto.CanonicalMIMEHeaderKey("X-Stainless-Retry-Count"):               {},
	textproto.CanonicalMIMEHeaderKey("X-Stainless-Runtime"):                   {},
	textproto.CanonicalMIMEHeaderKey("X-Stainless-Runtime-Version"):           {},
	textproto.CanonicalMIMEHeaderKey("X-Stainless-Timeout"):                   {},
}

// CodexExecutor is a stateless executor for Codex (OpenAI Responses API entrypoint).
// If api_key is unavailable on auth, it falls back to legacy via ClientAdapter.
type CodexExecutor struct {
	cfg *config.Config
}

func NewCodexExecutor(cfg *config.Config) *CodexExecutor { return &CodexExecutor{cfg: cfg} }

func (e *CodexExecutor) Identifier() string { return "codex" }

// PrepareRequest injects Codex credentials into the outgoing HTTP request.
func (e *CodexExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	apiKey, _ := codexCreds(auth)
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return nil
}

// HttpRequest injects Codex credentials into the request and executes it.
func (e *CodexExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("codex executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := newProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

func selectOriginalPayloadSource(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) []byte {
	if len(opts.OriginalRequest) > 0 {
		return opts.OriginalRequest
	}
	return req.Payload
}

func codexRequestURL(baseURL string, kind codexRequestKind) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	switch kind {
	case codexRequestKindResponsesCompact:
		return baseURL + "/responses/compact"
	default:
		return baseURL + "/responses"
	}
}

func codexTransparentRequestURL(baseURL string, kind codexRequestKind, rawQuery string) string {
	requestURL := codexRequestURL(baseURL, kind)
	rawQuery = strings.TrimSpace(strings.TrimPrefix(rawQuery, "?"))
	if rawQuery == "" {
		return requestURL
	}

	parsed, err := url.Parse(requestURL)
	if err != nil || parsed == nil {
		if strings.Contains(requestURL, "?") {
			return requestURL + "&" + rawQuery
		}
		return requestURL + "?" + rawQuery
	}
	parsed.RawQuery = rawQuery
	return parsed.String()
}

func (e *CodexExecutor) configuredTransparentMode() codexTransparentMode {
	if e == nil || e.cfg == nil {
		return codexTransparentModeOff
	}
	switch strings.ToLower(strings.TrimSpace(e.cfg.CodexRelay.TransparentMode)) {
	case string(codexTransparentModeShadow):
		return codexTransparentModeShadow
	case string(codexTransparentModeOn):
		return codexTransparentModeOn
	default:
		return codexTransparentModeOff
	}
}

func (e *CodexExecutor) effectiveTransparentMode(ctx context.Context, from sdktranslator.Format, originalPayload []byte, kind codexRequestKind) codexTransparentMode {
	mode := e.configuredTransparentMode()
	if mode == codexTransparentModeOff {
		return codexTransparentModeOff
	}
	if from != sdktranslator.FromString("openai-response") {
		return codexTransparentModeOff
	}
	if len(originalPayload) == 0 {
		return codexTransparentModeOff
	}
	if e.shouldForceLegacyHTTPResponses(ctx, kind) {
		return codexTransparentModeOff
	}
	return mode
}

func (e *CodexExecutor) shouldForceLegacyHTTPResponses(ctx context.Context, kind codexRequestKind) bool {
	if e == nil || e.cfg == nil || !e.cfg.CodexRelay.HTTPResponsesLegacyShaping {
		return false
	}
	if kind == codexRequestKindResponsesCompact {
		return false
	}
	ginCtx := ginContextFrom(ctx)
	if ginCtx == nil || ginCtx.Request == nil || ginCtx.Request.URL == nil {
		return false
	}
	return strings.TrimSpace(ginCtx.Request.URL.Path) == "/v1/responses"
}

func (e *CodexExecutor) prepareCodexRequest(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, kind codexRequestKind, baseModel, baseURL, apiKey string, from, to sdktranslator.Format) (codexPreparedRequest, error) {
	legacyPrepared, err := e.buildLegacyCodexRequest(ctx, auth, req, opts, kind, baseModel, baseURL, apiKey, from, to)
	if err != nil {
		return codexPreparedRequest{}, err
	}
	mode := e.effectiveTransparentMode(ctx, from, legacyPrepared.originalPayload, kind)
	if mode == codexTransparentModeOff {
		return legacyPrepared, nil
	}

	transparentPrepared, transparentErr := e.buildTransparentCodexRequest(ctx, auth, req, opts, kind, baseModel, baseURL, apiKey)
	if transparentErr != nil {
		logCodexTransparentUnavailable(ctx, mode, kind, transparentErr)
		return legacyPrepared, nil
	}
	if mode == codexTransparentModeShadow {
		logCodexTransparentShadowDiff(ctx, kind, legacyPrepared, transparentPrepared)
		return legacyPrepared, nil
	}

	logCodexTransparentSelected(ctx, kind)
	return transparentPrepared, nil
}

func (e *CodexExecutor) buildLegacyCodexRequest(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, kind codexRequestKind, baseModel, baseURL, apiKey string, from, to sdktranslator.Format) (codexPreparedRequest, error) {
	originalPayload := selectOriginalPayloadSource(req, opts)
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, kind == codexRequestKindResponsesStream)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, kind == codexRequestKindResponsesStream)

	body, err := thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return codexPreparedRequest{}, err
	}

	requestedModel := payloadRequestedModel(opts, req.Model)
	body = applyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel)

	switch kind {
	case codexRequestKindResponsesNonStream:
		body, _ = sjson.SetBytes(body, "model", baseModel)
		body, _ = sjson.SetBytes(body, "stream", true)
		body, _ = sjson.DeleteBytes(body, "previous_response_id")
		body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
		body, _ = sjson.DeleteBytes(body, "safety_identifier")
		if !gjson.GetBytes(body, "instructions").Exists() {
			body, _ = sjson.SetBytes(body, "instructions", "")
		}
	case codexRequestKindResponsesCompact:
		body, _ = sjson.SetBytes(body, "model", baseModel)
		body, _ = sjson.DeleteBytes(body, "stream")
	case codexRequestKindResponsesStream:
		body, _ = sjson.DeleteBytes(body, "previous_response_id")
		body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
		body, _ = sjson.DeleteBytes(body, "safety_identifier")
		body, _ = sjson.SetBytes(body, "model", baseModel)
		if !gjson.GetBytes(body, "instructions").Exists() {
			body, _ = sjson.SetBytes(body, "instructions", "")
		}
	}

	url := codexRequestURL(baseURL, kind)
	httpReq, err := e.cacheHelper(ctx, from, url, req, body)
	if err != nil {
		return codexPreparedRequest{}, err
	}
	applyCodexHeaders(httpReq, auth, apiKey, kind != codexRequestKindResponsesCompact, e.cfg)
	return codexPreparedRequest{
		body:            body,
		request:         httpReq,
		originalPayload: originalPayload,
	}, nil
}

func (e *CodexExecutor) buildTransparentCodexRequest(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, kind codexRequestKind, baseModel, baseURL, apiKey string) (codexPreparedRequest, error) {
	originalPayload := selectOriginalPayloadSource(req, opts)
	if len(originalPayload) == 0 {
		return codexPreparedRequest{}, fmt.Errorf("codex transparent relay: original request is empty")
	}
	snapshot, err := transparentCodexSnapshotFromContext(ctx)
	if err != nil {
		return codexPreparedRequest{}, fmt.Errorf("codex transparent relay: %w", err)
	}

	body := bytes.Clone(originalPayload)
	if currentModel := strings.TrimSpace(gjson.GetBytes(body, "model").String()); baseModel != "" && !strings.EqualFold(currentModel, baseModel) {
		body, err = sjson.SetBytes(body, "model", baseModel)
		if err != nil {
			return codexPreparedRequest{}, fmt.Errorf("codex transparent relay: rewrite model: %w", err)
		}
	}
	body, err = applyTransparentCodexBodyCompatibility(body)
	if err != nil {
		return codexPreparedRequest{}, fmt.Errorf("codex transparent relay: apply compatibility overrides: %w", err)
	}

	url := codexTransparentRequestURL(baseURL, kind, snapshot.rawQuery)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return codexPreparedRequest{}, err
	}
	applyTransparentCodexHeaders(httpReq, auth, apiKey, e.cfg, kind == codexRequestKindResponsesStream, snapshot.headers)
	return codexPreparedRequest{
		body:            body,
		request:         httpReq,
		originalPayload: originalPayload,
		transparent:     true,
	}, nil
}

func applyTransparentCodexBodyCompatibility(body []byte) ([]byte, error) {
	if gjson.GetBytes(body, "store").Type == gjson.False {
		return body, nil
	}

	// Transparent relay keeps the client request shape where possible, but Codex
	// /responses still requires an explicit store=false.
	updated, err := sjson.SetBytes(body, "store", false)
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func applyTransparentCodexHeaders(r *http.Request, auth *cliproxyauth.Auth, token string, cfg *config.Config, stream bool, snapshotHeaders http.Header) {
	if r == nil {
		return
	}
	var ginHeaders http.Header
	if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header
	}
	copyTransparentCodexHeaders(r.Header, ginHeaders)
	copyTransparentCodexHeaders(r.Header, snapshotHeaders)
	if strings.TrimSpace(r.Header.Get("Content-Type")) == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(r.Header.Get("Accept")) == "" {
		if stream {
			r.Header.Set("Accept", "text/event-stream")
		} else {
			r.Header.Set("Accept", "application/json")
		}
	}
	ensureCodexUserAgent(r.Header, nil, r.Context(), auth, cfg)
	if token = strings.TrimSpace(token); token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	} else {
		r.Header.Del("Authorization")
	}

	isAPIKey := false
	if auth != nil && auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["api_key"]); v != "" {
			isAPIKey = true
		}
	}
	if isAPIKey {
		r.Header.Del("Chatgpt-Account-Id")
	} else {
		accountID := ""
		if auth != nil && auth.Metadata != nil {
			if v, ok := auth.Metadata["account_id"].(string); ok {
				accountID = strings.TrimSpace(v)
			}
		}
		if accountID != "" {
			r.Header.Set("Chatgpt-Account-Id", accountID)
		} else {
			r.Header.Del("Chatgpt-Account-Id")
		}
	}

}

func copyTransparentCodexHeaders(target, source http.Header) {
	if target == nil || source == nil {
		return
	}
	for key, values := range source {
		canonical := textproto.CanonicalMIMEHeaderKey(key)
		if !shouldForwardTransparentCodexHeader(canonical) {
			continue
		}
		target.Del(canonical)
		for _, value := range values {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				target.Add(canonical, trimmed)
			}
		}
	}
}

func shouldForwardTransparentCodexHeader(key string) bool {
	_, ok := codexTransparentAllowedRequestHeaders[textproto.CanonicalMIMEHeaderKey(key)]
	return ok
}

func transparentCodexSnapshotFromContext(ctx context.Context) (codexTransparentSnapshot, error) {
	snapshot := codexTransparentSnapshot{}
	if ctx == nil {
		return snapshot, nil
	}
	ginCtx, ok := ctx.Value("gin").(*gin.Context)
	if !ok || ginCtx == nil || ginCtx.Request == nil {
		return snapshot, nil
	}
	if status := strings.TrimSpace(ginCtx.Request.Header.Get(codexTransparentSnapshotStatusHeader)); status != "" {
		return snapshot, fmt.Errorf("snapshot unavailable: %s", status)
	}
	headers, err := decodeTransparentCodexSnapshotHeaders(ginCtx.Request.Header)
	if err != nil {
		return snapshot, err
	}
	snapshot.headers = headers
	query, err := decodeTransparentCodexSnapshotQuery(ginCtx.Request.Header)
	if err != nil {
		return snapshot, err
	}
	if query != "" {
		snapshot.rawQuery = query
		return snapshot, nil
	}
	if ginCtx.Request.URL != nil {
		snapshot.rawQuery = strings.TrimSpace(ginCtx.Request.URL.RawQuery)
	}
	return snapshot, nil
}

func decodeTransparentCodexSnapshotHeaders(source http.Header) (http.Header, error) {
	if source == nil {
		return nil, nil
	}
	encoded := strings.TrimSpace(source.Get(codexTransparentClientHeadersHeader))
	if encoded == "" {
		return nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode client headers snapshot: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("client headers snapshot is empty")
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal client headers snapshot: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("client headers snapshot is empty")
	}
	headers := make(http.Header, len(raw))
	for key, value := range raw {
		canonical := textproto.CanonicalMIMEHeaderKey(key)
		if !shouldForwardTransparentCodexHeader(canonical) {
			continue
		}
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			headers.Set(canonical, trimmed)
		}
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("client headers snapshot has no allowed headers")
	}
	return headers, nil
}

func decodeTransparentCodexSnapshotQuery(source http.Header) (string, error) {
	if source == nil {
		return "", nil
	}
	encoded := strings.TrimSpace(source.Get(codexTransparentClientQueryHeader))
	if encoded == "" {
		return "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode client query snapshot: %w", err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("client query snapshot is empty")
	}
	query := strings.TrimSpace(strings.TrimPrefix(string(data), "?"))
	if query == "" {
		return "", fmt.Errorf("client query snapshot is empty")
	}
	return query, nil
}

func summarizeCodexTransparentDiff(legacy, transparent codexPreparedRequest) codexTransparentDiff {
	diff := codexTransparentDiff{}
	legacyHeaders := normalizeHeaderDiffSource(legacy.request)
	transparentHeaders := normalizeHeaderDiffSource(transparent.request)
	diff.headersOnlyLegacy, diff.headersOnlyTransparent, diff.headersChanged = diffStringMaps(legacyHeaders, transparentHeaders)
	diff.bodyOnlyLegacy, diff.bodyOnlyTransparent, diff.bodyChanged = diffJSONBodies(legacy.body, transparent.body)
	return diff
}

func normalizeHeaderDiffSource(req *http.Request) map[string]string {
	if req == nil || len(req.Header) == 0 {
		return nil
	}
	out := make(map[string]string, len(req.Header))
	for key, values := range req.Header {
		trimmedValues := make([]string, 0, len(values))
		for _, value := range values {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				trimmedValues = append(trimmedValues, trimmed)
			}
		}
		if len(trimmedValues) == 0 {
			continue
		}
		sort.Strings(trimmedValues)
		out[textproto.CanonicalMIMEHeaderKey(key)] = strings.Join(trimmedValues, ", ")
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func diffStringMaps(legacy, transparent map[string]string) (onlyLegacy, onlyTransparent, changed []string) {
	keys := make(map[string]struct{}, len(legacy)+len(transparent))
	for key := range legacy {
		keys[key] = struct{}{}
	}
	for key := range transparent {
		keys[key] = struct{}{}
	}
	allKeys := make([]string, 0, len(keys))
	for key := range keys {
		allKeys = append(allKeys, key)
	}
	sort.Strings(allKeys)
	for _, key := range allKeys {
		legacyValue, hasLegacy := legacy[key]
		transparentValue, hasTransparent := transparent[key]
		switch {
		case hasLegacy && !hasTransparent:
			onlyLegacy = append(onlyLegacy, key)
		case !hasLegacy && hasTransparent:
			onlyTransparent = append(onlyTransparent, key)
		case legacyValue != transparentValue:
			changed = append(changed, key)
		}
	}
	return onlyLegacy, onlyTransparent, changed
}

func diffJSONBodies(legacyBody, transparentBody []byte) (onlyLegacy, onlyTransparent, changed []string) {
	legacyTrimmed := bytes.TrimSpace(legacyBody)
	transparentTrimmed := bytes.TrimSpace(transparentBody)
	if len(legacyTrimmed) == 0 && len(transparentTrimmed) == 0 {
		return nil, nil, nil
	}
	if !json.Valid(legacyTrimmed) || !json.Valid(transparentTrimmed) {
		if !bytes.Equal(legacyTrimmed, transparentTrimmed) {
			return nil, nil, []string{"$"}
		}
		return nil, nil, nil
	}

	var legacyValue any
	var transparentValue any
	if err := json.Unmarshal(legacyTrimmed, &legacyValue); err != nil {
		return nil, nil, []string{"$"}
	}
	if err := json.Unmarshal(transparentTrimmed, &transparentValue); err != nil {
		return nil, nil, []string{"$"}
	}

	var diff codexTransparentDiff
	diffJSONValue("", legacyValue, true, transparentValue, true, &diff)
	sort.Strings(diff.bodyOnlyLegacy)
	sort.Strings(diff.bodyOnlyTransparent)
	sort.Strings(diff.bodyChanged)
	return diff.bodyOnlyLegacy, diff.bodyOnlyTransparent, diff.bodyChanged
}

func diffJSONValue(path string, legacy any, hasLegacy bool, transparent any, hasTransparent bool, diff *codexTransparentDiff) {
	if diff == nil {
		return
	}
	path = codexDiffPath(path)
	switch {
	case hasLegacy && !hasTransparent:
		diff.bodyOnlyLegacy = append(diff.bodyOnlyLegacy, path)
		return
	case !hasLegacy && hasTransparent:
		diff.bodyOnlyTransparent = append(diff.bodyOnlyTransparent, path)
		return
	case !hasLegacy && !hasTransparent:
		return
	}

	legacyMap, legacyIsMap := legacy.(map[string]any)
	transparentMap, transparentIsMap := transparent.(map[string]any)
	if legacyIsMap || transparentIsMap {
		if !legacyIsMap || !transparentIsMap {
			diff.bodyChanged = append(diff.bodyChanged, path)
			return
		}
		keys := make(map[string]struct{}, len(legacyMap)+len(transparentMap))
		for key := range legacyMap {
			keys[key] = struct{}{}
		}
		for key := range transparentMap {
			keys[key] = struct{}{}
		}
		keyList := make([]string, 0, len(keys))
		for key := range keys {
			keyList = append(keyList, key)
		}
		sort.Strings(keyList)
		for _, key := range keyList {
			nextPath := key
			if path != "$" {
				nextPath = path + "." + key
			}
			legacyValue, legacyExists := legacyMap[key]
			transparentValue, transparentExists := transparentMap[key]
			diffJSONValue(nextPath, legacyValue, legacyExists, transparentValue, transparentExists, diff)
		}
		return
	}

	legacySlice, legacyIsSlice := legacy.([]any)
	transparentSlice, transparentIsSlice := transparent.([]any)
	if legacyIsSlice || transparentIsSlice {
		if !legacyIsSlice || !transparentIsSlice {
			diff.bodyChanged = append(diff.bodyChanged, path)
			return
		}
		maxLen := len(legacySlice)
		if len(transparentSlice) > maxLen {
			maxLen = len(transparentSlice)
		}
		for i := 0; i < maxLen; i++ {
			nextPath := fmt.Sprintf("%s[%d]", path, i)
			var legacyValue any
			var transparentValue any
			hasLegacyValue := i < len(legacySlice)
			hasTransparentValue := i < len(transparentSlice)
			if hasLegacyValue {
				legacyValue = legacySlice[i]
			}
			if hasTransparentValue {
				transparentValue = transparentSlice[i]
			}
			diffJSONValue(nextPath, legacyValue, hasLegacyValue, transparentValue, hasTransparentValue, diff)
		}
		return
	}

	if !reflect.DeepEqual(legacy, transparent) {
		diff.bodyChanged = append(diff.bodyChanged, path)
	}
}

func codexDiffPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "$"
	}
	return path
}

func summarizeCodexDiffList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	const limit = 12
	if len(items) <= limit {
		return fmt.Sprintf("%v", items)
	}
	return fmt.Sprintf("%v (+%d more)", items[:limit], len(items)-limit)
}

func logCodexTransparentShadowDiff(ctx context.Context, kind codexRequestKind, legacy, transparent codexPreparedRequest) {
	diff := summarizeCodexTransparentDiff(legacy, transparent)
	if len(diff.headersOnlyLegacy) == 0 &&
		len(diff.headersOnlyTransparent) == 0 &&
		len(diff.headersChanged) == 0 &&
		len(diff.bodyOnlyLegacy) == 0 &&
		len(diff.bodyOnlyTransparent) == 0 &&
		len(diff.bodyChanged) == 0 {
		return
	}
	logWithRequestID(ctx).Infof(
		"codex transparent shadow diff kind=%s headers_only_legacy=%s headers_only_transparent=%s headers_changed=%s body_only_legacy=%s body_only_transparent=%s body_changed=%s",
		codexRequestKindLabel(kind),
		summarizeCodexDiffList(diff.headersOnlyLegacy),
		summarizeCodexDiffList(diff.headersOnlyTransparent),
		summarizeCodexDiffList(diff.headersChanged),
		summarizeCodexDiffList(diff.bodyOnlyLegacy),
		summarizeCodexDiffList(diff.bodyOnlyTransparent),
		summarizeCodexDiffList(diff.bodyChanged),
	)
}

func logCodexTransparentUnavailable(ctx context.Context, mode codexTransparentMode, kind codexRequestKind, err error) {
	if mode == codexTransparentModeShadow {
		logWithRequestID(ctx).Warnf("codex transparent relay shadow_unavailable kind=%s err=%v", codexRequestKindLabel(kind), err)
		return
	}
	logWithRequestID(ctx).Warnf("codex transparent relay fallback_to_legacy kind=%s err=%v", codexRequestKindLabel(kind), err)
}

func logCodexTransparentSelected(ctx context.Context, kind codexRequestKind) {
	logWithRequestID(ctx).Infof("codex transparent relay selected kind=%s mode=on", codexRequestKindLabel(kind))
}

func codexRequestKindLabel(kind codexRequestKind) string {
	switch kind {
	case codexRequestKindResponsesCompact:
		return "responses/compact"
	case codexRequestKindResponsesStream:
		return "responses-stream"
	default:
		return "responses"
	}
}

func firstCompletedEvent(data []byte) []byte {
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		if !bytes.HasPrefix(line, dataTag) {
			continue
		}
		line = bytes.TrimSpace(line[5:])
		if gjson.GetBytes(line, "type").String() == "response.completed" {
			return bytes.Clone(line)
		}
	}
	return nil
}

func shouldPassthroughTransparentOpenAIResponse(prepared codexPreparedRequest, from sdktranslator.Format, data []byte) bool {
	if !prepared.transparent {
		return false
	}
	if from != sdktranslator.FromString("openai-response") {
		return false
	}
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && json.Valid(trimmed)
}

func (e *CodexExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	if opts.Alt == "responses/compact" {
		return e.executeCompact(ctx, auth, req, opts)
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := codexCreds(auth)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}

	reporter := newUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.trackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FromString("codex")
	prepared, err := e.prepareCodexRequest(ctx, auth, req, opts, codexRequestKindResponsesNonStream, baseModel, baseURL, apiKey, from, to)
	if err != nil {
		return resp, err
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       prepared.request.URL.String(),
		Method:    http.MethodPost,
		Headers:   prepared.request.Header.Clone(),
		Body:      prepared.body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})
	httpClient := newProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(prepared.request)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	recordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			recordAPIResponseError(ctx, e.cfg, decErr)
			return resp, decErr
		}
		defer func() {
			if errClose := decodedBody.Close(); errClose != nil {
				log.Errorf("codex executor: close response body error: %v", errClose)
			}
		}()
		b, _ := io.ReadAll(decodedBody)
		appendAPIResponseChunk(ctx, e.cfg, b)
		logWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, summarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = newCodexStatusErr(httpResp.StatusCode, b)
		return resp, err
	}
	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := decodedBody.Close(); errClose != nil {
			log.Errorf("codex executor: close response body error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	appendAPIResponseChunk(ctx, e.cfg, data)

	if line := firstCompletedEvent(data); len(line) > 0 {
		if detail, ok := parseCodexUsage(line); ok {
			reporter.publish(ctx, detail)
		}
		var param any
		out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, prepared.originalPayload, prepared.body, line, &param)
		resp = cliproxyexecutor.Response{Payload: []byte(out), Headers: httpResp.Header.Clone()}
		return resp, nil
	}
	if shouldPassthroughTransparentOpenAIResponse(prepared, from, data) {
		reporter.publish(ctx, parseOpenAIUsage(data))
		reporter.ensurePublished(ctx)
		resp = cliproxyexecutor.Response{Payload: data, Headers: httpResp.Header.Clone()}
		return resp, nil
	}
	err = statusErr{code: 408, msg: "stream error: stream disconnected before completion: stream closed before response.completed"}
	return resp, err
}

func (e *CodexExecutor) executeCompact(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := codexCreds(auth)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}

	reporter := newUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.trackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FromString("openai-response")
	prepared, err := e.prepareCodexRequest(ctx, auth, req, opts, codexRequestKindResponsesCompact, baseModel, baseURL, apiKey, from, to)
	if err != nil {
		return resp, err
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       prepared.request.URL.String(),
		Method:    http.MethodPost,
		Headers:   prepared.request.Header.Clone(),
		Body:      prepared.body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})
	httpClient := newProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(prepared.request)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	recordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			recordAPIResponseError(ctx, e.cfg, decErr)
			return resp, decErr
		}
		defer func() {
			if errClose := decodedBody.Close(); errClose != nil {
				log.Errorf("codex executor: close response body error: %v", errClose)
			}
		}()
		b, _ := io.ReadAll(decodedBody)
		appendAPIResponseChunk(ctx, e.cfg, b)
		logWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, summarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = newCodexStatusErr(httpResp.StatusCode, b)
		return resp, err
	}
	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := decodedBody.Close(); errClose != nil {
			log.Errorf("codex executor: close response body error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	appendAPIResponseChunk(ctx, e.cfg, data)
	reporter.publish(ctx, parseOpenAIUsage(data))
	reporter.ensurePublished(ctx)
	if shouldPassthroughTransparentOpenAIResponse(prepared, from, data) {
		resp = cliproxyexecutor.Response{Payload: data, Headers: httpResp.Header.Clone()}
		return resp, nil
	}
	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, prepared.originalPayload, prepared.body, data, &param)
	resp = cliproxyexecutor.Response{Payload: []byte(out), Headers: httpResp.Header.Clone()}
	return resp, nil
}

func (e *CodexExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusBadRequest, msg: "streaming not supported for /responses/compact"}
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := codexCreds(auth)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}

	reporter := newUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.trackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FromString("codex")
	prepared, err := e.prepareCodexRequest(ctx, auth, req, opts, codexRequestKindResponsesStream, baseModel, baseURL, apiKey, from, to)
	if err != nil {
		return nil, err
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       prepared.request.URL.String(),
		Method:    http.MethodPost,
		Headers:   prepared.request.Header.Clone(),
		Body:      prepared.body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := newProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(prepared.request)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	recordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			recordAPIResponseError(ctx, e.cfg, decErr)
			return nil, decErr
		}
		data, readErr := io.ReadAll(decodedBody)
		if errClose := decodedBody.Close(); errClose != nil {
			log.Errorf("codex executor: close response body error: %v", errClose)
		}
		if readErr != nil {
			recordAPIResponseError(ctx, e.cfg, readErr)
			return nil, readErr
		}
		appendAPIResponseChunk(ctx, e.cfg, data)
		logWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, summarizeErrorBody(httpResp.Header.Get("Content-Type"), data))
		err = newCodexStatusErr(httpResp.StatusCode, data)
		return nil, err
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		decodedBody, errDecode := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if errDecode != nil {
			recordAPIResponseError(ctx, e.cfg, errDecode)
			reporter.publishFailure(ctx)
			out <- cliproxyexecutor.StreamChunk{Err: errDecode}
			return
		}
		defer func() {
			if errClose := decodedBody.Close(); errClose != nil {
				log.Errorf("codex executor: close response body error: %v", errClose)
			}
		}()
		scanner := bufio.NewScanner(decodedBody)
		scanner.Buffer(nil, 52_428_800) // 50MB
		var param any
		sawCompleted := false
		for scanner.Scan() {
			line := scanner.Bytes()
			appendAPIResponseChunk(ctx, e.cfg, line)

			if bytes.HasPrefix(line, dataTag) {
				data := bytes.TrimSpace(line[5:])
				if gjson.GetBytes(data, "type").String() == "response.completed" {
					sawCompleted = true
					if detail, ok := parseCodexUsage(data); ok {
						reporter.publish(ctx, detail)
					}
				}
			}

			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, prepared.originalPayload, prepared.body, bytes.Clone(line), &param)
			for i := range chunks {
				out <- cliproxyexecutor.StreamChunk{Payload: []byte(chunks[i])}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			recordAPIResponseError(ctx, e.cfg, errScan)
			reporter.publishFailure(ctx)
			out <- cliproxyexecutor.StreamChunk{Err: errScan}
			return
		}
		if !sawCompleted {
			errIncomplete := statusErr{code: http.StatusRequestTimeout, msg: "stream error: stream disconnected before completion: stream closed before response.completed"}
			recordAPIResponseError(ctx, e.cfg, errIncomplete)
			reporter.publishFailure(ctx)
			out <- cliproxyexecutor.StreamChunk{Err: errIncomplete}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

func (e *CodexExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	from := opts.SourceFormat
	to := sdktranslator.FromString("codex")
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)

	body, err := thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}

	body, _ = sjson.SetBytes(body, "model", baseModel)
	body, _ = sjson.DeleteBytes(body, "previous_response_id")
	body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
	body, _ = sjson.DeleteBytes(body, "safety_identifier")
	body, _ = sjson.SetBytes(body, "stream", false)
	if !gjson.GetBytes(body, "instructions").Exists() {
		body, _ = sjson.SetBytes(body, "instructions", "")
	}

	enc, err := tokenizerForCodexModel(baseModel)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex executor: tokenizer init failed: %w", err)
	}

	count, err := countCodexInputTokens(enc, body)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex executor: token counting failed: %w", err)
	}

	usageJSON := fmt.Sprintf(`{"response":{"usage":{"input_tokens":%d,"output_tokens":0,"total_tokens":%d}}}`, count, count)
	translated := sdktranslator.TranslateTokenCount(ctx, to, from, count, []byte(usageJSON))
	return cliproxyexecutor.Response{Payload: []byte(translated)}, nil
}

func tokenizerForCodexModel(model string) (tokenizer.Codec, error) {
	sanitized := strings.ToLower(strings.TrimSpace(model))
	switch {
	case sanitized == "":
		return tokenizer.Get(tokenizer.Cl100kBase)
	case strings.HasPrefix(sanitized, "gpt-5"):
		return tokenizer.ForModel(tokenizer.GPT5)
	case strings.HasPrefix(sanitized, "gpt-4.1"):
		return tokenizer.ForModel(tokenizer.GPT41)
	case strings.HasPrefix(sanitized, "gpt-4o"):
		return tokenizer.ForModel(tokenizer.GPT4o)
	case strings.HasPrefix(sanitized, "gpt-4"):
		return tokenizer.ForModel(tokenizer.GPT4)
	case strings.HasPrefix(sanitized, "gpt-3.5"), strings.HasPrefix(sanitized, "gpt-3"):
		return tokenizer.ForModel(tokenizer.GPT35Turbo)
	default:
		return tokenizer.Get(tokenizer.Cl100kBase)
	}
}

func countCodexInputTokens(enc tokenizer.Codec, body []byte) (int64, error) {
	if enc == nil {
		return 0, fmt.Errorf("encoder is nil")
	}
	if len(body) == 0 {
		return 0, nil
	}

	root := gjson.ParseBytes(body)
	var segments []string

	if inst := strings.TrimSpace(root.Get("instructions").String()); inst != "" {
		segments = append(segments, inst)
	}

	inputItems := root.Get("input")
	if inputItems.IsArray() {
		arr := inputItems.Array()
		for i := range arr {
			item := arr[i]
			switch item.Get("type").String() {
			case "message":
				content := item.Get("content")
				if content.IsArray() {
					parts := content.Array()
					for j := range parts {
						part := parts[j]
						if text := strings.TrimSpace(part.Get("text").String()); text != "" {
							segments = append(segments, text)
						}
					}
				}
			case "function_call":
				if name := strings.TrimSpace(item.Get("name").String()); name != "" {
					segments = append(segments, name)
				}
				if args := strings.TrimSpace(item.Get("arguments").String()); args != "" {
					segments = append(segments, args)
				}
			case "function_call_output":
				if out := strings.TrimSpace(item.Get("output").String()); out != "" {
					segments = append(segments, out)
				}
			default:
				if text := strings.TrimSpace(item.Get("text").String()); text != "" {
					segments = append(segments, text)
				}
			}
		}
	}

	tools := root.Get("tools")
	if tools.IsArray() {
		tarr := tools.Array()
		for i := range tarr {
			tool := tarr[i]
			if name := strings.TrimSpace(tool.Get("name").String()); name != "" {
				segments = append(segments, name)
			}
			if desc := strings.TrimSpace(tool.Get("description").String()); desc != "" {
				segments = append(segments, desc)
			}
			if params := tool.Get("parameters"); params.Exists() {
				val := params.Raw
				if params.Type == gjson.String {
					val = params.String()
				}
				if trimmed := strings.TrimSpace(val); trimmed != "" {
					segments = append(segments, trimmed)
				}
			}
		}
	}

	textFormat := root.Get("text.format")
	if textFormat.Exists() {
		if name := strings.TrimSpace(textFormat.Get("name").String()); name != "" {
			segments = append(segments, name)
		}
		if schema := textFormat.Get("schema"); schema.Exists() {
			val := schema.Raw
			if schema.Type == gjson.String {
				val = schema.String()
			}
			if trimmed := strings.TrimSpace(val); trimmed != "" {
				segments = append(segments, trimmed)
			}
		}
	}

	text := strings.Join(segments, "\n")
	if text == "" {
		return 0, nil
	}

	count, err := enc.Count(text)
	if err != nil {
		return 0, err
	}
	return int64(count), nil
}

func (e *CodexExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("codex executor: refresh called")
	if auth == nil {
		return nil, statusErr{code: 500, msg: "codex executor: auth is nil"}
	}
	var refreshToken string
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["refresh_token"].(string); ok && v != "" {
			refreshToken = v
		}
	}
	if refreshToken == "" {
		return auth, nil
	}
	svc := codexauth.NewCodexAuth(e.cfg)
	td, err := svc.RefreshTokensWithRetry(ctx, refreshToken, 3)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["id_token"] = td.IDToken
	auth.Metadata["access_token"] = td.AccessToken
	if td.RefreshToken != "" {
		auth.Metadata["refresh_token"] = td.RefreshToken
	}
	if td.AccountID != "" {
		auth.Metadata["account_id"] = td.AccountID
	}
	auth.Metadata["email"] = td.Email
	// Use unified key in files
	auth.Metadata["expired"] = td.Expire
	auth.Metadata["type"] = "codex"
	now := time.Now().Format(time.RFC3339)
	auth.Metadata["last_refresh"] = now
	return auth, nil
}

func (e *CodexExecutor) cacheHelper(ctx context.Context, from sdktranslator.Format, url string, req cliproxyexecutor.Request, rawJSON []byte) (*http.Request, error) {
	var cache codexCache
	if from == "claude" {
		userIDResult := gjson.GetBytes(req.Payload, "metadata.user_id")
		if userIDResult.Exists() {
			key := fmt.Sprintf("%s-%s", req.Model, userIDResult.String())
			var ok bool
			if cache, ok = getCodexCache(key); !ok {
				cache = codexCache{
					ID:     uuid.New().String(),
					Expire: time.Now().Add(1 * time.Hour),
				}
				setCodexCache(key, cache)
			}
		}
	} else if from == "openai-response" {
		promptCacheKey := gjson.GetBytes(req.Payload, "prompt_cache_key")
		if promptCacheKey.Exists() {
			cache.ID = promptCacheKey.String()
		}
	} else if from == "openai" {
		if apiKey := strings.TrimSpace(apiKeyFromContext(ctx)); apiKey != "" {
			cache.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:"+apiKey)).String()
		}
	}

	if cache.ID != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "prompt_cache_key", cache.ID)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rawJSON))
	if err != nil {
		return nil, err
	}
	if cache.ID != "" {
		httpReq.Header.Set("Conversation_id", cache.ID)
		httpReq.Header.Set("Session_id", cache.ID)
	}
	return httpReq, nil
}

func applyCodexHeaders(r *http.Request, auth *cliproxyauth.Auth, token string, stream bool, cfg *config.Config) {
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)

	var ginHeaders http.Header
	if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header
	}

	ensureHeaderWithPriority(r.Header, ginHeaders, "Version", "", "")
	ensureHeaderWithPriority(r.Header, ginHeaders, "Session_id", "", "")
	ensureCodexUserAgent(r.Header, ginHeaders, r.Context(), auth, cfg)

	if stream {
		r.Header.Set("Accept", "text/event-stream")
	} else {
		r.Header.Set("Accept", "application/json")
	}
	ensureHeaderWithPriority(r.Header, ginHeaders, "Originator", "", "")

	isAPIKey := false
	if auth != nil && auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["api_key"]); v != "" {
			isAPIKey = true
		}
	}
	if !isAPIKey {
		if auth != nil && auth.Metadata != nil {
			if accountID, ok := auth.Metadata["account_id"].(string); ok {
				r.Header.Set("Chatgpt-Account-Id", accountID)
			}
		}
	}
}

func newCodexStatusErr(statusCode int, body []byte) statusErr {
	err := statusErr{code: statusCode, msg: string(body)}
	if retryAfter := parseCodexRetryAfter(statusCode, body, time.Now()); retryAfter != nil {
		err.retryAfter = retryAfter
	}
	return err
}

func parseCodexRetryAfter(statusCode int, errorBody []byte, now time.Time) *time.Duration {
	if statusCode != http.StatusTooManyRequests || len(errorBody) == 0 {
		return nil
	}
	if strings.TrimSpace(gjson.GetBytes(errorBody, "error.type").String()) != "usage_limit_reached" {
		return nil
	}
	if resetsAt := gjson.GetBytes(errorBody, "error.resets_at").Int(); resetsAt > 0 {
		resetAtTime := time.Unix(resetsAt, 0)
		if resetAtTime.After(now) {
			retryAfter := resetAtTime.Sub(now)
			return &retryAfter
		}
	}
	if resetsInSeconds := gjson.GetBytes(errorBody, "error.resets_in_seconds").Int(); resetsInSeconds > 0 {
		retryAfter := time.Duration(resetsInSeconds) * time.Second
		return &retryAfter
	}
	return nil
}

func codexCreds(a *cliproxyauth.Auth) (apiKey, baseURL string) {
	if a == nil {
		return "", ""
	}
	if a.Attributes != nil {
		apiKey = a.Attributes["api_key"]
		baseURL = a.Attributes["base_url"]
	}
	if apiKey == "" && a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok {
			apiKey = v
		}
	}
	return
}

func (e *CodexExecutor) resolveCodexConfig(auth *cliproxyauth.Auth) *config.CodexKey {
	if auth == nil || e.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range e.cfg.CodexKey {
		entry := &e.cfg.CodexKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && attrBase != "" {
			if strings.EqualFold(cfgKey, attrKey) && strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range e.cfg.CodexKey {
			entry := &e.cfg.CodexKey[i]
			if strings.EqualFold(strings.TrimSpace(entry.APIKey), attrKey) {
				return entry
			}
		}
	}
	return nil
}
