package management

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type quotaAggregateTestExecutor struct {
	refreshCalls atomic.Int32
	failIDs      map[string]bool
	entered      chan string
	release      <-chan struct{}
	blockRefresh atomic.Bool
	ignoreCancel atomic.Bool
}

func (e *quotaAggregateTestExecutor) Identifier() string { return "antigravity" }

func (e *quotaAggregateTestExecutor) Refresh(ctx context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	e.refreshCalls.Add(1)
	if e.entered != nil && e.blockRefresh.Load() {
		e.entered <- auth.ID
		if e.ignoreCancel.Load() {
			<-e.release
		} else {
			select {
			case <-e.release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	if e.failIDs[auth.ID] {
		return nil, errors.New("synthetic refresh detail that must not be returned")
	}
	metadata := make(map[string]any, len(auth.Metadata)+1)
	for key, value := range auth.Metadata {
		metadata[key] = value
	}
	metadata["access_token"] = "fresh-access-" + auth.ID
	auth.Metadata = metadata
	return auth, nil
}

func (*quotaAggregateTestExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (*quotaAggregateTestExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (*quotaAggregateTestExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (*quotaAggregateTestExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

type quotaAggregateRoundTripper func(*http.Request) (*http.Response, error)

func (f quotaAggregateRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func quotaAggregateHTTPResponse(status int, body string, req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func quotaAggregateAuth(id, provider string, metadata map[string]any) *coreauth.Auth {
	return &coreauth.Auth{
		ID:       id,
		FileName: id + ".json",
		Provider: provider,
		Status:   coreauth.StatusActive,
		Metadata: metadata,
	}
}

func quotaAggregateManager(t *testing.T, executor *quotaAggregateTestExecutor, auths ...*coreauth.Auth) *coreauth.Manager {
	t.Helper()
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	for _, auth := range auths {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register %s: %v", auth.ID, err)
		}
	}
	return manager
}

func serveQuotaAggregate(handler *Handler, query string) *httptest.ResponseRecorder {
	router := gin.New()
	router.GET("/quota/aggregate", handler.GetQuotaAggregate)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/quota/aggregate"+query, nil)
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestQuotaAggregateRefreshFallbackAndSafeProjection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &quotaAggregateTestExecutor{failIDs: map[string]bool{"antigravity-refresh-fails": true}}
	good := quotaAggregateAuth("antigravity-good", "antigravity", map[string]any{
		"access_token": "stale-access-good", "refresh_token": "refresh-secret-good", "project_id": "project-good", "email": "good@example.invalid", "id_token": "id-token-secret-good",
	})
	bad := quotaAggregateAuth("antigravity-refresh-fails", "antigravity", map[string]any{"access_token": "stale-access-bad", "email": "bad@example.invalid"})
	disabled := quotaAggregateAuth("antigravity-disabled", "antigravity", map[string]any{"access_token": "disabled-access", "email": "disabled@example.invalid"})
	disabled.Disabled = true
	disabled.Status = coreauth.StatusDisabled
	codex := quotaAggregateAuth("codex-account", "codex", map[string]any{
		"access_token": "codex-secret", "refresh_token": "codex-refresh-secret", "id_token": "codex-id-token-secret", "email": "codex@example.invalid",
	})
	codex.Quota.Signals = map[string]string{
		"X-Codex-Plan-Type":                                "pro",
		"X-Codex-Primary-Used-Percent":                     "81",
		"X-Codex-Additional-Gemini-Primary-Window-Minutes": "300",
		"X-Codex-Reset-After-Seconds":                      "120",
		"X-Codex-Reset-At":                                 "2026-10-27T00:00:00Z",
		"X-Codex-Reset-After":                              "300",
		"X-Codex-Turn-State":                               "private-turn-state",
		"Authorization":                                    "Bearer private-header-value",
	}
	codex.ModelStates = map[string]*coreauth.ModelState{
		"gpt-model": {Quota: coreauth.QuotaState{Signals: map[string]string{
			"X-Codex-Secondary-Used-Percent": "19",
			"X-Codex-Reset-After-Seconds":    "30",
			"X-Codex-Reset-At":               "2026-10-26T12:00:00Z",
			"X-Codex-Reset-After":            "60",
			"X-Codex-Turn-State":             "private-model-state",
		}}},
	}
	manager := quotaAggregateManager(t, executor, good, bad, disabled, codex)
	var requestsMu sync.Mutex
	var requestURLs []string
	client := &http.Client{Transport: quotaAggregateRoundTripper(func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer fresh-access-") {
			t.Errorf("upstream request did not use refreshed token")
		}
		if got := req.Header.Get("User-Agent"); got != "antigravity/hub/2.23.0 darwin/arm64" {
			t.Errorf("User-Agent=%q", got)
		}
		requestsMu.Lock()
		requestURLs = append(requestURLs, req.URL.Host+req.URL.Path)
		requestsMu.Unlock()
		switch {
		case strings.HasSuffix(req.URL.Path, ":loadCodeAssist"):
			return quotaAggregateHTTPResponse(http.StatusBadGateway, `{"error":"synthetic-upstream-body"}`, req), nil
		case req.URL.Host == "daily-cloudcode-pa.googleapis.com":
			return quotaAggregateHTTPResponse(http.StatusBadGateway, `{"error":"synthetic-upstream-body"}`, req), nil
		case req.URL.Host == "daily-cloudcode-pa.sandbox.googleapis.com":
			return quotaAggregateHTTPResponse(http.StatusOK, `{"groups":[{"displayName":"Gemini 4 Argon","description":"dynamic group","buckets":[{"bucketId":"quota-week","window":"WEEKLY","resetTime":"2026-11-02T00:00:00Z","remainingFraction":0.35},{"bucketId":"unknown","window":"DAILY","resetTime":"2026-10-27T00:00:00Z","remainingFraction":null}]}]}`, req), nil
		default:
			return quotaAggregateHTTPResponse(http.StatusBadGateway, `{"error":"unexpected host"}`, req), nil
		}
	})}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	handler.quotaAggregate.httpClientFactory = func(context.Context, *config.Config, *coreauth.Auth) *http.Client { return client }

	recorder := serveQuotaAggregate(handler, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response quotaAggregateResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, response.Generated); err != nil {
		t.Fatalf("generated=%q is not RFC3339: %v", response.Generated, err)
	}
	if len(response.Antigravity) != 3 || len(response.Codex) != 1 {
		t.Fatalf("account counts: antigravity=%d codex=%d", len(response.Antigravity), len(response.Codex))
	}
	accounts := make(map[string]antigravityQuotaAccount, len(response.Antigravity))
	for _, account := range response.Antigravity {
		accounts[account.Name] = account
	}
	goodResult := accounts["antigravity-good.json"]
	if goodResult.Error != "" || goodResult.PlanError != "plan_unavailable" || goodResult.Plan != nil {
		t.Fatalf("plan failure should remain partial: %+v", goodResult)
	}
	if len(goodResult.Groups) != 1 || goodResult.Groups[0].DisplayName != "Gemini 4 Argon" || goodResult.Groups[0].Description != "dynamic group" {
		t.Fatalf("dynamic upstream group was not preserved: %+v", goodResult.Groups)
	}
	if len(goodResult.Groups[0].Buckets) != 2 || goodResult.Groups[0].Buckets[0].RemainingFraction == nil || *goodResult.Groups[0].Buckets[0].RemainingFraction != 0.35 || goodResult.Groups[0].Buckets[1].RemainingFraction != nil {
		t.Fatalf("bucket values were not preserved: %+v", goodResult.Groups[0].Buckets)
	}
	if badResult := accounts["antigravity-refresh-fails.json"]; badResult.Error != "token_refresh_failed" || len(badResult.Groups) != 0 {
		t.Fatalf("refresh failure was not isolated: %+v", badResult)
	}
	if !accounts["antigravity-disabled.json"].Disabled {
		t.Fatal("disabled Antigravity account was not listed as disabled")
	}
	if got := executor.refreshCalls.Load(); got != 2 {
		t.Fatalf("refresh calls=%d want=2 (disabled account must be skipped)", got)
	}
	requestsMu.Lock()
	var sawSandbox, sawCloud bool
	for _, requestURL := range requestURLs {
		if requestURL == "daily-cloudcode-pa.sandbox.googleapis.com/v1internal:retrieveUserQuotaSummary" {
			sawSandbox = true
		}
		if requestURL == "cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary" {
			sawCloud = true
		}
	}
	requestsMu.Unlock()
	if !sawSandbox || sawCloud {
		t.Fatalf("quota host fallback order was not respected: %v", requestURLs)
	}

	codexResult := response.Codex[0]
	if codexResult.Plan == nil || *codexResult.Plan != "pro" || codexResult.Quota.Signals["X-Codex-Primary-Used-Percent"] != "81" {
		t.Fatalf("Codex quota projection missing values: %+v", codexResult)
	}
	if len(codexResult.Quota.Signals) != 6 || codexResult.Quota.Signals["X-Codex-Turn-State"] != "" || codexResult.Quota.Signals["Authorization"] != "" ||
		codexResult.Quota.Signals["X-Codex-Reset-After-Seconds"] != "120" || codexResult.Quota.Signals["X-Codex-Reset-At"] != "2026-10-27T00:00:00Z" || codexResult.Quota.Signals["X-Codex-Reset-After"] != "300" {
		t.Fatalf("Codex quota projection included non-quota headers: %+v", codexResult.Quota.Signals)
	}
	if modelSignals := codexResult.ModelQuotas["gpt-model"].Signals; len(modelSignals) != 4 || modelSignals["X-Codex-Secondary-Used-Percent"] != "19" ||
		modelSignals["X-Codex-Reset-After-Seconds"] != "30" || modelSignals["X-Codex-Reset-At"] != "2026-10-26T12:00:00Z" || modelSignals["X-Codex-Reset-After"] != "60" || modelSignals["X-Codex-Turn-State"] != "" {
		t.Fatalf("model quota projection included non-quota data: %+v", modelSignals)
	}
	for _, forbidden := range []string{"stale-access-good", "fresh-access-", "refresh-secret-good", "id-token-secret-good", "codex-secret", "codex-refresh-secret", "codex-id-token-secret", "private-header-value", "private-turn-state", "synthetic-upstream-body", "synthetic refresh detail"} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("response exposed private test data (%q)", forbidden)
		}
	}
}

func TestQuotaAggregateCacheForceAndConcurrentCoalescing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	entered := make(chan string, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseRefresh := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseRefresh()
	executor := &quotaAggregateTestExecutor{entered: entered, release: release}
	manager := quotaAggregateManager(t, executor, quotaAggregateAuth("antigravity-a", "antigravity", map[string]any{"access_token": "old"}))
	var upstreamCalls atomic.Int32
	var blockNext atomic.Bool
	client := &http.Client{Transport: quotaAggregateRoundTripper(func(req *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		if strings.HasSuffix(req.URL.Path, ":loadCodeAssist") {
			if blockNext.CompareAndSwap(true, false) {
				<-release
			}
			return quotaAggregateHTTPResponse(http.StatusOK, `{"currentTier":{"name":"Pro"}}`, req), nil
		}
		return quotaAggregateHTTPResponse(http.StatusOK, `{"groups":[]}`, req), nil
	})}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	handler.quotaAggregate.httpClientFactory = func(context.Context, *config.Config, *coreauth.Auth) *http.Client { return client }

	if recorder := serveQuotaAggregate(handler, ""); recorder.Code != http.StatusOK {
		t.Fatalf("first request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := serveQuotaAggregate(handler, ""); recorder.Code != http.StatusOK {
		t.Fatalf("cached request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := executor.refreshCalls.Load(); got != 1 {
		t.Fatalf("cache reuse refresh calls=%d want=1", got)
	}
	if recorder := serveQuotaAggregate(handler, "?refresh=true"); recorder.Code != http.StatusOK {
		t.Fatalf("forced request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := executor.refreshCalls.Load(); got != 2 {
		t.Fatalf("forced refresh calls=%d want=2", got)
	}
	if got := upstreamCalls.Load(); got != 4 {
		t.Fatalf("cached/forced upstream calls=%d want=4", got)
	}

	blockNext.Store(true)
	executor.blockRefresh.Store(true)
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- serveQuotaAggregate(handler, "?refresh=true") }()
	<-entered
	handler.quotaAggregate.mu.Lock()
	flight := handler.quotaAggregate.flight
	handler.quotaAggregate.mu.Unlock()
	if flight == nil {
		t.Fatal("forced refresh did not create an in-flight entry")
	}
	secondDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { secondDone <- serveQuotaAggregate(handler, "?refresh=true") }()
	select {
	case <-flight.joined:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent forced request did not join the active refresh")
	}
	releaseRefresh()
	if recorder := <-firstDone; recorder.Code != http.StatusOK {
		t.Fatalf("first concurrent request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := <-secondDone; recorder.Code != http.StatusOK {
		t.Fatalf("second concurrent request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := executor.refreshCalls.Load(); got != 3 {
		t.Fatalf("concurrent forced refresh calls=%d want=3", got)
	}
	if got := upstreamCalls.Load(); got != 6 {
		t.Fatalf("coalesced concurrent upstream calls=%d want=6", got)
	}
}

func TestQuotaAggregateRetriesWhenAuthIsRemovedDuringFetch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &quotaAggregateTestExecutor{}
	manager := quotaAggregateManager(t, executor, quotaAggregateAuth("antigravity-removed", "antigravity", map[string]any{"access_token": "old"}))
	var removed atomic.Bool
	client := &http.Client{Transport: quotaAggregateRoundTripper(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, ":loadCodeAssist") {
			if removed.CompareAndSwap(false, true) {
				manager.Remove(context.Background(), "antigravity-removed")
			}
			return quotaAggregateHTTPResponse(http.StatusOK, `{"currentTier":{"name":"Pro"}}`, req), nil
		}
		return quotaAggregateHTTPResponse(http.StatusOK, `{"groups":[]}`, req), nil
	})}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	handler.quotaAggregate.httpClientFactory = func(context.Context, *config.Config, *coreauth.Auth) *http.Client { return client }
	for i := 0; i < 2; i++ {
		recorder := serveQuotaAggregate(handler, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("request %d status=%d body=%s", i+1, recorder.Code, recorder.Body.String())
		}
		var response quotaAggregateResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Antigravity) != 0 {
			t.Fatalf("request %d returned removed account: %+v", i+1, response.Antigravity)
		}
	}
	if got := executor.refreshCalls.Load(); got != 1 {
		t.Fatalf("refresh calls=%d want=1", got)
	}
}

func TestQuotaAggregateRefreshHonorsContextCancellation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	entered := make(chan string, 1)
	executor := &quotaAggregateTestExecutor{entered: entered}
	executor.blockRefresh.Store(true)
	manager := quotaAggregateManager(t, executor, quotaAggregateAuth("antigravity-a", "antigravity", map[string]any{"access_token": "old"}))
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := handler.loadQuotaAggregate(ctx, true)
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("aggregate error=%v want context cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("force refresh did not stop after request cancellation")
	}
}

func TestQuotaAggregateRefreshDoesNotWaitPastContextWhenManagerRefreshStalls(t *testing.T) {
	gin.SetMode(gin.TestMode)
	entered := make(chan string, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseRefresh := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseRefresh()
	executor := &quotaAggregateTestExecutor{entered: entered, release: release}
	executor.blockRefresh.Store(true)
	executor.ignoreCancel.Store(true)
	manager := quotaAggregateManager(t, executor, quotaAggregateAuth("antigravity-a", "antigravity", map[string]any{"access_token": "old"}))
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := handler.loadQuotaAggregate(ctx, true)
		done <- err
	}()
	<-entered
	key := quotaAggregateRefreshKey{manager: manager, authID: "antigravity-a"}
	handler.quotaAggregate.mu.Lock()
	call := handler.quotaAggregate.refreshes[key]
	handler.quotaAggregate.mu.Unlock()
	if call == nil {
		t.Fatal("manager refresh call was not registered")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("aggregate error=%v want deadline exceeded", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stalled manager refresh held the aggregate request past its deadline")
	}
	releaseRefresh()
	select {
	case <-call.done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stalled manager refresh did not finish after release")
	}
}
