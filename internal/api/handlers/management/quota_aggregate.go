package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/antigravity"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const (
	quotaAggregateCacheTTL = 90 * time.Second
	quotaAggregateWorkers  = 4
)

var errQuotaAggregateManagerUnavailable = errors.New("quota aggregate auth manager unavailable")
var errQuotaAggregateStale = errors.New("quota aggregate changed during refresh")

type quotaAggregateResponse struct {
	Generated   string                    `json:"generated"`
	Antigravity []antigravityQuotaAccount `json:"antigravity"`
	Codex       []codexQuotaAccount       `json:"codex"`
}

type antigravityQuotaAccount struct {
	Name      string                   `json:"name"`
	Email     string                   `json:"email"`
	Disabled  bool                     `json:"disabled"`
	Plan      *string                  `json:"plan"`
	Groups    []antigravity.QuotaGroup `json:"groups"`
	Error     string                   `json:"error,omitempty"`
	PlanError string                   `json:"plan_error,omitempty"`
}

type codexQuotaAccount struct {
	Name        string                           `json:"name"`
	Email       string                           `json:"email"`
	Disabled    bool                             `json:"disabled"`
	Plan        *string                          `json:"plan"`
	Quota       codexQuotaObservation            `json:"quota"`
	ModelQuotas map[string]codexQuotaObservation `json:"model_quotas"`
}

type codexQuotaObservation struct {
	Signals map[string]string `json:"signals"`
}

type quotaAggregateCacheEntry struct {
	fingerprint string
	fetchedAt   time.Time
	response    quotaAggregateResponse
	valid       bool
}

type quotaAggregateRefreshKey struct {
	manager *coreauth.Manager
	authID  string
}

type quotaAggregateRefreshCall struct {
	done chan struct{}
	auth *coreauth.Auth
	err  error
}

type quotaAggregateState struct {
	mu                sync.Mutex
	flight            *quotaAggregateFlight
	cache             quotaAggregateCacheEntry
	refreshes         map[quotaAggregateRefreshKey]*quotaAggregateRefreshCall
	httpClientFactory func(context.Context, *config.Config, *coreauth.Auth) *http.Client
}

type quotaAggregateFlight struct {
	done              chan struct{}
	joined            chan struct{}
	joinOnce          sync.Once
	manager           *coreauth.Manager
	stableFingerprint string
	response          quotaAggregateResponse
	err               error
}

// GetQuotaAggregate returns a cached provider snapshot, or refreshes it when
// refresh=true. Upstream failures are represented on the affected account.
func (h *Handler) GetQuotaAggregate(c *gin.Context) {
	if h == nil || c == nil || c.Request == nil {
		if c != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "quota_aggregate_unavailable"})
		}
		return
	}
	forceRefresh := strings.EqualFold(strings.TrimSpace(c.Query("refresh")), "true")
	ctx, cancel := context.WithTimeout(c.Request.Context(), defaultAPICallTimeout)
	defer cancel()
	response, err := h.loadQuotaAggregate(ctx, forceRefresh)
	if err != nil {
		if c.Request.Context().Err() != nil {
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "quota_aggregate_unavailable"})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *Handler) loadQuotaAggregate(ctx context.Context, forceRefresh bool) (quotaAggregateResponse, error) {
	for {
		manager, cfg, clientFactory := h.quotaAggregateDependencies()
		if manager == nil {
			return quotaAggregateResponse{}, errQuotaAggregateManagerUnavailable
		}
		auths := manager.List()
		fingerprint := quotaAggregateFingerprint(auths, cfg, true)

		h.quotaAggregate.mu.Lock()
		if flight := h.quotaAggregate.flight; flight != nil {
			flight.joinOnce.Do(func() { close(flight.joined) })
			done := flight.done
			h.quotaAggregate.mu.Unlock()
			select {
			case <-ctx.Done():
				return quotaAggregateResponse{}, ctx.Err()
			case <-done:
				if (errors.Is(flight.err, context.Canceled) || errors.Is(flight.err, context.DeadlineExceeded) || errors.Is(flight.err, errQuotaAggregateStale)) && ctx.Err() == nil {
					continue
				}
				if flight.err == nil {
					currentManager, currentConfig, _ := h.quotaAggregateDependencies()
					if currentManager != flight.manager || currentManager == nil ||
						quotaAggregateFingerprint(currentManager.List(), currentConfig, false) != flight.stableFingerprint {
						continue
					}
				}
				return flight.response, flight.err
			}
		}
		if !forceRefresh && h.quotaAggregate.cache.valid &&
			h.quotaAggregate.cache.fingerprint == fingerprint &&
			time.Since(h.quotaAggregate.cache.fetchedAt) < quotaAggregateCacheTTL {
			response := h.quotaAggregate.cache.response
			h.quotaAggregate.mu.Unlock()
			return response, nil
		}
		flight := &quotaAggregateFlight{done: make(chan struct{}), joined: make(chan struct{}), manager: manager}
		h.quotaAggregate.flight = flight
		h.quotaAggregate.mu.Unlock()

		response, err := h.buildQuotaAggregate(ctx, manager, cfg, clientFactory, auths)
		var cacheEntry quotaAggregateCacheEntry
		var stableFingerprint string
		cacheable := false
		if err == nil && ctx.Err() == nil {
			cacheEntry, stableFingerprint, cacheable = h.quotaAggregateCacheAfterFetch(manager, cfg, auths)
			if cacheable {
				cacheEntry.response = response
				cacheEntry.fetchedAt = time.Now()
				cacheEntry.valid = true
			} else {
				err = errQuotaAggregateStale
			}
		}
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}

		h.quotaAggregate.mu.Lock()
		if err == nil && cacheable && ctx.Err() == nil {
			h.quotaAggregate.cache = cacheEntry
		}
		flight.stableFingerprint = stableFingerprint
		flight.response = response
		flight.err = err
		h.quotaAggregate.flight = nil
		close(flight.done)
		h.quotaAggregate.mu.Unlock()
		if errors.Is(err, errQuotaAggregateStale) && ctx.Err() == nil {
			continue
		}
		return response, err
	}
}

func (h *Handler) quotaAggregateDependencies() (*coreauth.Manager, *config.Config, func(context.Context, *config.Config, *coreauth.Auth) *http.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	manager := h.authManager
	cfg := &config.Config{}
	if h.cfg != nil {
		cfg = h.cfg.CloneForRuntime()
	}
	return manager, cfg, h.quotaAggregate.httpClientFactory
}

// quotaForceRefresh lets request cancellation stop waiting for the manager's
// per-auth refresh lock, which is a non-cancelable mutex. Calls for the same
// manager/account share one background operation so retries do not queue up
// duplicate refreshes behind that lock.
func (h *Handler) quotaForceRefresh(ctx context.Context, manager *coreauth.Manager, authID string) (*coreauth.Auth, error) {
	key := quotaAggregateRefreshKey{manager: manager, authID: authID}
	for {
		h.quotaAggregate.mu.Lock()
		if h.quotaAggregate.refreshes == nil {
			h.quotaAggregate.refreshes = make(map[quotaAggregateRefreshKey]*quotaAggregateRefreshCall)
		}
		call := h.quotaAggregate.refreshes[key]
		if call == nil {
			call = &quotaAggregateRefreshCall{done: make(chan struct{})}
			h.quotaAggregate.refreshes[key] = call
			go func() {
				call.auth, call.err = manager.ForceRefreshAuth(ctx, authID)
				h.quotaAggregate.mu.Lock()
				delete(h.quotaAggregate.refreshes, key)
				close(call.done)
				h.quotaAggregate.mu.Unlock()
			}()
		}
		h.quotaAggregate.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-call.done:
			if ctx.Err() == nil && (errors.Is(call.err, context.Canceled) || errors.Is(call.err, context.DeadlineExceeded)) {
				continue
			}
			return call.auth, call.err
		}
	}
}

func (h *Handler) quotaAggregateCacheAfterFetch(manager *coreauth.Manager, cfg *config.Config, before []*coreauth.Auth) (quotaAggregateCacheEntry, string, bool) {
	currentManager, currentConfig, _ := h.quotaAggregateDependencies()
	if currentManager == nil || currentManager != manager {
		return quotaAggregateCacheEntry{}, "", false
	}
	after := currentManager.List()
	stableFingerprint := quotaAggregateFingerprint(after, currentConfig, false)
	if quotaAggregateFingerprint(before, cfg, false) != stableFingerprint {
		return quotaAggregateCacheEntry{}, "", false
	}
	return quotaAggregateCacheEntry{fingerprint: quotaAggregateFingerprint(after, currentConfig, true)}, stableFingerprint, true
}

func (h *Handler) buildQuotaAggregate(ctx context.Context, manager *coreauth.Manager, cfg *config.Config, clientFactory func(context.Context, *config.Config, *coreauth.Auth) *http.Client, auths []*coreauth.Auth) (quotaAggregateResponse, error) {
	sort.Slice(auths, func(i, j int) bool {
		if auths[i] == nil || auths[j] == nil {
			return auths[i] == nil && auths[j] != nil
		}
		leftProvider, rightProvider := strings.ToLower(auths[i].Provider), strings.ToLower(auths[j].Provider)
		if leftProvider != rightProvider {
			return leftProvider < rightProvider
		}
		return quotaAccountName(auths[i]) < quotaAccountName(auths[j])
	})
	response := quotaAggregateResponse{
		Antigravity: []antigravityQuotaAccount{},
		Codex:       []codexQuotaAccount{},
	}
	type antigravityJob struct {
		index int
		auth  *coreauth.Auth
	}
	var jobs []antigravityJob
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
		case "antigravity":
			account := antigravityAccountFromAuth(auth)
			index := len(response.Antigravity)
			response.Antigravity = append(response.Antigravity, account)
			if !account.Disabled {
				jobs = append(jobs, antigravityJob{index: index, auth: auth})
			}
		case "codex":
			response.Codex = append(response.Codex, codexAccountFromAuth(auth))
		}
	}

	if err := ctx.Err(); err != nil {
		return quotaAggregateResponse{}, err
	}
	workerCount := len(jobs)
	if workerCount > quotaAggregateWorkers {
		workerCount = quotaAggregateWorkers
	}
	if workerCount > 0 {
		jobQueue := make(chan antigravityJob)
		var workers sync.WaitGroup
		workers.Add(workerCount)
		for range workerCount {
			go func() {
				defer workers.Done()
				for job := range jobQueue {
					account, errFetch := h.fetchAntigravityQuota(ctx, manager, cfg, clientFactory, job.auth)
					if errFetch == nil {
						response.Antigravity[job.index] = account
					}
				}
			}()
		}
		for _, job := range jobs {
			select {
			case <-ctx.Done():
				close(jobQueue)
				workers.Wait()
				return quotaAggregateResponse{}, ctx.Err()
			case jobQueue <- job:
			}
		}
		close(jobQueue)
		workers.Wait()
	}
	if err := ctx.Err(); err != nil {
		return quotaAggregateResponse{}, err
	}
	response.Generated = time.Now().UTC().Format(time.RFC3339)
	return response, nil
}

func (h *Handler) fetchAntigravityQuota(ctx context.Context, manager *coreauth.Manager, cfg *config.Config, clientFactory func(context.Context, *config.Config, *coreauth.Auth) *http.Client, auth *coreauth.Auth) (antigravityQuotaAccount, error) {
	account := antigravityAccountFromAuth(auth)
	if account.Disabled {
		return account, nil
	}
	refreshed, errRefresh := h.quotaForceRefresh(ctx, manager, auth.ID)
	if errRefresh != nil {
		if ctx.Err() != nil {
			return account, ctx.Err()
		}
		account.Error = "token_refresh_failed"
		return account, nil
	}
	if refreshed == nil {
		account.Error = "token_refresh_failed"
		return account, nil
	}
	account = antigravityAccountFromAuth(refreshed)
	if account.Disabled {
		return account, nil
	}
	var accessToken string
	if refreshed.Metadata != nil {
		accessToken, _ = refreshed.Metadata["access_token"].(string)
	}
	if strings.TrimSpace(accessToken) == "" {
		account.Error = "access_token_missing"
		return account, nil
	}
	var client *http.Client
	if clientFactory != nil {
		client = clientFactory(ctx, cfg, refreshed)
	}
	if client == nil {
		client = helps.NewProxyAwareHTTPClient(ctx, cfg, refreshed, defaultAPICallTimeout)
	}
	provider := antigravity.NewAntigravityAuth(cfg, client)
	plan, errPlan := provider.FetchQuotaPlan(ctx, accessToken)
	if errPlan != nil {
		if ctx.Err() != nil {
			return account, ctx.Err()
		}
		account.PlanError = "plan_unavailable"
	} else {
		account.Plan = stringPointer(plan)
	}
	groups, errQuota := provider.FetchQuotaSummary(ctx, accessToken, authProjectID(refreshed))
	if errQuota != nil {
		if ctx.Err() != nil {
			return account, ctx.Err()
		}
		account.Error = "quota_unavailable"
		return account, nil
	}
	account.Groups = groups
	return account, nil
}

func antigravityAccountFromAuth(auth *coreauth.Auth) antigravityQuotaAccount {
	return antigravityQuotaAccount{
		Name:     quotaAccountName(auth),
		Email:    authEmail(auth),
		Disabled: quotaAccountDisabled(auth),
		Groups:   []antigravity.QuotaGroup{},
	}
}

func codexAccountFromAuth(auth *coreauth.Auth) codexQuotaAccount {
	signals := codexQuotaSignals(auth.Quota.Signals)
	plan := strings.TrimSpace(signals["X-Codex-Plan-Type"])
	if plan == "" {
		if claims := extractCodexIDTokenClaims(auth); claims != nil {
			plan, _ = claims["plan_type"].(string)
			plan = strings.TrimSpace(plan)
		}
	}
	modelQuotas := make(map[string]codexQuotaObservation)
	for model, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		modelSignals := codexQuotaSignals(state.Quota.Signals)
		if len(modelSignals) > 0 {
			modelQuotas[model] = codexQuotaObservation{Signals: modelSignals}
		}
	}
	return codexQuotaAccount{
		Name:        quotaAccountName(auth),
		Email:       authEmail(auth),
		Disabled:    quotaAccountDisabled(auth),
		Plan:        nullableString(plan),
		Quota:       codexQuotaObservation{Signals: signals},
		ModelQuotas: modelQuotas,
	}
}

func codexQuotaSignals(signals map[string]string) map[string]string {
	filtered := make(map[string]string)
	for name, value := range signals {
		canonicalName := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if !isAllowedCodexQuotaSignal(canonicalName) {
			continue
		}
		filtered[canonicalName] = value
	}
	return filtered
}

func isAllowedCodexQuotaSignal(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasPrefix(lower, "x-codex-") {
		return false
	}
	rest := strings.TrimPrefix(lower, "x-codex-")
	switch rest {
	case "active-limit", "plan-type", "credits-has-credits", "credits-unlimited", "credits-balance",
		"allowed", "limit-reached", "limit-name", "reset-after-seconds", "reset-at", "reset-after", "over-secondary-limit-percent":
		return true
	}
	for _, window := range []string{"primary", "secondary", "code-review-primary", "code-review-secondary"} {
		if strings.HasPrefix(rest, window+"-") && allowedCodexQuotaWindowField(strings.TrimPrefix(rest, window+"-")) {
			return true
		}
	}
	for _, window := range []string{"-primary-", "-secondary-"} {
		if index := strings.Index(rest, window); index > 0 {
			namespace := rest[:index]
			field := rest[index+len(window):]
			if validCodexQuotaNamespace(namespace) && allowedCodexQuotaWindowField(field) {
				return true
			}
		}
	}
	for _, field := range []string{"allowed", "limit-reached", "limit-name", "over-secondary-limit-percent"} {
		suffix := "-" + field
		if strings.HasSuffix(rest, suffix) {
			namespace := strings.TrimSuffix(rest, suffix)
			return validCodexQuotaNamespace(namespace)
		}
	}
	return false
}

func allowedCodexQuotaWindowField(field string) bool {
	switch field {
	case "allowed", "limit-reached", "limit-name", "used-percent", "window-minutes", "reset-after-seconds", "reset-at", "over-secondary-limit-percent":
		return true
	default:
		return false
	}
}

func validCodexQuotaNamespace(namespace string) bool {
	if namespace == "" || strings.HasPrefix(namespace, "-") || strings.HasSuffix(namespace, "-") {
		return false
	}
	for _, char := range namespace {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func quotaAccountName(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	name := strings.TrimSpace(auth.FileName)
	if name == "" {
		name = strings.TrimSpace(auth.ID)
	}
	if name == "" {
		return ""
	}
	return filepath.Base(strings.ReplaceAll(name, "\\", "/"))
}

func quotaAccountDisabled(auth *coreauth.Auth) bool {
	return auth != nil && (auth.Disabled || auth.Status == coreauth.StatusDisabled)
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringPointer(value string) *string {
	return &value
}

type quotaAggregateFingerprintRecord struct {
	ID                string                       `json:"id"`
	Provider          string                       `json:"provider"`
	Name              string                       `json:"name"`
	Email             string                       `json:"email"`
	ProjectID         string                       `json:"project_id"`
	Disabled          bool                         `json:"disabled"`
	Status            string                       `json:"status"`
	ProxyURL          string                       `json:"proxy_url"`
	Plan              *string                      `json:"plan"`
	QuotaSignals      map[string]string            `json:"quota_signals"`
	ModelQuotas       map[string]map[string]string `json:"model_quotas"`
	RegistrationEpoch uint64                       `json:"registration_epoch"`
	Generation        uint64                       `json:"generation,omitempty"`
	CredentialVersion uint64                       `json:"credential_version,omitempty"`
	UpdatedAt         time.Time                    `json:"updated_at,omitempty"`
}

func quotaAggregateFingerprint(auths []*coreauth.Auth, cfg *config.Config, includeLifecycle bool) string {
	records := make([]quotaAggregateFingerprintRecord, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		record := quotaAggregateFingerprintRecord{
			ID:                auth.ID,
			Provider:          strings.ToLower(strings.TrimSpace(auth.Provider)),
			Name:              quotaAccountName(auth),
			Email:             authEmail(auth),
			ProjectID:         authProjectID(auth),
			Disabled:          quotaAccountDisabled(auth),
			Status:            string(auth.Status),
			ProxyURL:          auth.ProxyURL,
			QuotaSignals:      codexQuotaSignals(auth.Quota.Signals),
			ModelQuotas:       make(map[string]map[string]string),
			RegistrationEpoch: auth.RegistrationEpoch,
		}
		if auth.Metadata != nil {
			if proxyURL, ok := auth.Metadata["proxy_url"].(string); ok && record.ProxyURL == "" {
				record.ProxyURL = strings.TrimSpace(proxyURL)
			}
		}
		if record.Provider == "codex" {
			if record.QuotaSignals["X-Codex-Plan-Type"] != "" {
				record.Plan = nullableString(record.QuotaSignals["X-Codex-Plan-Type"])
			} else if claims := extractCodexIDTokenClaims(auth); claims != nil {
				if plan, ok := claims["plan_type"].(string); ok {
					record.Plan = nullableString(strings.TrimSpace(plan))
				}
			}
			for model, state := range auth.ModelStates {
				if state != nil {
					filtered := codexQuotaSignals(state.Quota.Signals)
					if len(filtered) > 0 {
						record.ModelQuotas[model] = filtered
					}
				}
			}
		}
		if includeLifecycle {
			record.Status = string(auth.Status)
			record.Generation = auth.Generation
			record.CredentialVersion = auth.CredentialVersion
			record.UpdatedAt = auth.UpdatedAt
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Provider != records[j].Provider {
			return records[i].Provider < records[j].Provider
		}
		return records[i].ID < records[j].ID
	})
	globalProxy := ""
	if cfg != nil {
		globalProxy = strings.TrimSpace(cfg.ProxyURL)
	}
	data, _ := json.Marshal(struct {
		GlobalProxy string                            `json:"global_proxy"`
		Records     []quotaAggregateFingerprintRecord `json:"records"`
	}{GlobalProxy: globalProxy, Records: records})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
