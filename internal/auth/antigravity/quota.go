package antigravity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	antigravityQuotaUserAgent = "antigravity/hub/2.23.0 darwin/arm64"
	maxAntigravityQuotaBody   = 2 << 20
)

var errAntigravityQuotaUnavailable = errors.New("antigravity quota unavailable")

// QuotaGroup and QuotaBucket mirror the management fields returned by Google's
// retrieveUserQuotaSummary endpoint.
type QuotaGroup struct {
	DisplayName string        `json:"displayName"`
	Description string        `json:"description"`
	Buckets     []QuotaBucket `json:"buckets"`
}

type QuotaBucket struct {
	BucketID          string   `json:"bucketId"`
	Window            string   `json:"window"`
	ResetTime         string   `json:"resetTime"`
	RemainingFraction *float64 `json:"remainingFraction"`
}

// FetchQuotaPlan reads the current tier from loadCodeAssist. Callers can treat
// this as best-effort and fetch quota groups even when plan lookup fails.
func (o *AntigravityAuth) FetchQuotaPlan(ctx context.Context, accessToken string) (string, error) {
	body, err := json.Marshal(map[string]any{"metadata": map[string]string{"ideType": "ANTIGRAVITY"}})
	if err != nil {
		return "", errAntigravityQuotaUnavailable
	}
	responseBody, err := o.postQuotaJSON(ctx, "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist", accessToken, body)
	if err != nil {
		return "", err
	}
	var response struct {
		CurrentTier struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"currentTier"`
	}
	if errDecode := json.Unmarshal(responseBody, &response); errDecode != nil {
		return "", errAntigravityQuotaUnavailable
	}
	if plan := strings.TrimSpace(response.CurrentTier.Name); plan != "" {
		return plan, nil
	}
	if plan := strings.TrimSpace(response.CurrentTier.ID); plan != "" {
		return plan, nil
	}
	return "", errAntigravityQuotaUnavailable
}

// FetchQuotaSummary tries the production, sandbox, and general Cloud Code hosts
// in order. Upstream response bodies and transport errors are intentionally
// omitted from returned errors.
func (o *AntigravityAuth) FetchQuotaSummary(ctx context.Context, accessToken, projectID string) ([]QuotaGroup, error) {
	var project any
	if trimmed := strings.TrimSpace(projectID); trimmed != "" {
		project = trimmed
	}
	body, err := json.Marshal(map[string]any{"project": project})
	if err != nil {
		return nil, errAntigravityQuotaUnavailable
	}
	endpoints := [...]string{
		"https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
		"https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:retrieveUserQuotaSummary",
		"https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
	}
	for _, endpoint := range endpoints {
		responseBody, errPost := o.postQuotaJSON(ctx, endpoint, accessToken, body)
		if errPost != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		var response struct {
			Groups []QuotaGroup `json:"groups"`
		}
		if errDecode := json.Unmarshal(responseBody, &response); errDecode != nil {
			continue
		}
		if response.Groups == nil {
			response.Groups = []QuotaGroup{}
		}
		for i := range response.Groups {
			if response.Groups[i].Buckets == nil {
				response.Groups[i].Buckets = []QuotaBucket{}
			}
		}
		return response.Groups, nil
	}
	return nil, errAntigravityQuotaUnavailable
}

func (o *AntigravityAuth) postQuotaJSON(ctx context.Context, endpoint, accessToken string, body []byte) ([]byte, error) {
	if o == nil || o.httpClient == nil || strings.TrimSpace(accessToken) == "" {
		return nil, errAntigravityQuotaUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errAntigravityQuotaUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", antigravityQuotaUserAgent)

	resp, errDo := o.httpClient.Do(req)
	if errDo != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errAntigravityQuotaUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, errAntigravityQuotaUnavailable
	}
	responseBody, errRead := io.ReadAll(io.LimitReader(resp.Body, maxAntigravityQuotaBody+1))
	if errRead != nil || len(responseBody) > maxAntigravityQuotaBody {
		return nil, errAntigravityQuotaUnavailable
	}
	return responseBody, nil
}
