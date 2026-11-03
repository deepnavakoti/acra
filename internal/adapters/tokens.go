package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// cachedToken caches a bearer token until shortly before it expires.
type cachedToken struct {
	mu     sync.Mutex
	token  string
	expiry time.Time
}

func (c *cachedToken) get(fetch func() (string, time.Duration, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry) {
		return c.token, nil
	}
	tok, ttl, err := fetch()
	if err != nil {
		return "", err
	}
	if ttl > 2*time.Minute {
		ttl -= time.Minute
	}
	c.token, c.expiry = tok, time.Now().Add(ttl)
	return tok, nil
}

func metadataGet(ctx context.Context, hc *http.Client, rawURL string, hdr map[string]string) ([]byte, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return httpDo(hc, req)
}

// GCPMetadataToken fetches an access token from the GCE/GKE metadata server
// (Workload Identity or the node's service account). The metadata host is a
// fixed link-local address, so it is exempt from the https-only endpoint rule
// that applies to configurable endpoints. BaseURL is overridable for tests.
type GCPMetadataToken struct {
	BaseURL string // default http://metadata.google.internal
	HTTP    *http.Client
	c       cachedToken
}

// Token implements TokenSource.
func (g *GCPMetadataToken) Token(ctx context.Context) (string, error) {
	return g.c.get(func() (string, time.Duration, error) {
		base := g.BaseURL
		if base == "" {
			base = "http://metadata.google.internal"
		}
		body, err := metadataGet(ctx, g.HTTP, base+"/computeMetadata/v1/instance/service-accounts/default/token",
			map[string]string{"Metadata-Flavor": "Google"})
		if err != nil {
			return "", 0, fmt.Errorf("gcp metadata token: %w", err)
		}
		var r struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &r); err != nil || r.AccessToken == "" {
			return "", 0, errors.New("gcp metadata token: unexpected response")
		}
		return r.AccessToken, time.Duration(r.ExpiresIn) * time.Second, nil
	})
}

// AzureManagedIdentityToken fetches a token from the Azure Instance Metadata
// Service (VM / AKS managed identity). BaseURL is overridable for tests.
type AzureManagedIdentityToken struct {
	BaseURL  string // default http://169.254.169.254
	Resource string // default https://api.loganalytics.io/
	ClientID string // optional: user-assigned identity
	HTTP     *http.Client
	c        cachedToken
}

// Token implements TokenSource.
func (a *AzureManagedIdentityToken) Token(ctx context.Context) (string, error) {
	return a.c.get(func() (string, time.Duration, error) {
		base, res := a.BaseURL, a.Resource
		if base == "" {
			base = "http://169.254.169.254"
		}
		if res == "" {
			res = "https://api.loganalytics.io/"
		}
		q := url.Values{"api-version": {"2018-02-01"}, "resource": {res}}
		if a.ClientID != "" {
			q.Set("client_id", a.ClientID)
		}
		body, err := metadataGet(ctx, a.HTTP, base+"/metadata/identity/oauth2/token?"+q.Encode(),
			map[string]string{"Metadata": "true"})
		if err != nil {
			return "", 0, fmt.Errorf("azure managed identity token: %w", err)
		}
		var r struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   string `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &r); err != nil || r.AccessToken == "" {
			return "", 0, errors.New("azure managed identity token: unexpected response")
		}
		secs, _ := strconv.Atoi(r.ExpiresIn)
		return r.AccessToken, time.Duration(secs) * time.Second, nil
	})
}
