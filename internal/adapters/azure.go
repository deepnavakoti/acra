package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Azure reads Application Insights / Log Analytics data (workspace-based
// tables AppTraces, AppExceptions, AppDependencies) through the Log Analytics
// query API. Read-only: it only issues KQL queries.
type Azure struct {
	Endpoint    string // default https://api.loganalytics.azure.com
	WorkspaceID string
	Tokens      TokenSource
	HTTP        *http.Client
}

// Name implements Adapter.
func (a *Azure) Name() string { return "azure" }

func (a *Azure) endpoint() string {
	if a.Endpoint != "" {
		return strings.TrimRight(a.Endpoint, "/")
	}
	return "https://api.loganalytics.azure.com"
}

// buildKQL composes the query. Identifiers were validated by SafeID and so
// contain no quote, backslash or whitespace that could break out of the literal.
func buildKQL(q Query) string {
	var conds []string
	if q.TraceID != "" {
		conds = append(conds, fmt.Sprintf(`OperationId == "%s"`, q.TraceID))
	}
	if q.AgentID != "" {
		conds = append(conds, fmt.Sprintf(`tostring(Properties["agent_id"]) == "%s"`, q.AgentID))
	}
	if q.Service != "" {
		conds = append(conds, fmt.Sprintf(`AppRoleName == "%s"`, q.Service))
	}
	return fmt.Sprintf(`union isfuzzy=true AppTraces, AppExceptions, AppDependencies
| where TimeGenerated between (datetime(%s) .. datetime(%s))
| where %s
| extend Msg = coalesce(column_ifexists("Message", ""), column_ifexists("OuterMessage", ""), column_ifexists("Name", ""))
| project TimeGenerated, Type, Msg, SeverityLevel = column_ifexists("SeverityLevel", int(null)), ResultCode = column_ifexists("ResultCode", ""), Success = column_ifexists("Success", bool(null)), AppRoleName, OperationId, ItemId = column_ifexists("ItemId", "")
| order by TimeGenerated asc
| take %d`,
		q.Start.Format(time.RFC3339), q.End.Format(time.RFC3339), strings.Join(conds, " or "), q.Limit)
}

type laResponse struct {
	Tables []struct {
		Name    string `json:"name"`
		Columns []struct {
			Name string `json:"name"`
		} `json:"columns"`
		Rows [][]any `json:"rows"`
	} `json:"tables"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Fetch implements Adapter.
func (a *Azure) Fetch(ctx context.Context, q Query) (Result, error) {
	q, err := q.Validate()
	if err != nil {
		return Result{}, err
	}
	if a.WorkspaceID == "" || !SafeID(a.WorkspaceID) {
		return Result{}, errors.New("azure: invalid workspace id")
	}
	if err := checkBaseURL(a.endpoint()); err != nil {
		return Result{}, err
	}
	tok, err := a.Tokens.Token(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("azure: token: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"query": buildKQL(q)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.endpoint()+"/v1/workspaces/"+url.PathEscape(a.WorkspaceID)+"/query", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	data, err := httpDo(a.HTTP, req)
	if err != nil {
		return Result{}, fmt.Errorf("azure: %w", err)
	}
	var lr laResponse
	if err := json.Unmarshal(data, &lr); err != nil {
		return Result{}, fmt.Errorf("azure: bad response: %w", err)
	}
	res := Result{Source: "azure", Signals: []Signal{}}
	if lr.Error != nil {
		res.Partial = true
		res.Warnings = append(res.Warnings, "azure reported a partial error: "+clip(lr.Error.Code, 80))
	}
	for _, t := range lr.Tables {
		idx := map[string]int{}
		for i, c := range t.Columns {
			idx[c.Name] = i
		}
		get := func(row []any, name string) any {
			if i, ok := idx[name]; ok && i < len(row) {
				return row[i]
			}
			return nil
		}
		for _, row := range t.Rows {
			ts, _ := time.Parse(time.RFC3339Nano, str(get(row, "TimeGenerated")))
			typ := str(get(row, "Type"))
			sev := azureSeverity(get(row, "SeverityLevel"), typ, get(row, "Success"))
			attrs := map[string]string{"type": typ}
			if v := str(get(row, "ResultCode")); v != "" {
				attrs["resultCode"] = v
			}
			if v := str(get(row, "OperationId")); v != "" {
				attrs["operationId"] = v
			}
			res.Signals = append(res.Signals, Signal{
				Source: "azure", Kind: "log", Time: ts, Severity: sev,
				Resource: str(get(row, "AppRoleName")), Message: clip(str(get(row, "Msg")), 1000),
				Attrs: attrs, Ref: str(get(row, "ItemId")),
			})
		}
	}
	if len(res.Signals) >= q.Limit {
		res.Partial = true
		res.Warnings = append(res.Warnings, "result limit reached; older/newer rows may be missing")
	}
	return res, nil
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return fmt.Sprintf("%v", x)
	case bool:
		return fmt.Sprintf("%v", x)
	}
	return fmt.Sprintf("%v", v)
}

func azureSeverity(level any, typ string, success any) string {
	if typ == "AppExceptions" {
		return "error"
	}
	if b, ok := success.(bool); ok && !b {
		return "error"
	}
	if f, ok := level.(float64); ok {
		switch int(f) {
		case 0:
			return "debug"
		case 1:
			return "info"
		case 2:
			return "warning"
		case 3:
			return "error"
		default:
			return "critical"
		}
	}
	return "info"
}

// AzureClientCredentials obtains tokens for a service principal (OAuth2 client
// credentials). Tokens are cached until shortly before expiry.
type AzureClientCredentials struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Scope        string // default https://api.loganalytics.io/.default
	Authority    string // default https://login.microsoftonline.com
	HTTP         *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// Token implements TokenSource.
func (c *AzureClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expiry) > time.Minute {
		return c.token, nil
	}
	if !SafeID(c.TenantID) || c.ClientID == "" || c.ClientSecret == "" {
		return "", errors.New("azure: tenant, client id and client secret are required")
	}
	authority := strings.TrimRight(c.Authority, "/")
	if authority == "" {
		authority = "https://login.microsoftonline.com"
	}
	if err := checkBaseURL(authority); err != nil {
		return "", err
	}
	scope := c.Scope
	if scope == "" {
		scope = "https://api.loganalytics.io/.default"
	}
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {c.ClientID},
		"client_secret": {c.ClientSecret}, "scope": {scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		authority+"/"+url.PathEscape(c.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	data, err := httpDo(c.HTTP, req)
	if err != nil {
		return "", fmt.Errorf("azure token endpoint: %w", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("azure: token response missing access_token")
	}
	c.token = tr.AccessToken
	c.expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}
