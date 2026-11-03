package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/deepnavakoti/acra/internal/adapters"
	"github.com/deepnavakoti/acra/internal/adapters/kubeclient"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/llm"
)

func splitEnv(name string) []string {
	var out []string
	for _, p := range strings.Split(os.Getenv(name), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// authFromEnv builds the authenticator from ACRA_API_TOKEN (one admin token) and
// ACRA_API_TOKENS ("token:principal:role|role,..."). With neither set, auth is
// disabled and the server is open: acceptable for the local demo only.
func authFromEnv() (*identity.Authenticator, error) {
	tokens := map[string]identity.Principal{}
	if t := os.Getenv("ACRA_API_TOKEN"); t != "" {
		if len(t) < 16 {
			return nil, fmt.Errorf("ACRA_API_TOKEN must be at least 16 characters")
		}
		tokens[t] = identity.Principal{ID: "admin-token", Roles: []string{identity.RoleAdmin}}
	}
	if spec := os.Getenv("ACRA_API_TOKENS"); spec != "" {
		m, err := identity.ParseTokens(spec)
		if err != nil {
			return nil, err
		}
		for t, p := range m {
			tokens[t] = p
		}
	}
	return identity.New(tokens), nil
}

// adaptersFromEnv enables each cloud adapter whose configuration is present.
// Adapters are read-only and optional; a misconfigured one is logged and skipped
// rather than aborting startup.
func adaptersFromEnv() []adapters.Adapter {
	hc := &http.Client{Timeout: 30 * time.Second}
	var out []adapters.Adapter

	if ws := os.Getenv("ACRA_AZURE_WORKSPACE_ID"); ws != "" {
		var ts adapters.TokenSource
		switch {
		case os.Getenv("ACRA_AZURE_CLIENT_SECRET") != "":
			ts = &adapters.AzureClientCredentials{
				TenantID: os.Getenv("ACRA_AZURE_TENANT_ID"), ClientID: os.Getenv("ACRA_AZURE_CLIENT_ID"),
				ClientSecret: os.Getenv("ACRA_AZURE_CLIENT_SECRET"), HTTP: hc,
			}
		default:
			ts = &adapters.AzureManagedIdentityToken{ClientID: os.Getenv("ACRA_AZURE_MSI_CLIENT_ID")}
		}
		out = append(out, &adapters.Azure{WorkspaceID: ws, Tokens: ts, HTTP: hc})
		log.Print("adapter enabled: azure (Log Analytics)")
	}

	if region, groups := os.Getenv("ACRA_AWS_REGION"), splitEnv("ACRA_AWS_LOG_GROUPS"); region != "" && len(groups) > 0 {
		var creds adapters.AWSCredentialSource = adapters.EnvAWSCreds{}
		if role, file := os.Getenv("AWS_ROLE_ARN"), os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); role != "" && file != "" {
			creds = &adapters.WebIdentityCreds{RoleARN: role, TokenFile: file, Region: region, HTTP: hc}
		}
		out = append(out, &adapters.AWS{Region: region, LogGroups: groups, Creds: creds, HTTP: hc})
		log.Print("adapter enabled: aws (CloudWatch Logs)")
	}

	if project := os.Getenv("ACRA_GCP_PROJECT"); project != "" {
		var ts adapters.TokenSource = &adapters.GCPMetadataToken{}
		if t := os.Getenv("ACRA_GCP_TOKEN"); t != "" {
			ts = adapters.StaticToken(t)
		}
		out = append(out, &adapters.GCP{ProjectID: project, Tokens: ts, HTTP: hc})
		log.Print("adapter enabled: gcp (Cloud Logging)")
	}

	if ns := splitEnv("ACRA_K8S_NAMESPACES"); len(ns) > 0 {
		r, err := kubeclient.FromConfig(os.Getenv("ACRA_KUBECONFIG"))
		if err != nil {
			log.Printf("adapter skipped: k8s: %v", err)
		} else {
			out = append(out, &adapters.Kubernetes{Reader: r, Namespaces: ns})
			log.Printf("adapter enabled: k8s (namespaces %v)", ns)
		}
	}

	if u := os.Getenv("ACRA_KAGENT_URL"); u != "" {
		var tok adapters.TokenSource
		if t := os.Getenv("ACRA_KAGENT_TOKEN"); t != "" {
			tok = adapters.StaticToken(t)
		}
		out = append(out, &adapters.KAgent{Endpoint: u, Method: os.Getenv("ACRA_KAGENT_METHOD"), Token: tok, HTTP: hc})
		log.Print("adapter enabled: kagent (advisory only)")
	}
	return out
}

// llmFromEnv returns the optional narrator/judge client. nil when unconfigured.
func llmFromEnv() *llm.Client {
	base := os.Getenv("ACRA_LLM_BASE_URL")
	if base == "" {
		return nil
	}
	c := &llm.Client{BaseURL: base, APIKey: os.Getenv("ACRA_LLM_API_KEY"), Model: os.Getenv("ACRA_LLM_MODEL"),
		MaxTokens: 800, HTTP: &http.Client{Timeout: 60 * time.Second}}
	if err := c.Validate(); err != nil {
		log.Printf("llm disabled: %v", err)
		return nil
	}
	log.Print("llm enabled (narrative + rubric judge); rules decide hypotheses and confidence")
	return c
}
