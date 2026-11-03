// Command apiserver serves the ACRA /v1 API, embeds the evidence store, and
// serves the console. Run it locally (no cluster) for the demo:
//
//	go run ./cmd/apiserver        # then open http://localhost:8080
//	go run ./cmd/workload inject-drift combinative
//
// Production use: pass -key-file (persistent signing key), -demo=false, and set
// ACRA_API_TOKEN (or ACRA_API_TOKENS). See wire.go for the adapter/LLM
// environment variables.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/deepnavakoti/acra/internal/a2a"
	"github.com/deepnavakoti/acra/internal/api"
	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/gateway"
	"github.com/deepnavakoti/acra/internal/incident"
	"github.com/deepnavakoti/acra/internal/mcp"
	"github.com/deepnavakoti/acra/internal/pipeline"
	"github.com/deepnavakoti/acra/internal/rca"
	"github.com/deepnavakoti/acra/internal/telemetry"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	console := flag.String("console", "console/index.html", "path to the console HTML")
	db := flag.String("db", filepath.Join(os.TempDir(), "acra-evidence.db"), "evidence store path")
	incDB := flag.String("incident-db", filepath.Join(os.TempDir(), "acra-incidents.db"), "incident store path")
	keyFile := flag.String("key-file", "", "ed25519 signing key (hex seed); created if missing. Empty = ephemeral key and a fresh store each run (demo mode)")
	demo := flag.Bool("demo", true, "expose POST /v1/demo/inject (disable in production)")
	mcpOn := flag.Bool("mcp", true, "serve the read-only tool gateway over MCP at POST /mcp")
	a2aOn := flag.Bool("a2a", true, "serve incidents and investigation over A2A at POST /a2a, plus the Agent Card under /.well-known/")
	publicURL := flag.String("public-url", os.Getenv("ACRA_PUBLIC_URL"), "externally reachable base URL, used in the A2A Agent Card")
	origins := flag.String("allowed-origins", os.Getenv("ACRA_ALLOWED_ORIGINS"), "comma-separated browser origins allowed to call /mcp and /a2a (none by default)")
	flag.Parse()

	// With an ephemeral key, old evidence could not verify, so the demo starts
	// from a clean store. With a persistent key the stores are kept.
	if *keyFile == "" {
		log.Print("WARNING: no -key-file: using an ephemeral signing key and wiping stores (demo mode)")
		_ = os.Remove(*db)
		_ = os.Remove(*incDB)
	}
	priv, err := evidence.LoadOrCreateKey(*keyFile)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	store, err := evidence.Open(*db, priv)
	if err != nil {
		log.Fatalf("open evidence store: %v", err)
	}
	defer store.Close()
	incidents, err := incident.Open(*incDB)
	if err != nil {
		log.Fatalf("open incident store: %v", err)
	}
	defer incidents.Close()

	auth, err := authFromEnv()
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	if !auth.Enabled() {
		log.Print("WARNING: ACRA_API_TOKEN not set: the API is unauthenticated (local demo only)")
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Best-effort OpenTelemetry export (no-op unless OTEL_EXPORTER_OTLP_ENDPOINT set).
	shutdown := telemetry.Init(sigCtx)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdown(c)
	}()

	svc := pipeline.New(pipeline.Config{AutoInvestigate: os.Getenv("ACRA_AUTO_INVESTIGATE") == "1"}, contract.NewRegistry(), incidents)
	svc.Evidence = store
	svc.Adapters = adaptersFromEnv()
	eng := &rca.Engine{}
	if c := llmFromEnv(); c != nil {
		eng.Narrator = c
		svc.Judge = contract.LLMJudge{C: c}
	}
	svc.Engine = eng
	svc.Start(sigCtx, 15*time.Second)

	gw := gateway.New(gateway.Config{}, &gateway.EvidenceAuditor{Store: store})
	if err := api.RegisterReadTools(gw, svc, func(id string) (any, error) { return store.Trace(id) }); err != nil {
		log.Fatalf("gateway tools: %v", err)
	}

	srv := api.New(store, *console)
	srv.Auth, srv.Pipeline, srv.Gateway, srv.DemoEnabled = auth, svc, gw, *demo
	var allowed []string
	for _, o := range strings.Split(*origins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			allowed = append(allowed, o)
		}
	}
	if *mcpOn {
		srv.MCP = &mcp.Server{Backend: gw, Version: version, AllowedOrigins: allowed}
	}
	if *a2aOn {
		srv.A2A = &a2a.Server{Backend: a2a.PipelineBackend{S: svc}, Version: version, PublicURL: *publicURL, AllowedOrigins: allowed}
	}

	hs := &http.Server{
		Addr: *addr, Handler: srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 90 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10,
	}
	go func() {
		<-sigCtx.Done()
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = hs.Shutdown(c)
	}()
	log.Printf("acra-apiserver: listening on %s · console %s · demo=%v · auth=%v", *addr, *console, *demo, auth.Enabled())
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	svc.Wait()
}
