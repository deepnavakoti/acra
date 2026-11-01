// Command apiserver serves the ACRA /v1 API, embeds the evidence store, and
// serves the console. Run it locally (no cluster) for the demo:
//
//	go run ./cmd/apiserver        # then open http://localhost:8080
//	go run ./cmd/workload inject-drift combinative
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/deepnavakoti/acra/internal/api"
	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/telemetry"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	console := flag.String("console", "console/index.html", "path to the console HTML")
	db := flag.String("db", filepath.Join(os.TempDir(), "acra-evidence.db"), "evidence store path")
	flag.Parse()

	// Fresh store each run so the demo starts green.
	_ = os.Remove(*db)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	store, err := evidence.Open(*db, priv)
	if err != nil {
		log.Fatalf("open evidence store: %v", err)
	}
	defer store.Close()

	// Best-effort OpenTelemetry export (no-op unless OTEL_EXPORTER_OTLP_ENDPOINT set).
	ctx := context.Background()
	shutdown := telemetry.Init(ctx)
	defer shutdown(ctx)

	srv := api.New(store, *console)
	log.Printf("acra-apiserver: listening on %s · console %s", *addr, *console)
	log.Fatal(http.ListenAndServe(*addr, srv.Routes()))
}
