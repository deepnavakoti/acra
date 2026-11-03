// Command gate runs the ACRA gate service: POST /v1/gate/evaluate runs the real
// detector set against a proposed write and returns ADMIT or HOLD. The policy is
// loaded from a server-side file; callers cannot supply it.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deepnavakoti/acra/internal/detectors"
	"github.com/deepnavakoti/acra/internal/evidence"
	"github.com/deepnavakoti/acra/internal/gatesvc"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/valkey"
)

func main() {
	addr := flag.String("addr", ":8081", "listen address")
	policyPath := flag.String("policy", "/etc/acra/policy.json", "gate policy JSON file")
	db := flag.String("db", "", "evidence store path (optional; decisions are anchored when set)")
	keyFile := flag.String("key-file", "", "ed25519 signing key (required with -db)")
	valkeyURL := flag.String("valkey-url", os.Getenv("ACRA_VALKEY_URL"), "persist epochs in Valkey (valkey://host:6379 or rediss://host:6379); empty = in-memory")
	flag.Parse()

	pol, err := gatesvc.LoadPolicy(*policyPath)
	if err != nil {
		log.Fatalf("acra-gate: %v", err) // fail closed: no policy, no gate
	}

	tokens := map[string]identity.Principal{}
	if t := os.Getenv("ACRA_API_TOKEN"); t != "" {
		if len(t) < 16 {
			log.Fatal("acra-gate: ACRA_API_TOKEN must be at least 16 characters")
		}
		tokens[t] = identity.Principal{ID: "admin-token", Roles: []string{identity.RoleAdmin}}
	}
	if s := os.Getenv("ACRA_API_TOKENS"); s != "" {
		m, err := identity.ParseTokens(s)
		if err != nil {
			log.Fatalf("acra-gate: %v", err)
		}
		for k, v := range m {
			tokens[k] = v
		}
	}
	auth := identity.New(tokens)
	if !auth.Enabled() {
		log.Print("WARNING: ACRA_API_TOKEN not set: the gate API is unauthenticated")
	}

	var store *evidence.Store
	if *db != "" {
		if *keyFile == "" {
			log.Fatal("acra-gate: -db requires -key-file so decisions stay verifiable across restarts")
		}
		priv, err := evidence.LoadOrCreateKey(*keyFile)
		if err != nil {
			log.Fatalf("acra-gate: key: %v", err)
		}
		if store, err = evidence.Open(*db, priv); err != nil {
			log.Fatalf("acra-gate: evidence store: %v", err)
		}
		defer store.Close()
	}

	dets := detectors.Default()
	ids := make([]string, 0, len(dets))
	for _, d := range dets {
		ids = append(ids, d.ID())
	}
	log.Printf("acra-gate: loaded %d detectors %v, %d approved tuples", len(dets), ids, len(pol.ApprovedTuples))

	svc := gatesvc.New(pol, dets, auth, store)
	if *valkeyURL != "" {
		vc, err := valkey.New(valkey.Options{URL: *valkeyURL, Username: os.Getenv("ACRA_VALKEY_USERNAME"),
			Password: os.Getenv("ACRA_VALKEY_PASSWORD")})
		if err != nil {
			log.Fatalf("acra-gate: %v", err)
		}
		defer vc.Close()
		pc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = vc.Ping(pc)
		cancel()
		if err != nil {
			log.Fatalf("acra-gate: valkey unreachable (refusing to start with a fence it cannot persist): %v", err)
		}
		svc.Epochs = &gatesvc.ValkeyEpochs{C: vc}
		log.Print("acra-gate: epoch fence persisted in Valkey")
	} else {
		log.Print("acra-gate: epoch fence is in-memory (lost on restart; set ACRA_VALKEY_URL to persist)")
	}
	hs := &http.Server{Addr: *addr, Handler: svc.Routes(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(c)
	}()
	log.Printf("acra-gate: listening on %s", *addr)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
