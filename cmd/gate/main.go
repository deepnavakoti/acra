// Command gate runs the ACRA gate service. It loads the detector set and serves
// health. The Kyverno/AdmissionReview adapter that feeds real cluster writes
// into gate.Evaluate is wired in M6 (see docs/06-build-plan.md); the detector
// logic itself is complete and unit-tested in internal/gate + internal/detectors.
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/deepnavakoti/acra/internal/detectors"
)

func main() {
	dets := detectors.Default()
	ids := make([]string, 0, len(dets))
	for _, d := range dets {
		ids = append(ids, d.ID())
	}
	log.Printf("acra-gate: loaded %d detectors %v", len(dets), ids)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	addr := ":8081"
	log.Printf("acra-gate: listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
