// Command workload drives the synthetic workload. In v1 its main job is
// inject-drift, a thin client that asks the apiserver to inject one drift:
//
//	go run ./cmd/workload inject-drift combinative   # or independence|epoch|authority
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/deepnavakoti/acra/internal/workload"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "inject-drift" {
		fmt.Printf("usage: workload inject-drift <%v>\n", workload.Kinds)
		os.Exit(2)
	}
	kind := "combinative"
	if len(os.Args) > 2 {
		kind = os.Args[2]
	}
	base := os.Getenv("ACRA_API")
	if base == "" {
		base = "http://localhost:8080"
	}

	resp, err := http.Post(base+"/v1/demo/inject?kind="+url.QueryEscape(kind), "application/json", nil)
	if err != nil {
		fmt.Printf("inject-drift: %v (is the apiserver running?)\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("inject-drift failed (%d): %s\n", resp.StatusCode, body)
		os.Exit(1)
	}
	fmt.Printf("injected %q drift — the gate HELD it. Open the console → Tickets.\n%s\n", kind, body)
}
