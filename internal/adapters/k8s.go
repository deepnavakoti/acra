package adapters

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PodStatus is the subset of pod state ACRA reasons about.
type PodStatus struct {
	Name       string
	Phase      string
	Restarts   int32
	Reason     string // e.g. CrashLoopBackOff, OOMKilled, ImagePullBackOff
	ExitCode   int32
	Ready      bool
	Node       string
	UID        string
	StartedAt  time.Time
	Containers []string
}

// KubeEvent is one Kubernetes Event.
type KubeEvent struct {
	Time    time.Time
	Type    string // Normal | Warning
	Reason  string
	Object  string
	Message string
	Count   int32
}

// KubeReader is the read-only seam to the cluster. The production
// implementation (client-go) is a thin wrapper; tests use a fake, so the
// adapter logic is verified without a cluster. It exposes NO write methods by
// design.
type KubeReader interface {
	ListPods(ctx context.Context, namespace, labelSelector string) ([]PodStatus, error)
	ListEvents(ctx context.Context, namespace string, since time.Time) ([]KubeEvent, error)
	PodLogs(ctx context.Context, namespace, pod string, tailLines int64, since time.Time) (string, error)
}

// Kubernetes turns cluster state into Signals. Only the namespace in the query
// is read, and the namespace must be on the allowlist.
type Kubernetes struct {
	Reader     KubeReader
	Namespaces []string // allowlist; empty denies everything
}

// Name implements Adapter.
func (k *Kubernetes) Name() string { return "k8s" }

// Fetch implements Adapter. The query's Service is used as the app label.
func (k *Kubernetes) Fetch(ctx context.Context, q Query) (Result, error) {
	q, err := q.Validate()
	if err != nil {
		return Result{}, err
	}
	if q.Namespace == "" {
		return Result{}, errors.New("k8s: namespace is required")
	}
	allowed := false
	for _, n := range k.Namespaces {
		if n == q.Namespace {
			allowed = true
		}
	}
	if !allowed {
		return Result{}, fmt.Errorf("k8s: namespace %q is not allowed", q.Namespace)
	}
	sel := ""
	if q.Service != "" {
		sel = "app=" + q.Service
	}
	res := Result{Source: "k8s", Signals: []Signal{}}

	pods, err := k.Reader.ListPods(ctx, q.Namespace, sel)
	if err != nil {
		return Result{}, fmt.Errorf("k8s: listing pods: %w", err)
	}
	var crashing []PodStatus
	for _, p := range pods {
		sev := "info"
		switch {
		case p.Reason == "OOMKilled" || p.ExitCode == 137:
			sev = "critical"
		case p.Reason == "CrashLoopBackOff" || p.Reason == "ImagePullBackOff" || p.Reason == "ErrImagePull":
			sev = "error"
		case p.Restarts > 0 || !p.Ready:
			sev = "warning"
		}
		if sev != "info" {
			crashing = append(crashing, p)
		}
		res.Signals = append(res.Signals, Signal{
			Source: "k8s", Kind: "state", Time: p.StartedAt, Severity: sev, Resource: p.Name,
			Message: fmt.Sprintf("pod %s phase=%s ready=%t restarts=%d reason=%s exit=%d",
				p.Name, p.Phase, p.Ready, p.Restarts, p.Reason, p.ExitCode),
			Attrs: map[string]string{"podUid": p.UID, "node": p.Node, "reason": p.Reason},
			Ref:   p.UID,
		})
	}

	evs, err := k.Reader.ListEvents(ctx, q.Namespace, q.Start)
	if err != nil {
		res.Partial = true
		res.Warnings = append(res.Warnings, "events unavailable: "+clip(err.Error(), 200))
	}
	for _, e := range evs {
		if e.Time.After(q.End) || e.Time.Before(q.Start) {
			continue
		}
		sev := "info"
		if e.Type == "Warning" {
			sev = "warning"
		}
		if e.Reason == "OOMKilling" || e.Reason == "Evicted" || e.Reason == "FailedScheduling" {
			sev = "error"
		}
		res.Signals = append(res.Signals, Signal{
			Source: "k8s", Kind: "event", Time: e.Time, Severity: sev, Resource: e.Object,
			Message: clip(e.Reason+": "+e.Message, 500), Attrs: map[string]string{"reason": e.Reason},
		})
	}

	// Logs only for pods that look unhealthy, to keep volume bounded.
	for i, p := range crashing {
		if i >= 3 {
			res.Partial = true
			res.Warnings = append(res.Warnings, "logs fetched for the first 3 unhealthy pods only")
			break
		}
		logs, err := k.Reader.PodLogs(ctx, q.Namespace, p.Name, 50, q.Start)
		if err != nil {
			res.Partial = true
			res.Warnings = append(res.Warnings, "logs unavailable for "+p.Name)
			continue
		}
		for _, line := range lastLines(logs, 50) {
			res.Signals = append(res.Signals, Signal{
				Source: "k8s", Kind: "log", Time: q.End, Severity: guessSeverity(line),
				Resource: p.Name, Message: clip(line, 500),
			})
		}
	}
	if len(res.Signals) > q.Limit {
		res.Signals = res.Signals[:q.Limit]
		res.Partial = true
		res.Warnings = append(res.Warnings, "signal limit reached")
	}
	return res, nil
}

func lastLines(s string, n int) []string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	var out []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
