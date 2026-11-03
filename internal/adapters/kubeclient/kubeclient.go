// Package kubeclient is the client-go implementation of adapters.KubeReader.
// It performs only list/get calls; the ClusterRole it needs is read-only.
package kubeclient

import (
	"context"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/deepnavakoti/acra/internal/adapters"
)

// Reader reads cluster state with a client-go clientset.
type Reader struct {
	cs kubernetes.Interface
}

// New wraps an existing clientset (also used by tests with the fake clientset).
func New(cs kubernetes.Interface) *Reader { return &Reader{cs: cs} }

// FromConfig builds a Reader from in-cluster config, or a kubeconfig path when
// one is given.
func FromConfig(kubeconfig string) (*Reader, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("kubeclient: %w", err)
	}
	cfg.Timeout = 15 * time.Second
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return New(cs), nil
}

var _ adapters.KubeReader = (*Reader)(nil)

// ListPods implements adapters.KubeReader.
func (r *Reader) ListPods(ctx context.Context, ns, selector string) ([]adapters.PodStatus, error) {
	list, err := r.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 200})
	if err != nil {
		return nil, err
	}
	out := make([]adapters.PodStatus, 0, len(list.Items))
	for _, p := range list.Items {
		ps := adapters.PodStatus{
			Name: p.Name, Phase: string(p.Status.Phase), Node: p.Spec.NodeName, UID: string(p.UID),
		}
		if p.Status.StartTime != nil {
			ps.StartedAt = p.Status.StartTime.Time
		}
		ready := true
		for _, c := range p.Status.ContainerStatuses {
			ps.Containers = append(ps.Containers, c.Name)
			ps.Restarts += c.RestartCount
			if !c.Ready {
				ready = false
			}
			if w := c.State.Waiting; w != nil && w.Reason != "" {
				ps.Reason = w.Reason
			}
			if t := c.LastTerminationState.Terminated; t != nil {
				if ps.Reason == "" {
					ps.Reason = t.Reason
				}
				ps.ExitCode = t.ExitCode
			}
			if t := c.State.Terminated; t != nil {
				ps.Reason, ps.ExitCode = t.Reason, t.ExitCode
			}
		}
		ps.Ready = ready && p.Status.Phase == corev1.PodRunning
		out = append(out, ps)
	}
	return out, nil
}

// ListEvents implements adapters.KubeReader.
func (r *Reader) ListEvents(ctx context.Context, ns string, since time.Time) ([]adapters.KubeEvent, error) {
	list, err := r.cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return nil, err
	}
	var out []adapters.KubeEvent
	for _, e := range list.Items {
		t := e.LastTimestamp.Time
		if t.IsZero() {
			t = e.EventTime.Time
		}
		if t.IsZero() {
			t = e.CreationTimestamp.Time
		}
		if t.Before(since) {
			continue
		}
		out = append(out, adapters.KubeEvent{
			Time: t, Type: e.Type, Reason: e.Reason, Count: e.Count,
			Object: e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name, Message: e.Message,
		})
	}
	return out, nil
}

// PodLogs implements adapters.KubeReader.
func (r *Reader) PodLogs(ctx context.Context, ns, pod string, tail int64, since time.Time) (string, error) {
	opts := &corev1.PodLogOptions{TailLines: &tail}
	if !since.IsZero() {
		t := metav1.NewTime(since)
		opts.SinceTime = &t
	}
	rc, err := r.cs.CoreV1().Pods(ns).GetLogs(pod, opts).Stream(ctx)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 1<<20))
	return string(b), err
}
