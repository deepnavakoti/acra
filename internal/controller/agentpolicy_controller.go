// Package controller is ACRA's operator: it reconciles AgentPolicy objects,
// reading live drift from the apiserver and reflecting it into the policy's
// status so the cluster itself reports which agents are drifting
// (docs/06-build-plan.md, M3).
package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	acrav1 "github.com/deepnavakoti/acra/api/v1alpha1"
	"github.com/deepnavakoti/acra/internal/model"
)

// AgentPolicyReconciler reconciles an AgentPolicy against live drift.
type AgentPolicyReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIServer string // base URL of the apiserver, e.g. http://acra-apiserver.acra-system.svc
}

// +kubebuilder:rbac:groups=acra.dev,resources=agentpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=acra.dev,resources=agentpolicies/status,verbs=get;update;patch

// Reconcile reads the apiserver's tickets, computes this agent's open drifts,
// and patches the AgentPolicy status. It requeues so it keeps the status fresh
// as drifts are injected and cleared.
func (r *AgentPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	var ap acrav1.AgentPolicy
	if err := r.Get(ctx, req.NamespacedName, &ap); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	tickets, err := r.fetchTickets(ctx)
	if err != nil {
		// apiserver not reachable yet — try again shortly, don't error-loop.
		log.Info("apiserver unreachable; requeueing", "err", err.Error())
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	open := []string{}
	for _, t := range tickets {
		if t.Agent == ap.Spec.Agent && t.State != "closed" {
			open = append(open, t.ID)
		}
	}

	phase := "Watching"
	if len(open) > 0 {
		phase = "Drifting"
	}

	ap.Status.Phase = phase
	ap.Status.OpenTickets = open
	if len(open) == 0 {
		ap.Status.LastCleanRun = time.Now().UTC().Format(time.RFC3339)
	}
	if err := r.Status().Update(ctx, &ap); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("reconciled", "agent", ap.Spec.Agent, "phase", phase, "open", len(open))

	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *AgentPolicyReconciler) fetchTickets(ctx context.Context) ([]model.Ticket, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.APIServer+"/v1/tickets", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var env struct {
		Data []model.Ticket `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// SetupWithManager wires the reconciler to watch AgentPolicy.
func (r *AgentPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&acrav1.AgentPolicy{}).
		Complete(r)
}
