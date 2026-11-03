// Package controller is ACRA's operator: it reconciles AgentPolicy objects,
// reading live drift from the apiserver and reflecting it into the policy's
// status so the cluster itself reports which agents are drifting
// (docs/06-build-plan.md, M3).
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	acrav1 "github.com/deepnavakoti/acra/api/v1alpha1"
	"github.com/deepnavakoti/acra/internal/model"
)

// maxTicketsBody bounds how much of the apiserver response the operator reads.
const maxTicketsBody = 8 << 20

// AgentPolicyReconciler reconciles an AgentPolicy against live drift.
type AgentPolicyReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIServer string // base URL of the apiserver, e.g. http://acra-apiserver.acra-system.svc
	Token     string // optional bearer token for the apiserver (ACRA_API_TOKEN)
	HTTP      *http.Client
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
		// Drift state is UNKNOWN, not clean: never report a false green
		// (invariant 7). Record Unknown and retry shortly.
		log.Info("apiserver unreachable; marking Unknown", "err", err.Error())
		ap.Status.Phase = "Unknown"
		ap.Status.Conditions = setCondition(ap.Status.Conditions, metav1.Condition{
			Type: "Synced", Status: metav1.ConditionFalse, Reason: "ApiserverUnavailable",
			Message: err.Error(), ObservedGeneration: ap.Generation,
		})
		if uerr := r.Status().Update(ctx, &ap); uerr != nil {
			return ctrl.Result{}, uerr
		}
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
	ap.Status.Conditions = setCondition(ap.Status.Conditions, metav1.Condition{
		Type: "Synced", Status: metav1.ConditionTrue, Reason: "Reconciled",
		Message: "drift state read from apiserver", ObservedGeneration: ap.Generation,
	})
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
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}
	hc := r.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apiserver returned HTTP %d", resp.StatusCode)
	}
	var env struct {
		Data []model.Ticket `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTicketsBody)).Decode(&env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// setCondition upserts a condition by type, bumping LastTransitionTime only
// when the status actually changes.
func setCondition(conds []metav1.Condition, c metav1.Condition) []metav1.Condition {
	c.LastTransitionTime = metav1.Now()
	for i := range conds {
		if conds[i].Type == c.Type {
			if conds[i].Status == c.Status {
				c.LastTransitionTime = conds[i].LastTransitionTime
			}
			conds[i] = c
			return conds
		}
	}
	return append(conds, c)
}

// SetupWithManager wires the reconciler to watch AgentPolicy.
func (r *AgentPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&acrav1.AgentPolicy{}).
		Complete(r)
}
