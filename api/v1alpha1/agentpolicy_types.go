// Package v1alpha1 defines the AgentPolicy CRD — the contract between the
// controller and the cluster (see docs/04-api-and-schemas.md §2).
// NOTE: requires k8s deps (run `go mod tidy` / `make generate`) to compile and
// to produce deepcopy + CRD manifests. API group is a placeholder: acra.dev.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/deepnavakoti/acra/internal/model"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="OpenTickets",type=string,JSONPath=`.status.openTickets`

// AgentPolicy governs one agent: the only tuples that may produce effects, the
// signed baseline it must stay inside, the invariants the gate enforces, and
// the drift/independence thresholds.
type AgentPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentPolicySpec   `json:"spec,omitempty"`
	Status AgentPolicyStatus `json:"status,omitempty"`
}

type AgentPolicySpec struct {
	// Agent this policy governs, e.g. "decision-agent".
	Agent string `json:"agent"`
	// ApprovedTuples: the only (prompt,manifest,ruleset,formula) combinations
	// allowed to produce effects. Anything outside = combinative drift.
	ApprovedTuples []model.Tuple `json:"approvedTuples"`
	// Baseline references a signed baseline object (changed only by 2-approver PR).
	Baseline BaselineRef `json:"baseline"`
	// Invariants the gate enforces on every consequential write.
	Invariants []string `json:"invariants"`
	// Thresholds for opening tickets / evidence independence.
	Thresholds Thresholds `json:"thresholds"`
}

type BaselineRef struct {
	Ref string `json:"ref"` // e.g. "a-0210"
}

type Thresholds struct {
	// DriftMagnitude: open a ticket above this.
	DriftMagnitude int `json:"driftMagnitude"`
	// MinIndependentRoots: evidence independence floor (default 2).
	MinIndependentRoots int `json:"minIndependentRoots"`
}

type AgentPolicyStatus struct {
	// Phase: Watching|Drifting|HeldForApproval|Remediating|Verifying.
	Phase        string             `json:"phase,omitempty"`
	OpenTickets  []string           `json:"openTickets,omitempty"`
	LastCleanRun string             `json:"lastCleanRun,omitempty"`
	Conditions   []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

type AgentPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentPolicy `json:"items"`
}
