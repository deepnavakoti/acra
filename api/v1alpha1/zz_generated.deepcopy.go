// Deepcopy methods for the AgentPolicy CRD. Hand-written for v0.1; controller-gen
// regenerates these once the operator's codegen is wired in. These satisfy
// runtime.Object so controller-runtime can cache and reconcile the type.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"

	"github.com/deepnavakoti/acra/internal/model"
)

func (in *AgentPolicy) DeepCopyInto(out *AgentPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *AgentPolicy) DeepCopy() *AgentPolicy {
	if in == nil {
		return nil
	}
	out := new(AgentPolicy)
	in.DeepCopyInto(out)
	return out
}

func (in *AgentPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *AgentPolicySpec) DeepCopyInto(out *AgentPolicySpec) {
	*out = *in // copies Agent, Baseline (value), Thresholds (value)
	if in.ApprovedTuples != nil {
		out.ApprovedTuples = make([]model.Tuple, len(in.ApprovedTuples))
		copy(out.ApprovedTuples, in.ApprovedTuples)
	}
	if in.Invariants != nil {
		out.Invariants = make([]string, len(in.Invariants))
		copy(out.Invariants, in.Invariants)
	}
}

func (in *AgentPolicyStatus) DeepCopyInto(out *AgentPolicyStatus) {
	*out = *in
	if in.OpenTickets != nil {
		out.OpenTickets = make([]string, len(in.OpenTickets))
		copy(out.OpenTickets, in.OpenTickets)
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

func (in *AgentPolicyList) DeepCopyInto(out *AgentPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]AgentPolicy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *AgentPolicyList) DeepCopy() *AgentPolicyList {
	if in == nil {
		return nil
	}
	out := new(AgentPolicyList)
	in.DeepCopyInto(out)
	return out
}

func (in *AgentPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
