// Package v1alpha1 — group/version registration for the AgentPolicy CRD.
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the API group+version for ACRA's CRDs.
	GroupVersion = schema.GroupVersion{Group: "acra.dev", Version: "v1alpha1"}
	// SchemeBuilder registers the types with a runtime scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	// AddToScheme adds the types in this group to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&AgentPolicy{}, &AgentPolicyList{})
}
