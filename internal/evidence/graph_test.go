package evidence

import "testing"

// The recursive-evidence-collapse case from docs/03 §2:
// doc-4411 (root) -> e-7 -> s-12 (memory summary, derived) -> a-3 -> c-9f2.
// The claim cites the chain three times, but every path roots at doc-4411.
// Independence must be 1, not 3.
func TestIndependence_RecursiveCollapse(t *testing.T) {
	g := NewGraph()
	g.AddNode(Node{ID: "doc-4411", Kind: Root, Provider: "doc-4411"})
	g.AddNode(Node{ID: "e-7", Kind: Derived})
	g.AddNode(Node{ID: "s-12", Kind: Derived}) // memory summary — never a root
	g.AddNode(Node{ID: "a-3", Kind: Derived})
	g.AddNode(Node{ID: "c-9f2", Kind: Derived})

	g.AddEdge("c-9f2", "a-3")
	g.AddEdge("a-3", "s-12")
	g.AddEdge("s-12", "e-7")
	g.AddEdge("e-7", "doc-4411")
	// two extra citations of the same chain (the "cited 3 times")
	g.AddEdge("c-9f2", "s-12")
	g.AddEdge("c-9f2", "e-7")

	if got := g.Independence("c-9f2"); got != 1 {
		t.Fatalf("independence = %d, want 1 (one root cited three times)", got)
	}
	if g.Independent("c-9f2", 2) {
		t.Fatal("claim must NOT be independent at required=2")
	}
}

// Two genuinely distinct roots -> independence 2.
func TestIndependence_TwoRoots(t *testing.T) {
	g := NewGraph()
	g.AddNode(Node{ID: "doc-A", Kind: Root, Provider: "doc-A"})
	g.AddNode(Node{ID: "receipt-B", Kind: Root, Provider: "provider-B"})
	g.AddNode(Node{ID: "claim", Kind: Derived})
	g.AddEdge("claim", "doc-A")
	g.AddEdge("claim", "receipt-B")

	if got := g.Independence("claim"); got != 2 {
		t.Fatalf("independence = %d, want 2", got)
	}
	if !g.Independent("claim", 2) {
		t.Fatal("claim should be independent at required=2")
	}
}

// Same provider reached by two different paths/caches -> one root (m4 dedup).
func TestIndependence_SameProviderDedup(t *testing.T) {
	g := NewGraph()
	g.AddNode(Node{ID: "live", Kind: Root, Provider: "provider-X"})
	g.AddNode(Node{ID: "cached", Kind: Root, Provider: "provider-X"}) // same provider
	g.AddNode(Node{ID: "claim", Kind: Derived})
	g.AddEdge("claim", "live")
	g.AddEdge("claim", "cached")

	if got := g.Independence("claim"); got != 1 {
		t.Fatalf("independence = %d, want 1 (same provider, two paths)", got)
	}
}
