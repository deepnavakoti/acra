package evidence

// Lineage independence (docs/03-core-specs.md §2).
//
// Independence = the number of DISTINCT ROOTS supporting a claim — never the
// number of citations. A derived artifact (a summary, a memory-index hit, an
// agent's own prior output) is NEVER a root, however many times it is cited.
// Roots are deduplicated by provider/source identity: two calls to the same
// provider (even via different paths or caches) count as ONE root.

// NodeKind classifies a lineage node.
type NodeKind int

const (
	// Derived: a summary, a memory-index entry, an agent's own output. Never a root.
	Derived NodeKind = iota
	// Root: an origin document or an external provider receipt.
	Root
)

// Node is one entry in the lineage graph.
type Node struct {
	ID   string
	Kind NodeKind
	// Provider identifies the source for root-dedup (e.g. a provider id or doc id).
	// Empty means "dedup by ID".
	Provider string
}

// Graph is a lineage DAG: edges point child -> parent (toward roots).
type Graph struct {
	nodes   map[string]Node
	parents map[string][]string // child -> its direct parents (sources)
}

// NewGraph builds an empty lineage graph.
func NewGraph() *Graph {
	return &Graph{nodes: map[string]Node{}, parents: map[string][]string{}}
}

// AddNode registers a node (idempotent).
func (g *Graph) AddNode(n Node) { g.nodes[n.ID] = n }

// AddEdge records that `child` derives from `parent` (parent is a source of child).
func (g *Graph) AddEdge(child, parent string) {
	g.parents[child] = append(g.parents[child], parent)
}

// Independence returns the count of distinct roots reachable from claim,
// deduplicated by provider identity.
func (g *Graph) Independence(claim string) int {
	roots := map[string]struct{}{}
	seen := map[string]bool{}
	g.walk(claim, seen, roots)
	return len(roots)
}

func (g *Graph) walk(id string, seen map[string]bool, roots map[string]struct{}) {
	if seen[id] {
		return
	}
	seen[id] = true
	if n, ok := g.nodes[id]; ok && n.Kind == Root {
		roots[rootKey(n)] = struct{}{}
		// a root has no further sources that count; stop here
		return
	}
	for _, p := range g.parents[id] {
		g.walk(p, seen, roots)
	}
}

func rootKey(n Node) string {
	if n.Provider != "" {
		return "p:" + n.Provider
	}
	return "id:" + n.ID
}

// Independent reports whether claim meets the required independence floor.
func (g *Graph) Independent(claim string, required int) bool {
	return g.Independence(claim) >= required
}
