package sbom

import "testing"

func TestClassifyScope(t *testing.T) {
	t.Run("cyclonedx graph", func(t *testing.T) {
		// root -> a, b; a -> c. Root is identified by having no inbound edge.
		s := &SBOM{Relationships: []Relationship{
			{SourceID: "root", TargetID: "a", Type: RelDependsOn},
			{SourceID: "root", TargetID: "b", Type: RelDependsOn},
			{SourceID: "a", TargetID: "c", Type: RelDependsOn},
		}}
		got := s.ClassifyScope()
		want := map[string]string{"a": ScopeDirect, "b": ScopeDirect, "c": ScopeTransitive}
		for id, sc := range want {
			if got[id] != sc {
				t.Errorf("%s = %q, want %q", id, got[id], sc)
			}
		}
		if len(got) != len(want) {
			t.Errorf("got %d entries, want %d: %v", len(got), len(want), got)
		}
	})
	t.Run("spdx with DESCRIBES", func(t *testing.T) {
		// DOCUMENT --DESCRIBES--> root; root --DEPENDS_ON--> a; a --DEPENDS_ON--> b.
		s := &SBOM{Relationships: []Relationship{
			{SourceID: "SPDXRef-DOCUMENT", TargetID: "root", Type: RelDescribes},
			{SourceID: "root", TargetID: "a", Type: RelDependsOn},
			{SourceID: "a", TargetID: "b", Type: RelDependsOn},
		}}
		got := s.ClassifyScope()
		if got["a"] != ScopeDirect || got["b"] != ScopeTransitive {
			t.Errorf("got %v", got)
		}
	})
	t.Run("direct wins over transitive", func(t *testing.T) {
		// root -> a, a -> b, root -> b. b is reachable both ways; direct wins.
		s := &SBOM{Relationships: []Relationship{
			{SourceID: "root", TargetID: "a", Type: RelDependsOn},
			{SourceID: "a", TargetID: "b", Type: RelDependsOn},
			{SourceID: "root", TargetID: "b", Type: RelDependsOn},
		}}
		if got := s.ClassifyScope(); got["b"] != ScopeDirect {
			t.Errorf("b = %q, want direct", got["b"])
		}
	})
	t.Run("transitive first then direct", func(t *testing.T) {
		// Edge order reversed from the case above: the transitive edge to b is
		// seen before the direct one. Direct must still win.
		s := &SBOM{Relationships: []Relationship{
			{SourceID: "a", TargetID: "b", Type: RelDependsOn},
			{SourceID: "root", TargetID: "a", Type: RelDependsOn},
			{SourceID: "root", TargetID: "b", Type: RelDependsOn},
		}}
		if got := s.ClassifyScope(); got["b"] != ScopeDirect {
			t.Errorf("b = %q, want direct", got["b"])
		}
	})
	t.Run("no graph", func(t *testing.T) {
		if got := (&SBOM{}).ClassifyScope(); got != nil {
			t.Errorf("expected nil for empty relationships, got %v", got)
		}
	})
	t.Run("cycle with no root", func(t *testing.T) {
		// a -> b -> a with no DESCRIBES: every node has an inbound edge so
		// no root can be inferred. The graph exists, so the result is an
		// empty map rather than nil.
		s := &SBOM{Relationships: []Relationship{
			{SourceID: "a", TargetID: "b", Type: RelDependsOn},
			{SourceID: "b", TargetID: "a", Type: RelDependsOn},
		}}
		got := s.ClassifyScope()
		if got == nil {
			t.Fatal("expected non-nil map for cycle-only graph")
		}
		if len(got) != 0 {
			t.Errorf("expected empty map, got %v", got)
		}
	})
	t.Run("unrelated relationship types", func(t *testing.T) {
		// CONTAINS/other edges are ignored; with no DEPENDS_ON or DESCRIBES
		// this is still the flat-list case.
		s := &SBOM{Relationships: []Relationship{
			{SourceID: "a", TargetID: "b", Type: "CONTAINS"},
		}}
		if got := s.ClassifyScope(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
	t.Run("only DESCRIBES", func(t *testing.T) {
		// A DESCRIBES edge with no DEPENDS_ON edges: roots exist but no
		// packages are classified; the map is empty (not nil).
		s := &SBOM{Relationships: []Relationship{
			{SourceID: "doc", TargetID: "root", Type: RelDescribes},
		}}
		got := s.ClassifyScope()
		if got == nil {
			t.Fatal("expected non-nil map when roots exist")
		}
		if len(got) != 0 {
			t.Errorf("expected empty map, got %v", got)
		}
	})
}
