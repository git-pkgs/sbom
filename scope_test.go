package sbom

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

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

func TestClassifyScopeDeclaredRoot(t *testing.T) {
	t.Run("cyclonedx component with edges is the only root", func(t *testing.T) {
		// The project links requests; the stray lock entry orphan -> x is
		// not a root once the project is declared.
		s := &SBOM{
			Document: Document{Component: Component{ID: "project"}},
			Relationships: []Relationship{
				{SourceID: "project", TargetID: "requests", Type: RelDependsOn},
				{SourceID: "requests", TargetID: "urllib3", Type: RelDependsOn},
				{SourceID: "orphan", TargetID: "x", Type: RelDependsOn},
			},
		}
		got := s.ClassifyScope()
		want := map[string]string{"requests": ScopeDirect, "urllib3": ScopeTransitive, "x": ScopeTransitive}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for id, sc := range want {
			if got[id] != sc {
				t.Errorf("%s = %q, want %q", id, got[id], sc)
			}
		}
		if ids, declared := s.Roots(); !declared || len(ids) != 1 || ids[0] != "project" {
			t.Errorf("Roots() = %v, %v; want [project], true", ids, declared)
		}
	})
	t.Run("spdx DESCRIBES target with edges is the only root", func(t *testing.T) {
		s := &SBOM{Relationships: []Relationship{
			{SourceID: "SPDXRef-DOCUMENT", TargetID: "root", Type: RelDescribes},
			{SourceID: "root", TargetID: "a", Type: RelDependsOn},
			{SourceID: "other", TargetID: "b", Type: RelDependsOn},
		}}
		got := s.ClassifyScope()
		if got["a"] != ScopeDirect || got["b"] != ScopeTransitive {
			t.Errorf("got %v", got)
		}
		if _, declared := s.Roots(); !declared {
			t.Error("Roots() declared = false, want true")
		}
	})
	t.Run("declared root without edges falls back to inference", func(t *testing.T) {
		// syft's CycloneDX for a poetry.lock: metadata.component is the
		// scanned directory with no edges, so requests is inferred as a root.
		s := &SBOM{
			Document: Document{Component: Component{ID: "dir"}},
			Relationships: []Relationship{
				{SourceID: "requests", TargetID: "urllib3", Type: RelDependsOn},
			},
		}
		got := s.ClassifyScope()
		if len(got) != 1 || got["urllib3"] != ScopeDirect {
			t.Errorf("got %v, want urllib3 direct", got)
		}
		ids, declared := s.Roots()
		if declared {
			t.Error("Roots() declared = true, want false")
		}
		if len(ids) != 2 || ids[0] != "dir" || ids[1] != "requests" {
			t.Errorf("Roots() = %v, want [dir requests]", ids)
		}
	})
	t.Run("no graph", func(t *testing.T) {
		s := &SBOM{Document: Document{Component: Component{ID: "project"}}}
		if got := s.ClassifyScope(); got != nil {
			t.Errorf("got %v, want nil", got)
		}
		if ids, declared := s.Roots(); ids != nil || declared {
			t.Errorf("Roots() = %v, %v; want nil, false", ids, declared)
		}
	})
}

func TestClassifyScopeCycloneDXMetadataComponent(t *testing.T) {
	data := []byte(`{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "app"}},
  "components": [
    {"bom-ref": "requests", "type": "library", "name": "requests", "version": "2.31.0"},
    {"bom-ref": "urllib3", "type": "library", "name": "urllib3", "version": "2.1.0"},
    {"bom-ref": "pytest", "type": "library", "name": "pytest", "version": "8.0.0"},
    {"bom-ref": "pluggy", "type": "library", "name": "pluggy", "version": "1.4.0"}
  ],
  "dependencies": [
    {"ref": "app", "dependsOn": ["requests"]},
    {"ref": "requests", "dependsOn": ["urllib3"]},
    {"ref": "pytest", "dependsOn": ["pluggy"]}
  ]
}`)
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Document.Component.ID != "app" {
		t.Fatalf("Component.ID = %q, want app", doc.Document.Component.ID)
	}
	got := doc.ClassifyScope()
	want := map[string]string{"requests": ScopeDirect, "urllib3": ScopeTransitive, "pluggy": ScopeTransitive}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for id, sc := range want {
		if got[id] != sc {
			t.Errorf("%s = %q, want %q", id, got[id], sc)
		}
	}

	var buf bytes.Buffer
	if err := Encode(&buf, doc, FormatCycloneDXJSON); err != nil {
		t.Fatal(err)
	}
	again, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if again.Document.Component.ID != "app" {
		t.Errorf("encoded Component.ID = %q, want app", again.Document.Component.ID)
	}
}

// syft's CycloneDX output for one small project per lock format, generated
// with syft 1.55.0. Lock files that list the project (package-lock.json,
// Cargo.lock, uv.lock, yarn berry) give it a node of its own; the others
// list only dependencies.
func TestClassifyScopeSyftLockFiles(t *testing.T) {
	tests := []struct {
		file  string
		want  map[string]string
		roots []string
	}{
		{"npm", map[string]string{"express": ScopeDirect, "accepts": ScopeTransitive}, []string{"", "app"}},
		{"cargo", map[string]string{"serde": ScopeDirect, "serde_derive": ScopeTransitive}, []string{"", "app"}},
		{"uv", map[string]string{"requests": ScopeDirect, "urllib3": ScopeTransitive}, []string{"", "app"}},
		{"berry", map[string]string{"express": ScopeDirect, "accepts": ScopeTransitive}, []string{"", "app"}},
		{"poetry", map[string]string{"requests": ScopeDirect, "urllib3": ScopeTransitive}, []string{""}},
		{"pdm", map[string]string{"requests": ScopeDirect, "urllib3": ScopeTransitive}, []string{""}},
		{"pnpm9", map[string]string{"express": ScopeDirect, "accepts": ScopeTransitive}, []string{""}},
		{"yarn", map[string]string{"express": ScopeDirect, "accepts": ScopeTransitive}, []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "cyclonedx", "syft-lock", tt.file+".cdx.json"))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			names := map[string]string{}
			for _, p := range doc.Packages {
				names[p.ID] = p.Name
			}
			got := map[string]string{}
			for id, sc := range doc.ClassifyScope() {
				got[names[id]] = sc
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("scope = %v, want %v", got, tt.want)
			}
			// The scanned directory, which syft names in metadata.component
			// without edges, is a root too; it has no package entry.
			ids, declared := doc.Roots()
			var roots []string
			for _, id := range ids {
				roots = append(roots, names[id])
			}
			slices.Sort(roots)
			if declared || !slices.Equal(roots, tt.roots) {
				t.Errorf("Roots() = %v, %v; want %v, false", roots, declared, tt.roots)
			}
		})
	}
}
