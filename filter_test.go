package sbom

import (
	"strings"
	"testing"
)

func TestFilterProperties(t *testing.T) {
	s := New(TypeCycloneDX)
	s.AddPackage(Package{
		Name:    "a",
		Version: "1.0",
		Properties: []Property{
			{Name: "tool:scratch", Value: "x"},
			{Name: "cdx:type", Value: "library"},
			{Name: "tool:size", Value: "100"},
		},
	})
	s.AddPackage(Package{
		Name:    "b",
		Version: "2.0",
		Properties: []Property{
			{Name: "tool:scratch", Value: "y"},
		},
	})

	s.FilterProperties(func(name string) bool {
		return !strings.HasPrefix(name, "tool:")
	})

	if got := len(s.Packages[0].Properties); got != 1 {
		t.Errorf("package a: properties = %d, want 1", got)
	}
	if s.Packages[0].Properties[0].Name != "cdx:type" {
		t.Errorf("package a kept the wrong property: %+v", s.Packages[0].Properties)
	}
	if got := len(s.Packages[1].Properties); got != 0 {
		t.Errorf("package b: properties = %d, want 0", got)
	}
}

func TestFilterProperties_NilPredicate(t *testing.T) {
	s := New(TypeCycloneDX)
	s.AddPackage(Package{Name: "a", Version: "1.0", Properties: []Property{{Name: "x"}}})
	s.FilterProperties(nil)
	if len(s.Packages[0].Properties) != 1 {
		t.Error("nil predicate should be a no-op")
	}
}

func TestFilterProperties_EmptyPackages(t *testing.T) {
	s := New(TypeCycloneDX)
	s.FilterProperties(func(string) bool { return true })
	// No-op; just shouldn't panic.
}
