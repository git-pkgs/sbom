package sbom

import "testing"

func TestCycloneDXLicenseShapes(t *testing.T) {
	in := `{
	  "bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[
	    {"name":"a","licenses":[{"license":{"id":"MIT"}}]},
	    {"name":"b","licenses":[{"license":{"name":"Apache 2.0"}}]},
	    {"name":"c","licenses":[{"expression":"MIT OR Apache-2.0"}]}
	  ]
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]string{"a": "MIT", "b": "Apache 2.0", "c": "MIT OR Apache-2.0"}
	for _, p := range doc.Packages {
		if p.LicenseDeclared != want[p.Name] {
			t.Errorf("%s license = %q, want %q", p.Name, p.LicenseDeclared, want[p.Name])
		}
	}
}

func TestCycloneDXNestedComponents(t *testing.T) {
	in := `{
	  "bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[
	    {"bom-ref":"root","name":"root","components":[
	      {"bom-ref":"child","name":"child","purl":"pkg:npm/child@1.0.0"}
	    ]}
	  ]
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Packages) != 2 {
		t.Fatalf("Packages = %d, want 2 (nested flattened)", len(doc.Packages))
	}
	found := false
	for _, r := range doc.Relationships {
		if r.SourceID == "root" && r.TargetID == "child" && r.Type == "DEPENDS_ON" {
			found = true
		}
	}
	if !found {
		t.Errorf("nested component should produce DEPENDS_ON relationship: %+v", doc.Relationships)
	}
}

func TestCycloneDXDependencies(t *testing.T) {
	in := `{
	  "bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[{"bom-ref":"a","name":"a"},{"bom-ref":"b","name":"b"}],
	  "dependencies":[{"ref":"a","dependsOn":["b"]}]
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Relationships) != 1 {
		t.Fatalf("Relationships = %d, want 1", len(doc.Relationships))
	}
	r := doc.Relationships[0]
	if r.SourceID != "a" || r.TargetID != "b" || r.Type != "DEPENDS_ON" {
		t.Errorf("relationship = %+v", r)
	}
}
