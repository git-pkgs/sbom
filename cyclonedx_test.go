package sbom

import (
	"reflect"
	"testing"
)

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

func TestCycloneDXPackageMetadata(t *testing.T) {
	in := `{
	  "bomFormat":"CycloneDX","specVersion":"1.6",
	  "components":[{
	    "bom-ref":"pkg","type":"device_driver","name":"driver","version":"1.0.0",
	    "author":"Jane Doe","supplier":{"name":"Acme"},
	    "hashes":[{"alg":"SHA-256","content":"abc"},{"alg":"BLAKE2b-256","content":"def"}],
	    "purl":"pkg:generic/driver@1.0.0",
	    "externalReferences":[{"type":"website","url":"https://example.com"}],
	    "properties":[{"name":"scope","value":"runtime"}]
	  }]
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	p := doc.Packages[0]
	if p.Type != "DEVICE-DRIVER" {
		t.Errorf("Type = %q", p.Type)
	}
	if p.SupplierType != SupplierOrganization || p.Supplier != "Acme" {
		t.Errorf("supplier = %q/%q", p.SupplierType, p.Supplier)
	}
	if p.OriginatorType != SupplierPerson || p.Originator != "Jane Doe" {
		t.Errorf("originator = %q/%q", p.OriginatorType, p.Originator)
	}
	wantChecksums := []Checksum{{Algorithm: "SHA256", Value: "abc"}, {Algorithm: "BLAKE2b256", Value: "def"}}
	if !reflect.DeepEqual(p.Checksums, wantChecksums) {
		t.Errorf("Checksums = %#v, want %#v", p.Checksums, wantChecksums)
	}
	wantReferences := []ExternalRef{
		{Category: "PACKAGE_MANAGER", Type: "purl", Locator: "pkg:generic/driver@1.0.0"},
		{Category: "website", Type: "website", Locator: "https://example.com"},
	}
	if !reflect.DeepEqual(p.ExternalRefs, wantReferences) {
		t.Errorf("ExternalRefs = %#v, want %#v", p.ExternalRefs, wantReferences)
	}
	if !reflect.DeepEqual(p.Properties, []Property{{Name: "scope", Value: "runtime"}}) {
		t.Errorf("Properties = %#v", p.Properties)
	}
}
