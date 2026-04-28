package sbom

import (
	"os"
	"testing"
)

func readFixture(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Type
	}{
		{"cyclonedx", `{"bomFormat":"CycloneDX","specVersion":"1.6"}`, TypeCycloneDX},
		{"spdx version", `{"spdxVersion":"SPDX-2.3"}`, TypeSPDX},
		{"spdx id only", `{"SPDXID":"SPDXRef-DOCUMENT"}`, TypeSPDX},
		{"github envelope", `{"sbom":{"spdxVersion":"SPDX-2.3"}}`, TypeSPDX},
		{"intoto envelope", `{"predicateType":"https://spdx.dev/Document","predicate":{}}`, TypeSPDX},
		{"unknown json", `{"foo":1}`, TypeUnknown},
		{"not json", `<bom/>`, TypeUnknown},
		{"empty", ``, TypeUnknown},
		{"whitespace", "  \n\t", TypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Detect([]byte(tt.in)); got != tt.want {
				t.Errorf("Detect(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseCycloneDXMinimal(t *testing.T) {
	doc, err := Parse(readFixture(t, "cyclonedx/minimal.cdx.json"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Type != TypeCycloneDX {
		t.Errorf("Type = %q, want cyclonedx", doc.Type)
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("SpecVersion = %q, want 1.6", doc.SpecVersion)
	}
	if doc.Document.Name != "Test Application" {
		t.Errorf("Document.Name = %q", doc.Document.Name)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(doc.Packages))
	}
	p := doc.Packages[0]
	if p.Name != "rails" || p.Version != "7.0.0" {
		t.Errorf("package = %s@%s, want rails@7.0.0", p.Name, p.Version)
	}
	if p.PURL() != "pkg:gem/rails@7.0.0" {
		t.Errorf("PURL = %q", p.PURL())
	}
	if p.LicenseDeclared != "MIT" {
		t.Errorf("LicenseDeclared = %q, want MIT", p.LicenseDeclared)
	}
}

func TestParseSPDXMinimal(t *testing.T) {
	doc, err := Parse(readFixture(t, "spdx/minimal.spdx.json"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Type != TypeSPDX {
		t.Errorf("Type = %q, want spdx", doc.Type)
	}
	if doc.SpecVersion != "SPDX-2.3" {
		t.Errorf("SpecVersion = %q", doc.SpecVersion)
	}
	if doc.Document.Name != "Test SBOM" {
		t.Errorf("Document.Name = %q", doc.Document.Name)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(doc.Packages))
	}
	p := doc.Packages[0]
	if p.Name != "rails" || p.Version != "7.0.0" {
		t.Errorf("package = %s@%s, want rails@7.0.0", p.Name, p.Version)
	}
	if p.LicenseConcluded != "MIT" {
		t.Errorf("LicenseConcluded = %q, want MIT", p.LicenseConcluded)
	}
	if len(doc.Relationships) != 1 || doc.Relationships[0].Type != "DESCRIBES" {
		t.Errorf("Relationships = %+v", doc.Relationships)
	}
	if doc.Relationships[0].Target != p.Name {
		t.Errorf("relationship target name not resolved: %+v", doc.Relationships[0])
	}
}

func TestParseUnrecognized(t *testing.T) {
	if _, err := Parse([]byte(`{"foo":1}`)); err != ErrUnrecognized {
		t.Errorf("err = %v, want ErrUnrecognized", err)
	}
	if _, err := Parse([]byte(`not json`)); err != ErrUnrecognized {
		t.Errorf("err = %v, want ErrUnrecognized", err)
	}
}

func TestParseSPDXEnvelope(t *testing.T) {
	wrapped := `{"sbom":` + string(readFixture(t, "spdx/minimal.spdx.json")) + `}`
	doc, err := Parse([]byte(wrapped))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Type != TypeSPDX || len(doc.Packages) != 1 {
		t.Errorf("envelope unwrap failed: type=%q pkgs=%d", doc.Type, len(doc.Packages))
	}
}

func TestPackageDedup(t *testing.T) {
	s := newSBOM(TypeCycloneDX)
	s.addPackage(Package{Name: "a", Version: "1"})
	s.addPackage(Package{Name: "a", Version: "1", Description: "second"})
	s.addPackage(Package{Name: "a", Version: "2"})
	if len(s.Packages) != 2 {
		t.Fatalf("Packages = %d, want 2", len(s.Packages))
	}
	if s.Packages[0].Description != "second" {
		t.Errorf("dedup should keep latest: %+v", s.Packages[0])
	}
}

func TestPackagePURLAndCPE(t *testing.T) {
	p := Package{ExternalRefs: []ExternalRef{
		{Category: "SECURITY", Type: "cpe23Type", Locator: "cpe:2.3:a:rails:rails:7.0.0"},
		{Category: "PACKAGE_MANAGER", Type: "purl", Locator: "pkg:gem/rails@7.0.0"},
	}}
	if p.PURL() != "pkg:gem/rails@7.0.0" {
		t.Errorf("PURL = %q", p.PURL())
	}
	if p.CPE() != "cpe:2.3:a:rails:rails:7.0.0" {
		t.Errorf("CPE = %q", p.CPE())
	}
	empty := Package{}
	if empty.PURL() != "" || empty.CPE() != "" {
		t.Errorf("empty package should have no purl/cpe")
	}
}
