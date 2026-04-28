package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sampleSBOM() *SBOM {
	s := New(TypeCycloneDX)
	s.Document = Document{
		Name:      "demo",
		Namespace: "https://example.com/demo",
		Component: Component{Type: "application", Name: "demo", Version: "1.0.0"},
		Creators:  []Creator{{Type: "Tool", Name: "test-1.0"}},
	}
	s.AddPackage(Package{
		Name: "lodash", Version: "4.17.21", LicenseDeclared: "MIT",
		ExternalRefs: []ExternalRef{{Category: "PACKAGE_MANAGER", Type: "purl", Locator: "pkg:npm/lodash@4.17.21"}},
	})
	s.AddPackage(Package{Name: "left-pad", Version: "1.3.0"})
	return s
}

func TestEncodeRoundTrip(t *testing.T) {
	src := sampleSBOM()
	for _, f := range []Format{FormatCycloneDXJSON, FormatSPDXJSON} {
		t.Run(formatName(f), func(t *testing.T) {
			var buf bytes.Buffer
			if err := Encode(&buf, src, f); err != nil {
				t.Fatalf("Encode: %v", err)
			}
			out, err := Parse(buf.Bytes())
			if err != nil {
				t.Fatalf("Parse: %v\n%s", err, buf.String())
			}
			// SPDX adds a synthetic root package; CycloneDX does not.
			wantPkgs := len(src.Packages)
			if f == FormatSPDXJSON {
				wantPkgs++
			}
			if len(out.Packages) != wantPkgs {
				t.Errorf("Packages = %d, want %d", len(out.Packages), wantPkgs)
			}
			var p *Package
			for i := range out.Packages {
				if out.Packages[i].Name == "lodash" {
					p = &out.Packages[i]
				}
			}
			if p == nil {
				t.Fatalf("lodash not round-tripped:\n%s", buf.String())
			}
			want := src.Packages[0]
			if p.PURL() != want.PURL() {
				t.Errorf("PURL = %q, want %q", p.PURL(), want.PURL())
			}
			if p.LicenseDeclared != want.LicenseDeclared {
				t.Errorf("LicenseDeclared = %q, want %q", p.LicenseDeclared, want.LicenseDeclared)
			}
		})
	}
}

func TestEncodeCycloneDXXML(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, sampleSBOM(), FormatCycloneDXXML); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`xmlns="http://cyclonedx.org/schema/bom/1.5"`,
		`<name>lodash</name>`,
		`<purl>pkg:npm/lodash@4.17.21</purl>`,
		`<id>MIT</id>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestEncodeSPDXNoEnvelopeFields(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, sampleSBOM(), FormatSPDXJSON); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"sbom", "predicate", "predicateType"} {
		if _, ok := m[k]; ok {
			t.Errorf("encoder leaked parse-only field %q", k)
		}
	}
}

func formatName(f Format) string {
	switch f {
	case FormatCycloneDXJSON:
		return "cyclonedx-json"
	case FormatCycloneDXXML:
		return "cyclonedx-xml"
	case FormatSPDXJSON:
		return "spdx-json"
	}
	return "unknown"
}
