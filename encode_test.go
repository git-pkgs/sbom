package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"slices"
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
		Properties:   []Property{{Name: "location", Value: "package.json"}},
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

func TestEncodeSPDXSourceInfoRoundTrip(t *testing.T) {
	data, err := os.ReadFile("testdata/spdx/syft-lock/poetry.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	src, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	if err := Encode(&buf, src, FormatSPDXJSON); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("Parse encoded: %v", err)
	}
	for _, name := range []string{"requests", "urllib3"} {
		want := findPackage(t, src, name).SourceInfo
		if want == "" {
			t.Fatalf("%s: fixture has no SourceInfo", name)
		}
		if got := findPackage(t, out, name).SourceInfo; got != want {
			t.Errorf("%s: SourceInfo = %q, want %q", name, got, want)
		}
	}
}

func TestEncodeCycloneDXPropertiesRoundTrip(t *testing.T) {
	src := sampleSBOM()
	var buf bytes.Buffer
	if err := Encode(&buf, src, FormatCycloneDXJSON); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, buf.String())
	}
	for i := range out.Packages {
		if out.Packages[i].Name != "lodash" {
			continue
		}
		if !slices.Equal(out.Packages[i].Properties, src.Packages[0].Properties) {
			t.Errorf("Properties = %#v, want %#v", out.Packages[i].Properties, src.Packages[0].Properties)
		}
		return
	}
	t.Fatalf("lodash not round-tripped:\n%s", buf.String())
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
		`<property name="location">package.json</property>`,
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

func TestEncodeSPDXGeneratedPackageIDsAndRelationshipOrder(t *testing.T) {
	s := sampleSBOM()
	var output bytes.Buffer
	if err := Encode(&output, s, FormatSPDXJSON); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var doc spdxDoc
	if err := json.Unmarshal(output.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantIDs := []string{spdxRootPkgID, "SPDXRef-Package-0", "SPDXRef-Package-1"}
	for i, want := range wantIDs {
		if doc.Packages[i].SPDXID != want {
			t.Errorf("Packages[%d].SPDXID = %q, want %q", i, doc.Packages[i].SPDXID, want)
		}
	}
	for i := range doc.Relationships {
		if doc.Relationships[i].RelatedSPDXElement != wantIDs[i+1] {
			t.Errorf("Relationships[%d] = %#v", i, doc.Relationships[i])
		}
	}
}

func TestEncodeComponentLicenseExpression(t *testing.T) {
	s := sampleSBOM()
	s.Document.Component.LicenseExpression = "MIT OR Apache-2.0"

	var jsonOutput bytes.Buffer
	if err := Encode(&jsonOutput, s, FormatCycloneDXJSON); err != nil {
		t.Fatalf("Encode CycloneDX JSON: %v", err)
	}
	var jsonDocument struct {
		Metadata struct {
			Component struct {
				Licenses []struct {
					Expression string `json:"expression"`
				} `json:"licenses"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(jsonOutput.Bytes(), &jsonDocument); err != nil {
		t.Fatalf("unmarshal CycloneDX JSON: %v", err)
	}
	licenses := jsonDocument.Metadata.Component.Licenses
	if len(licenses) != 1 || licenses[0].Expression != "MIT OR Apache-2.0" {
		t.Fatalf("root licenses = %#v", licenses)
	}

	var xmlOutput bytes.Buffer
	if err := Encode(&xmlOutput, s, FormatCycloneDXXML); err != nil {
		t.Fatalf("Encode CycloneDX XML: %v", err)
	}
	if !strings.Contains(xmlOutput.String(), "<expression>MIT OR Apache-2.0</expression>") {
		t.Fatalf("missing root license expression:\n%s", xmlOutput.String())
	}
}

func TestEncodeMixedComponentLicenses(t *testing.T) {
	s := sampleSBOM()
	s.Document.Component.LicenseExpression = "MIT OR Apache-2.0"
	s.Document.Component.LicenseNames = []string{"Acme Internal Terms"}
	s.Document.Component.ExtractedLicenses = []ExtractedLicense{{
		Name: "LICENSE.custom",
		Text: "Custom file terms\n",
	}}

	var jsonOutput bytes.Buffer
	if err := Encode(&jsonOutput, s, FormatCycloneDXJSON); err != nil {
		t.Fatalf("Encode CycloneDX JSON: %v", err)
	}
	var jsonDocument map[string]any
	if err := json.Unmarshal(jsonOutput.Bytes(), &jsonDocument); err != nil {
		t.Fatalf("unmarshal CycloneDX JSON: %v", err)
	}
	metadata := jsonDocument["metadata"].(map[string]any)
	component := metadata["component"].(map[string]any)
	licenses := component["licenses"].([]any)
	if len(licenses) != 3 {
		t.Fatalf("CycloneDX licenses = %#v", licenses)
	}
	for _, value := range licenses {
		if _, ok := value.(map[string]any)["expression"]; ok {
			t.Fatalf("mixed CycloneDX license choices must not contain an expression: %#v", licenses)
		}
	}

	var xmlOutput bytes.Buffer
	if err := Encode(&xmlOutput, s, FormatCycloneDXXML); err != nil {
		t.Fatalf("Encode CycloneDX XML: %v", err)
	}
	for _, want := range []string{
		"<name>MIT OR Apache-2.0</name>",
		"<name>Acme Internal Terms</name>",
		"<name>LICENSE.custom</name>",
	} {
		if !strings.Contains(xmlOutput.String(), want) {
			t.Errorf("CycloneDX XML missing %q:\n%s", want, xmlOutput.String())
		}
	}
	for _, unwanted := range []string{"<components></components>", "<dependencies></dependencies>"} {
		if strings.Contains(xmlOutput.String(), unwanted) {
			t.Errorf("CycloneDX XML contains empty container %q:\n%s", unwanted, xmlOutput.String())
		}
	}

	var spdxOutput bytes.Buffer
	if err := Encode(&spdxOutput, s, FormatSPDXJSON); err != nil {
		t.Fatalf("Encode SPDX JSON: %v", err)
	}
	var spdxDocument spdxDoc
	if err := json.Unmarshal(spdxOutput.Bytes(), &spdxDocument); err != nil {
		t.Fatalf("unmarshal SPDX JSON: %v", err)
	}
	root := spdxDocument.Packages[0]
	if !strings.Contains(root.LicenseDeclared, "(MIT OR Apache-2.0)") {
		t.Errorf("root licenseDeclared = %q", root.LicenseDeclared)
	}
	if !strings.Contains(root.LicenseDeclared, ") AND LicenseRef-") {
		t.Errorf("root licenseDeclared does not combine independent declarations with AND: %q",
			root.LicenseDeclared)
	}
	if len(spdxDocument.ExtractedLicensingInfos) != 2 {
		t.Fatalf("extracted licensing infos = %#v", spdxDocument.ExtractedLicensingInfos)
	}
	fileLicense := spdxDocument.ExtractedLicensingInfos[1]
	if fileLicense.Name != "LICENSE.custom" || fileLicense.ExtractedText != "Custom file terms\n" {
		t.Errorf("file license = %#v", fileLicense)
	}
	wantID := extractedLicenseID("", fileLicense.Name, fileLicense.ExtractedText)
	if fileLicense.LicenseID != wantID || !strings.Contains(root.LicenseDeclared, wantID) {
		t.Errorf("file LicenseRef mismatch: info=%q expression=%q want=%q",
			fileLicense.LicenseID, root.LicenseDeclared, wantID)
	}
}

func TestExtractedLicenseIDHonorsExplicitID(t *testing.T) {
	if got := extractedLicenseID("LicenseRef-Custom", "name", "text"); got != "LicenseRef-Custom" {
		t.Fatalf("extractedLicenseID = %q", got)
	}
	if got := extractedLicenseID("Custom", "name", "text"); got != "LicenseRef-Custom" {
		t.Fatalf("extractedLicenseID = %q", got)
	}
}

func TestComponentLicensesToSPDXDeduplicatesExtractedInfo(t *testing.T) {
	component := Component{
		LicenseNames: []string{"Acme Terms", "Acme Terms"},
		ExtractedLicenses: []ExtractedLicense{
			{Name: "LICENSE.custom", Text: "Custom terms"},
			{Name: "LICENSE.custom", Text: "Custom terms"},
		},
	}

	expression, infos := componentLicensesToSPDX(component)
	if len(infos) != 2 {
		t.Fatalf("extracted licensing infos = %#v, want 2 unique entries", infos)
	}
	if strings.Count(expression, "LicenseRef-") != 2 {
		t.Fatalf("license expression = %q, want 2 unique LicenseRefs", expression)
	}
	if !strings.Contains(expression, " AND ") {
		t.Fatalf("license expression = %q, want conjunction", expression)
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

func TestEncodeCycloneDXXMLLicensesBeforePURL(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, sampleSBOM(), FormatCycloneDXXML); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := xmlChildNames(t, buf.Bytes(), func(start xml.StartElement) bool {
		return start.Name.Local == "component" && xmlAttr(start, "bom-ref") == "pkg:npm/lodash@4.17.21"
	})
	want := []string{"name", "version", "licenses", "purl", "properties"}
	if !slices.Equal(got, want) {
		t.Errorf("component elements = %v, want %v\n%s", got, want, buf.String())
	}
}

func TestCycloneDXXMLComponentElementOrder(t *testing.T) {
	component := cdxComponentToXML(&cdxComponent{
		BOMRef: "alpha", Type: "library", Name: "alpha", Version: "1.0.0",
		Description: "Alpha", Copyright: "Copyright Acme", Author: "Jane Doe",
		PURL: "pkg:npm/alpha@1.0.0", Supplier: &cdxOrgEntity{Name: "Acme"},
		Hashes:             []cdxHash{{Alg: "SHA-256", Content: "abc"}},
		Licenses:           []cdxLicense{{Expression: "MIT"}},
		Pedigree:           &cdxPedigree{Ancestors: []cdxComponent{{Type: "library", Name: "upstream"}}},
		ExternalReferences: []cdxExtRef{{Type: "website", URL: "https://example.com"}},
		Properties:         []cdxProperty{{Name: "scope", Value: "runtime"}},
		Components:         []cdxComponent{{Type: "library", Name: "child"}},
	})
	data, err := xml.Marshal(component)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := xmlChildNames(t, data, func(xml.StartElement) bool { return true })
	// The supported subset of the CycloneDX 1.5 XSD component sequence.
	want := []string{
		"supplier", "author", "name", "version", "description", "hashes", "licenses",
		"copyright", "purl", "pedigree", "externalReferences", "properties", "components",
	}
	if !slices.Equal(got, want) {
		t.Errorf("component elements = %v, want %v\n%s", got, want, data)
	}
}

func TestCycloneDXXMLMetadataElementOrder(t *testing.T) {
	data, err := xml.Marshal(cdxMetadataXML{
		Timestamp:   "2026-01-01T00:00:00Z",
		Tools:       &cdxToolsXML{Tools: []cdxTool{{Vendor: "Tool", Name: "test"}}},
		Component:   &cdxComponentXML{Type: "application", Name: "demo"},
		Manufacture: &cdxOrgEntity{Name: "Maker"},
		Supplier:    &cdxOrgEntity{Name: "Acme"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := xmlChildNames(t, data, func(xml.StartElement) bool { return true })
	want := []string{"timestamp", "tools", "component", "manufacture", "supplier"}
	if !slices.Equal(got, want) {
		t.Errorf("metadata elements = %v, want %v\n%s", got, want, data)
	}
}

func TestParseCycloneDXXMLPreviousElementOrder(t *testing.T) {
	// Element order emitted by earlier versions of this encoder.
	doc, err := Parse([]byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="alpha">
      <name>alpha</name>
      <version>1.0.0</version>
      <copyright>Copyright Acme</copyright>
      <author>Jane Doe</author>
      <purl>pkg:npm/alpha@1.0.0</purl>
      <supplier><name>Acme</name></supplier>
      <hashes><hash alg="SHA-256">abc</hash></hashes>
      <licenses><license><id>MIT</id></license></licenses>
    </component>
  </components>
</bom>`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(doc.Packages))
	}
	p := doc.Packages[0]
	if p.Copyright != "Copyright Acme" || p.Originator != "Jane Doe" || p.Supplier != "Acme" ||
		p.PURL() != "pkg:npm/alpha@1.0.0" || p.LicenseDeclared != "MIT" ||
		!slices.Equal(p.Checksums, []Checksum{{Algorithm: "SHA256", Value: "abc"}}) {
		t.Errorf("package = %#v", p)
	}
}

// xmlChildNames returns the local names of the direct children of the first
// element matched by match.
func xmlChildNames(t *testing.T, data []byte, match func(xml.StartElement) bool) []string {
	t.Helper()
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var names []string
	depth, matchedDepth := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decoding XML: %v\n%s", err, data)
		}
		switch token := token.(type) {
		case xml.StartElement:
			depth++
			if matchedDepth == 0 && match(token) {
				matchedDepth = depth
			} else if matchedDepth != 0 && depth == matchedDepth+1 {
				names = append(names, token.Name.Local)
			}
		case xml.EndElement:
			if depth == matchedDepth {
				return names
			}
			depth--
		}
	}
	t.Fatalf("no matching element in:\n%s", data)
	return nil
}

func xmlAttr(start xml.StartElement, name string) string {
	for _, attr := range start.Attr {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}
