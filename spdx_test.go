package sbom

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSPDXExternalRefPURL(t *testing.T) {
	in := `{
	  "spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	  "packages":[{
	    "SPDXID":"SPDXRef-p","name":"lodash","versionInfo":"4.17.21",
	    "externalRefs":[
	      {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.21"},
	      {"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:lodash:lodash:4.17.21"}
	    ]
	  }]
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	p := doc.Packages[0]
	if p.PURL() != "pkg:npm/lodash@4.17.21" {
		t.Errorf("PURL = %q", p.PURL())
	}
	if p.CPE() != "cpe:2.3:a:lodash:lodash:4.17.21" {
		t.Errorf("CPE = %q", p.CPE())
	}
}

func TestSPDXEmptyDocumentPreservesNilSlices(t *testing.T) {
	doc, err := Parse([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Packages != nil {
		t.Errorf("Packages = %#v, want nil", doc.Packages)
	}
	if doc.Relationships != nil {
		t.Errorf("Relationships = %#v, want nil", doc.Relationships)
	}
}

func TestSPDXEmptyCreatorsPreserveNilSlice(t *testing.T) {
	in := `{
	  "spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	  "creationInfo":{"created":"2026-01-01T00:00:00Z","creators":[]}
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Document.Creators != nil {
		t.Errorf("Document.Creators = %#v, want nil", doc.Document.Creators)
	}
}

func TestSPDXOrganizationOnlyCreatorPreservesNilSlice(t *testing.T) {
	in := `{
	  "spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	  "creationInfo":{"creators":["Organization: Acme"]}
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Document.Supplier != "Acme" {
		t.Errorf("Document.Supplier = %q, want Acme", doc.Document.Supplier)
	}
	if doc.Document.Creators != nil {
		t.Errorf("Document.Creators = %#v, want nil", doc.Document.Creators)
	}
}

func TestSPDXMixedCreatorsPreserveOrder(t *testing.T) {
	in := `{
	  "spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	  "creationInfo":{"creators":[
	    "Tool: syft","Organization: Acme","Person: Jane Doe","Tool: scanner"
	  ]}
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Document.Supplier != "Acme" {
		t.Errorf("Document.Supplier = %q, want Acme", doc.Document.Supplier)
	}
	want := []Creator{
		{Type: "Tool", Name: "syft"},
		{Type: "Person", Name: "Jane Doe"},
		{Type: "Tool", Name: "scanner"},
	}
	if !reflect.DeepEqual(doc.Document.Creators, want) {
		t.Errorf("Document.Creators = %#v, want %#v", doc.Document.Creators, want)
	}
}

func TestSPDXSupplierOriginator(t *testing.T) {
	in := `{
	  "spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	  "creationInfo":{"created":"2024-01-01T00:00:00Z","creators":["Tool: syft","Organization: Acme"]},
	  "packages":[{
	    "SPDXID":"SPDXRef-p","name":"x",
	    "supplier":"Organization: Acme Inc",
	    "originator":"Person: Jane Doe"
	  }]
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Document.Supplier != "Acme" {
		t.Errorf("Document.Supplier = %q", doc.Document.Supplier)
	}
	if len(doc.Document.Creators) != 1 || doc.Document.Creators[0].Name != "syft" {
		t.Errorf("Creators = %+v", doc.Document.Creators)
	}
	p := doc.Packages[0]
	if p.SupplierType != SupplierOrganization || p.Supplier != "Acme Inc" {
		t.Errorf("supplier = %s/%s", p.SupplierType, p.Supplier)
	}
	if p.OriginatorType != SupplierPerson || p.Originator != "Jane Doe" {
		t.Errorf("originator = %s/%s", p.OriginatorType, p.Originator)
	}
}

func TestSPDXInTotoEnvelope(t *testing.T) {
	in := `{
	  "predicateType":"https://spdx.dev/Document",
	  "predicate":{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	    "packages":[{"SPDXID":"SPDXRef-p","name":"x"}]}
	}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Packages) != 1 || doc.Packages[0].Name != "x" {
		t.Errorf("predicate unwrap failed: %+v", doc.Packages)
	}
}

func TestSPDXGitHubEnvelope(t *testing.T) {
	inner := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	  "packages":[{"SPDXID":"SPDXRef-p","name":"x"}]}`
	for _, depth := range []int{1, 2} {
		in := inner
		for range depth {
			in = `{"sbom":` + in + `}`
		}
		doc, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("depth %d: Parse: %v", depth, err)
		}
		if len(doc.Packages) != 1 || doc.Packages[0].Name != "x" {
			t.Errorf("depth %d: sbom unwrap failed: %+v", depth, doc.Packages)
		}
	}
}

func TestSPDXEnvelopeDepthLimit(t *testing.T) {
	const depth = 100
	in := strings.Repeat(`{"sbom":`, depth) + `{}` + strings.Repeat(`}`, depth)
	_, err := Parse([]byte(in))
	if !errors.Is(err, ErrUnrecognized) {
		t.Fatalf("Parse = %v, want ErrUnrecognized", err)
	}
}

func TestSPDXDependencyOfNormalised(t *testing.T) {
	inputs := map[string]string{
		"json": `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
			"packages": [
				{"SPDXID": "SPDXRef-a", "name": "a", "sourceInfo": "acquired package info from installed python package manifest file: /poetry.lock"},
				{"SPDXID": "SPDXRef-b", "name": "b"}],
			"relationships": [{"spdxElementId": "SPDXRef-b", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-a"}]}`,
		"tag-value": "SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\n\n" +
			"PackageName: a\nSPDXID: SPDXRef-a\nPackageSourceInfo: acquired package info from installed python package manifest file: /poetry.lock\n\n" +
			"PackageName: b\nSPDXID: SPDXRef-b\n\n" +
			"Relationship: SPDXRef-b DEPENDENCY_OF SPDXRef-a\n",
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			doc, err := Parse([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			want := Relationship{SourceID: "SPDXRef-a", Source: "a", TargetID: "SPDXRef-b", Target: "b", Type: RelDependsOn}
			if len(doc.Relationships) != 1 || doc.Relationships[0] != want {
				t.Errorf("Relationships = %+v, want [%+v]", doc.Relationships, want)
			}
			if got := doc.Packages[0].SourceInfo; got != "acquired package info from installed python package manifest file: /poetry.lock" {
				t.Errorf("SourceInfo = %q", got)
			}
		})
	}
}
