package sbom

import (
	"errors"
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
