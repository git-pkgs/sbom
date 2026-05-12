// Package sbom parses Software Bill of Materials documents into a unified
// data model. It reads CycloneDX and SPDX (JSON serialisations) and
// normalises both into the same Document/Package/Relationship shape so
// callers don't need to care which format they were handed.
//
// The model and field mappings are a port of github.com/andrew/sbom (Ruby).
//
//	doc, err := sbom.Parse(data)
//	for _, p := range doc.Packages {
//	    fmt.Println(p.Name, p.Version, p.PURL())
//	}
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Type identifies the source SBOM specification.
type Type string

const (
	TypeUnknown   Type = ""
	TypeCycloneDX Type = "cyclonedx"
	TypeSPDX      Type = "spdx"
)

// ErrUnrecognized is returned when the input does not look like any
// supported SBOM format.
var ErrUnrecognized = errors.New("sbom: unrecognized format")

// Supplier/originator type values, shared across both formats.
const (
	SupplierOrganization = "Organization"
	SupplierPerson       = "Person"
)

// Document holds metadata about the SBOM document itself, distinct from
// the packages it describes.
type Document struct {
	Name        string
	ID          string
	Type        Type
	SpecVersion string
	DataLicense string
	Namespace   string
	Created     string
	Supplier    string
	Creators    []Creator
	Component   Component
}

// Creator is a tool, person, or organization that produced the document.
type Creator struct {
	Type string
	Name string
}

// Component is the root subject the SBOM describes (CycloneDX
// metadata.component / SPDX root package).
type Component struct {
	Type    string
	Name    string
	Version string
}

// ExternalRef is a typed pointer to an external resource. PURLs and CPEs
// are stored here in both formats.
type ExternalRef struct {
	Category string
	Type     string
	Locator  string
}

// Checksum is a single hash over a package artefact.
type Checksum struct {
	Algorithm string
	Value     string
}

// Property is an arbitrary name/value annotation on a package.
type Property struct {
	Name  string
	Value string
}

// Package is a single component/package entry from the SBOM, regardless
// of source format.
type Package struct {
	ID               string
	Name             string
	Version          string
	Type             string
	Description      string
	Supplier         string
	SupplierType     string
	Originator       string
	OriginatorType   string
	Homepage         string
	DownloadLocation string
	Filename         string
	LicenseConcluded string
	LicenseDeclared  string
	Copyright        string
	Checksums        []Checksum
	ExternalRefs     []ExternalRef
	Properties       []Property
}

// PURL returns the Package URL for this package, if one was declared. In
// CycloneDX this is the top-level purl field; in SPDX it lives in
// externalRefs with referenceType "purl". Both are normalised into
// ExternalRefs so this is a simple lookup.
func (p *Package) PURL() string {
	for _, r := range p.ExternalRefs {
		if r.Type == "purl" {
			return r.Locator
		}
	}
	return ""
}

// CPE returns the first CPE identifier for this package, if any.
func (p *Package) CPE() string {
	for _, r := range p.ExternalRefs {
		if r.Type == "cpe22Type" || r.Type == "cpe23Type" {
			return r.Locator
		}
	}
	return ""
}

// Relationship links two elements in the SBOM. SourceID/TargetID are the
// raw identifiers from the document; Source/Target are resolved names
// where the parser could determine them.
type Relationship struct {
	SourceID string
	Source   string
	TargetID string
	Target   string
	Type     string
}

// SBOM is the unified parse result.
type SBOM struct {
	Type          Type
	SpecVersion   string
	Document      Document
	Packages      []Package
	Relationships []Relationship

	// pkgIndex keys packages by (name, version) so duplicates collapse the
	// same way the Ruby implementation's @packages[[name, version]] does.
	pkgIndex map[[2]string]int
}

// New returns an empty SBOM ready for AddPackage calls. Use this when
// building a document for Encode rather than parsing one.
func New(t Type) *SBOM {
	return &SBOM{Type: t, pkgIndex: map[[2]string]int{}}
}

func newSBOM(t Type) *SBOM { return New(t) }

// AddPackage appends p, replacing any existing package with the same
// (Name, Version) pair.
func (s *SBOM) AddPackage(p Package) { s.addPackage(p) }

// FilterProperties walks every package and removes properties whose
// names keep returns false for. Useful when handing a document to a
// downstream consumer that doesn't recognise a particular property
// namespace — for example, strip a tool-specific "mytool:" prefix
// before sharing outside the team that produced it. The filter
// mutates the SBOM in place; callers wanting a copy should Encode
// + Parse around the call.
//
// Document- and Component-level metadata is untouched; only the
// per-package Properties slice is filtered.
func (s *SBOM) FilterProperties(keep func(name string) bool) {
	if keep == nil {
		return
	}
	for i := range s.Packages {
		props := s.Packages[i].Properties
		filtered := props[:0]
		for _, p := range props {
			if keep(p.Name) {
				filtered = append(filtered, p)
			}
		}
		s.Packages[i].Properties = filtered
	}
}

func (s *SBOM) addPackage(p Package) {
	if s.pkgIndex == nil {
		s.pkgIndex = map[[2]string]int{}
	}
	key := [2]string{p.Name, p.Version}
	if i, ok := s.pkgIndex[key]; ok {
		s.Packages[i] = p
		return
	}
	s.pkgIndex[key] = len(s.Packages)
	s.Packages = append(s.Packages, p)
}

// Parse sniffs the SBOM format from content and parses it. Only JSON
// serialisations are supported.
func Parse(data []byte) (*SBOM, error) {
	switch Detect(data) {
	case TypeCycloneDX:
		return parseCycloneDX(data)
	case TypeSPDX:
		return parseSPDX(data)
	}
	// Fall back to trying both, mirroring Parser#try_both_parsers.
	if doc, err := parseSPDX(data); err == nil && len(doc.Packages) > 0 {
		return doc, nil
	}
	if doc, err := parseCycloneDX(data); err == nil && len(doc.Packages) > 0 {
		return doc, nil
	}
	return nil, ErrUnrecognized
}

// Detect inspects content and returns the SBOM Type without fully parsing
// it. Returns TypeUnknown if the format can't be determined.
//
// Only the top-level object keys are scanned; nested arrays and objects are
// skipped without allocation so detection cost is independent of document
// size once a discriminator is found.
func Detect(data []byte) Type {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return TypeUnknown
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if _, err := dec.Token(); err != nil { // opening '{'
		return TypeUnknown
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return TypeUnknown
		}
		key, ok := tok.(string)
		if !ok {
			return TypeUnknown
		}
		switch key {
		case "bomFormat":
			var v string
			if dec.Decode(&v) == nil && v == "CycloneDX" {
				return TypeCycloneDX
			}
			return TypeUnknown
		case "spdxVersion", "SPDXID":
			return TypeSPDX
		case "sbom":
			return TypeSPDX
		case "predicateType":
			var v string
			if dec.Decode(&v) == nil && strings.Contains(v, "spdx") {
				return TypeSPDX
			}
		default:
			if err := skipValue(dec); err != nil {
				return TypeUnknown
			}
		}
	}
	return TypeUnknown
}

// skipValue advances dec past the next JSON value without decoding it.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if _, ok := tok.(json.Delim); !ok {
		return nil // scalar
	}
	depth := 1
	for depth > 0 {
		tok, err = dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func wrapErr(format string, err error) error {
	return fmt.Errorf("sbom: "+format+": %w", err)
}
