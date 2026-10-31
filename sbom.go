// Package sbom parses Software Bill of Materials documents into a unified
// data model. It reads CycloneDX JSON/XML and SPDX JSON/tag-value and
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
	"maps"
	"slices"
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
// metadata.component / SPDX root package). ID is its CycloneDX bom-ref, the
// identifier dependency edges from the root use; it is empty when the
// document gives none.
type Component struct {
	ID                string
	Type              string
	Name              string
	Version           string
	LicenseExpression string
	LicenseNames      []string
	ExtractedLicenses []ExtractedLicense
}

// ExtractedLicense is non-SPDX license text associated with a component.
// ID is optional. Encode prefixes a supplied ID with LicenseRef- when needed,
// or generates a stable LicenseRef when ID is empty.
type ExtractedLicense struct {
	ID   string
	Name string
	Text string
}

// ExternalRef is a typed pointer to an external resource. PURLs and CPEs
// are stored here in both formats.
type ExternalRef struct {
	Category string
	Type     string
	Locator  string
}

const purlExternalReferenceType = "purl"

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
	// SourceInfo is SPDX's free-text note on where the package information
	// came from (PackageSourceInfo).
	SourceInfo       string
	LicenseConcluded string
	LicenseDeclared  string
	Copyright        string
	Checksums        []Checksum
	ExternalRefs     []ExternalRef
	Properties       []Property
	Ancestors        []Ancestor
}

// Ancestor is a component a package was derived from, such as the upstream
// project of a fork (CycloneDX pedigree.ancestors). Ancestors describe
// provenance only: they are not installed packages and never produce
// relationships. Version is optional because an ancestor may be known only
// as a repository. CycloneDX requires Name; Type defaults to library.
type Ancestor struct {
	Type    string
	Name    string
	Version string
	PURL    string
}

// PURL returns the Package URL for this package, if one was declared. In
// CycloneDX this is the top-level purl field; in SPDX it lives in
// externalRefs with referenceType "purl". Both are normalised into
// ExternalRefs so this is a simple lookup.
func (p *Package) PURL() string {
	for _, r := range p.ExternalRefs {
		if r.Type == purlExternalReferenceType {
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

// Relationship type values. SPDX has ~40 of these; we name the two the
// parsers emit and ClassifyScope reads. CycloneDX dependency edges and
// SPDX DEPENDENCY_OF edges are normalised to RelDependsOn.
const (
	RelDependsOn = "DEPENDS_ON"
	RelDescribes = "DESCRIBES"
)

// spdxDependencyOf is the SPDX inverse of DEPENDS_ON, which syft emits.
const spdxDependencyOf = "DEPENDENCY_OF"

// Scope values returned by ClassifyScope.
const (
	ScopeDirect     = "direct"
	ScopeTransitive = "transitive"
)

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

	pkgIndex map[packageKey]int
}

type packageKey struct {
	name, version, id, purls string
}

// New returns an empty SBOM ready for AddPackage calls. Use this when
// building a document for Encode rather than parsing one.
func New(t Type) *SBOM {
	return &SBOM{Type: t, pkgIndex: map[packageKey]int{}}
}

func newSizedSBOM(t Type, packages, relationships int) *SBOM {
	s := &SBOM{
		Type:     t,
		pkgIndex: make(map[packageKey]int, packages),
	}
	if packages > 0 {
		s.Packages = make([]Package, 0, packages)
	}
	if relationships > 0 {
		s.Relationships = make([]Relationship, 0, relationships)
	}
	return s
}

// AddPackage appends p, replacing any existing package with the same
// name, version, document ID, and set of PURLs.
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

// ClassifyScope derives direct-vs-transitive scope for each package from
// the relationship graph. A package is ScopeDirect if a root depends on it,
// ScopeTransitive if only a non-root does, and absent from the map if the
// graph doesn't mention it at all.
//
// When the document declares its root, as the target of a DESCRIBES edge
// (SPDX's document-to-root-package link) or as Document.Component.ID (the
// CycloneDX metadata.component bom-ref), and that root has DEPENDS_ON edges,
// the declared roots are the only roots. Otherwise roots are inferred: nodes
// that originate DEPENDS_ON edges but are never a DEPENDS_ON target, plus any
// declared root. An inferred root is not necessarily the project: for a lock
// file that doesn't list the project itself the top-level dependencies are
// inferred as roots, except for packages syft records as coming from such a
// lock file (poetry.lock, pdm.lock, pnpm-lock.yaml and yarn v1's yarn.lock):
// those are ScopeDirect themselves, and what they depend on is transitive.
// So is a package from such a lock file that no edge names, when other
// packages of the lock file have edges.
//
// Returns nil for a flat-list SBOM with no dependency graph so callers can
// tell "no graph" apart from "graph present but this package is a root".
func (s *SBOM) ClassifyScope() map[string]string {
	roots, top, _ := s.scopeRoots()
	if roots == nil {
		// No DEPENDS_ON or DESCRIBES edges: a flat-list SBOM. nil (as
		// distinct from empty) lets callers hide scope entirely.
		return nil
	}
	out := map[string]string{}
	for id := range top {
		out[id] = ScopeDirect
	}
	if len(roots) == 0 && len(top) == 0 {
		// Edges exist but form a cycle with no declared root: nothing
		// is classifiable, but the graph is present, so return empty
		// rather than nil.
		return out
	}
	for _, r := range s.Relationships {
		if r.Type != RelDependsOn {
			continue
		}
		if roots[r.SourceID] {
			out[r.TargetID] = ScopeDirect
		} else if out[r.TargetID] == "" {
			out[r.TargetID] = ScopeTransitive
		}
	}
	return out
}

// Roots returns the IDs ClassifyScope treats as roots, and whether all of
// them are declared by the document rather than inferred from the graph. Declared
// roots are the project; inferred ones may be top-level dependencies of a
// lock file that leaves the project out. It returns nil for a flat-list SBOM.
func (s *SBOM) Roots() (ids []string, declared bool) {
	roots, _, declared := s.scopeRoots()
	if roots == nil {
		return nil, false
	}
	ids = make([]string, 0, len(roots))
	for id := range roots {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, declared
}

// scopeRoots returns the root set for ClassifyScope, nil when there is no
// graph, the inferred roots that are top-level dependencies instead (see
// topLevelDependencies), and whether every root is declared.
func (s *SBOM) scopeRoots() (roots, top map[string]bool, declared bool) {
	targets := map[string]bool{}
	sources := map[string]bool{}
	declaredRoots := map[string]bool{}
	for _, r := range s.Relationships {
		switch r.Type {
		case RelDependsOn:
			sources[r.SourceID] = true
			targets[r.TargetID] = true
		case RelDescribes:
			declaredRoots[r.TargetID] = true
		}
	}
	if len(sources) == 0 && len(declaredRoots) == 0 {
		return nil, nil, false
	}
	if id := s.Document.Component.ID; id != "" {
		declaredRoots[id] = true
	}
	// A declared root with edges of its own names the project's direct
	// dependencies, so nothing needs inferring.
	linked := map[string]bool{}
	for id := range declaredRoots {
		if sources[id] {
			linked[id] = true
		}
	}
	if len(linked) > 0 {
		return linked, nil, true
	}
	inferred := map[string]bool{}
	for id := range sources {
		if !targets[id] {
			inferred[id] = true
		}
	}
	edged := maps.Clone(sources)
	maps.Copy(edged, targets)
	top = s.topLevelDependencies(inferred, edged)
	roots = maps.Clone(declaredRoots)
	for id := range inferred {
		if !top[id] {
			roots[id] = true
		}
	}
	declared = len(roots) > 0 && len(roots) == len(declaredRoots)
	return roots, top, declared
}

func (s *SBOM) addPackage(p Package) {
	if s.pkgIndex == nil {
		s.pkgIndex = map[packageKey]int{}
	}
	key := packageKey{p.Name, p.Version, p.ID, packagePURLKey(p.ExternalRefs)}
	if i, ok := s.pkgIndex[key]; ok {
		s.Packages[i] = p
		return
	}
	s.pkgIndex[key] = len(s.Packages)
	s.Packages = append(s.Packages, p)
}

func packagePURLKey(refs []ExternalRef) string {
	var purls []string
	for _, ref := range refs {
		if ref.Type == purlExternalReferenceType && ref.Locator != "" {
			purls = append(purls, ref.Locator)
		}
	}
	slices.Sort(purls)
	return strings.Join(slices.Compact(purls), "\x00")
}

// Parse reads CycloneDX JSON/XML or SPDX JSON/tag-value, detecting the format.
func Parse(data []byte) (*SBOM, error) {
	data = trimDocument(data)
	detected := detect(data)
	if detected.xml {
		return parseCycloneDXXML(data)
	}
	if detected.tagValue {
		return parseSPDXTagValue(data)
	}
	switch detected.typ {
	case TypeCycloneDX:
		return parseCycloneDX(data)
	case TypeSPDX:
		return parseSPDX(data, detected.spdxEnvelope)
	}
	// Fall back to trying both, mirroring Parser#try_both_parsers.
	if doc, err := parseSPDX(data, false); err == nil && len(doc.Packages) > 0 {
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
// It scans JSON keys, the XML root, or the tag-value document header.
func Detect(data []byte) Type {
	return detect(data).typ
}

type detectedFormat struct {
	typ          Type
	spdxEnvelope bool
	xml          bool
	tagValue     bool
}

func trimDocument(data []byte) []byte {
	return bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(data), []byte("\xef\xbb\xbf")))
}

func detect(data []byte) detectedFormat {
	data = trimDocument(data)
	if len(data) == 0 {
		return detectedFormat{}
	}
	if data[0] == '<' {
		return detectCycloneDXXML(data)
	}
	if data[0] != '{' {
		return detectSPDXTagValue(data)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if _, err := dec.Token(); err != nil { // opening '{'
		return detectedFormat{}
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return detectedFormat{}
		}
		key, ok := tok.(string)
		if !ok {
			return detectedFormat{}
		}
		switch key {
		case "bomFormat":
			var v string
			if dec.Decode(&v) == nil && v == cdxBOMFormat {
				return detectedFormat{typ: TypeCycloneDX}
			}
			return detectedFormat{}
		case "spdxVersion", "SPDXID":
			return detectedFormat{typ: TypeSPDX}
		case "sbom":
			return detectedFormat{typ: TypeSPDX, spdxEnvelope: true}
		case "predicateType":
			var v string
			if dec.Decode(&v) == nil && strings.Contains(v, "spdx") {
				return detectedFormat{typ: TypeSPDX, spdxEnvelope: true}
			}
		default:
			if err := skipValue(dec); err != nil {
				return detectedFormat{}
			}
		}
	}
	return detectedFormat{}
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
