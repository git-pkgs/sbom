package sbom

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

// Format selects an output serialisation for Encode.
type Format int

const (
	FormatCycloneDXJSON Format = iota
	FormatCycloneDXXML
	FormatSPDXJSON
)

const (
	spdxSpecVersion = "SPDX-2.3"
	spdxDocID       = "SPDXRef-DOCUMENT"
	spdxRootPkgID   = "SPDXRef-Package-root"
	spdxNoAssertion = "NOASSERTION"
)

// Encode writes s to w in the requested Format. Document fields left empty
// are filled with spec-mandated defaults (timestamps, NOASSERTION, etc.).
func Encode(w io.Writer, s *SBOM, f Format) error {
	switch f {
	case FormatCycloneDXJSON:
		return jsonEncode(w, buildCycloneDX(s))
	case FormatCycloneDXXML:
		bom := buildCycloneDX(s)
		bom.XMLNS = cdxXMLNS
		if _, err := io.WriteString(w, xml.Header); err != nil {
			return err
		}
		enc := xml.NewEncoder(w)
		enc.Indent("", "  ")
		return enc.Encode(bom)
	case FormatSPDXJSON:
		return jsonEncode(w, buildSPDX(s))
	}
	return fmt.Errorf("sbom: unsupported format %d", f)
}

func jsonEncode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func buildCycloneDX(s *SBOM) *cdxBOM {
	bom := &cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  firstNonEmpty(s.SpecVersion, cdxSpecVersion),
		BOMVersion:   1,
		SerialNumber: s.Document.ID,
		Metadata: &cdxMetadata{
			Timestamp: firstNonEmpty(s.Document.Created, nowUTC()),
		},
	}
	if c := s.Document.Component; c.Name != "" {
		bom.Metadata.Component = &cdxComponent{
			Type: firstNonEmpty(c.Type, "application"), Name: c.Name, Version: c.Version,
		}
	}
	for _, c := range s.Document.Creators {
		bom.Metadata.Tools = append(bom.Metadata.Tools, cdxTool{Vendor: c.Type, Name: c.Name})
	}
	for i := range s.Packages {
		bom.Components = append(bom.Components, packageToCDX(&s.Packages[i]))
	}
	return bom
}

func packageToCDX(p *Package) cdxComponent {
	purl := p.PURL()
	c := cdxComponent{
		BOMRef:      firstNonEmpty(p.ID, purl),
		Type:        firstNonEmpty(strings.ToLower(p.Type), cdxDefaultCompType),
		Name:        p.Name,
		Version:     p.Version,
		Description: p.Description,
		PURL:        purl,
	}
	if lic := firstNonEmpty(p.LicenseDeclared, p.LicenseConcluded); lic != "" {
		c.Licenses = []cdxLicense{{License: &cdxLicenseID{ID: lic}, ID: lic}}
	}
	return c
}

func buildSPDX(s *SBOM) *spdxDoc {
	doc := &spdxDoc{
		SPDXVersion:       firstNonEmpty(s.SpecVersion, spdxSpecVersion),
		SPDXID:            firstNonEmpty(s.Document.ID, spdxDocID),
		Name:              s.Document.Name,
		DataLicense:       firstNonEmpty(s.Document.DataLicense, "CC0-1.0"),
		DocumentNamespace: s.Document.Namespace,
		CreationInfo: &spdxCreationInfo{
			Created: firstNonEmpty(s.Document.Created, nowUTC()),
		},
	}
	for _, c := range s.Document.Creators {
		doc.CreationInfo.Creators = append(doc.CreationInfo.Creators, c.Type+": "+c.Name)
	}
	if s.Document.Supplier != "" {
		doc.CreationInfo.Creators = append(doc.CreationInfo.Creators,
			SupplierOrganization+": "+s.Document.Supplier)
	}

	root := spdxPackage{
		SPDXID: spdxRootPkgID, Name: s.Document.Component.Name,
		VersionInfo: s.Document.Component.Version, DownloadLocation: spdxNoAssertion,
	}
	doc.Packages = append(doc.Packages, root)

	for i := range s.Packages {
		sp := packageToSPDX(&s.Packages[i], i)
		doc.Packages = append(doc.Packages, sp)
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID: spdxRootPkgID, RelationshipType: "DEPENDS_ON",
			RelatedSPDXElement: sp.SPDXID,
		})
	}
	return doc
}

func packageToSPDX(p *Package, i int) spdxPackage {
	sp := spdxPackage{
		SPDXID:           firstNonEmpty(p.ID, fmt.Sprintf("SPDXRef-Package-%d", i)),
		Name:             p.Name,
		VersionInfo:      p.Version,
		DownloadLocation: firstNonEmpty(p.DownloadLocation, spdxNoAssertion),
		LicenseConcluded: firstNonEmpty(p.LicenseConcluded, spdxNoAssertion),
		LicenseDeclared:  firstNonEmpty(p.LicenseDeclared, spdxNoAssertion),
	}
	if purl := p.PURL(); purl != "" {
		sp.ExternalRefs = append(sp.ExternalRefs, spdxExtRef{
			Category: "PACKAGE-MANAGER", Type: "purl", Locator: purl,
		})
	}
	return sp
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
