package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
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
		if _, err := io.WriteString(w, xml.Header); err != nil {
			return err
		}
		enc := xml.NewEncoder(w)
		enc.Indent("", "  ")
		return enc.Encode(cycloneDXXML(bom))
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
		BOMFormat:    cdxBOMFormat,
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
			Licenses: componentLicensesToCDX(c),
		}
	}
	if len(s.Document.Creators) > 0 {
		bom.Metadata.Tools = make([]cdxTool, len(s.Document.Creators))
		for i := range s.Document.Creators {
			creator := &s.Document.Creators[i]
			bom.Metadata.Tools[i] = cdxTool{Vendor: creator.Type, Name: creator.Name}
		}
	}
	if len(s.Packages) > 0 {
		bom.Components = make([]cdxComponent, len(s.Packages))
		for i := range s.Packages {
			bom.Components[i] = packageToCDX(&s.Packages[i])
		}
	}
	return bom
}

func packageToCDX(p *Package) cdxComponent {
	purl := p.PURL()
	c := cdxComponent{
		BOMRef:      firstNonEmpty(p.ID, purl),
		Type:        cdxPackageType(p.Type),
		Name:        p.Name,
		Version:     p.Version,
		Description: p.Description,
		PURL:        purl,
	}
	if lic := firstNonEmpty(p.LicenseDeclared, p.LicenseConcluded); lic != "" {
		c.Licenses = []cdxLicense{{License: &cdxLicenseID{ID: lic}, ID: lic}}
	}
	if len(p.Properties) > 0 {
		c.Properties = make([]cdxProperty, len(p.Properties))
		for i := range p.Properties {
			c.Properties[i] = cdxProperty(p.Properties[i])
		}
	}
	return c
}

func cdxPackageType(packageType string) string {
	switch packageType {
	case "APPLICATION":
		return "application"
	case "CONTAINER":
		return "container"
	case "DATA":
		return "data"
	case "DEVICE":
		return "device"
	case "DEVICE-DRIVER":
		return "device-driver"
	case "FILE":
		return "file"
	case "FIRMWARE":
		return "firmware"
	case "FRAMEWORK":
		return "framework"
	case "LIBRARY":
		return "library"
	case "MACHINE-LEARNING-MODEL":
		return "machine-learning-model"
	case "OPERATING-SYSTEM":
		return "operating-system"
	case "PLATFORM":
		return "platform"
	case "CRYPTOGRAPHIC-ASSET":
		return "cryptographic-asset"
	case "":
		return cdxDefaultCompType
	}
	return strings.ToLower(packageType)
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
	creatorCount := len(s.Document.Creators)
	if s.Document.Supplier != "" {
		creatorCount++
	}
	if creatorCount > 0 {
		doc.CreationInfo.Creators = make([]string, 0, creatorCount)
		for i := range s.Document.Creators {
			creator := &s.Document.Creators[i]
			doc.CreationInfo.Creators = append(doc.CreationInfo.Creators, creator.Type+": "+creator.Name)
		}
		if s.Document.Supplier != "" {
			doc.CreationInfo.Creators = append(doc.CreationInfo.Creators,
				SupplierOrganization+": "+s.Document.Supplier)
		}
	}

	root := spdxPackage{
		SPDXID: spdxRootPkgID, Name: s.Document.Component.Name,
		VersionInfo: s.Document.Component.Version, DownloadLocation: spdxNoAssertion,
	}
	root.LicenseDeclared, doc.ExtractedLicensingInfos = componentLicensesToSPDX(s.Document.Component)
	doc.Packages = make([]spdxPackage, len(s.Packages)+1)
	doc.Packages[0] = root
	doc.Relationships = make([]spdxRelationship, len(s.Packages))
	for i := range s.Packages {
		sp := packageToSPDX(&s.Packages[i], i)
		doc.Packages[i+1] = sp
		doc.Relationships[i] = spdxRelationship{
			SPDXElementID: spdxRootPkgID, RelationshipType: RelDependsOn,
			RelatedSPDXElement: sp.SPDXID,
		}
	}
	return doc
}

func componentLicensesToCDX(c Component) []cdxLicense {
	if c.LicenseExpression != "" && len(c.LicenseNames) == 0 && len(c.ExtractedLicenses) == 0 {
		return []cdxLicense{{Expression: c.LicenseExpression}}
	}

	licenses := make([]cdxLicense, 0, 1+len(c.LicenseNames)+len(c.ExtractedLicenses))
	if c.LicenseExpression != "" {
		licenses = append(licenses, cdxNamedLicense(c.LicenseExpression))
	}
	for _, name := range c.LicenseNames {
		if name != "" {
			licenses = append(licenses, cdxNamedLicense(name))
		}
	}
	for _, extracted := range c.ExtractedLicenses {
		if extracted.Name != "" {
			licenses = append(licenses, cdxNamedLicense(extracted.Name))
		}
	}
	return licenses
}

func cdxNamedLicense(name string) cdxLicense {
	return cdxLicense{License: &cdxLicenseID{Name: name}, Name: name}
}

func componentLicensesToSPDX(c Component) (string, []spdxExtractedLicenseInfo) {
	parts := make([]string, 0, 1+len(c.LicenseNames)+len(c.ExtractedLicenses))
	if c.LicenseExpression != "" {
		parts = append(parts, c.LicenseExpression)
	}

	infos := make([]spdxExtractedLicenseInfo, 0, len(c.LicenseNames)+len(c.ExtractedLicenses))
	seen := make(map[string]bool)
	appendInfo := func(info spdxExtractedLicenseInfo) {
		if seen[info.LicenseID] {
			return
		}
		seen[info.LicenseID] = true
		parts = append(parts, info.LicenseID)
		infos = append(infos, info)
	}
	for _, name := range c.LicenseNames {
		if name == "" {
			continue
		}
		id := extractedLicenseID("", name, name)
		appendInfo(spdxExtractedLicenseInfo{LicenseID: id, Name: name, ExtractedText: name})
	}
	for _, extracted := range c.ExtractedLicenses {
		if extracted.Name == "" && extracted.Text == "" {
			continue
		}
		text := firstNonEmpty(extracted.Text, extracted.Name)
		id := extractedLicenseID(extracted.ID, extracted.Name, text)
		appendInfo(spdxExtractedLicenseInfo{
			LicenseID: id, Name: extracted.Name, ExtractedText: text,
		})
	}
	return joinLicenseExpression(parts), infos
}

func extractedLicenseID(id, name, text string) string {
	if id != "" {
		if strings.HasPrefix(id, "LicenseRef-") {
			return id
		}
		return "LicenseRef-" + id
	}
	digest := sha256.Sum256([]byte(name + "\x00" + text))
	return fmt.Sprintf("LicenseRef-Component-%x", digest[:8])
}

func joinLicenseExpression(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	for i, part := range parts {
		if len(parts) > 1 && (strings.Contains(part, " AND ") || strings.Contains(part, " OR ")) {
			parts[i] = "(" + part + ")"
		}
	}
	return strings.Join(parts, " AND ")
}

func packageToSPDX(p *Package, i int) spdxPackage {
	sp := spdxPackage{
		SPDXID:           p.ID,
		Name:             p.Name,
		VersionInfo:      p.Version,
		DownloadLocation: firstNonEmpty(p.DownloadLocation, spdxNoAssertion),
		LicenseConcluded: firstNonEmpty(p.LicenseConcluded, spdxNoAssertion),
		LicenseDeclared:  firstNonEmpty(p.LicenseDeclared, spdxNoAssertion),
	}
	if sp.SPDXID == "" {
		sp.SPDXID = "SPDXRef-Package-" + strconv.Itoa(i)
	}
	if purl := p.PURL(); purl != "" {
		sp.ExternalRefs = []spdxExtRef{{
			Category: "PACKAGE-MANAGER", Type: purlExternalReferenceType, Locator: purl,
		}}
	}
	return sp
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
