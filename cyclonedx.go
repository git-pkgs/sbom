package sbom

import (
	"encoding/json"
	"encoding/xml"
	"strings"
)

const (
	cdxBOMFormat       = "CycloneDX"
	cdxXMLNS           = "http://cyclonedx.org/schema/bom/1.5"
	cdxSpecVersion     = "1.5"
	cdxDefaultCompType = "library"
)

type cdxBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	BOMVersion   int             `json:"version"`
	SerialNumber string          `json:"serialNumber,omitempty"`
	Metadata     *cdxMetadata    `json:"metadata,omitempty"`
	Components   []cdxComponent  `json:"components,omitempty"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxBOMXML struct {
	XMLName      xml.Name            `xml:"bom"`
	XMLNS        string              `xml:"xmlns,attr"`
	Version      int                 `xml:"version,attr"`
	SerialNumber string              `xml:"serialNumber,attr,omitempty"`
	Metadata     *cdxMetadataXML     `xml:"metadata,omitempty"`
	Components   *cdxComponentsXML   `xml:"components,omitempty"`
	Dependencies *cdxDependenciesXML `xml:"dependencies,omitempty"`
}

type cdxMetadataXML struct {
	Timestamp string           `xml:"timestamp,omitempty"`
	Tools     *cdxToolsXML     `xml:"tools,omitempty"`
	Component *cdxComponentXML `xml:"component,omitempty"`
	Supplier  *cdxOrgEntity    `xml:"supplier,omitempty"`
}

type cdxToolsXML struct {
	Tools []cdxTool `xml:"tool"`
}

type cdxComponentsXML struct {
	Components []cdxComponentXML `xml:"component"`
}

type cdxDependenciesXML struct {
	Dependencies []cdxDependency `xml:"dependency"`
}

type cdxComponentXML struct {
	BOMRef             string                    `xml:"bom-ref,attr,omitempty"`
	Type               string                    `xml:"type,attr"`
	Name               string                    `xml:"name"`
	Version            string                    `xml:"version,omitempty"`
	Description        string                    `xml:"description,omitempty"`
	Copyright          string                    `xml:"copyright,omitempty"`
	Author             string                    `xml:"author,omitempty"`
	PURL               string                    `xml:"purl,omitempty"`
	Supplier           *cdxOrgEntity             `xml:"supplier,omitempty"`
	Hashes             *cdxHashesXML             `xml:"hashes,omitempty"`
	Licenses           *cdxLicensesXML           `xml:"licenses,omitempty"`
	ExternalReferences *cdxExternalReferencesXML `xml:"externalReferences,omitempty"`
	Properties         *cdxPropertiesXML         `xml:"properties,omitempty"`
	Components         *cdxComponentsXML         `xml:"components,omitempty"`
}

type cdxHashesXML struct {
	Hashes []cdxHash `xml:"hash"`
}

type cdxLicensesXML struct {
	Licenses   []cdxLicense `xml:"license,omitempty"`
	Expression string       `xml:"expression,omitempty"`
}

type cdxExternalReferencesXML struct {
	References []cdxExtRef `xml:"reference"`
}

type cdxPropertiesXML struct {
	Properties []cdxProperty `xml:"property"`
}

func cycloneDXXML(bom *cdxBOM) cdxBOMXML {
	result := cdxBOMXML{
		XMLNS: cdxXMLNS, Version: bom.BOMVersion, SerialNumber: bom.SerialNumber,
	}
	if bom.Metadata != nil {
		result.Metadata = &cdxMetadataXML{
			Timestamp: bom.Metadata.Timestamp,
			Component: cdxComponentToXMLPtr(bom.Metadata.Component),
			Supplier:  bom.Metadata.Supplier,
		}
		if len(bom.Metadata.Tools) > 0 {
			result.Metadata.Tools = &cdxToolsXML{Tools: bom.Metadata.Tools}
		}
	}
	if len(bom.Components) > 0 {
		result.Components = componentsToXML(bom.Components)
	}
	if len(bom.Dependencies) > 0 {
		result.Dependencies = &cdxDependenciesXML{Dependencies: bom.Dependencies}
	}
	return result
}

func componentsToXML(components []cdxComponent) *cdxComponentsXML {
	result := &cdxComponentsXML{Components: make([]cdxComponentXML, 0, len(components))}
	for i := range components {
		result.Components = append(result.Components, cdxComponentToXML(&components[i]))
	}
	return result
}

func cdxComponentToXMLPtr(component *cdxComponent) *cdxComponentXML {
	if component == nil {
		return nil
	}
	result := cdxComponentToXML(component)
	return &result
}

func cdxComponentToXML(component *cdxComponent) cdxComponentXML {
	result := cdxComponentXML{
		BOMRef: component.BOMRef, Type: component.Type, Name: component.Name,
		Version: component.Version, Description: component.Description,
		Copyright: component.Copyright, Author: component.Author, PURL: component.PURL,
		Supplier: component.Supplier,
	}
	if len(component.Hashes) > 0 {
		result.Hashes = &cdxHashesXML{Hashes: component.Hashes}
	}
	if len(component.Licenses) > 0 {
		result.Licenses = licensesToXML(component.Licenses)
	}
	if len(component.ExternalReferences) > 0 {
		result.ExternalReferences = &cdxExternalReferencesXML{References: component.ExternalReferences}
	}
	if len(component.Properties) > 0 {
		result.Properties = &cdxPropertiesXML{Properties: component.Properties}
	}
	if len(component.Components) > 0 {
		result.Components = componentsToXML(component.Components)
	}
	return result
}

func licensesToXML(licenses []cdxLicense) *cdxLicensesXML {
	result := &cdxLicensesXML{}
	if len(licenses) == 1 && licenses[0].Expression != "" {
		result.Expression = licenses[0].Expression
		return result
	}
	result.Licenses = make([]cdxLicense, 0, len(licenses))
	for _, license := range licenses {
		if license.License != nil {
			license.ID = license.License.ID
			license.Name = license.License.Name
		}
		result.Licenses = append(result.Licenses, license)
	}
	return result
}

type cdxMetadata struct {
	Timestamp   string        `json:"timestamp,omitempty"`
	Tools       []cdxTool     `json:"-"`
	Component   *cdxComponent `json:"component,omitempty"`
	Supplier    *cdxOrgEntity `json:"supplier,omitempty"`
	Manufacture *cdxOrgEntity `json:"manufacture,omitempty"`
}

// CycloneDX 1.5+ replaced metadata.tools with metadata.tools.components, but
// plenty of generators still emit the legacy array. We only emit the legacy
// shape (matches what git-pkgs has always written) and ignore tools on parse.
type cdxTool struct {
	Vendor  string `json:"vendor"  xml:"vendor"`
	Name    string `json:"name"    xml:"name"`
	Version string `json:"version" xml:"version"`
}

type cdxOrgEntity struct {
	Name string `json:"name" xml:"name"`
}

type cdxComponent struct {
	BOMRef             string         `json:"bom-ref,omitempty"`
	Type               string         `json:"type"`
	Name               string         `json:"name"`
	Version            string         `json:"version,omitempty"`
	Description        string         `json:"description,omitempty"`
	Copyright          string         `json:"copyright,omitempty"`
	Author             string         `json:"author,omitempty"`
	PURL               string         `json:"purl,omitempty"`
	Supplier           *cdxOrgEntity  `json:"supplier,omitempty"`
	Hashes             []cdxHash      `json:"hashes,omitempty"`
	Licenses           []cdxLicense   `json:"licenses,omitempty"`
	ExternalReferences []cdxExtRef    `json:"externalReferences,omitempty"`
	Properties         []cdxProperty  `json:"properties,omitempty"`
	Components         []cdxComponent `json:"components,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"     xml:"alg,attr"`
	Content string `json:"content" xml:",chardata"`
}

// cdxLicense has different nesting in JSON vs XML: JSON wraps the id/name in
// a "license" object, XML puts <id>/<name> directly under <license>. The JSON
// path uses License; the XML path uses ID/Name.
type cdxLicense struct {
	License    *cdxLicenseID `json:"license,omitempty"    xml:"-"`
	Expression string        `json:"expression,omitempty" xml:"expression,omitempty"`
	ID         string        `json:"-"                    xml:"id,omitempty"`
	Name       string        `json:"-"                    xml:"name,omitempty"`
}

type cdxLicenseID struct {
	ID   string `json:"id,omitempty"   xml:"id,omitempty"`
	Name string `json:"name,omitempty" xml:"name,omitempty"`
}

type cdxExtRef struct {
	Type string `json:"type" xml:"type,attr"`
	URL  string `json:"url"  xml:"url"`
}

type cdxProperty struct {
	Name  string `json:"name"  xml:"name,attr"`
	Value string `json:"value" xml:",chardata"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"                 xml:"ref,attr"`
	DependsOn []string `json:"dependsOn,omitempty" xml:"dependency,omitempty"`
}

func parseCycloneDX(data []byte) (*SBOM, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, wrapErr("cyclonedx json", err)
	}
	if bom.BOMFormat != cdxBOMFormat {
		return nil, ErrUnrecognized
	}

	packageCount := len(bom.Components)
	nestedRelationshipCount := 0
	for i := range bom.Components {
		if len(bom.Components[i].Components) > 0 {
			packageCount, nestedRelationshipCount = cdxComponentStats(bom.Components)
			break
		}
	}
	relationshipCount := nestedRelationshipCount
	for i := range bom.Dependencies {
		relationshipCount += len(bom.Dependencies[i].DependsOn)
	}

	s := newSizedSBOM(TypeCycloneDX, packageCount, relationshipCount)
	s.SpecVersion = bom.SpecVersion
	s.Document = Document{
		ID:          bom.SerialNumber,
		Type:        TypeCycloneDX,
		SpecVersion: bom.SpecVersion,
	}

	if m := bom.Metadata; m != nil {
		s.Document.Created = m.Timestamp
		if m.Component != nil {
			s.Document.Name = m.Component.Name
			s.Document.Component = Component{
				Type:    m.Component.Type,
				Name:    m.Component.Name,
				Version: m.Component.Version,
			}
		}
		if m.Supplier != nil {
			s.Document.Supplier = m.Supplier.Name
		} else if m.Manufacture != nil {
			s.Document.Supplier = m.Manufacture.Name
		}
	}

	cdxWalkComponents(s, bom.Components, "")

	for i := range bom.Dependencies {
		d := &bom.Dependencies[i]
		for _, t := range d.DependsOn {
			s.Relationships = append(s.Relationships, Relationship{
				SourceID: d.Ref, TargetID: t, Type: RelDependsOn,
			})
		}
	}

	return s, nil
}

func cdxComponentStats(components []cdxComponent) (packages, relationships int) {
	packages = len(components)
	for i := range components {
		children := components[i].Components
		relationships += len(children)
		childPackages, childRelationships := cdxComponentStats(children)
		packages += childPackages
		relationships += childRelationships
	}
	return packages, relationships
}

func cdxWalkComponents(s *SBOM, comps []cdxComponent, parent string) {
	for i := range comps {
		c := &comps[i]
		s.addPackage(cdxPackage(c))

		ref := c.BOMRef
		if ref == "" {
			ref = c.Name
		}
		if parent != "" {
			s.Relationships = append(s.Relationships, Relationship{
				SourceID: parent, TargetID: ref, Type: RelDependsOn,
			})
		}
		if len(c.Components) > 0 {
			cdxWalkComponents(s, c.Components, ref)
		}
	}
}

func cdxPackage(c *cdxComponent) Package {
	p := Package{
		ID:          c.BOMRef,
		Name:        c.Name,
		Version:     c.Version,
		Type:        normalizePackageType(c.Type),
		Description: c.Description,
		Copyright:   c.Copyright,
	}
	if len(c.Hashes) > 0 {
		p.Checksums = make([]Checksum, len(c.Hashes))
		for i := range c.Hashes {
			p.Checksums[i] = Checksum{
				Algorithm: normalizeChecksumAlgorithm(c.Hashes[i].Alg),
				Value:     c.Hashes[i].Content,
			}
		}
	}
	if c.Supplier != nil && c.Supplier.Name != "" {
		p.Supplier = c.Supplier.Name
		p.SupplierType = SupplierOrganization
	}
	if c.Author != "" {
		p.Originator = c.Author
		p.OriginatorType = SupplierPerson
	}
	for _, l := range c.Licenses {
		if id := l.value(); id != "" {
			p.LicenseConcluded = id
			p.LicenseDeclared = id
		}
	}
	externalReferenceCount := len(c.ExternalReferences)
	if c.PURL != "" {
		externalReferenceCount++
	}
	if externalReferenceCount > 0 {
		p.ExternalRefs = make([]ExternalRef, externalReferenceCount)
		next := 0
		if c.PURL != "" {
			p.ExternalRefs[0] = ExternalRef{
				Category: "PACKAGE_MANAGER", Type: purlExternalReferenceType, Locator: c.PURL,
			}
			next = 1
		}
		for i := range c.ExternalReferences {
			r := &c.ExternalReferences[i]
			p.ExternalRefs[next+i] = ExternalRef{
				Category: r.Type, Type: r.Type, Locator: r.URL,
			}
		}
	}
	if len(c.Properties) > 0 {
		p.Properties = make([]Property, len(c.Properties))
		for i := range c.Properties {
			p.Properties[i] = Property(c.Properties[i])
		}
	}
	return p
}

func normalizeChecksumAlgorithm(algorithm string) string {
	switch algorithm {
	case "MD-5":
		return "MD5"
	case "SHA-1":
		return "SHA1"
	case "SHA-256":
		return "SHA256"
	case "SHA-384":
		return "SHA384"
	case "SHA-512":
		return "SHA512"
	case "SHA3-256":
		return "SHA3256"
	case "SHA3-384":
		return "SHA3384"
	case "SHA3-512":
		return "SHA3512"
	}
	return strings.ReplaceAll(algorithm, "-", "")
}

func (l cdxLicense) value() string {
	if l.Expression != "" {
		return l.Expression
	}
	if l.License == nil {
		return ""
	}
	if l.License.ID != "" {
		return l.License.ID
	}
	return l.License.Name
}

func normalizePackageType(t string) string {
	t = strings.TrimSpace(t)
	switch t {
	case "application":
		return "APPLICATION"
	case "container":
		return "CONTAINER"
	case "data":
		return "DATA"
	case "device":
		return "DEVICE"
	case "device-driver":
		return "DEVICE-DRIVER"
	case "file":
		return "FILE"
	case "firmware":
		return "FIRMWARE"
	case "framework":
		return "FRAMEWORK"
	case "library":
		return "LIBRARY"
	case "machine-learning-model":
		return "MACHINE-LEARNING-MODEL"
	case "operating-system":
		return "OPERATING-SYSTEM"
	case "platform":
		return "PLATFORM"
	case "cryptographic-asset":
		return "CRYPTOGRAPHIC-ASSET"
	}
	return strings.ToUpper(strings.ReplaceAll(t, "_", "-"))
}
