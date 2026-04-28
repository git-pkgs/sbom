package sbom

import (
	"encoding/json"
	"encoding/xml"
	"strings"
)

const (
	cdxXMLNS           = "http://cyclonedx.org/schema/bom/1.5"
	cdxSpecVersion     = "1.5"
	cdxDefaultCompType = "library"
)

type cdxBOM struct {
	XMLName      xml.Name        `json:"-"             xml:"bom"`
	XMLNS        string          `json:"-"             xml:"xmlns,attr"`
	BOMFormat    string          `json:"bomFormat"     xml:"-"`
	SpecVersion  string          `json:"specVersion"   xml:"-"`
	BOMVersion   int             `json:"version"       xml:"version,attr"`
	SerialNumber string          `json:"serialNumber,omitempty" xml:"serialNumber,attr,omitempty"`
	Metadata     *cdxMetadata    `json:"metadata,omitempty"     xml:"metadata,omitempty"`
	Components   []cdxComponent  `json:"components"    xml:"components>component"`
	Dependencies []cdxDependency `json:"dependencies,omitempty" xml:"dependencies>dependency,omitempty"`
}

type cdxMetadata struct {
	Timestamp   string        `json:"timestamp,omitempty"   xml:"timestamp,omitempty"`
	Tools       []cdxTool     `json:"-"                     xml:"tools>tool,omitempty"`
	Component   *cdxComponent `json:"component,omitempty"   xml:"component,omitempty"`
	Supplier    *cdxOrgEntity `json:"supplier,omitempty"    xml:"supplier,omitempty"`
	Manufacture *cdxOrgEntity `json:"manufacture,omitempty" xml:"-"`
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
	BOMRef             string         `json:"bom-ref,omitempty"     xml:"bom-ref,attr,omitempty"`
	Type               string         `json:"type"                  xml:"type,attr"`
	Name               string         `json:"name"                  xml:"name"`
	Version            string         `json:"version,omitempty"     xml:"version,omitempty"`
	Description        string         `json:"description,omitempty" xml:"description,omitempty"`
	Copyright          string         `json:"copyright,omitempty"   xml:"copyright,omitempty"`
	Author             string         `json:"author,omitempty"      xml:"author,omitempty"`
	PURL               string         `json:"purl,omitempty"        xml:"purl,omitempty"`
	Supplier           *cdxOrgEntity  `json:"supplier,omitempty"    xml:"supplier,omitempty"`
	Hashes             []cdxHash      `json:"hashes,omitempty"      xml:"hashes>hash,omitempty"`
	Licenses           []cdxLicense   `json:"licenses,omitempty"    xml:"licenses>license,omitempty"`
	ExternalReferences []cdxExtRef    `json:"externalReferences,omitempty" xml:"externalReferences>reference,omitempty"`
	Properties         []cdxProperty  `json:"properties,omitempty"  xml:"properties>property,omitempty"`
	Components         []cdxComponent `json:"components,omitempty"  xml:"components>component,omitempty"`
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
	if bom.BOMFormat != "CycloneDX" {
		return nil, ErrUnrecognized
	}

	s := newSBOM(TypeCycloneDX)
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

	for _, d := range bom.Dependencies {
		for _, t := range d.DependsOn {
			s.Relationships = append(s.Relationships, Relationship{
				SourceID: d.Ref, TargetID: t, Type: "DEPENDS_ON",
			})
		}
	}

	return s, nil
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
				SourceID: parent, TargetID: ref, Type: "DEPENDS_ON",
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
	if c.Supplier != nil && c.Supplier.Name != "" {
		p.Supplier = c.Supplier.Name
		p.SupplierType = SupplierOrganization
	}
	if c.Author != "" {
		p.Originator = c.Author
		p.OriginatorType = SupplierPerson
	}
	for _, h := range c.Hashes {
		p.Checksums = append(p.Checksums, Checksum{
			Algorithm: strings.ReplaceAll(h.Alg, "-", ""),
			Value:     h.Content,
		})
	}
	for _, l := range c.Licenses {
		if id := l.value(); id != "" {
			p.LicenseConcluded = id
			p.LicenseDeclared = id
		}
	}
	if c.PURL != "" {
		p.ExternalRefs = append(p.ExternalRefs, ExternalRef{
			Category: "PACKAGE_MANAGER", Type: "purl", Locator: c.PURL,
		})
	}
	for _, r := range c.ExternalReferences {
		p.ExternalRefs = append(p.ExternalRefs, ExternalRef{
			Category: r.Type, Type: r.Type, Locator: r.URL,
		})
	}
	for _, pr := range c.Properties {
		p.Properties = append(p.Properties, Property(pr))
	}
	return p
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
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(t), "_", "-"))
}
