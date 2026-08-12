package sbom

import (
	"encoding/json"
	"strings"
)

type spdxDoc struct {
	SPDXVersion             string                     `json:"spdxVersion"`
	SPDXID                  string                     `json:"SPDXID"`
	Name                    string                     `json:"name"`
	DataLicense             string                     `json:"dataLicense"`
	DocumentNamespace       string                     `json:"documentNamespace"`
	CreationInfo            *spdxCreationInfo          `json:"creationInfo"`
	Packages                []spdxPackage              `json:"packages"`
	Relationships           []spdxRelationship         `json:"relationships,omitempty"`
	ExtractedLicensingInfos []spdxExtractedLicenseInfo `json:"hasExtractedLicensingInfos,omitempty"`
}

type spdxEnvelope struct {
	SBOM          json.RawMessage `json:"sbom"`
	Predicate     json.RawMessage `json:"predicate"`
	PredicateType string          `json:"predicateType"`
}

type spdxExtractedLicenseInfo struct {
	LicenseID     string `json:"licenseId"`
	ExtractedText string `json:"extractedText"`
	Name          string `json:"name,omitempty"`
}

type spdxCreationInfo struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion"`
}

type spdxPackage struct {
	SPDXID                string         `json:"SPDXID"`
	Name                  string         `json:"name"`
	VersionInfo           string         `json:"versionInfo,omitempty"`
	DownloadLocation      string         `json:"downloadLocation"`
	Homepage              string         `json:"homepage,omitempty"`
	PackageFileName       string         `json:"packageFileName,omitempty"`
	LicenseConcluded      string         `json:"licenseConcluded,omitempty"`
	LicenseDeclared       string         `json:"licenseDeclared,omitempty"`
	CopyrightText         string         `json:"copyrightText,omitempty"`
	Description           string         `json:"description,omitempty"`
	Supplier              string         `json:"supplier,omitempty"`
	Originator            string         `json:"originator,omitempty"`
	PrimaryPackagePurpose string         `json:"primaryPackagePurpose,omitempty"`
	Checksums             []spdxChecksum `json:"checksums,omitempty"`
	ExternalRefs          []spdxExtRef   `json:"externalRefs,omitempty"`
}

type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type spdxExtRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

const maxEnvelopeDepth = 3

func parseSPDX(data []byte, envelope bool) (*SBOM, error) {
	var err error
	data, err = unwrapSPDXEnvelope(data, envelope)
	if err != nil {
		return nil, err
	}

	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, wrapErr("spdx json", err)
	}
	if doc.SPDXVersion == "" && doc.SPDXID == "" {
		return nil, ErrUnrecognized
	}

	s := newSizedSBOM(TypeSPDX, len(doc.Packages), len(doc.Relationships))
	s.SpecVersion = doc.SPDXVersion
	s.Document = Document{
		Name:        doc.Name,
		ID:          doc.SPDXID,
		Type:        TypeSPDX,
		SpecVersion: doc.SPDXVersion,
		DataLicense: doc.DataLicense,
		Namespace:   doc.DocumentNamespace,
	}
	if ci := doc.CreationInfo; ci != nil {
		s.Document.Created = ci.Created
		s.Document.Creators = make([]Creator, 0, len(ci.Creators))
		for _, c := range ci.Creators {
			typ, name := splitColon(c)
			if typ == SupplierOrganization {
				s.Document.Supplier = name
			} else {
				s.Document.Creators = append(s.Document.Creators, Creator{Type: typ, Name: name})
			}
		}
	}

	var elements map[string]string
	if len(doc.Relationships) > 0 {
		elements = make(map[string]string, len(doc.Packages)+1)
		elements[doc.SPDXID] = doc.Name
	}
	for i := range doc.Packages {
		sp := &doc.Packages[i]
		p := Package{
			ID:               sp.SPDXID,
			Name:             sp.Name,
			Version:          sp.VersionInfo,
			Type:             normalizePackageType(sp.PrimaryPackagePurpose),
			Description:      sp.Description,
			Homepage:         sp.Homepage,
			DownloadLocation: sp.DownloadLocation,
			Filename:         sp.PackageFileName,
			LicenseConcluded: sp.LicenseConcluded,
			LicenseDeclared:  sp.LicenseDeclared,
			Copyright:        sp.CopyrightText,
		}
		if sp.Supplier != "" {
			p.SupplierType, p.Supplier = splitColon(sp.Supplier)
		}
		if sp.Originator != "" {
			p.OriginatorType, p.Originator = splitColon(sp.Originator)
		}
		if len(sp.Checksums) > 0 {
			p.Checksums = make([]Checksum, len(sp.Checksums))
			for i := range sp.Checksums {
				p.Checksums[i] = Checksum(sp.Checksums[i])
			}
		}
		if len(sp.ExternalRefs) > 0 {
			p.ExternalRefs = make([]ExternalRef, len(sp.ExternalRefs))
			for i := range sp.ExternalRefs {
				p.ExternalRefs[i] = ExternalRef(sp.ExternalRefs[i])
			}
		}
		if elements != nil {
			elements[sp.SPDXID] = sp.Name
		}
		s.addPackage(p)
	}

	for i := range doc.Relationships {
		r := &doc.Relationships[i]
		s.Relationships = append(s.Relationships, Relationship{
			SourceID: r.SPDXElementID,
			Source:   elements[r.SPDXElementID],
			TargetID: r.RelatedSPDXElement,
			Target:   elements[r.RelatedSPDXElement],
			Type:     r.RelationshipType,
		})
	}

	return s, nil
}

func unwrapSPDXEnvelope(data []byte, envelope bool) ([]byte, error) {
	for range maxEnvelopeDepth - 1 {
		if !envelope {
			break
		}
		var outer spdxEnvelope
		if err := json.Unmarshal(data, &outer); err != nil {
			return nil, wrapErr("spdx json", err)
		}
		if len(outer.SBOM) > 0 {
			data = outer.SBOM
			envelope = detect(data).spdxEnvelope
			continue
		}
		if strings.Contains(outer.PredicateType, "spdx") && len(outer.Predicate) > 0 {
			data = outer.Predicate
			envelope = detect(data).spdxEnvelope
			continue
		}
		break
	}
	return data, nil
}

func splitColon(s string) (typ, name string) {
	if i := strings.Index(s, ": "); i >= 0 {
		return s[:i], s[i+2:]
	}
	return "", s
}
