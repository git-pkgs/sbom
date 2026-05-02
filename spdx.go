package sbom

import (
	"encoding/json"
	"strings"
)

type spdxDoc struct {
	SPDXVersion       string             `json:"spdxVersion"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DataLicense       string             `json:"dataLicense"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      *spdxCreationInfo  `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships,omitempty"`

	// Envelope unwrapping: GitHub's dependency-graph API nests under
	// "sbom", and in-toto attestations nest under "predicate".
	SBOM          json.RawMessage `json:"sbom,omitempty"`
	Predicate     json.RawMessage `json:"predicate,omitempty"`
	PredicateType string          `json:"predicateType,omitempty"`
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

func parseSPDX(data []byte) (*SBOM, error) {
	var doc spdxDoc
	for range maxEnvelopeDepth {
		doc = spdxDoc{}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, wrapErr("spdx json", err)
		}
		if len(doc.SBOM) > 0 {
			data = doc.SBOM
			continue
		}
		if strings.Contains(doc.PredicateType, "spdx") && len(doc.Predicate) > 0 {
			data = doc.Predicate
			continue
		}
		break
	}
	if doc.SPDXVersion == "" && doc.SPDXID == "" {
		return nil, ErrUnrecognized
	}

	s := newSBOM(TypeSPDX)
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
		for _, c := range ci.Creators {
			typ, name := splitColon(c)
			if typ == SupplierOrganization {
				s.Document.Supplier = name
			} else {
				s.Document.Creators = append(s.Document.Creators, Creator{Type: typ, Name: name})
			}
		}
	}

	elements := map[string]string{doc.SPDXID: doc.Name}
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
		for _, c := range sp.Checksums {
			p.Checksums = append(p.Checksums, Checksum(c))
		}
		for _, r := range sp.ExternalRefs {
			p.ExternalRefs = append(p.ExternalRefs, ExternalRef(r))
		}
		elements[sp.SPDXID] = sp.Name
		s.addPackage(p)
	}

	for _, r := range doc.Relationships {
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

func splitColon(s string) (typ, name string) {
	if i := strings.Index(s, ": "); i >= 0 {
		return s[:i], s[i+2:]
	}
	return "", s
}
