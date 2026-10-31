package sbom

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"unicode"
)

const spdxTripleFields = 3

func detectSPDXTagValue(data []byte) detectedFormat {
	scanner := newSPDXScanner(data)
	for scanner.Scan() {
		line := strings.TrimLeftFunc(scanner.Text(), unicode.IsSpace)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tag, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(tag) == "PackageName" {
			break
		}
		value, err := readSPDXText(scanner, value)
		if err != nil {
			break
		}
		if strings.TrimSpace(tag) == "SPDXVersion" && strings.HasPrefix(value, "SPDX-") {
			return detectedFormat{typ: TypeSPDX, tagValue: true}
		}
	}
	return detectedFormat{}
}

func newSPDXScanner(data []byte) *bufio.Scanner {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, len(data)+1)
	return scanner
}

type spdxTagParser struct {
	doc        spdxDoc
	pkg        *spdxPackage
	inDocument bool
}

func parseSPDXTagValue(data []byte) (*SBOM, error) {
	p := spdxTagParser{inDocument: true}
	scanner := newSPDXScanner(data)
	for scanner.Scan() {
		line := strings.TrimLeftFunc(scanner.Text(), unicode.IsSpace)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tag, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(tag) == "" {
			return nil, wrapErr("spdx tag-value", fmt.Errorf("expected tag: value, got %q", line))
		}
		value, err := readSPDXText(scanner, value)
		if err != nil {
			return nil, wrapErr("spdx tag-value", err)
		}
		if err := p.apply(strings.TrimSpace(tag), value); err != nil {
			return nil, wrapErr("spdx tag-value", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, wrapErr("spdx tag-value", err)
	}
	return normalizeSPDX(&p.doc), nil
}

func readSPDXText(scanner *bufio.Scanner, value string) (string, error) {
	text, multiline := strings.CutPrefix(strings.TrimLeftFunc(value, unicode.IsSpace), "<text>")
	if !multiline {
		return strings.TrimSpace(value), nil
	}
	var b strings.Builder
	for {
		before, after, closed := strings.Cut(text, "</text>")
		b.WriteString(before)
		if closed {
			if strings.TrimSpace(after) != "" {
				return "", fmt.Errorf("unexpected content after </text>")
			}
			return b.String(), nil
		}
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("unterminated <text> value")
		}
		b.WriteByte('\n')
		text = scanner.Text()
	}
}

func (p *spdxTagParser) apply(tag, value string) error {
	switch tag {
	case "SPDXVersion":
		p.doc.SPDXVersion = value
	case "DataLicense":
		p.doc.DataLicense = value
	case "DocumentName":
		p.doc.Name = value
	case "DocumentNamespace":
		p.doc.DocumentNamespace = value
	case "Creator", "Created", "LicenseListVersion":
		p.creationInfo(tag, value)
	case "PackageName":
		p.inDocument = false
		p.doc.Packages = append(p.doc.Packages, spdxPackage{Name: value})
		p.pkg = &p.doc.Packages[len(p.doc.Packages)-1]
	case "FileName", "SnippetSPDXID", "LicenseID", "Annotator", "Reviewer":
		p.inDocument = false
		p.pkg = nil
	case "SPDXID":
		if p.pkg != nil {
			p.pkg.SPDXID = value
		} else if p.inDocument {
			p.doc.SPDXID = value
		}
	case "Relationship":
		fields := strings.Fields(value)
		if len(fields) != spdxTripleFields {
			return fmt.Errorf("invalid Relationship %q", value)
		}
		p.doc.Relationships = append(p.doc.Relationships, spdxRelationship{
			SPDXElementID: fields[0], RelationshipType: fields[1], RelatedSPDXElement: fields[2],
		})
	default:
		if p.pkg != nil {
			return p.packageField(tag, value)
		}
	}
	return nil
}

func (p *spdxTagParser) creationInfo(tag, value string) {
	if p.doc.CreationInfo == nil {
		p.doc.CreationInfo = &spdxCreationInfo{}
	}
	switch tag {
	case "Creator":
		p.doc.CreationInfo.Creators = append(p.doc.CreationInfo.Creators, value)
	case "Created":
		p.doc.CreationInfo.Created = value
	case "LicenseListVersion":
		p.doc.CreationInfo.LicenseListVersion = value
	}
}

func (p *spdxTagParser) packageField(tag, value string) error {
	switch tag {
	case "PackageVersion":
		p.pkg.VersionInfo = value
	case "PackageFileName":
		p.pkg.PackageFileName = value
	case "PackageSupplier":
		p.pkg.Supplier = value
	case "PackageOriginator":
		p.pkg.Originator = value
	case "PackageDownloadLocation":
		p.pkg.DownloadLocation = value
	case "PackageHomePage":
		p.pkg.Homepage = value
	case "PackageLicenseConcluded":
		p.pkg.LicenseConcluded = value
	case "PackageLicenseDeclared":
		p.pkg.LicenseDeclared = value
	case "PackageCopyrightText":
		p.pkg.CopyrightText = value
	case "PackageDescription":
		p.pkg.Description = value
	case "PackageSourceInfo":
		p.pkg.SourceInfo = value
	case "PrimaryPackagePurpose":
		p.pkg.PrimaryPackagePurpose = value
	case "PackageChecksum":
		algorithm, checksum, ok := strings.Cut(value, ":")
		algorithm, checksum = strings.TrimSpace(algorithm), strings.TrimSpace(checksum)
		if !ok || algorithm == "" || checksum == "" {
			return fmt.Errorf("invalid PackageChecksum %q", value)
		}
		p.pkg.Checksums = append(p.pkg.Checksums, spdxChecksum{Algorithm: algorithm, Value: checksum})
	case "ExternalRef":
		fields := strings.Fields(value)
		if len(fields) != spdxTripleFields {
			return fmt.Errorf("invalid ExternalRef %q", value)
		}
		p.pkg.ExternalRefs = append(p.pkg.ExternalRefs, spdxExtRef{Category: fields[0], Type: fields[1], Locator: fields[2]})
	}
	return nil
}
