package sbom

import (
	"bufio"
	"bytes"
	"encoding/json/jsontext"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	tagLinePrefixLimit     = 4096
	tagLineInitialCapacity = 256
	spdxTextEnd            = "</text>"
)

var spdxTextEndBytes = []byte(spdxTextEnd)

type textEndState uint8

const (
	textEndAbsent textEndState = iota
	textEndValid
	textEndInvalid
)

// Metadata is the format information available without parsing an SBOM model.
type Metadata struct {
	Type        Type
	SpecVersion string
}

// Inspect reads enough of r to identify an SBOM and its specification version.
// It returns ErrUnrecognized when the content is unsupported or malformed.
func Inspect(r io.Reader) (Metadata, error) {
	if r == nil {
		return Metadata{}, ErrUnrecognized
	}

	source := &errorRecordingReader{reader: r}
	reader := bufio.NewReader(source)
	if err := trimReaderPrefix(reader); err != nil {
		return inspectResult(Metadata{}, err, source.err)
	}

	start, err := reader.Peek(1)
	if err != nil {
		return inspectResult(Metadata{}, err, source.err)
	}

	var metadata Metadata
	switch start[0] {
	case '{':
		metadata, err = inspectJSON(reader)
	case '<':
		metadata, err = inspectXML(reader)
	default:
		metadata, err = inspectTagValue(reader)
	}
	return inspectResult(metadata, err, source.err)
}

func inspectResult(metadata Metadata, parseErr, readErr error) (Metadata, error) {
	if readErr != nil {
		return Metadata{}, fmt.Errorf("sbom: inspect: %w", readErr)
	}
	if parseErr != nil {
		return Metadata{}, fmt.Errorf("%w: %v", ErrUnrecognized, parseErr)
	}
	if metadata.Type == TypeUnknown {
		return Metadata{}, ErrUnrecognized
	}
	return metadata, nil
}

type errorRecordingReader struct {
	reader io.Reader
	err    error
}

func (r *errorRecordingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

func trimReaderPrefix(reader *bufio.Reader) error {
	bomAllowed := true
	for {
		r, _, err := reader.ReadRune()
		if err != nil {
			return err
		}
		if unicode.IsSpace(r) {
			continue
		}
		if r == '\ufeff' && bomAllowed {
			bomAllowed = false
			continue
		}
		return reader.UnreadRune()
	}
}

type jsonInspection struct {
	bomFormat            string
	specVersion          string
	spdxVersion          string
	hasSPDXVersion       bool
	hasSPDXID            bool
	hasSBOM              bool
	sbomSpecVersion      string
	predicateType        string
	predicateSpecVersion string
}

func (i jsonInspection) metadata() Metadata {
	switch {
	case i.bomFormat == cdxBOMFormat:
		return Metadata{Type: TypeCycloneDX, SpecVersion: i.specVersion}
	case i.hasSPDXVersion || i.hasSPDXID:
		return Metadata{Type: TypeSPDX, SpecVersion: i.spdxVersion}
	case i.hasSBOM:
		return Metadata{Type: TypeSPDX, SpecVersion: i.sbomSpecVersion}
	case strings.Contains(i.predicateType, "spdx"):
		return Metadata{Type: TypeSPDX, SpecVersion: i.predicateSpecVersion}
	default:
		return Metadata{}
	}
}

func inspectJSON(reader io.Reader) (Metadata, error) {
	decoder := jsontext.NewDecoder(reader,
		jsontext.AllowDuplicateNames(true),
		jsontext.AllowInvalidUTF8(true),
	)
	inspection, err := inspectJSONObject(decoder, true)
	if err != nil {
		return Metadata{}, err
	}
	return inspection.metadata(), nil
}

func inspectJSONObject(decoder *jsontext.Decoder, stopWhenComplete bool) (jsonInspection, error) {
	opening, err := decoder.ReadToken()
	if err != nil {
		return jsonInspection{}, err
	}
	if opening.Kind() != '{' {
		return jsonInspection{}, fmt.Errorf("expected JSON object")
	}

	var inspection jsonInspection
	for decoder.PeekKind() != '}' {
		name, err := decoder.ReadToken()
		if err != nil {
			return jsonInspection{}, err
		}
		if name.Kind() != '"' {
			return jsonInspection{}, fmt.Errorf("expected JSON object name")
		}

		switch name.String() {
		case "bomFormat":
			inspection.bomFormat, err = readJSONString(decoder)
		case "specVersion":
			inspection.specVersion, err = readJSONString(decoder)
		case "spdxVersion":
			inspection.hasSPDXVersion = true
			inspection.spdxVersion, err = readJSONString(decoder)
		case spdxTagID:
			inspection.hasSPDXID = true
			err = decoder.SkipValue()
		case "sbom":
			inspection.hasSBOM = true
			var nested jsonInspection
			nested, err = inspectJSONValue(decoder, true)
			if metadata := nested.metadata(); metadata.Type == TypeSPDX {
				inspection.sbomSpecVersion = metadata.SpecVersion
			}
		case "predicateType":
			inspection.predicateType, err = readJSONString(decoder)
		case "predicate":
			var nested jsonInspection
			nested, err = inspectJSONValue(decoder, strings.Contains(inspection.predicateType, "spdx"))
			if metadata := nested.metadata(); metadata.Type == TypeSPDX {
				inspection.predicateSpecVersion = metadata.SpecVersion
			}
		default:
			err = decoder.SkipValue()
		}
		if err != nil {
			return jsonInspection{}, err
		}
		if metadata := inspection.metadata(); stopWhenComplete && metadata.Type != TypeUnknown && metadata.SpecVersion != "" {
			return inspection, nil
		}
	}
	if _, err := decoder.ReadToken(); err != nil {
		return jsonInspection{}, err
	}
	return inspection, nil
}

func inspectJSONValue(decoder *jsontext.Decoder, stopWhenComplete bool) (jsonInspection, error) {
	if decoder.PeekKind() != '{' {
		return jsonInspection{}, decoder.SkipValue()
	}
	return inspectJSONObject(decoder, stopWhenComplete)
}

func readJSONString(decoder *jsontext.Decoder) (string, error) {
	if decoder.PeekKind() != '"' {
		return "", decoder.SkipValue()
	}
	token, err := decoder.ReadToken()
	if err != nil {
		return "", err
	}
	return token.String(), nil
}

func inspectXML(reader io.Reader) (Metadata, error) {
	decoder := xml.NewDecoder(reader)
	for {
		token, err := decoder.Token()
		if err != nil {
			return Metadata{}, err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "bom" {
			return Metadata{}, nil
		}
		version := cycloneDXXMLVersion(start.Name.Space)
		if start.Name.Space != "" && version == "" {
			return Metadata{}, nil
		}
		return Metadata{Type: TypeCycloneDX, SpecVersion: version}, nil
	}
}

func inspectTagValue(reader *bufio.Reader) (Metadata, error) {
	inText := false
	for {
		line, textEnd, err := readLinePrefix(reader)
		if err == io.EOF {
			return Metadata{}, nil
		}
		if err != nil {
			return Metadata{}, err
		}
		if inText {
			closed, valid := inspectTextEnd(textEnd)
			if !valid {
				return Metadata{}, nil
			}
			inText = !closed
			continue
		}

		metadata, multiline, done := inspectTagLine(line, textEnd)
		if done {
			return metadata, nil
		}
		inText = multiline
	}
}

func inspectTextEnd(textEnd textEndState) (bool, bool) {
	if textEnd == textEndAbsent {
		return false, true
	}
	return true, textEnd == textEndValid
}

func inspectTagLine(line []byte, textEnd textEndState) (Metadata, bool, bool) {
	lineText := strings.TrimLeftFunc(string(line), unicode.IsSpace)
	if lineText == "" || strings.HasPrefix(lineText, "#") {
		return Metadata{}, false, false
	}
	tag, value, ok := strings.Cut(lineText, ":")
	tag = strings.TrimSpace(tag)
	if !ok || tag == spdxTagPackageName {
		return Metadata{}, false, true
	}

	value = strings.TrimLeftFunc(value, unicode.IsSpace)
	if text, multiline := strings.CutPrefix(value, "<text>"); multiline {
		if textEnd == textEndAbsent {
			return Metadata{}, true, false
		}
		if textEnd == textEndInvalid {
			return Metadata{}, false, true
		}
		value, _, _ = strings.Cut(text, spdxTextEnd)
	}
	value = strings.TrimSpace(value)
	if tag == spdxTagVersion && strings.HasPrefix(value, "SPDX-") {
		return Metadata{Type: TypeSPDX, SpecVersion: value}, false, true
	}
	return Metadata{}, false, false
}

func readLinePrefix(reader *bufio.Reader) ([]byte, textEndState, error) {
	prefix := make([]byte, 0, tagLineInitialCapacity)
	var tail [len(spdxTextEnd) - 1]byte
	tailLen := 0
	foundTextEnd := false
	var trailing textEndTrailing

	for {
		fragment, more, err := reader.ReadLine()
		if err != nil {
			return nil, textEndAbsent, err
		}
		if foundTextEnd {
			trailing.add(fragment)
		} else if after, found := fragmentTextEnd(tail[:tailLen], fragment); found {
			foundTextEnd = true
			trailing.add(after)
		} else {
			tailLen = updateTextTail(tail[:], tailLen, fragment)
		}
		if remaining := tagLinePrefixLimit - len(prefix); remaining > 0 {
			prefix = append(prefix, fragment[:min(remaining, len(fragment))]...)
		}
		if !more {
			switch {
			case !foundTextEnd:
				return prefix, textEndAbsent, nil
			case trailing.valid():
				return prefix, textEndValid, nil
			default:
				return prefix, textEndInvalid, nil
			}
		}
	}
}

func fragmentTextEnd(tail, fragment []byte) ([]byte, bool) {
	var boundary [2 * (len(spdxTextEnd) - 1)]byte
	n := copy(boundary[:], tail)
	n += copy(boundary[n:], fragment[:min(len(fragment), len(spdxTextEnd)-1)])
	index := bytes.Index(boundary[:n], spdxTextEndBytes)
	if index >= 0 {
		consumed := index + len(spdxTextEnd) - len(tail)
		return fragment[consumed:], true
	}
	if index := bytes.Index(fragment, spdxTextEndBytes); index >= 0 {
		return fragment[index+len(spdxTextEnd):], true
	}
	return nil, false
}

type textEndTrailing struct {
	pending    [utf8.UTFMax]byte
	pendingLen int
	invalid    bool
}

func (t *textEndTrailing) add(data []byte) {
	if t.invalid {
		return
	}
	if t.pendingLen > 0 {
		for len(data) > 0 && !utf8.FullRune(t.pending[:t.pendingLen]) {
			t.pending[t.pendingLen] = data[0]
			t.pendingLen++
			data = data[1:]
		}
		if !utf8.FullRune(t.pending[:t.pendingLen]) {
			return
		}
		r, _ := utf8.DecodeRune(t.pending[:t.pendingLen])
		if !unicode.IsSpace(r) {
			t.invalid = true
			return
		}
		t.pendingLen = 0
	}
	for len(data) > 0 {
		if !utf8.FullRune(data) {
			t.pendingLen = copy(t.pending[:], data)
			return
		}
		r, size := utf8.DecodeRune(data)
		if !unicode.IsSpace(r) {
			t.invalid = true
			return
		}
		data = data[size:]
	}
}

func (t *textEndTrailing) valid() bool {
	return !t.invalid && t.pendingLen == 0
}

func updateTextTail(tail []byte, tailLen int, fragment []byte) int {
	if len(fragment) >= len(tail) {
		return copy(tail, fragment[len(fragment)-len(tail):])
	}
	var combined [2 * (len(spdxTextEnd) - 1)]byte
	n := copy(combined[:], tail[:tailLen])
	n += copy(combined[n:], fragment)
	start := max(0, n-len(tail))
	return copy(tail, combined[start:n])
}
