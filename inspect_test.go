package sbom

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspect(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Metadata
	}{
		{
			name: "cyclonedx json",
			in:   `{"components":[{"name":"example"}],"specVersion":"1.6","bomFormat":"CycloneDX"}`,
			want: Metadata{Type: TypeCycloneDX, SpecVersion: "1.6"},
		},
		{
			name: "spdx json",
			in:   `{"packages":[],"spdxVersion":"SPDX-2.3"}`,
			want: Metadata{Type: TypeSPDX, SpecVersion: "SPDX-2.3"},
		},
		{
			name: "github envelope",
			in:   `{"sbom":{"packages":[],"spdxVersion":"SPDX-2.3"}}`,
			want: Metadata{Type: TypeSPDX, SpecVersion: "SPDX-2.3"},
		},
		{
			name: "predicate before type",
			in:   `{"predicate":{"packages":[],"spdxVersion":"SPDX-2.2"},"predicateType":"https://spdx.dev/Document"}`,
			want: Metadata{Type: TypeSPDX, SpecVersion: "SPDX-2.2"},
		},
		{
			name: "cyclonedx xml",
			in:   `<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components/></bom>`,
			want: Metadata{Type: TypeCycloneDX, SpecVersion: "1.5"},
		},
		{
			name: "spdx tag value",
			in:   "\ufeff  # generated\nDataLicense: CC0-1.0\nSPDXVersion: SPDX-2.3\nPackageName: example\n",
			want: Metadata{Type: TypeSPDX, SpecVersion: "SPDX-2.3"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Inspect(&chunkReader{reader: strings.NewReader(test.in), size: 3})
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("Inspect = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestInspectFixtures(t *testing.T) {
	err := filepath.WalkDir("testdata", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsed, err := Parse(data)
		if err != nil {
			return err
		}
		t.Run(path, func(t *testing.T) {
			metadata, err := Inspect(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			want := Metadata{Type: parsed.Type, SpecVersion: parsed.SpecVersion}
			if metadata != want {
				t.Fatalf("Inspect = %+v, want %+v", metadata, want)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInspectStopsAfterMetadata(t *testing.T) {
	input := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` + strings.Repeat(`{"name":"example"},`, 100_000) + `{"name":"last"}]}`
	reader := &countingReader{reader: strings.NewReader(input)}

	metadata, err := Inspect(reader)
	if err != nil {
		t.Fatal(err)
	}
	if metadata != (Metadata{Type: TypeCycloneDX, SpecVersion: "1.6"}) {
		t.Fatalf("Inspect = %+v", metadata)
	}
	if reader.read >= len(input) {
		t.Fatalf("Inspect read the complete %d byte document", len(input))
	}
}

func TestInspectSkipsLongTagValueText(t *testing.T) {
	input := "DocumentComment: <text>\n" + strings.Repeat("x", 100_000) + "\nSPDXVersion: SPDX-1.0\n</text>\nSPDXVersion: SPDX-2.3\n"
	metadata, err := Inspect(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if metadata != (Metadata{Type: TypeSPDX, SpecVersion: "SPDX-2.3"}) {
		t.Fatalf("Inspect = %+v", metadata)
	}
}

func TestInspectLongTagValueTextEnd(t *testing.T) {
	for _, test := range []struct {
		name    string
		padding int
		suffix  string
		wantErr bool
	}{
		{name: "closing tag beyond prefix", padding: tagLinePrefixLimit + 1, suffix: " \t\u2003"},
		{name: "closing tag split at prefix", padding: tagLinePrefixLimit - 3, suffix: " \t"},
		{name: "unicode whitespace split at prefix", padding: tagLinePrefixLimit - len(spdxTextEnd) - 1, suffix: "\u2003"},
		{name: "invalid suffix", padding: tagLinePrefixLimit + 1, suffix: "suffix", wantErr: true},
		{name: "first closing tag wins", padding: tagLinePrefixLimit - 3, suffix: "suffix" + spdxTextEnd, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := "DocumentComment: <text>\n" + strings.Repeat("x", test.padding) + spdxTextEnd + test.suffix + "\nSPDXVersion: SPDX-2.3\n"
			metadata, err := Inspect(&chunkReader{reader: strings.NewReader(input), size: 3})
			if test.wantErr {
				if metadata != (Metadata{}) || !errors.Is(err, ErrUnrecognized) {
					t.Fatalf("Inspect = %+v, %v", metadata, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if metadata != (Metadata{Type: TypeSPDX, SpecVersion: "SPDX-2.3"}) {
				t.Fatalf("Inspect = %+v", metadata)
			}
		})
	}
}

func TestInspectErrors(t *testing.T) {
	for _, input := range []string{
		"",
		`{"foo":1}`,
		`{"bomFormat":`,
		`<document/>`,
		"PackageName: example",
		"DocumentComment: <text>comment</text>suffix\nSPDXVersion: SPDX-2.3",
		"DocumentComment: <text>\ncomment\n</text>suffix\nSPDXVersion: SPDX-2.3",
	} {
		if metadata, err := Inspect(strings.NewReader(input)); metadata != (Metadata{}) || !errors.Is(err, ErrUnrecognized) {
			t.Errorf("Inspect(%q) = %+v, %v", input, metadata, err)
		}
	}

	sentinel := errors.New("read failed")
	reader := &failingReader{data: []byte(`{"packages":[`), err: sentinel}
	if _, err := Inspect(reader); !errors.Is(err, sentinel) {
		t.Fatalf("Inspect error = %v, want %v", err, sentinel)
	}
}

type chunkReader struct {
	reader io.Reader
	size   int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	return r.reader.Read(p[:min(len(p), r.size)])
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}

type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
