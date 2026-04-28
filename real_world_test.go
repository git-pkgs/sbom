package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRealWorldFixtures(t *testing.T) {
	tests := []struct {
		path     string
		typ      Type
		minPkgs  int
		minRels  int
		wantPURL bool
	}{
		{"cyclonedx/alpine.cdx.json", TypeCycloneDX, 10, 0, true},
		{"cyclonedx/laravel.cdx.json", TypeCycloneDX, 50, 0, true},
		{"cyclonedx/nginx.cdx.json", TypeCycloneDX, 10, 0, true},
		{"cyclonedx/juice-shop.cdx.json", TypeCycloneDX, 100, 0, true},
		{"cyclonedx/snyk-purl.cdx.json", TypeCycloneDX, 1, 0, true},
		{"spdx/alpine.spdx.json", TypeSPDX, 10, 1, true},
		{"spdx/nginx.spdx.json", TypeSPDX, 10, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			doc, err := Parse(readFixture(t, tt.path))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if doc.Type != tt.typ {
				t.Errorf("Type = %q, want %q", doc.Type, tt.typ)
			}
			if len(doc.Packages) < tt.minPkgs {
				t.Errorf("Packages = %d, want >= %d", len(doc.Packages), tt.minPkgs)
			}
			if len(doc.Relationships) < tt.minRels {
				t.Errorf("Relationships = %d, want >= %d", len(doc.Relationships), tt.minRels)
			}
			named, withPURL := tallyPackages(doc.Packages)
			if named != len(doc.Packages) {
				t.Errorf("%d packages have empty names", len(doc.Packages)-named)
			}
			if tt.wantPURL && withPURL == 0 {
				t.Errorf("no packages with PURL")
			}
		})
	}
}

func tallyPackages(pkgs []Package) (named, withPURL int) {
	for i := range pkgs {
		if pkgs[i].Name != "" {
			named++
		}
		if pkgs[i].PURL() != "" {
			withPURL++
		}
	}
	return named, withPURL
}

func TestRealWorldAllParse(t *testing.T) {
	// Every JSON fixture should parse without error and yield at least one
	// package. Guards against regressions when new fixtures are added.
	dirs := []string{"testdata/cyclonedx", "testdata/spdx"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir %s: %v", dir, err)
		}
		for _, e := range entries {
			if filepath.Ext(e.Name()) != ".json" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			t.Run(path, func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				doc, err := Parse(data)
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if len(doc.Packages) == 0 {
					t.Errorf("no packages parsed")
				}
			})
		}
	}
}
