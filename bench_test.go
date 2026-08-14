package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"testing"
)

const benchmarkPackageCount = 840

var (
	benchmarkDocument *SBOM
	benchmarkError    error
)

var benchFixtures = []struct {
	name string
	path string
}{
	{"CycloneDX/minimal", "cyclonedx/minimal.cdx.json"},
	{"CycloneDX/alpine", "cyclonedx/alpine.cdx.json"},
	{"CycloneDX/laravel", "cyclonedx/laravel.cdx.json"},
	{"CycloneDX/nginx", "cyclonedx/nginx.cdx.json"},
	{"CycloneDX/juice-shop", "cyclonedx/juice-shop.cdx.json"},
	{"SPDX/minimal", "spdx/minimal.spdx.json"},
	{"SPDX/alpine", "spdx/alpine.spdx.json"},
	{"SPDX/nginx", "spdx/nginx.spdx.json"},
}

func BenchmarkParse(b *testing.B) {
	for _, f := range benchFixtures {
		benchmarkParse(b, f.name, readFixture(b, f.path))
	}
}

func BenchmarkParseLarge(b *testing.B) {
	benchmarkParse(b, "CycloneDX/840-packages", readFixture(b, "cyclonedx/juice-shop.cdx.json"))
	benchmarkParse(b, "SPDX/large", readFixture(b, "spdx/nginx.spdx.json"))
}

func BenchmarkParseCycloneDXComponents(b *testing.B) {
	benchmarkParse(b, "flat", benchmarkCycloneDX(b, benchmarkPackageCount, false, 0, 0))
	benchmarkParse(b, "nested", benchmarkCycloneDX(b, benchmarkPackageCount, true, 0, 0))
}

func BenchmarkParseDenseDependencyGraph(b *testing.B) {
	benchmarkParse(b, "CycloneDX/256-by-32", benchmarkCycloneDX(b, 256, false, 32, 0))
}

func BenchmarkParseSPDXEnvelopes(b *testing.B) {
	data := readFixture(b, "spdx/nginx.spdx.json")
	github := append(append([]byte(`{"sbom":`), data...), '}')
	intoto := append([]byte(`{"predicateType":"https://spdx.dev/Document","predicate":`), data...)
	intoto = append(intoto, '}')
	benchmarkParse(b, "GitHub", github)
	benchmarkParse(b, "in-toto", intoto)
}

func BenchmarkParseDuplicatePackageIdentities(b *testing.B) {
	benchmarkParse(b, "CycloneDX", benchmarkCycloneDX(b, benchmarkPackageCount, false, 0, 2))
	benchmarkParse(b, "SPDX", benchmarkSPDX(b, benchmarkPackageCount, 2))
}

func BenchmarkEncodeLarge(b *testing.B) {
	benchmarks := []struct {
		name   string
		path   string
		format Format
	}{
		{"CycloneDX/JSON", "cyclonedx/juice-shop.cdx.json", FormatCycloneDXJSON},
		{"CycloneDX/XML", "cyclonedx/juice-shop.cdx.json", FormatCycloneDXXML},
		{"SPDX/JSON", "spdx/nginx.spdx.json", FormatSPDXJSON},
	}
	for _, benchmark := range benchmarks {
		doc := mustParseBenchmark(b, readFixture(b, benchmark.path))
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.ReportMetric(float64(len(doc.Packages)), "pkgs")
			for range b.N {
				benchmarkError = Encode(io.Discard, doc, benchmark.format)
			}
			if benchmarkError != nil {
				b.Fatal(benchmarkError)
			}
		})
	}
}

func BenchmarkParseThenEncode(b *testing.B) {
	benchmarks := []struct {
		name   string
		path   string
		format Format
	}{
		{"CycloneDX/JSON", "cyclonedx/juice-shop.cdx.json", FormatCycloneDXJSON},
		{"SPDX/JSON", "spdx/nginx.spdx.json", FormatSPDXJSON},
	}
	for _, benchmark := range benchmarks {
		data := readFixture(b, benchmark.path)
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for range b.N {
				benchmarkDocument, benchmarkError = Parse(data)
				if benchmarkError == nil {
					benchmarkError = Encode(io.Discard, benchmarkDocument, benchmark.format)
				}
			}
			if benchmarkError != nil {
				b.Fatal(benchmarkError)
			}
		})
	}
}

func BenchmarkDetect(b *testing.B) {
	for _, f := range benchFixtures {
		data := readFixture(b, f.path)
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = Detect(data)
			}
		})
	}
}

func BenchmarkPackagePURL(b *testing.B) {
	doc := mustParseBenchmark(b, readFixture(b, "cyclonedx/juice-shop.cdx.json"))
	b.Run(fmt.Sprintf("%d-pkgs", len(doc.Packages)), func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			for j := range doc.Packages {
				_ = doc.Packages[j].PURL()
			}
		}
	})
}

func benchmarkParse(b *testing.B, name string, data []byte) {
	b.Helper()
	doc := mustParseBenchmark(b, data)
	b.Run(name, func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		b.ReportMetric(float64(len(doc.Packages)), "pkgs")
		b.ReportMetric(float64(len(doc.Relationships)), "rels")
		for range b.N {
			benchmarkDocument, benchmarkError = Parse(data)
		}
		if benchmarkError != nil {
			b.Fatal(benchmarkError)
		}
	})
}

func mustParseBenchmark(b testing.TB, data []byte) *SBOM {
	b.Helper()
	doc, err := Parse(data)
	if err != nil {
		b.Fatal(err)
	}
	return doc
}

func benchmarkCycloneDX(b testing.TB, packageCount int, nested bool, dependencyWidth, identities int) []byte {
	b.Helper()
	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		BOMVersion:  1,
		Metadata: &cdxMetadata{
			Timestamp: "2026-01-01T00:00:00Z",
			Component: &cdxComponent{Type: "application", Name: "benchmark", Version: "1.0.0"},
		},
	}
	component := func(i int) cdxComponent {
		identity := i
		if identities > 0 {
			identity %= packageCount / identities
		}
		return cdxComponent{
			BOMRef:      fmt.Sprintf("component-%d", i),
			Type:        "library",
			Name:        fmt.Sprintf("package-%d", identity),
			Version:     fmt.Sprintf("1.%d.0", identity%20),
			Description: "A package with representative CycloneDX metadata",
			Copyright:   "Copyright 2026 Example",
			Author:      "Example Maintainer",
			PURL:        fmt.Sprintf("pkg:generic/package-%d@1.%d.0", identity, identity%20),
			Supplier:    &cdxOrgEntity{Name: "Example Org"},
			Hashes: []cdxHash{
				{Alg: "SHA-256", Content: "c314ca2bdaf4317fb92300e22b3ff9a4494a6e8d4d3c80baab6ad441bf52c390"},
				{Alg: "SHA-512", Content: "950319f7d7b8339c29ee29ff9ac69f1ea1453ffc967928c3d36df20477d8b817"},
			},
			Licenses: []cdxLicense{{License: &cdxLicenseID{ID: "MIT"}}},
			ExternalReferences: []cdxExtRef{
				{Type: "website", URL: "https://example.com/package"},
				{Type: "vcs", URL: "https://example.com/package.git"},
			},
			Properties: []cdxProperty{
				{Name: "benchmark:source", Value: "registry"},
				{Name: "benchmark:scope", Value: "runtime"},
			},
		}
	}

	if nested {
		const roots = 20
		bom.Components = make([]cdxComponent, roots)
		for root := range roots {
			index := root * (packageCount / roots)
			bom.Components[root] = component(index)
			current := &bom.Components[root]
			for offset := 1; offset < packageCount/roots; offset++ {
				current.Components = []cdxComponent{component(index + offset)}
				current = &current.Components[0]
			}
		}
	} else {
		bom.Components = make([]cdxComponent, packageCount)
		for i := range packageCount {
			bom.Components[i] = component(i)
		}
	}

	if dependencyWidth > 0 {
		bom.Dependencies = make([]cdxDependency, packageCount)
		for i := range packageCount {
			dependency := cdxDependency{
				Ref:       fmt.Sprintf("component-%d", i),
				DependsOn: make([]string, dependencyWidth),
			}
			for j := range dependencyWidth {
				dependency.DependsOn[j] = fmt.Sprintf("component-%d", (i+j+1)%packageCount)
			}
			bom.Dependencies[i] = dependency
		}
	}
	return marshalBenchmarkJSON(b, &bom)
}

func benchmarkSPDX(b testing.TB, packageCount, identities int) []byte {
	b.Helper()
	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		SPDXID:            spdxDocID,
		Name:              "benchmark",
		DataLicense:       "CC0-1.0",
		DocumentNamespace: "https://example.com/benchmark",
		CreationInfo: &spdxCreationInfo{
			Created:  "2026-01-01T00:00:00Z",
			Creators: []string{"Tool: benchmark", "Organization: Example Org"},
		},
		Packages: make([]spdxPackage, packageCount),
	}
	for i := range packageCount {
		identity := i
		if identities > 0 {
			identity %= packageCount / identities
		}
		doc.Packages[i] = spdxPackage{
			SPDXID:                fmt.Sprintf("SPDXRef-Package-%d", i),
			Name:                  fmt.Sprintf("package-%d", identity),
			VersionInfo:           fmt.Sprintf("1.%d.0", identity%20),
			DownloadLocation:      "https://example.com/package.tar.gz",
			Homepage:              "https://example.com/package",
			PackageFileName:       "package.tar.gz",
			LicenseConcluded:      "MIT",
			LicenseDeclared:       "MIT",
			CopyrightText:         "Copyright 2026 Example",
			Description:           "A package with representative SPDX metadata",
			Supplier:              "Organization: Example Org",
			Originator:            "Person: Example Maintainer",
			PrimaryPackagePurpose: "LIBRARY",
			Checksums: []spdxChecksum{{
				Algorithm: "SHA256",
				Value:     "c314ca2bdaf4317fb92300e22b3ff9a4494a6e8d4d3c80baab6ad441bf52c390",
			}},
			ExternalRefs: []spdxExtRef{{
				Category: "PACKAGE-MANAGER",
				Type:     "purl",
				Locator:  fmt.Sprintf("pkg:generic/package-%d@1.%d.0", identity, identity%20),
			}},
		}
	}
	return marshalBenchmarkJSON(b, &doc)
}

func marshalBenchmarkJSON(b testing.TB, value any) []byte {
	b.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		b.Fatal(err)
	}
	return data
}
