package sbom

import (
	"fmt"
	"testing"
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
		data := readFixture(b, f.path)
		doc, err := Parse(data)
		if err != nil {
			b.Fatalf("%s: %v", f.path, err)
		}
		pkgs := len(doc.Packages)
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ReportMetric(float64(pkgs), "pkgs")
			for i := 0; i < b.N; i++ {
				if _, err := Parse(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDetect(b *testing.B) {
	for _, f := range benchFixtures {
		data := readFixture(b, f.path)
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = Detect(data)
			}
		})
	}
}

func BenchmarkPackagePURL(b *testing.B) {
	doc, _ := Parse(readFixture(b, "cyclonedx/juice-shop.cdx.json"))
	b.Run(fmt.Sprintf("%d-pkgs", len(doc.Packages)), func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for j := range doc.Packages {
				_ = doc.Packages[j].PURL()
			}
		}
	})
}
