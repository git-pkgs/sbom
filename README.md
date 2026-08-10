# sbom

Go library for reading and writing Software Bill of Materials documents. Reads CycloneDX and SPDX JSON into a single `Document` / `Package` / `Relationship` model, and writes that model back out as CycloneDX (JSON or XML) or SPDX JSON.

Ported from [github.com/andrew/sbom](https://github.com/andrew/sbom).

## Installation

```
go get github.com/git-pkgs/sbom
```

## Parsing

```go
import "github.com/git-pkgs/sbom"

data, _ := os.ReadFile("bom.cdx.json")
doc, err := sbom.Parse(data)
if err != nil {
    log.Fatal(err)
}

fmt.Println(doc.Type)             // cyclonedx
fmt.Println(doc.SpecVersion)      // 1.6
fmt.Println(doc.Document.Name)    // my-app

for _, p := range doc.Packages {
    fmt.Println(p.Name, p.Version, p.PURL())
}
```

`Parse` auto-detects the format. `Detect` returns just the type without a full parse and runs in roughly constant time regardless of document size, since it only token-scans top-level keys until it hits a discriminator.

```go
switch sbom.Detect(data) {
case sbom.TypeCycloneDX:
case sbom.TypeSPDX:
}
```

## Generating

Build an `*sbom.SBOM`, populate `Document` and `Packages`, then `Encode`:

```go
s := sbom.New(sbom.TypeCycloneDX)
s.Document = sbom.Document{
    Name:      "my-app",
    Namespace: "https://example.com/my-app",
    Component: sbom.Component{
        Type:              "application",
        Name:              "my-app",
        Version:           "1.2.3",
        LicenseExpression: "MIT",
        LicenseNames:      []string{"Additional Project Terms"},
        ExtractedLicenses: []sbom.ExtractedLicense{{
            Name: "LICENSE.custom",
            Text: "Custom license text",
        }},
    },
    Creators:  []sbom.Creator{{Type: "Tool", Name: "my-tool-1.0"}},
}
s.AddPackage(sbom.Package{
    Name: "lodash", Version: "4.17.21", LicenseDeclared: "MIT",
    ExternalRefs: []sbom.ExternalRef{{Type: "purl", Locator: "pkg:npm/lodash@4.17.21"}},
})

sbom.Encode(os.Stdout, s, sbom.FormatCycloneDXJSON)
sbom.Encode(os.Stdout, s, sbom.FormatSPDXJSON)
```

## Relationships

Both parsers normalise dependency edges to `sbom.RelDependsOn` and SPDX's document-to-root link to `sbom.RelDescribes`. `ClassifyScope` walks that graph to tag each package as a direct or transitive dependency of the document's root:

```go
doc, _ := sbom.Parse(data)
scope := doc.ClassifyScope()
for _, p := range doc.Packages {
    switch scope[p.ID] {
    case sbom.ScopeDirect:
    case sbom.ScopeTransitive:
    default:
        // root, or a flat-list SBOM with no dependency graph
    }
}
```

`ClassifyScope` returns `nil` when the document has no dependency graph at all, so callers can hide a scope filter rather than showing every package as unclassified.

## Supported formats

| Format | Parse | Encode | Notes |
| --- | --- | --- | --- |
| CycloneDX JSON | yes | yes | nested components flattened, `license.id` / `license.name` / `expression` all read |
| CycloneDX XML | no | yes | |
| SPDX JSON | yes | yes | `{"sbom": ...}` and in-toto `{"predicate": ...}` envelopes unwrapped on parse |

XML/YAML/tag-value parsing is not handled yet.

## Why not protobom?

[protobom](https://github.com/protobom/protobom) is the OpenSSF normaliser and covers every serialisation. It's pure Go (no cgo) but importing `pkg/reader` adds about 21 indirect modules including `google.golang.org/protobuf`, `sigs.k8s.io/release-utils`, logrus, tablewriter, and a handful of terminal-colour libraries that have no business in a parser. This module has zero dependencies and the field mappings were already worked out in the Ruby gem, so for tools that just need the package list it's a smaller surface to audit. If you need full spec coverage, use protobom.

## Benchmarks

```
go test -bench . -benchmem
```

On an M1 Pro, `Parse` runs at roughly 100-165 MB/s; the 3 MB syft-generated `nginx.spdx.json` (151 packages) parses in about 18 ms. `Detect` is sub-microsecond on the same file.

## License

MIT
