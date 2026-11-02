package sbom

import (
	"path"
	"strings"
)

// These lock files list only the project's dependencies, not the project
// itself, so a package from one that nothing depends on is a direct
// dependency rather than the project. npm's package-lock.json, Cargo.lock,
// uv.lock and yarn berry's yarn.lock do list the project, and are left to
// root inference.
var projectlessLockFiles = map[string]bool{
	"poetry.lock":    true,
	"pdm.lock":       true,
	"pnpm-lock.yaml": true,
	"yarn.lock":      true, // yarn v1; see yarnBerryWorkspaces
}

const (
	// syftLocationPath is the CycloneDX property syft records the file a
	// package was read from in.
	syftLocationPath = "syft:location:0:path"
	// yarnBerryWorkspaceVersion is the version yarn berry gives the
	// workspace entries it records for the project.
	yarnBerryWorkspaceVersion = "0.0.0-use.local"
)

// lockFile returns the path of the file syft read p from: the location
// property in CycloneDX, or the path ending SPDX's PackageSourceInfo, as in
// "acquired package info from installed python package manifest file:
// /poetry.lock".
func (p *Package) lockFile() string {
	if loc := p.property(syftLocationPath); loc != "" {
		return loc
	}
	if i := strings.LastIndex(p.SourceInfo, ": /"); i >= 0 {
		return p.SourceInfo[i+2:]
	}
	return ""
}

// topLevelDependencies returns the IDs of packages from a lock file that
// leaves the project out which nothing depends on, so are dependencies of
// the project rather than the project itself: the inferred roots among them,
// and those without any edge, such as a dependency that has none of its own.
// A package without edges counts only when other packages of its lock file
// have edges, so a lock file the graph leaves out stays unclassified.
// edged holds the IDs that are the source or target of a DEPENDS_ON edge.
func (s *SBOM) topLevelDependencies(inferred, edged map[string]bool) map[string]bool {
	var berryLocks map[string]bool
	lockHasEdges := map[string]bool{}
	for i := range s.Packages {
		if p := &s.Packages[i]; edged[p.ID] {
			lockHasEdges[p.lockFile()] = true
		}
	}
	var top map[string]bool
	for i := range s.Packages {
		p := &s.Packages[i]
		lock := p.lockFile()
		if !inferred[p.ID] && (edged[p.ID] || !lockHasEdges[lock]) {
			continue
		}
		name := path.Base(lock)
		if lock == "" || !projectlessLockFiles[name] {
			continue
		}
		if name == "yarn.lock" {
			if berryLocks == nil {
				berryLocks = s.yarnBerryWorkspaces()
			}
			if berryLocks[lock] {
				continue
			}
		}
		if top == nil {
			top = map[string]bool{}
		}
		top[p.ID] = true
	}
	return top
}

// yarnBerryWorkspaces returns the yarn.lock paths that record a workspace
// entry, which yarn v1 lock files don't have.
func (s *SBOM) yarnBerryWorkspaces() map[string]bool {
	locks := map[string]bool{}
	for i := range s.Packages {
		p := &s.Packages[i]
		if lock := p.lockFile(); p.Version == yarnBerryWorkspaceVersion && path.Base(lock) == "yarn.lock" {
			locks[lock] = true
		}
	}
	return locks
}

func (p *Package) property(name string) string {
	for _, prop := range p.Properties {
		if prop.Name == name {
			return prop.Value
		}
	}
	return ""
}
