package sbom

// syft records which lock file entry a package came from in the
// syft:package:metadataType property. These lock files list only the
// project's dependencies, not the project itself, so a package from one
// that nothing depends on is a direct dependency rather than the project.
// npm's package-lock.json, Cargo.lock, uv.lock and yarn berry's yarn.lock
// do list the project, and are left to root inference.
var projectlessLockEntries = map[string]bool{
	"python-poetry-lock-entry":   true,
	"python-pdm-lock-entry":      true,
	"javascript-pnpm-lock-entry": true,
	"javascript-yarn-lock-entry": true, // yarn v1; see yarnBerryWorkspaces
}

const (
	syftMetadataType = "syft:package:metadataType"
	syftLocationPath = "syft:location:0:path"
	// yarnBerryWorkspaceVersion is the version yarn berry gives the
	// workspace entries it records for the project.
	yarnBerryWorkspaceVersion = "0.0.0-use.local"
)

// topLevelDependencies returns the IDs among candidates that are packages
// from a lock file that leaves the project out, so are dependencies of the
// project rather than the project itself.
func (s *SBOM) topLevelDependencies(candidates map[string]bool) map[string]bool {
	var berryLocks map[string]bool
	var top map[string]bool
	for i := range s.Packages {
		p := &s.Packages[i]
		if !candidates[p.ID] {
			continue
		}
		kind := p.property(syftMetadataType)
		if !projectlessLockEntries[kind] {
			continue
		}
		if kind == "javascript-yarn-lock-entry" {
			if berryLocks == nil {
				berryLocks = s.yarnBerryWorkspaces()
			}
			if berryLocks[p.property(syftLocationPath)] {
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
		if p.Version == yarnBerryWorkspaceVersion && p.property(syftMetadataType) == "javascript-yarn-lock-entry" {
			locks[p.property(syftLocationPath)] = true
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
