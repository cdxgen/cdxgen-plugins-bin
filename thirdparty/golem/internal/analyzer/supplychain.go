package analyzer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func (a *Analyzer) supplyChainEvidence(modules []model.Module) *model.SupplyChainEvidence {
	evidence := &model.SupplyChainEvidence{Properties: map[string]string{}}
	goModPath := filepath.Join(a.options.Dir, "go.mod")
	if data, err := os.ReadFile(goModPath); err == nil {
		if parsed, err := modfile.Parse(goModPath, data, nil); err == nil {
			if parsed.Go != nil {
				evidence.GoDirectiveVersion = parsed.Go.Version
			}
			if parsed.Toolchain != nil {
				evidence.ToolchainDirective = sanitizeToolName(parsed.Toolchain.Name)
			}
			for _, replace := range parsed.Replace {
				directive := model.GoModDirective{Kind: "replace", ModulePath: replace.Old.Path, Version: replace.Old.Version, TargetModulePath: replace.New.Path, TargetVersion: replace.New.Version, Source: "go.mod"}
				directive.LocalReplacement = isLocalReplacement(replace.New.Path, replace.New.Version)
				directive.TargetPathKind = replacementPathKind(replace.New.Path, replace.New.Version)
				evidence.Replaces = append(evidence.Replaces, directive)
			}
			for _, exclude := range parsed.Exclude {
				evidence.Excludes = append(evidence.Excludes, model.GoModDirective{Kind: "exclude", ModulePath: exclude.Mod.Path, Version: exclude.Mod.Version, Source: "go.mod"})
			}
		}
	}
	if _, err := os.Stat(filepath.Join(a.options.Dir, "go.work")); err == nil {
		evidence.GoWorkPresent = true
		if data, err := os.ReadFile(filepath.Join(a.options.Dir, "go.work")); err == nil {
			if parsed, err := modfile.ParseWork(filepath.Join(a.options.Dir, "go.work"), data, nil); err == nil {
				evidence.WorkspaceModuleCount = len(parsed.Use)
			}
		}
	}
	vendorModules := vendorModules(a.options.Dir)
	evidence.VendorDirectoryPresent = len(vendorModules) > 0
	evidence.VendorModuleCount = len(vendorModules)
	for _, mod := range modules {
		compliance := model.ModuleCompliance{Path: mod.Path, Version: mod.Version, PURL: mod.PURL, Main: mod.Main, Vendored: vendorModules[mod.Path], PrivateModuleCandidate: privateModuleCandidate(mod)}
		compliance.LicenseFiles = licenseFiles(mod.Dir)
		if mod.Replace != nil {
			compliance.Properties = map[string]string{"replacementModule": mod.Replace.Path}
			if isLocalReplacement(mod.Replace.Path, mod.Replace.Version) {
				compliance.Properties["localReplacement"] = "true"
			}
		}
		evidence.Modules = append(evidence.Modules, compliance)
	}
	sort.Slice(evidence.Replaces, func(i, j int) bool { return evidence.Replaces[i].ModulePath < evidence.Replaces[j].ModulePath })
	sort.Slice(evidence.Excludes, func(i, j int) bool { return evidence.Excludes[i].ModulePath < evidence.Excludes[j].ModulePath })
	sort.Slice(evidence.Modules, func(i, j int) bool { return evidence.Modules[i].Path < evidence.Modules[j].Path })
	if evidence.GoDirectiveVersion == "" && evidence.ToolchainDirective == "" && !evidence.GoWorkPresent && !evidence.VendorDirectoryPresent && len(evidence.Replaces) == 0 && len(evidence.Excludes) == 0 && len(evidence.Modules) == 0 {
		return nil
	}
	if len(evidence.Properties) == 0 {
		evidence.Properties = nil
	}
	return evidence
}

func isLocalReplacement(path string, version string) bool {
	if version != "" || path == "" {
		return false
	}
	return isRelativeReplacementPath(path) || isAbsoluteReplacementPath(path)
}

func replacementPathKind(path string, version string) string {
	if version != "" {
		return "module"
	}
	if isAbsoluteReplacementPath(path) {
		return "absolute"
	}
	if isRelativeReplacementPath(path) {
		return "relative"
	}
	return "module"
}

func isRelativeReplacementPath(path string) bool {
	return strings.HasPrefix(path, ".")
}

func isAbsoluteReplacementPath(path string) bool {
	if filepath.IsAbs(path) || strings.HasPrefix(path, string(filepath.Separator)) {
		return true
	}
	if len(path) >= 3 && isWindowsDriveLetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		return true
	}
	return strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`)
}

func isWindowsDriveLetter(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func vendorModules(root string) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(filepath.Join(root, "vendor", "modules.txt"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) > 0 && strings.Contains(fields[0], ".") {
			out[fields[0]] = true
		}
	}
	return out
}

func privateModuleCandidate(mod model.Module) bool {
	if mod.Path == "" || mod.Main {
		return false
	}
	first, _, _ := strings.Cut(mod.Path, "/")
	lower := strings.ToLower(first)
	if lower == "localhost" || strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".corp") || strings.HasSuffix(lower, ".lan") {
		return true
	}
	if mod.Version == "" && mod.GoMod == "" {
		return true
	}
	return false
}

func licenseFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if lower == "license" || strings.HasPrefix(lower, "license.") || lower == "copying" || strings.HasPrefix(lower, "copying.") || lower == "notice" || strings.HasPrefix(lower, "notice.") || strings.HasPrefix(lower, "third_party_notices") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files
}
