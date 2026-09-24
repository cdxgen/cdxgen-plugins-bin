// Command overlay applies the patches under overlay/patches to the vendored
// Trivy sources and writes a `go build -overlay` file that swaps the patched
// copies in. The vendor directory itself is left untouched.
//
// Go refuses overlays for files under GOMODCACHE, which is why the build
// vendors its dependencies first; see the Makefile.
//
//	go mod vendor
//	go run ./overlay
//	go build -mod=vendor -overlay=.overlay/overlay.json -tags grpcnotrace .
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	vendorDir := flag.String("vendor", "vendor", "vendor directory produced by `go mod vendor`")
	patchDir := flag.String("patches", filepath.Join("overlay", "patches"), "directory of unified diffs, relative to the vendor directory")
	outDir := flag.String("out", ".overlay", "output directory for the patched files and overlay.json")
	flag.Parse()
	if err := run(*vendorDir, *patchDir, *outDir); err != nil {
		fmt.Fprintln(os.Stderr, "overlay:", err)
		os.Exit(1)
	}
}

func run(vendorDir, patchDir, outDir string) error {
	if _, err := os.Stat(filepath.Join(vendorDir, "modules.txt")); err != nil {
		return fmt.Errorf("%s is not a vendor directory; run `go mod vendor` first: %w", vendorDir, err)
	}
	patchFiles, err := filepath.Glob(filepath.Join(patchDir, "*.patch"))
	if err != nil {
		return err
	}
	if len(patchFiles) == 0 {
		return fmt.Errorf("no patches in %s", patchDir)
	}
	sort.Strings(patchFiles)

	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	replace := map[string]string{}
	patchedBy := map[string]string{}
	for _, patchFile := range patchFiles {
		text, err := os.ReadFile(patchFile)
		if err != nil {
			return err
		}
		filePatches, err := parsePatch(string(text))
		if err != nil {
			return fmt.Errorf("%s: %w", patchFile, err)
		}
		for _, fp := range filePatches {
			// One section per file keeps every patch reviewable on its own
			// against pristine upstream code.
			if prev, ok := patchedBy[fp.path]; ok {
				return fmt.Errorf("%s: %s is already patched by %s", patchFile, fp.path, prev)
			}
			patchedBy[fp.path] = patchFile

			vendored := filepath.Join(vendorDir, filepath.FromSlash(fp.path))
			original, err := os.ReadFile(vendored)
			if err != nil {
				return fmt.Errorf("%s: %w", patchFile, err)
			}
			patched, err := fp.apply(string(original))
			if err != nil {
				return fmt.Errorf("%s: %w", patchFile, err)
			}
			if fp.deleted {
				replace[vendored] = ""
				continue
			}
			target := filepath.Join(outDir, "files", filepath.FromSlash(fp.path))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(target, []byte(patched), 0o644); err != nil {
				return err
			}
			replace[vendored] = target
		}
	}

	data, err := json.MarshalIndent(struct{ Replace map[string]string }{replace}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	overlayFile := filepath.Join(outDir, "overlay.json")
	if err := os.WriteFile(overlayFile, append(data, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("overlay: %d files patched by %d patches -> %s\n", len(replace), len(patchFiles), overlayFile)
	return nil
}
