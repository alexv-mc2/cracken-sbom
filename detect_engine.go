package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Engine discovery when --syft is omitted. It looks next to the cracken-sbom
// binary, in every absolute PATH folder and in the user cache folder, and
// accepts only a file whose SHA-256 equals the pinned engine-manifest.json
// digest for this platform. It never downloads anything.

const engineCacheSubdir = "cracken-sbom"

var engineSearch struct {
	sync.Mutex
	rejected []string // "path: reason", from the last search
}

func engineCandidates() []string {
	var out []string
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			out = append(out, filepath.Join(filepath.Dir(real), "syft"))
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.IsAbs(dir) {
			out = append(out, filepath.Join(dir, "syft"))
		}
	}
	if cache, err := os.UserCacheDir(); err == nil {
		out = append(out, filepath.Join(cache, engineCacheSubdir, "syft"))
	}
	return out
}

// locatePinnedEngine is the EngineLocator detect registers.
func locatePinnedEngine() (string, bool) {
	var manifest engineManifest
	if json.Unmarshal(engineManifestJSON, &manifest) != nil {
		return "", false
	}
	engineSearch.Lock()
	defer engineSearch.Unlock()
	engineSearch.rejected = nil
	seen := map[string]bool{}
	for _, c := range engineCandidates() {
		real, err := filepath.EvalSymlinks(c)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		info, err := os.Stat(real)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := verifyEngine(real, manifest); err != nil {
			engineSearch.rejected = append(engineSearch.rejected, fmt.Sprintf("%s: not the pinned Syft %s (%s)", c, engineVersion, err))
			continue
		}
		return real, true
	}
	return "", false
}

// engineNotFoundError explains, in plain words, how to install the engine.
func engineNotFoundError() error {
	var b strings.Builder
	fmt.Fprintf(&b, "syft not found. cracken-sbom needs Syft %s, checked against its pinned SHA-256, and never downloads it.\n", engineVersion)
	b.WriteString("Looked next to cracken-sbom, in every folder in PATH")
	if cache, err := os.UserCacheDir(); err == nil {
		fmt.Fprintf(&b, " and in %s", filepath.Join(cache, engineCacheSubdir))
	}
	b.WriteString(".\n")
	engineSearch.Lock()
	for _, r := range engineSearch.rejected {
		fmt.Fprintf(&b, "Skipped %s.\n", r)
	}
	engineSearch.Unlock()
	fmt.Fprintf(&b, "Install it like this (needs the network once; scanning does not):\n")
	fmt.Fprintf(&b, "  1. Download syft_%s_%s_%s.tar.gz and syft_%s_checksums.txt from https://github.com/anchore/syft/releases/tag/v%s\n", engineVersion, runtime.GOOS, runtime.GOARCH, engineVersion, engineVersion)
	b.WriteString("  2. Verify them as described in https://github.com/alexv-mc2/cracken-sbom/blob/main/docs/VERIFICATION.md\n")
	b.WriteString("     (from a source checkout: COSIGN=/path/to/cosign scripts/provision-syft.sh /absolute/path/to/syft)\n")
	b.WriteString("  3. Put the syft binary next to cracken-sbom or in a PATH folder, or pass --syft /absolute/path/to/syft")
	return errors.New(b.String())
}

// locateExtractor finds unblob (preferred) or binwalk in PATH for firmware
// images. The generate flow resolves and checks it again.
func locateExtractor() (path, kind string, ok bool) {
	for _, name := range []string{"unblob", "binwalk"} {
		for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
			if !filepath.IsAbs(dir) {
				continue
			}
			p := filepath.Join(dir, name)
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
				return p, name, true
			}
		}
	}
	return "", "", false
}

func extractorNotFoundError() error {
	return errors.New("no firmware extractor found: install unblob (preferred) or binwalk 3 and run again, or pass --extractor /absolute/path/to/unblob\n" +
		"  pipx install unblob\n" +
		"  unblob --show-external-dependencies   (lists the helper tools each image format needs)\n" +
		"Details: https://github.com/alexv-mc2/cracken-sbom#firmware-images")
}
