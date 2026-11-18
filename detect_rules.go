package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// detectPlan is what detect found and what it will do about it.
type detectPlan struct {
	What       string   // one line: what this is, in plain words
	Evidence   []string // the files that show it
	TargetType string   // generate --target-type; empty when no SBOM is built
	Why        string   // why this target type
	Notes      []string // extra hints printed after the plan
	Guidance   []string // steps to print when no SBOM is built
	// Unrecognised: nothing detect can build from; detect exits non-zero.
	Unrecognised bool
}

const yoctoGuideURL = "https://github.com/alexv-mc2/cracken-sbom/blob/main/docs/YOCTO.md"

// Ecosystem evidence that alone does not make a source project.
func weakEvidence(g detectGlob) bool {
	return g.Ecosystem == "linux" || g.Ecosystem == "github-actions" || g.Cataloger == "java-jvm-cataloger"
}

// Root file system folders where Syft finds an OS package database.
var rootfsTopDirs = map[string]bool{"var": true, "lib": true, "usr": true, "etc": true}

func isRegularFile(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.Mode().IsRegular()
}

func isDir(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.IsDir()
}

func planForPath(ctx context.Context, target string, info os.FileInfo) (detectPlan, error) {
	if info.IsDir() {
		return planForFolder(ctx, target)
	}
	return planForFile(target)
}

func planForFolder(ctx context.Context, dir string) (detectPlan, error) {
	if plan, ok := yoctoPlan(dir); ok {
		return plan, nil
	}
	walk, err := walkFolder(ctx, dir, defaultWalkLimits, detectGlobs)
	if err != nil {
		return detectPlan{}, err
	}
	var notes []string
	if walk.Truncated {
		notes = append(notes, fmt.Sprintf("Detection looked at the first %d entries and %d folder levels only; Syft still scans the whole folder.", min(walk.Entries, defaultWalkLimits.MaxEntries), defaultWalkLimits.MaxDepth))
	}
	// 1. A root file system: an OS package database in the usual place.
	var osHits []globHit
	for _, h := range walk.Hits {
		first := strings.SplitN(h.Rel, "/", 2)[0]
		if h.Glob.Kind == globOS && !strings.HasPrefix(path.Base(h.Glob.Pattern), "*.") && rootfsTopDirs[first] {
			osHits = append(osHits, h)
		}
	}
	if len(osHits) > 0 && isDir(filepath.Join(dir, "etc")) {
		ev := []string{}
		if isRegularFile(filepath.Join(dir, "etc", "os-release")) {
			ev = append(ev, "etc/os-release")
		} else if isRegularFile(filepath.Join(dir, "usr", "lib", "os-release")) {
			ev = append(ev, "usr/lib/os-release")
		}
		ev = append(ev, describeHits(osHits, 3)...)
		return detectPlan{
			What: "an unpacked root file system (Linux)", Evidence: ev, TargetType: "rootfs",
			Why:   "the package database lists what is installed; version strings in programs are checked too",
			Notes: notes,
		}, nil
	}
	// 2. A source or build folder with manifests and lockfiles.
	byEco := map[string][]globHit{}
	strong := 0
	for _, h := range walk.Hits {
		if h.Glob.Kind == globDeclared {
			byEco[h.Glob.Ecosystem] = append(byEco[h.Glob.Ecosystem], h)
			if !weakEvidence(h.Glob) {
				strong++
			}
		}
	}
	installedPython := []globHit{}
	for _, h := range walk.Hits {
		if h.Glob.Kind == globInstalled && h.Glob.Ecosystem == "python" {
			installedPython = append(installedPython, h)
		}
	}
	if strong == 0 && len(installedPython) > 0 {
		return detectPlan{
			What: "installed Python packages (site-packages)", Evidence: describeHits(installedPython, 3), TargetType: "python",
			Why: "each package's METADATA states its name and version", Notes: notes,
		}, nil
	}
	dockerNote := ""
	if len(walk.Dockerfiles) > 0 {
		dockerNote = fmt.Sprintf("Also found %s. This SBOM lists the project's declared dependencies; for what ships in the container, build the image, docker save it to a .tar and run cracken-sbom detect on that file.", walk.Dockerfiles[0])
	}
	if strong > 0 || len(byEco) > 0 {
		ecos := make([]string, 0, len(byEco))
		for e := range byEco {
			ecos = append(ecos, e)
		}
		sort.Strings(ecos)
		ev := []string{}
		for _, e := range ecos {
			ev = append(ev, fmt.Sprintf("%s: %s", e, strings.Join(describeHits(byEco[e], 3), ", ")))
		}
		if dockerNote != "" {
			notes = append(notes, dockerNote)
		}
		onlyNPM := len(ecos) == 1 && ecos[0] == "javascript"
		if onlyNPM && (isRegularFile(filepath.Join(dir, "package-lock.json")) || isRegularFile(filepath.Join(dir, "npm-shrinkwrap.json"))) {
			return detectPlan{
				What: "an npm project with a lockfile", Evidence: ev, TargetType: "npm",
				Why:   "package-lock.json states every dependency and the whole dependency graph",
				Notes: notes,
			}, nil
		}
		what := "a source project folder with manifests or lockfiles"
		if strong == 0 {
			what = "a folder with CI workflow, kernel or runtime files only"
		}
		return detectPlan{
			What: what, Evidence: ev, TargetType: "dir",
			Why:   "Syft reads every manifest and lockfile it knows below this folder",
			Notes: notes,
		}, nil
	}
	// 3. Nothing to scan directly: explain what was found instead.
	var archives []string
	for _, f := range walk.TopFiles {
		p, err := planForFile(filepath.Join(dir, filepath.FromSlash(f)))
		if err == nil && p.TargetType != "" {
			archives = append(archives, fmt.Sprintf("%s (%s)", f, p.What))
		}
	}
	if len(archives) > 0 {
		g := []string{"Run detect on the file itself, for example:"}
		for _, a := range archives[:min(len(archives), 3)] {
			name := strings.SplitN(a, " (", 2)[0]
			g = append(g, "  cracken-sbom detect "+shellQuote(filepath.Join(dir, filepath.FromSlash(name))))
		}
		return detectPlan{What: "a folder that holds image or firmware files", Evidence: archives, Guidance: g, Notes: notes}, nil
	}
	var installed []globHit
	for _, h := range walk.Hits {
		if h.Glob.Kind == globInstalled {
			installed = append(installed, h)
		}
	}
	if len(installed) > 0 {
		if dockerNote != "" {
			notes = append(notes, dockerNote)
		}
		return detectPlan{
			What: "a folder with installed packages or package archives (no lockfile)", Evidence: describeHits(installed, 3), TargetType: "dir",
			Why:   "Syft reads the package metadata it finds below this folder",
			Notes: append(notes, "Without a lockfile the dependency graph is incomplete; commit a lockfile for a better SBOM."),
		}, nil
	}
	if isRegularFile(filepath.Join(dir, "package.json")) {
		return detectPlan{
			What: "an npm project without a lockfile", Evidence: []string{"package.json"}, Notes: notes,
			Guidance: []string{
				"Syft lists npm dependencies from package-lock.json, which this folder does not have.",
				"Create it without installing anything, then run detect again:",
				"  npm install --package-lock-only",
				"  cracken-sbom detect " + shellQuote(dir),
			},
		}, nil
	}
	if len(walk.Dockerfiles) > 0 {
		return dockerfilePlan(walk.Dockerfiles[0]), nil
	}
	return detectPlan{
		What: "nothing cracken-sbom can list", Unrecognised: true, Notes: notes,
		Guidance: []string{
			"No lockfile, package manifest, package database, image archive or firmware file was found.",
			"Point detect at one of these: a project folder with a lockfile (package-lock.json, go.mod, Cargo.lock, poetry.lock, ...),",
			"an unpacked root file system, a docker save or OCI archive (.tar), or a firmware image (.bin, .img).",
		},
	}, nil
}

func describeHits(hits []globHit, max int) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, h := range hits {
		if seen[h.Rel] {
			continue
		}
		seen[h.Rel] = true
		if len(out) < max {
			out = append(out, h.Rel)
		}
	}
	if extra := len(seen) - len(out); extra > 0 {
		out = append(out, fmt.Sprintf("and %d more", extra))
	}
	return out
}

func yoctoPlan(dir string) (detectPlan, bool) {
	ev := []string{}
	for _, f := range []string{"conf/local.conf", "conf/bblayers.conf"} {
		if isRegularFile(filepath.Join(dir, filepath.FromSlash(f))) {
			ev = append(ev, f)
		}
	}
	for _, d := range []string{"tmp/deploy/spdx", "tmp/deploy/images"} {
		if isDir(filepath.Join(dir, filepath.FromSlash(d))) {
			ev = append(ev, d+"/")
		}
	}
	if len(ev) == 0 {
		if isRegularFile(filepath.Join(dir, "oe-init-build-env")) {
			return detectPlan{
				What: "a Yocto Project source tree (poky)", Evidence: []string{"oe-init-build-env"},
				Guidance: []string{
					"The SBOM comes from the build folder, not from the layer sources.",
					"Run detect in your build folder instead, usually: cracken-sbom detect " + shellQuote(filepath.Join(dir, "build")),
				},
			}, true
		}
		return detectPlan{}, false
	}
	plan := detectPlan{What: "a Yocto build folder", Evidence: ev}
	if _, ok := defaultRegistry.target("yocto"); ok {
		plan.Guidance = []string{
			"Use the Yocto target, which reads the SPDX files the build wrote:",
			"  cracken-sbom generate --target-type yocto --target " + shellQuote(dir) + " --target-id RELEASE --output NEW-DIR",
			"Details: " + yoctoGuideURL,
		}
		return plan, true
	}
	plan.Guidance = []string{
		"This version of cracken-sbom does not read Yocto SPDX files yet.",
		"Scanning a build folder directly would list build-host tools, not what ships on your device.",
		"What to do now:",
		"  1. Use the SBOM your build already writes: current Yocto releases (5.0 Scarthgap, 6.0 Wrynose) create",
		"     an SPDX SBOM for each image next to it in tmp/deploy/images/<machine>/. Upload it to crAcken as described in:",
		"     " + yoctoGuideURL,
		"  2. Or list the finished image: unpack the image's *.rootfs.tar.* into a new folder and run",
		"     cracken-sbom detect on that folder; it is then scanned as a root file system.",
	}
	return plan, true
}

func dockerfilePlan(rel string) detectPlan {
	return detectPlan{
		What: "a Dockerfile (the recipe for a container image)", Evidence: []string{rel},
		Guidance: []string{
			"cracken-sbom lists what is inside the built image, not the recipe. Build and save the image, then run detect on the archive:",
			"  docker build -t my-image:1.0 .",
			"  docker save -o my-image-1.0.tar my-image:1.0",
			"  cracken-sbom detect my-image-1.0.tar",
		},
	}
}

const maxTarHeaders = 4096

// tarImageKind reads tar headers only (never file contents) and reports
// whether the file is a docker save archive or an OCI image layout.
func tarImageKind(p string) (kind string, isTar bool) {
	f, err := os.Open(p)
	if err != nil {
		return "", false
	}
	defer f.Close()
	head := make([]byte, 512)
	if _, err := io.ReadFull(f, head); err != nil || !bytes.Equal(head[257:262], []byte("ustar")) {
		return "", false
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", false
	}
	names := map[string]bool{}
	r := tar.NewReader(f)
	for i := 0; i < maxTarHeaders; i++ {
		h, err := r.Next()
		if err != nil {
			break
		}
		names[strings.TrimPrefix(path.Clean(h.Name), "./")] = true
	}
	switch {
	case names["manifest.json"]:
		// docker save (also Docker 25+, which adds an OCI layout beside it).
		return "docker-archive", true
	case names["oci-layout"] && names["index.json"]:
		return "oci-archive", true
	}
	return "", true
}

func planForFile(p string) (detectPlan, error) {
	name := filepath.Base(p)
	if isDockerfileName(name) {
		return dockerfilePlan(name), nil
	}
	if kind, isTar := tarImageKind(p); isTar {
		switch kind {
		case "docker-archive":
			return detectPlan{What: "a container image saved with docker save", Evidence: []string{name + ": manifest.json in the archive"}, TargetType: kind,
				Why: "Syft reads the image layers inside the archive; nothing is pulled or run"}, nil
		case "oci-archive":
			return detectPlan{What: "a container image in OCI layout", Evidence: []string{name + ": oci-layout and index.json in the archive"}, TargetType: kind,
				Why: "Syft reads the image layers inside the archive; nothing is pulled or run"}, nil
		}
		return detectPlan{What: "a tar archive that is not a container image", Evidence: []string{name},
			Guidance: []string{
				"If it is a root file system (for example a Yocto *.rootfs.tar), unpack it into a new folder and run detect on that folder:",
				"  mkdir rootfs && tar -xf " + shellQuote(name) + " -C rootfs && cracken-sbom detect rootfs",
			}}, nil
	}
	sniff, err := sniffFirmware(p)
	if err != nil {
		return detectPlan{}, fmt.Errorf("cannot read %s", shellQuote(p))
	}
	if sniff.Signature != nil && (!sniff.Compressed || sniff.FirmwareExt) {
		ev := fmt.Sprintf("%s: %s at byte %d", name, sniff.Signature.Name, sniff.At)
		return detectPlan{What: "a firmware image", Evidence: []string{ev}, TargetType: firmwareTargetType,
			Why: "unblob (or binwalk) unpacks it on this computer, then the root file system inside is scanned"}, nil
	}
	if sniff.FirmwareExt {
		return detectPlan{What: "a firmware image", Evidence: []string{name + ": firmware file name; no known signature in the first 8 MiB (it may be encrypted or vendor-specific)"},
			TargetType: firmwareTargetType, Why: "unblob (or binwalk) tries to unpack it on this computer, then the root file system inside is scanned"}, nil
	}
	if sniff.Signature != nil && sniff.Compressed {
		return detectPlan{What: "a compressed file (" + sniff.Signature.Name + ")", Evidence: []string{name},
			Guidance: []string{"Unpack it first, then run cracken-sbom detect on the result (a .tar archive or a folder)."}}, nil
	}
	for _, g := range detectGlobs {
		if g.Kind == globDeclared && globMatch(g.Pattern, name) {
			return detectPlan{What: "a single " + g.Ecosystem + " manifest or lockfile", Evidence: []string{name},
				Guidance: []string{"Run detect on the project folder that holds it, for example:", "  cracken-sbom detect " + shellQuote(filepath.Dir(p))}}, nil
		}
	}
	return detectPlan{What: "a file cracken-sbom does not recognise", Evidence: []string{name}, Unrecognised: true,
		Guidance: []string{
			"Supported files: a docker save or OCI image archive (.tar) and firmware images (.bin, .img, SquashFS, UBI, uImage, ...).",
			"For a project, run detect on its folder.",
		}}, nil
}

// shellQuote quotes a word for a POSIX shell when it needs quoting.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
