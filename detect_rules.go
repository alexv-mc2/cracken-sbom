package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
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
	// Target overrides the --target passed to generate (default: the path
	// detect looked at); Extra are further generate arguments.
	Target string
	Extra  []string
	// Choices are alternative generate arguments when detect cannot pick one
	// (several Yocto images or machines); detect prints one command each.
	Choices [][]string
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

// yoctoImage is one image's SPDX in a deploy directory: the file the
// IMAGE_LINK_NAME link points at, or the newest dated file.
type yoctoImage struct {
	Name     string // e.g. core-image-minimal-qemux86-64.rootfs
	File     string // real file name, e.g. ...rootfs-20261118093000.spdx.tar.zst
	Builds   int    // dated builds of this image in the directory
	TarZst   bool
	HasLink  bool
	realPath string
}

var yoctoDateSuffix = regexp.MustCompile(`-[0-9]{8,14}$`)

// yoctoImageFiles lists the image SPDX files directly in dir: SPDX 2.2
// *.spdx.tar.zst archives and SPDX 3 *.rootfs.spdx.json documents.
func yoctoImageFiles(dir string) []yoctoImage {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil
	}
	byName := map[string]*yoctoImage{}
	linked := map[string]bool{}
	reals := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		tarZst := strings.HasSuffix(name, ".spdx.tar.zst")
		if !tarZst && !yoctoRootfsName.MatchString(name) {
			continue
		}
		real, err := filepath.EvalSymlinks(filepath.Join(dir, name))
		if err != nil || !within(root, real) || !isRegularFile(real) {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			linked[real] = true
			continue
		}
		reals[real] = name
	}
	for real, file := range reals {
		stem := strings.TrimSuffix(strings.TrimSuffix(file, ".spdx.tar.zst"), ".spdx.json")
		image := yoctoDateSuffix.ReplaceAllString(stem, "")
		img := byName[image]
		if img == nil {
			img = &yoctoImage{Name: image}
			byName[image] = img
		}
		img.Builds++
		// The linked file is the current build; otherwise the newest name wins.
		if !img.HasLink && (linked[real] || file > img.File) {
			img.File, img.realPath, img.HasLink = file, real, linked[real]
			img.TarZst = strings.HasSuffix(file, ".spdx.tar.zst")
		}
	}
	out := []yoctoImage{}
	for _, img := range byName {
		out = append(out, *img)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// yoctoMachineDirs lists tmp/deploy/images/<machine>/ folders with image SPDX.
func yoctoMachineDirs(build string) []string {
	base := filepath.Join(build, "tmp", "deploy", "images")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		dir := filepath.Join(base, e.Name())
		if e.IsDir() && len(yoctoImageFiles(dir)) > 0 {
			out = append(out, dir)
		}
	}
	sort.Strings(out)
	return out
}

// yoctoImageArgs are the generate arguments for one image in a deploy dir.
// --yocto-image is the real file's stem, which matches that one file and
// the link to it but no other build.
func yoctoImageArgs(dir string, img yoctoImage, several bool) []string {
	args := []string{"--target", dir}
	if several || img.Builds > 1 {
		stem := strings.TrimSuffix(strings.TrimSuffix(img.File, ".spdx.tar.zst"), ".spdx.json")
		args = append(args, "--yocto-image", stem)
	}
	return args
}

func yoctoDeployPlan(dir string, images []yoctoImage, ev []string) detectPlan {
	what := "a Yocto deploy folder with the image SPDX the build wrote"
	if len(images) > 1 {
		plan := detectPlan{What: what, Evidence: ev}
		plan.Guidance = []string{fmt.Sprintf("It holds %d different images; choose one and run its command:", len(images))}
		for _, img := range images {
			plan.Choices = append(plan.Choices, yoctoImageArgs(dir, img, true))
		}
		plan.Guidance = append(plan.Guidance, "Details: "+yoctoGuideURL)
		return plan
	}
	img := images[0]
	args := yoctoImageArgs(dir, img, false)
	format := "SPDX 3 (*.rootfs.spdx.json)"
	if img.TarZst {
		format = "SPDX 2.2 (*.spdx.tar.zst)"
	}
	plan := detectPlan{
		What: what, Evidence: append(ev, img.File), TargetType: "yocto",
		Why:    "the build's own " + format + " lists what is installed in the image " + img.Name + ", and the CVEs it already patched go into a separate VEX file",
		Target: args[1], Extra: args[2:],
	}
	plan.Notes = append(plan.Notes, "Which file goes where: upload cracken-upload.zip from the output folder to crAcken (SPDX upload method: ZIP archive); give sbom.cdx.json and sbom.vex.cdx.json to BSI TR-03183-2 reviewers or your customer.")
	if img.Builds > 1 {
		plan.Notes = append(plan.Notes, fmt.Sprintf("The folder holds %d builds of %s; the current one (%s) is used.", img.Builds, img.Name, img.File))
	}
	if img.TarZst {
		if _, err := exec.LookPath("zstd"); err != nil {
			plan.Notes = append(plan.Notes, "Unpacking the .spdx.tar.zst needs zstd: install it (for example apt install zstd or brew install zstd).")
		}
	}
	return plan
}

func yoctoPlan(dir string) (detectPlan, bool) {
	_, yoctoTarget := defaultRegistry.target("yocto")
	// 1. tmp/deploy/images/<machine>/ itself.
	if yoctoTarget {
		if images := yoctoImageFiles(dir); len(images) > 0 {
			return yoctoDeployPlan(dir, images, nil), true
		}
	}
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
	if yoctoTarget {
		// 2. A build folder: look in tmp/deploy/images/<machine>/.
		machines := yoctoMachineDirs(dir)
		switch {
		case len(machines) == 1:
			plan := yoctoDeployPlan(machines[0], yoctoImageFiles(machines[0]), nil)
			plan.What = "a Yocto build folder"
			plan.Evidence = append(append(ev, filepath.ToSlash(mustRel(dir, machines[0]))+"/"), plan.Evidence...)
			return plan, true
		case len(machines) > 1:
			plan := detectPlan{What: "a Yocto build folder", Evidence: ev,
				Guidance: []string{fmt.Sprintf("It holds images for %d machines; choose one and run its command:", len(machines))}}
			for _, m := range machines {
				images := yoctoImageFiles(m)
				for _, img := range images {
					plan.Choices = append(plan.Choices, yoctoImageArgs(m, img, len(images) > 1))
				}
			}
			plan.Guidance = append(plan.Guidance, "Details: "+yoctoGuideURL)
			return plan, true
		}
		return detectPlan{What: "a Yocto build folder", Evidence: ev, Guidance: []string{
			"No image SPDX was found in tmp/deploy/images/<machine>/ yet.",
			"Enable the SPDX output (INHERIT += \"create-spdx\"; on by default in Poky), build the image with bitbake,",
			"then run cracken-sbom detect on this folder again. Details: " + yoctoGuideURL,
		}}, true
	}
	plan := detectPlan{What: "a Yocto build folder", Evidence: ev}
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

func mustRel(base, p string) string {
	if rel, err := filepath.Rel(base, p); err == nil {
		return rel
	}
	return p
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
