package main

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectGlobTableMatchesPinnedEngine(t *testing.T) {
	if detectGlobsSyftVersion != engineVersion {
		t.Fatalf("detect_globs_gen.go is from Syft %s but the engine is %s; run scripts/gen-detect-globs.py", detectGlobsSyftVersion, engineVersion)
	}
	kinds := map[globKind]int{}
	for _, g := range detectGlobs {
		kinds[g.Kind]++
	}
	if kinds[globDeclared] < 20 || kinds[globOS] < 5 || kinds[globInstalled] < 5 {
		t.Fatalf("generated table looks incomplete: %v", kinds)
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		pattern, rel string
		want         bool
	}{
		{"**/package-lock.json", "package-lock.json", true},
		{"**/package-lock.json", "web/app/package-lock.json", true},
		{"**/package-lock.json", "package-lock.json.bak", false},
		{"**/lib/dpkg/status", "var/lib/dpkg/status", true},
		{"**/lib/dpkg/status", "lib/dpkg/status", true},
		{"**/var/lib/pacman/local/**/desc", "var/lib/pacman/local/a-1/desc", true},
		{"**/*dist-info/METADATA", "site-packages/a-1.0.dist-info/METADATA", true},
		{"*pom.xml", "maven/pom.xml", true},
		{"**/*.gemspec", "x.gemspec.txt", false},
	} {
		if got := globMatch(c.pattern, c.rel); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.pattern, c.rel, got)
		}
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, "/") {
			continue
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func folderPlan(t *testing.T, dir string) detectPlan {
	t.Helper()
	plan, err := planForFolder(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestDetectFolderRules(t *testing.T) {
	for _, c := range []struct {
		name, target, what string
		files              map[string]string
	}{
		{"npm", "npm", "npm project", map[string]string{"package.json": "{}", "package-lock.json": `{"lockfileVersion":3,"packages":{}}`, "node_modules/x/package.json": "{}"}},
		{"many-ecosystems", "dir", "source project", map[string]string{"go.mod": "module x", "web/package-lock.json": "{}", "api/Cargo.lock": ""}},
		{"rootfs", "rootfs", "root file system", map[string]string{"etc/os-release": "ID=debian", "var/lib/dpkg/status": ""}},
		{"python", "python", "Python", map[string]string{"site-packages/a-1.0.dist-info/METADATA": "Name: a"}},
		{"jars-only", "dir", "no lockfile", map[string]string{"lib/app.jar": ""}},
		{"repo-with-rootfs-fixture", "dir", "source project", map[string]string{"go.mod": "module x", "fixtures/rootfs/etc/os-release": "", "fixtures/rootfs/var/lib/dpkg/status": ""}},
	} {
		t.Run(c.name, func(t *testing.T) {
			plan := folderPlan(t, writeTree(t, c.files))
			if plan.TargetType != c.target || !strings.Contains(plan.What, c.what) {
				t.Fatalf("got %q / %q, want %q", plan.TargetType, plan.What, c.target)
			}
		})
	}
}

func TestDetectGuidanceOnlyFolders(t *testing.T) {
	yocto := folderPlan(t, writeTree(t, map[string]string{"conf/local.conf": "MACHINE = \"qemux86-64\"", "tmp/deploy/spdx/": ""}))
	if yocto.TargetType != "" || !strings.Contains(yocto.What, "Yocto build") || !strings.Contains(strings.Join(yocto.Guidance, "\n"), "docs/YOCTO.md") {
		t.Fatalf("yocto plan: %+v", yocto)
	}
	docker := folderPlan(t, writeTree(t, map[string]string{"Dockerfile": "FROM scratch", "README.md": ""}))
	if docker.TargetType != "" || !strings.Contains(strings.Join(docker.Guidance, "\n"), "docker save") {
		t.Fatalf("dockerfile plan: %+v", docker)
	}
	npm := folderPlan(t, writeTree(t, map[string]string{"package.json": "{}"}))
	if npm.TargetType != "" || !strings.Contains(strings.Join(npm.Guidance, "\n"), "npm install --package-lock-only") {
		t.Fatalf("package.json without lockfile: %+v", npm)
	}
	empty := folderPlan(t, writeTree(t, map[string]string{"notes.txt": "hello"}))
	if !empty.Unrecognised {
		t.Fatalf("empty folder must be unrecognised: %+v", empty)
	}
	withImage := writeTree(t, map[string]string{})
	writeImageTar(t, filepath.Join(withImage, "app.tar"), map[string]string{"manifest.json": "[]", "layer.tar": ""})
	if p := folderPlan(t, withImage); p.TargetType != "" || !strings.Contains(strings.Join(p.Guidance, "\n"), "detect") {
		t.Fatalf("folder with an image archive: %+v", p)
	}
}

func writeImageTar(t *testing.T, path string, files map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for name, content := range files {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(content)), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDetectFileRules(t *testing.T) {
	dir := t.TempDir()
	docker := filepath.Join(dir, "docker.tar")
	writeImageTar(t, docker, map[string]string{"manifest.json": "[]", "repositories": "{}"})
	oci := filepath.Join(dir, "oci.tar")
	writeImageTar(t, oci, map[string]string{"oci-layout": "{}", "index.json": "{}"})
	plain := filepath.Join(dir, "rootfs.tar")
	writeImageTar(t, plain, map[string]string{"etc/os-release": ""})
	squash := filepath.Join(dir, "update.pkg")
	os.WriteFile(squash, append([]byte("hsqs"), make([]byte, 100)...), 0600)
	vendor := filepath.Join(dir, "router.bin")
	os.WriteFile(vendor, append(append(make([]byte, 64), []byte("hsqs")...), make([]byte, 100)...), 0600)
	opaque := filepath.Join(dir, "image.img")
	os.WriteFile(opaque, make([]byte, 4096), 0600)
	gz := filepath.Join(dir, "data.gz")
	os.WriteFile(gz, []byte{0x1f, 0x8b, 0x08, 0, 0, 0}, 0600)
	ext4 := filepath.Join(dir, "disk.raw")
	raw := make([]byte, 0x500)
	raw[0x438], raw[0x439] = 0x53, 0xef
	os.WriteFile(ext4, raw, 0600)
	text := filepath.Join(dir, "notes.txt")
	os.WriteFile(text, []byte("hello"), 0600)
	lock := filepath.Join(dir, "Cargo.lock")
	os.WriteFile(lock, []byte(""), 0600)
	for _, c := range []struct {
		path, target string
		unrecognised bool
	}{
		{docker, "docker-archive", false}, {oci, "oci-archive", false}, {plain, "", false},
		{squash, firmwareTargetType, false}, {vendor, firmwareTargetType, false}, {opaque, firmwareTargetType, false},
		{ext4, firmwareTargetType, false}, {gz, "", false}, {lock, "", false}, {text, "", true},
	} {
		plan, err := planForFile(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if plan.TargetType != c.target || plan.Unrecognised != c.unrecognised {
			t.Errorf("%s: got %q (unrecognised %v): %s", filepath.Base(c.path), plan.TargetType, plan.Unrecognised, plan.What)
		}
	}
}

// isolateEngineSearch makes the locator see only the given PATH and an
// empty cache folder.
func isolateEngineSearch(t *testing.T, path string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("PATH", path)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
}

func fakeSyft(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "syft")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectRunsTheGeneratePipeline(t *testing.T) {
	project := writeTree(t, map[string]string{"package-lock.json": `{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo"}}}`})
	output := filepath.Join(t.TempDir(), "evidence")
	var out bytes.Buffer
	args := []string{"detect", project, "--syft", fakeSyft(t), "--output", output, "--target-id", "release-1.0"}
	if err := runCLI(context.Background(), args, &out, successRunner, fixedNow); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	text := out.String()
	for _, want := range []string{"Found: an npm project with a lockfile", "Command: cracken-sbom generate --target-type npm --target ", "Generated sbom.cdx.json"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if _, err := os.Stat(filepath.Join(output, "sbom.cdx.json")); err != nil {
		t.Fatal("no SBOM written")
	}
}

func TestNoArgumentsDetectsTheCurrentFolderWithDefaults(t *testing.T) {
	parent := t.TempDir()
	project := filepath.Join(parent, "app")
	os.MkdirAll(filepath.Join(project, ".git", "refs", "heads"), 0700)
	os.WriteFile(filepath.Join(project, "go.mod"), []byte("module app\n"), 0600)
	os.WriteFile(filepath.Join(project, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0600)
	sha := strings.Repeat("ab", 20)
	os.WriteFile(filepath.Join(project, ".git", "refs", "heads", "main"), []byte(sha+"\n"), 0600)
	syftDir := filepath.Dir(fakeSyft(t))
	isolateEngineSearch(t, syftDir) // the fake is rejected: wrong digest
	t.Chdir(project)
	var out bytes.Buffer
	err := runCLI(context.Background(), []string{"--dry-run", "--syft", filepath.Join(syftDir, "syft")}, &out, successRunner, fixedNow)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	text := out.String()
	for _, want := range []string{"--target-type dir", "--target-id " + sha, "app-sbom-20261004-120000", "Dry run: nothing was built"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 {
		t.Fatal("dry run created files")
	}
}

func TestDetectYoctoExplainsAndSucceeds(t *testing.T) {
	build := writeTree(t, map[string]string{"conf/local.conf": "", "conf/bblayers.conf": ""})
	var out bytes.Buffer
	if err := runCLI(context.Background(), []string{"detect", build}, &out, nil, fixedNow); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Yocto build folder") || !strings.Contains(out.String(), "No SBOM was written.") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestMissingSyftSaysHowToInstall(t *testing.T) {
	wrong := fakeSyft(t)
	isolateEngineSearch(t, filepath.Dir(wrong))
	project := writeTree(t, map[string]string{"Cargo.lock": ""})
	err := runCLI(context.Background(), []string{"detect", project}, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil {
		t.Fatal("missing engine accepted")
	}
	for _, want := range []string{"syft not found", "Install it like this", "Skipped " + wrong, "v" + engineVersion} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q:\n%v", want, err)
		}
	}
	// generate without --syft gives the same message.
	args := []string{"generate", "--target-type", "dir", "--target", project, "--target-id", "r1", "--output", filepath.Join(t.TempDir(), "o")}
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, successRunner, fixedNow); err == nil || !strings.Contains(err.Error(), "syft not found") {
		t.Fatalf("generate: %v", err)
	}
}

func TestFirmwareWithoutExtractorSaysHowToInstall(t *testing.T) {
	isolateEngineSearch(t, t.TempDir())
	image := filepath.Join(t.TempDir(), "fw.bin")
	os.WriteFile(image, append([]byte("hsqs"), make([]byte, 64)...), 0600)
	err := runCLI(context.Background(), []string{"detect", image, "--syft", fakeSyft(t)}, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "pipx install unblob") {
		t.Fatalf("got %v", err)
	}
}

func TestHelpPrintsAndSucceeds(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"help", "generate"}, {"generate", "--help"}, {"detect", "--help"}, {"detect", "-h"}, {"--version"}} {
		var out bytes.Buffer
		if err := runCLI(context.Background(), args, &out, nil, fixedNow); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if out.Len() == 0 || strings.Contains(out.String(), "invalid flags") {
			t.Fatalf("%v printed %q", args, out.String())
		}
	}
}

func TestFlagAndPathErrorsNameTheFlagOrPath(t *testing.T) {
	args, _ := cliFixture(t)
	err := runCLI(context.Background(), append(args, "--bogus", "secret-value"), &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "unknown flag --bogus") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("generate unknown flag: %v", err)
	}
	err = runCLI(context.Background(), []string{"detect", "--bogus"}, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "unknown flag --bogus") {
		t.Fatalf("detect unknown flag: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "no-such-folder")
	err = runCLI(context.Background(), []string{"detect", missing}, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("detect bad path: %v", err)
	}
	args, _ = cliFixture(t)
	args[4] = missing // --target
	err = runCLI(context.Background(), args, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.HasPrefix(err.Error(), "--target:") {
		t.Fatalf("generate bad target: %v", err)
	}
	err = runCLI(context.Background(), []string{"generate", "--target-type", "dir"}, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "missing --target, --target-id, --output") {
		t.Fatalf("generate missing flags: %v", err)
	}
	err = runCLI(context.Background(), []string{"frobnicate"}, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), `unknown command "frobnicate"`) {
		t.Fatalf("unknown command: %v", err)
	}
}

func TestGitHeadReadsPackedRefs(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".git/HEAD":        "ref: refs/heads/release\n",
		".git/packed-refs": "# pack-refs with: peeled\n" + strings.Repeat("c", 40) + " refs/heads/release\n",
	})
	if sha, ok := gitHead(filepath.Join(dir, ".git")); !ok || sha != strings.Repeat("c", 40) {
		t.Fatalf("got %q %v", sha, ok)
	}
	bad := writeTree(t, map[string]string{".git/HEAD": "ref: refs/../../etc/passwd\n"})
	if _, ok := gitHead(filepath.Join(bad, ".git")); ok {
		t.Fatal("unsafe ref accepted")
	}
}
