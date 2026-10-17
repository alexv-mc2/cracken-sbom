package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// The fake extractor stands in for unblob: it answers --version and writes a
// known tree into --extract-dir. Real extractors are exercised by the manual
// end-to-end run described in the README, not in unit tests, because they need
// helper tools that this repository does not provision.
const fakeExtractorScript = `#!/bin/sh
if [ "$1" = --version ]; then echo "fake-unblob 9.8.7"; exit 0; fi
if [ "$1" = --help ]; then exit 0; fi
while [ $# -gt 0 ]; do
  case "$1" in --extract-dir) dir=$2; shift ;; esac
  shift
done
[ -n "$dir" ] || exit 2
base="$dir/image.bin_extract"
mkdir -p "$base/0-4096.unknown" "$base/4096-9000.squashfs_extract/etc" "$base/4096-9000.squashfs_extract/bin" "$base/9000-9100.zip_extract"
echo ID=debian > "$base/4096-9000.squashfs_extract/etc/os-release"
echo sh > "$base/4096-9000.squashfs_extract/bin/sh"
echo "data" > "$base/9000-9100.zip_extract/readme.txt"
%s
`

type firmwareFixture struct {
	args      []string
	output    string
	extractor string
	image     string
	dir       string
}

func newFirmwareFixture(t *testing.T, script, extractorName string) firmwareFixture {
	t.Helper()
	dir := t.TempDir()
	image := filepath.Join(dir, "device-1.2.3.bin")
	if os.WriteFile(image, []byte("synthetic firmware image bytes"), 0600) != nil {
		t.Fatal("create image")
	}
	syft := filepath.Join(dir, "syft")
	if os.WriteFile(syft, []byte("unused mock runner executable"), 0700) != nil {
		t.Fatal("create mock engine")
	}
	extractor := filepath.Join(dir, extractorName)
	if os.WriteFile(extractor, []byte(script), 0700) != nil {
		t.Fatal("create fake extractor")
	}
	output := filepath.Join(dir, "new-output")
	args := []string{"generate", "--target-type", "firmware-image", "--target", image, "--target-id", "release-1.0", "--output", output, "--syft", syft, "--extractor", extractor}
	return firmwareFixture{args, output, extractor, image, dir}
}

func stagingLeft(dir string) bool {
	entries, _ := filepath.Glob(filepath.Join(dir, ".cracken-sbom-*"))
	return len(entries) > 0
}

func TestFirmwareImageEndToEndWithFakeExtractor(t *testing.T) {
	f := newFirmwareFixture(t, strings.Replace(fakeExtractorScript, "%s", "", 1), "unblob")
	var scanned, scannedType string
	runner := func(_ context.Context, _, target, targetType string) ([]byte, error) {
		scanned, scannedType = target, targetType
		if _, err := os.Stat(filepath.Join(target, "etc", "os-release")); err != nil {
			t.Error("engine was not pointed at the selected root filesystem")
		}
		return []byte(validRawSBOM), nil
	}
	var printed bytes.Buffer
	if err := runCLI(context.Background(), f.args, &printed, runner, fixedNow); err != nil {
		t.Fatal(err)
	}
	if scannedType != "rootfs" || !strings.HasSuffix(filepath.ToSlash(scanned), "image.bin_extract/4096-9000.squashfs_extract") {
		t.Fatalf("unexpected engine target: %q (%s)", scanned, scannedType)
	}
	if _, err := os.Stat(scanned); !os.IsNotExist(err) {
		t.Fatal("extraction tree survived generation")
	}
	if stagingLeft(f.dir) {
		t.Fatal("private extraction workspace left behind")
	}
	if strings.Contains(printed.String(), f.dir) {
		t.Fatal("success output leaks local path")
	}

	imageData, _ := os.ReadFile(f.image)
	extractorData, _ := os.ReadFile(f.extractor)
	provenance, _ := os.ReadFile(filepath.Join(f.output, "provenance.json"))
	var p struct {
		Target   map[string]string `json:"target"`
		Config   string            `json:"configuration_sha256"`
		Firmware struct {
			SourceType string `json:"source_type"`
			Image      struct {
				FileName string `json:"file_name"`
				Size     int64  `json:"size_bytes"`
				SHA256   string `json:"sha256"`
			} `json:"image"`
			Extractor struct {
				Kind, Version string
				SHA256        string `json:"entry_file_sha256"`
			} `json:"extractor"`
			ExtractedAt  string   `json:"extracted_at"`
			SelectedRoot string   `json:"selected_root"`
			Files        int      `json:"extracted_file_count"`
			Unused       []string `json:"unused_entries"`
			Truncated    bool     `json:"unused_entries_truncated"`
			Others       []string `json:"other_root_candidates"`
			Errors       bool     `json:"extractor_reported_errors"`
		} `json:"firmware"`
	}
	if err := json.Unmarshal(provenance, &p); err != nil {
		t.Fatal(err)
	}
	fw := p.Firmware
	if p.Target["type"] != "firmware-image" || p.Config != configurationDigest("firmware-image") {
		t.Fatal("target type or configuration digest wrong")
	}
	if fw.SourceType != "firmware-image" || fw.Image.FileName != "device-1.2.3.bin" || fw.Image.Size != int64(len(imageData)) || fw.Image.SHA256 != sha256Hex(imageData) {
		t.Fatalf("image facts wrong: %+v", fw.Image)
	}
	if fw.Extractor.Kind != "unblob" || fw.Extractor.Version != "9.8.7" || fw.Extractor.SHA256 != sha256Hex(extractorData) {
		t.Fatalf("extractor facts wrong: %+v", fw.Extractor)
	}
	if fw.ExtractedAt != "2026-10-04T12:00:00Z" || fw.SelectedRoot != "image.bin_extract/4096-9000.squashfs_extract" || fw.Files != 3 {
		t.Fatalf("extraction facts wrong: %+v", fw)
	}
	if strings.Join(fw.Unused, ",") != "image.bin_extract/0-4096.unknown,image.bin_extract/9000-9100.zip_extract" || fw.Truncated || len(fw.Others) != 0 || fw.Errors {
		t.Fatalf("unused entries wrong: %+v", fw.Unused)
	}

	sbom, _ := os.ReadFile(filepath.Join(f.output, "sbom.cdx.json"))
	var doc struct {
		Metadata struct {
			Properties []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal(sbom, &doc); err != nil {
		t.Fatal(err)
	}
	props := map[string]string{}
	for _, pr := range doc.Metadata.Properties {
		props[pr.Name] = pr.Value
	}
	for name, want := range map[string]string{
		"cracken:target:type": "firmware-image", "cracken:firmware:source-type": "firmware-image",
		"cracken:firmware:image-name": "device-1.2.3.bin", "cracken:firmware:image-sha256": sha256Hex(imageData),
		"cracken:firmware:extractor": "unblob", "cracken:firmware:extractor-version": "9.8.7",
		"cracken:firmware:selected-root": "image.bin_extract/4096-9000.squashfs_extract", "cracken:firmware:extracted-file-count": "3",
		"cracken:firmware:unused-entry-count": "2", "cracken:firmware:extractor-reported-errors": "false",
	} {
		if props[name] != want {
			t.Errorf("property %s = %q, want %q", name, props[name], want)
		}
	}
	if strings.Contains(string(sbom), f.dir) || strings.Contains(string(sbom), "readme.txt") || strings.Contains(string(sbom), "0-4096.unknown") {
		t.Fatal("SBOM carries local paths or extracted file names")
	}
	quality, _ := os.ReadFile(filepath.Join(f.output, "quality.json"))
	if !bytes.Contains(quality, []byte("best-effort extraction of a firmware image")) {
		t.Fatal("quality.json lacks the extraction warning")
	}
}

func TestFirmwareImageExtractorErrorsWithPartialOutputAreRecorded(t *testing.T) {
	f := newFirmwareFixture(t, strings.Replace(fakeExtractorScript, "%s", "exit 1", 1), "unblob")
	if err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	quality, _ := os.ReadFile(filepath.Join(f.output, "quality.json"))
	provenance, _ := os.ReadFile(filepath.Join(f.output, "provenance.json"))
	if !bytes.Contains(quality, []byte("extractor reported errors")) || !bytes.Contains(provenance, []byte(`"extractor_reported_errors": true`)) {
		t.Fatal("extractor failure was hidden")
	}
}

func TestFirmwareImageWithoutRootFilesystemFailsAndListsEntries(t *testing.T) {
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 1.0.0; exit 0; fi\nif [ \"$1\" = --help ]; then exit 0; fi\nwhile [ $# -gt 0 ]; do case \"$1\" in --extract-dir) d=$2; shift;; esac; shift; done\nmkdir -p \"$d/x_extract/0-10.gzip_extract\" \"$d/x_extract/boot\"\necho a > \"$d/x_extract/loader.bin\"\n"
	f := newFirmwareFixture(t, script, "unblob")
	called := false
	runner := func(context.Context, string, string, string) ([]byte, error) { called = true; return nil, nil }
	err := runCLI(context.Background(), f.args, &bytes.Buffer{}, runner, fixedNow)
	if err == nil || called {
		t.Fatal("image without a root filesystem reached the engine")
	}
	for _, want := range []string{"no root filesystem", "0-10.gzip_extract/", "boot/", "loader.bin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), f.dir) {
		t.Fatal("error leaks local path")
	}
	if _, statErr := os.Stat(f.output); !os.IsNotExist(statErr) || stagingLeft(f.dir) {
		t.Fatal("failure left output or workspace")
	}
}

func TestFirmwareImageExtractorProducingNothingFails(t *testing.T) {
	f := newFirmwareFixture(t, "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 1.0.0; exit 0; fi\nif [ \"$1\" = --help ]; then exit 0; fi\nexit 1\n", "unblob")
	err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "produced no output") {
		t.Fatalf("unexpected result: %v", err)
	}
	if stagingLeft(f.dir) {
		t.Fatal("failure left workspace")
	}
}

func TestFirmwareImageFlagValidation(t *testing.T) {
	f := newFirmwareFixture(t, strings.Replace(fakeExtractorScript, "%s", "", 1), "unblob")
	without := func(flag string) []string {
		var out []string
		for i := 0; i < len(f.args); i++ {
			if f.args[i] == flag {
				i++
				continue
			}
			out = append(out, f.args[i])
		}
		return out
	}
	cases := map[string][]string{
		"missing-extractor":  without("--extractor"),
		"relative-extractor": append(without("--extractor"), "--extractor", "unblob"),
		"unknown-kind":       append(append([]string{}, f.args...), "--extractor-kind", "ghidra"),
		"directory-target":   append(without("--target"), "--target", f.dir),
		"extractor-on-rootfs": func() []string {
			a, _ := cliFixture(t)
			return append(a, "--extractor", f.extractor)
		}(),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			called := false
			runner := func(context.Context, string, string, string) ([]byte, error) {
				called = true
				return nil, errors.New("x")
			}
			if runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow) == nil || called {
				t.Fatal("invalid firmware invocation accepted")
			}
		})
	}
}

func TestFirmwareExtractorKindDetection(t *testing.T) {
	for _, c := range []struct{ given, canonical, explicit, want string }{
		{"/x/unblob", "/y/unblob", "", "unblob"},
		{"/x/binwalk", "/y/binwalk", "", "binwalk"},
		{"/x/link", "/y/bin/UNBLOB", "", "unblob"},
		{"/x/tool", "/y/tool", "binwalk", "binwalk"},
		{"/x/unblob", "/y/unblob", "binwalk", "binwalk"},
	} {
		got, err := detectExtractorKind(c.given, c.canonical, c.explicit)
		if err != nil || got != c.want {
			t.Errorf("%+v: got %q, %v", c, got, err)
		}
	}
	if _, err := detectExtractorKind("/x/tool", "/y/tool", ""); err == nil {
		t.Error("unknown extractor name accepted without --extractor-kind")
	}
}

func TestFirmwareSymlinkedExtractorIsResolved(t *testing.T) {
	f := newFirmwareFixture(t, strings.Replace(fakeExtractorScript, "%s", "", 1), "unblob")
	link := filepath.Join(f.dir, "bin-link")
	if os.Symlink(f.extractor, link) != nil {
		t.Fatal("create symlink")
	}
	args := append([]string{}, f.args...)
	args[len(args)-1] = link
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
}

func mkfile(t *testing.T, root string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if os.MkdirAll(filepath.Dir(p), 0700) != nil || os.WriteFile(p, []byte("x"), 0600) != nil {
			t.Fatal("create fixture file")
		}
	}
}

func TestSelectRootFSPicksLargestAndReportsOthers(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "a_extract/etc/x", "a_extract/bin/x")                                           // 2 files
	mkfile(t, dir, "b_extract/etc/x", "b_extract/bin/x", "b_extract/lib/x", "b_extract/usr/bin/x") // 4
	mkfile(t, dir, "c_extract/etc/x", "c_extract/lib/x")                                           // 2
	mkfile(t, dir, "other/readme")
	root, others, _, err := selectRootFS(context.Background(), dir)
	if err != nil || root != "b_extract" || strings.Join(others, ",") != "a_extract,c_extract" {
		t.Fatalf("root=%q others=%v err=%v", root, others, err)
	}
}

func TestSelectRootFSDoesNotTreatNestedTreesAsSeparateRoots(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "fs/etc/x", "fs/bin/x", "fs/usr/bin/x", "fs/usr/lib/x", "fs/opt/app/etc/y", "fs/opt/app/bin/y")
	root, others, _, err := selectRootFS(context.Background(), dir)
	if err != nil || root != "fs" || len(others) != 0 {
		t.Fatalf("root=%q others=%v err=%v", root, others, err)
	}
}

func TestSelectRootFSAcceptsPackageDatabaseAndMergedUsr(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "db_extract/var/lib/dpkg/status")
	if root, _, _, err := selectRootFS(context.Background(), dir); err != nil || root != "db_extract" {
		t.Fatalf("package database root: %q %v", root, err)
	}
	merged := t.TempDir()
	mkfile(t, merged, "m/etc/x", "m/usr/bin/x")
	if os.Symlink("usr/bin", filepath.Join(merged, "m", "bin")) != nil {
		t.Fatal("symlink")
	}
	if root, _, _, err := selectRootFS(context.Background(), merged); err != nil || root != "m" {
		t.Fatalf("merged usr root: %q %v", root, err)
	}
}

func TestSelectRootFSTieBreakIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "z/etc/x", "z/bin/x", "a/etc/x", "a/bin/x")
	for i := 0; i < 3; i++ {
		if root, _, _, err := selectRootFS(context.Background(), dir); err != nil || root != "a" {
			t.Fatalf("root=%q err=%v", root, err)
		}
	}
}

func TestSelectRootFSRejectsTreesWithoutRootLayout(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "blob/etc/only", "blob/data/x", "bin/alone")
	if _, _, _, err := selectRootFS(context.Background(), dir); !errors.Is(err, errNoRootFS) {
		t.Fatalf("expected errNoRootFS, got %v", err)
	}
}

func TestSelectRootFSDoesNotFollowSymlinkedDirectories(t *testing.T) {
	outside := t.TempDir()
	mkfile(t, outside, "etc/x", "bin/x", "lib/x")
	dir := t.TempDir()
	if os.Symlink(outside, filepath.Join(dir, "escape")) != nil {
		t.Fatal("symlink")
	}
	if root, _, _, err := selectRootFS(context.Background(), dir); err == nil {
		t.Fatalf("symlink to an outside tree was selected: %q", root)
	}
}

func TestEntriesBesideSkipsImageLinkAndListsSiblings(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(t.TempDir(), "image.bin")
	mkfile(t, dir, "image.bin.extracted/1000/etc/x", "image.bin.extracted/2000/y", "image.bin.extracted/1000/etc/z")
	if os.Symlink(image, filepath.Join(dir, "image.bin")) != nil {
		t.Fatal("symlink")
	}
	listed, total := entriesBeside(dir, "image.bin.extracted/1000", image, 1)
	if total != 1 || strings.Join(listed, ",") != "image.bin.extracted/2000" {
		t.Fatalf("listed=%v total=%d", listed, total)
	}
}

func TestFirmwarePropertyValueWithholdsUnsafeNames(t *testing.T) {
	for _, v := range []string{"device-1.2.3.bin", "image.bin_extract/0-10.tar_extract", "my firmware v2.bin"} {
		if firmwarePropertyValue(v) != v {
			t.Errorf("safe value %q was altered", v)
		}
	}
	for _, v := range []string{"https://x@example.org/a", "token=abc.bin", "a\\b", "../up", "line\nbreak", ""} {
		if firmwarePropertyValue(v) != "withheld-unsafe-characters" {
			t.Errorf("unsafe value %q was kept", v)
		}
	}
}

func TestFirmwareProvenanceRejectsInvalidFacts(t *testing.T) {
	good := FirmwareInfo{ImageName: "a.bin", ImageSHA256: strings.Repeat("a", 64), ExtractorKind: "unblob", ExtractorVersion: "1.0.0", ExtractorEntrySHA256: strings.Repeat("b", 64), ExtractedAt: "2026-10-04T12:00:00Z", RootPath: "r"}
	ctx := testContext()
	ctx.TargetType = "firmware-image"
	ctx.Firmware = &good
	if _, err := createProvenance([]byte("{}\n"), ctx, Quality{}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*FirmwareInfo){
		"kind":   func(f *FirmwareInfo) { f.ExtractorKind = "other" },
		"digest": func(f *FirmwareInfo) { f.ImageSHA256 = "short" },
		"time":   func(f *FirmwareInfo) { f.ExtractedAt = "yesterday" },
		"root":   func(f *FirmwareInfo) { f.RootPath = "" },
	} {
		bad := good
		mutate(&bad)
		ctx.Firmware = &bad
		if _, err := createProvenance([]byte("{}\n"), ctx, Quality{}); err == nil {
			t.Errorf("invalid %s accepted", name)
		}
	}
}

// The extracted tree goes through the unchanged rootfs scan, so the resolved
// scan policy digest is the rootfs one; extraction facts live in the firmware block.
func TestFirmwareImageUsesRootfsScanPolicyDigest(t *testing.T) {
	if configurationDigest("firmware-image") != configurationDigest("rootfs") {
		t.Fatal("firmware-image must share the rootfs scan policy digest")
	}
}

// binwalk 3 layout: a link to the image beside <image>.extracted/<offset>/, a JSON
// log, and exit status 0 even when something failed.
const fakeBinwalkScript = `#!/bin/sh
if [ "$1" = --version ]; then echo "binwalk 3.1.0"; exit 0; fi
if [ "$1" = --help ]; then exit 0; fi
for a in "$@"; do image=$a; done
while [ $# -gt 0 ]; do
  case "$1" in --directory) dir=$2; shift ;; --log) log=$2; shift ;; esac
  shift
done
name=$(basename "$image")
mkdir -p "$dir/$name.extracted/1000/etc" "$dir/$name.extracted/1000/bin" "$dir/$name.extracted/2000"
ln -s "$image" "$dir/$name"
echo ID=debian > "$dir/$name.extracted/1000/etc/os-release"
echo sh > "$dir/$name.extracted/1000/bin/sh"
echo blob > "$dir/$name.extracted/2000/data"
printf '[{"Analysis":{"extractions":{"a":{"success":%s}}}}]' %s > "$log"
`

func TestFirmwareImageBinwalkLayout(t *testing.T) {
	f := newFirmwareFixture(t, fmt.Sprintf(fakeBinwalkScript, "true", `""`), "binwalk")
	if err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Firmware struct {
			Extractor struct{ Kind, Version string }
			Root      string   `json:"selected_root"`
			Files     int      `json:"extracted_file_count"`
			Unused    []string `json:"unused_entries"`
			Errors    bool     `json:"extractor_reported_errors"`
		}
	}
	data, _ := os.ReadFile(filepath.Join(f.output, "provenance.json"))
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	fw := p.Firmware
	if fw.Extractor.Kind != "binwalk" || fw.Extractor.Version != "3.1.0" || fw.Root != "device-1.2.3.bin.extracted/1000" {
		t.Fatalf("unexpected firmware facts: %+v", fw)
	}
	// os-release and sh in the root, data beside it; the image link is not data.
	if fw.Files != 3 || strings.Join(fw.Unused, ",") != "device-1.2.3.bin.extracted/2000" || fw.Errors {
		t.Fatalf("link to the image was counted or listed: %+v", fw)
	}
}

func TestFirmwareImageBinwalkLogFailureIsReportedDespiteExitZero(t *testing.T) {
	f := newFirmwareFixture(t, fmt.Sprintf(fakeBinwalkScript, "false", `""`), "binwalk")
	if err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	quality, _ := os.ReadFile(filepath.Join(f.output, "quality.json"))
	if !bytes.Contains(quality, []byte("extractor reported errors")) {
		t.Fatal("binwalk failure in the JSON log was not reported")
	}
}

func TestBinwalkLogShowsFailure(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0600)
		return p
	}
	if binwalkLogShowsFailure(write("ok", `[{"Analysis":{"extractions":{"a":{"success":true}}}}]`)) {
		t.Error("successful log reported as failure")
	}
	// The loose stream binwalk 3.1 writes with --matryoshka.
	loose := `[
{"Analysis":{"file_path":"a","file_map":[],"extractions":{"x":{"success":true}}}}
],
{"Analysis":{"file_path":"b","file_map":[],"extractions":{}}}
]`
	if binwalkLogShowsFailure(write("loose", loose)) {
		t.Error("real binwalk log shape reported as failure")
	}
	if !binwalkLogShowsFailure(write("loose-bad", strings.Replace(loose, `"x":{"success":true}`, `"x":{"success":false}`, 1))) {
		t.Error("failure in the loose stream not detected")
	}
	if !binwalkLogShowsFailure(write("bad", `[{"Analysis":{"extractions":{"a":{"success":true},"b":{"success":false}}}}]`)) {
		t.Error("failed extraction not detected")
	}
	if !binwalkLogShowsFailure(write("junk", `not json`)) || !binwalkLogShowsFailure(filepath.Join(dir, "missing")) {
		t.Error("unreadable log must count as unconfirmed")
	}
}

func TestFirmwareImageNoRootWithBinwalkLayoutListsInnerEntries(t *testing.T) {
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 3.1.0; exit 0; fi\nif [ \"$1\" = --help ]; then exit 0; fi\nfor a in \"$@\"; do image=$a; done\nwhile [ $# -gt 0 ]; do case \"$1\" in --directory) d=$2; shift;; esac; shift; done\nn=$(basename \"$image\")\nmkdir -p \"$d/$n.extracted/0\"\nln -s \"$image\" \"$d/$n\"\n"
	f := newFirmwareFixture(t, script, "binwalk")
	err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "0/") || strings.Contains(err.Error(), "device-1.2.3.bin,") || !strings.Contains(err.Error(), "binwalk --list") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFirmwareImageHelperOutlivingExtractorIsStopped(t *testing.T) {
	script := strings.Replace(fakeExtractorScript, "%s", "sleep 60 &\necho $! > \"$(dirname \"$0\")/helper.pid\"", 1)
	f := newFirmwareFixture(t, script, "unblob")
	start := time.Now()
	if err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatal("generation waited for a leftover helper")
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, "helper.pid"))
	if err != nil {
		t.Fatal("fake extractor did not record its helper")
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	deadline := time.Now().Add(3 * time.Second)
	for processRuns(pid) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if processRuns(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("helper process survived the extraction")
	}
}

func TestFirmwareImageUnsafeNamesAreWithheldFromSBOMOnly(t *testing.T) {
	f := newFirmwareFixture(t, strings.Replace(fakeExtractorScript, "%s", "", 1), "unblob")
	unsafe := filepath.Join(f.dir, "token=1.bin")
	if os.Rename(f.image, unsafe) != nil {
		t.Fatal("rename image")
	}
	args := append([]string{}, f.args...)
	args[4] = unsafe
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	sbom, _ := os.ReadFile(filepath.Join(f.output, "sbom.cdx.json"))
	provenance, _ := os.ReadFile(filepath.Join(f.output, "provenance.json"))
	if strings.Contains(string(sbom), "token=1") || !strings.Contains(string(sbom), "withheld-unsafe-characters") {
		t.Fatal("unsafe image name reached the SBOM")
	}
	if !strings.Contains(string(provenance), "token=1.bin") {
		t.Fatal("exact image name missing from local provenance")
	}
}

func TestFirmwareImageWorkDir(t *testing.T) {
	script := strings.Replace(fakeExtractorScript, "%s", "echo \"$dir\" > \"$(dirname \"$0\")/extract-dir\"", 1)
	f := newFirmwareFixture(t, script, "unblob")
	work := t.TempDir()
	args := append(append([]string{}, f.args...), "--work-dir", work)
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(f.dir, "extract-dir"))
	resolved, _ := filepath.EvalSymlinks(work)
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), resolved+string(filepath.Separator)) {
		t.Fatalf("extraction did not use --work-dir: %q", raw)
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatal("work directory not cleaned")
	}
	for name, bad := range map[string][]string{
		"relative": append(append([]string{}, f.args...), "--work-dir", "relative"),
		"missing":  append(append([]string{}, f.args...), "--work-dir", filepath.Join(work, "nope")),
		"on-rootfs": func() []string {
			a, _ := cliFixture(t)
			return append(a, "--work-dir", work)
		}(),
	} {
		if err := runCLI(context.Background(), bad, &bytes.Buffer{}, successRunner, fixedNow); err == nil {
			t.Errorf("%s --work-dir accepted", name)
		}
	}
}

func TestSelectRootFSLargestWinsDatabaseBreaksTiesAndAllCandidatesAreCounted(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "big/etc/a", "big/bin/a", "big/lib/a", "big/usr/a", "big/var/a")
	mkfile(t, dir, "small/etc/a", "small/bin/a", "small/var/lib/opkg/status")
	for i := 0; i < 24; i++ {
		mkfile(t, dir, fmt.Sprintf("extra%02d/etc/a", i), fmt.Sprintf("extra%02d/bin/a", i))
	}
	root, others, total, err := selectRootFS(context.Background(), dir)
	if err != nil || root != "big" || total != 25 || len(others) != maxListedCandidates {
		t.Fatalf("root=%q listed=%d total=%d err=%v", root, len(others), total, err)
	}
	// Equal size: the tree with a package database wins over an earlier name.
	tie := t.TempDir()
	mkfile(t, tie, "a/etc/x", "a/bin/x", "b/etc/x", "b/var/lib/opkg/status")
	if root, _, _, err := selectRootFS(context.Background(), tie); err != nil || root != "b" {
		t.Fatalf("tie root=%q err=%v", root, err)
	}
}

func TestFirmwareImageChangedDuringExtractionFails(t *testing.T) {
	// The fake extractor rewrites the image while "extracting".
	script := strings.Replace(fakeExtractorScript, "%s", "echo changed >> \"$image\"", 1)
	script = strings.Replace(script, "while [ $# -gt 0 ]; do", "for image in \"$@\"; do :; done\nwhile [ $# -gt 0 ]; do", 1)
	f := newFirmwareFixture(t, script, "unblob")
	err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("modified image accepted: %v", err)
	}
	if _, statErr := os.Stat(f.output); !os.IsNotExist(statErr) || stagingLeft(f.dir) {
		t.Fatal("failure left output or workspace")
	}
}

func TestTopLevelListingIsSafeForTerminals(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "a\u202eevil", "\x1b[31mred")
	for i := 0; i < 80; i++ {
		mkfile(t, dir, strings.Repeat("\u00e9", 100)+fmt.Sprint(i))
	}
	text := topLevelListing(dir, "/none", 1)
	if !utf8.ValidString(text) || strings.ContainsAny(text, "\u202e\x1b\u2026") || !strings.Contains(text, "...") {
		t.Fatalf("unsafe listing: %q", text)
	}
}

func TestFinalProvenanceRequiresFirmwareBlock(t *testing.T) {
	ctx := testContext()
	ctx.TargetType = "firmware-image"
	if _, err := validateContext(ctx); err != nil {
		t.Fatalf("pre-check must accept a context before extraction: %v", err)
	}
	if _, err := createProvenance([]byte("{}\n"), ctx, Quality{}); err == nil {
		t.Fatal("final provenance without firmware facts accepted")
	}
}

// processRuns is false for a missing process and for a zombie: where PID 1 does
// not reap orphans (some containers), a killed helper stays listed as a zombie
// although it can no longer run or write.
func processRuns(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state != "" && !strings.HasPrefix(state, "Z")
}

func TestSelectUnblobOptions(t *testing.T) {
	for _, c := range []struct {
		name, help string
		want       string
	}{
		{"current", "  -n, --randomness-depth INTEGER RANGE\n  --report PATH", "--randomness-depth 0"},
		{"older", "  -n, --entropy-depth INTEGER\n  --report PATH", "--entropy-depth 0"},
		{"neither", "  --extract-dir DIRECTORY", ""},
		{"empty", "", ""},
	} {
		if got := strings.Join(selectUnblobOptions(c.help), " "); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// A fake unblob that rejects unknown flags like a real usage error would.
func TestFirmwareImageUnblobNeverPassesFlagsItDoesNotList(t *testing.T) {
	script := `#!/bin/sh
case "$1" in
  --version) echo 1.0.0; exit 0 ;;
  --help) echo "  -e, --extract-dir DIRECTORY"; exit 0 ;;
esac
for a in "$@"; do
  case "$a" in --randomness-depth|--entropy-depth|--log) echo "usage error" >&2; exit 2 ;; esac
done
while [ $# -gt 0 ]; do case "$1" in --extract-dir) d=$2; shift ;; esac; shift; done
mkdir -p "$d/x/etc" "$d/x/bin"; echo a > "$d/x/etc/a"; echo b > "$d/x/bin/b"
`
	f := newFirmwareFixture(t, script, "unblob")
	if err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	provenance, _ := os.ReadFile(filepath.Join(f.output, "provenance.json"))
	if !bytes.Contains(provenance, []byte(`"extractor_reported_errors": false`)) {
		t.Fatal("extractor was called with unsupported flags")
	}
}

func TestEdgeDigestCoversFirstAndLastMiB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	data := make([]byte, 5<<20)
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("write")
	}
	base, _ := edgeDigest(path)
	for _, offset := range []int{0, len(data) - 1} {
		changed := append([]byte{}, data...)
		changed[offset] = 1
		_ = os.WriteFile(path, changed, 0600)
		if got, _ := edgeDigest(path); got == base {
			t.Errorf("change at %d not detected", offset)
		}
	}
	changed := append([]byte{}, data...)
	changed[len(data)/2] = 1
	_ = os.WriteFile(path, changed, 0600)
	if got, _ := edgeDigest(path); got != base {
		t.Error("documented limit changed: middle rewrite is not covered")
	}
	// A file between 1 and 2 MiB is covered completely.
	small := make([]byte, 1500000)
	_ = os.WriteFile(path, small, 0600)
	base, _ = edgeDigest(path)
	small[1400000] = 1
	_ = os.WriteFile(path, small, 0600)
	if got, _ := edgeDigest(path); got == base {
		t.Error("change in a 1.5 MB file not detected")
	}
}

func TestFirmwareImageChangedExtractorFails(t *testing.T) {
	// The fake extractor appends to itself while "extracting".
	script := strings.Replace(fakeExtractorScript, "%s", "echo '# changed' >> \"$0\"", 1)
	f := newFirmwareFixture(t, script, "unblob")
	err := runCLI(context.Background(), f.args, &bytes.Buffer{}, successRunner, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "extractor file changed") {
		t.Fatalf("modified extractor accepted: %v", err)
	}
	if _, statErr := os.Stat(f.output); !os.IsNotExist(statErr) || stagingLeft(f.dir) {
		t.Fatal("failure left output or workspace")
	}
}
