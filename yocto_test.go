package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeConvertEngine stands in for `syft convert`: it emits one CycloneDX
// component per SPDX package with the bom-ref shapes Syft 1.55 uses
// (package-id qualifier for SPDX 3, SPDXID without "SPDXRef-" for SPDX 2).
type fakeConvertEngine struct{ calls int }

func (f *fakeConvertEngine) Scan(context.Context, string, string, string) ([]byte, error) {
	return nil, errors.New("scan not expected")
}

func (f *fakeConvertEngine) Convert(_ context.Context, _ string, input string) ([]byte, error) {
	f.calls++
	data, err := os.ReadFile(input)
	if err != nil {
		return nil, err
	}
	components := []any{}
	if g, err := parseSPDX3(data); err == nil {
		for _, n := range g.nodes {
			if spdx3HasType(n, "software_Package") && n["software_primaryPurpose"] != "source" {
				components = append(components, map[string]any{"bom-ref": "pkg:yocto/x?package-id=" + url.QueryEscape(spdx3ID(n)), "type": "library", "name": n["name"], "version": n["software_packageVersion"]})
			}
		}
	} else {
		var doc spdx2Doc
		if json.Unmarshal(data, &doc) != nil {
			return nil, errors.New("not SPDX")
		}
		for _, p := range doc.Packages {
			c := map[string]any{"bom-ref": strings.TrimPrefix(p["SPDXID"].(string), "SPDXRef-"), "type": "library", "name": p["name"]}
			if v, ok := p["versionInfo"]; ok {
				c["version"] = v
			}
			components = append(components, c)
		}
	}
	return json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components})
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(dst, 0700)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if os.WriteFile(filepath.Join(dst, e.Name()), data, 0600) != nil {
			t.Fatal("copy")
		}
	}
}

func yoctoRun(t *testing.T, target string, extra ...string) (string, *fakeConvertEngine) {
	t.Helper()
	dir := t.TempDir()
	syft := filepath.Join(dir, "syft")
	_ = os.WriteFile(syft, []byte("unused"), 0700)
	output := filepath.Join(dir, "out")
	args := append([]string{"--target-type", "yocto", "--target", target, "--target-id", "yocto-1", "--output", output, "--syft", syft}, extra...)
	o, err := parseOptions(args)
	if err != nil {
		t.Fatal(err)
	}
	engine := &fakeConvertEngine{}
	if err := RunGenerate(context.Background(), o, Env{Engine: engine, Now: fixedNow, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	return output, engine
}

func readJSON(t *testing.T, file string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		t.Fatal("invalid JSON")
	}
	return m
}

// vexFacts resolves every VEX reference against the SBOM.
func vexFacts(t *testing.T, output string) map[string]string {
	t.Helper()
	sbom := readJSON(t, filepath.Join(output, "sbom.cdx.json"))
	if _, has := sbom["vulnerabilities"]; has {
		t.Fatal("vulnerability data inside the SBOM")
	}
	names := map[string]string{}
	for _, v := range sbom["components"].([]any) {
		c := v.(map[string]any)
		names[c["bom-ref"].(string)] = c["name"].(string)
	}
	vex := readJSON(t, filepath.Join(output, yoctoVEXFile))
	if vex["specVersion"] != "1.6" || vex["components"] != nil {
		t.Fatal("VEX must be CycloneDX 1.6 without an inventory")
	}
	facts := map[string]string{}
	for _, v := range vex["vulnerabilities"].([]any) {
		vuln := v.(map[string]any)
		for _, a := range vuln["affects"].([]any) {
			ref := a.(map[string]any)["ref"].(string)
			name, ok := names[ref]
			if !ok {
				t.Fatalf("VEX reference %s is not an SBOM bom-ref", ref)
			}
			facts[vuln["id"].(string)+" "+name] = vuln["analysis"].(map[string]any)["state"].(string)
		}
	}
	return facts
}

func TestYoctoSPDX3SelectionAndVEX(t *testing.T) {
	output, engine := yoctoRun(t, filepath.Join("fixtures", "yocto", "spdx3"))
	if engine.calls != 1 {
		t.Fatal("convert must run once")
	}
	sbom := readJSON(t, filepath.Join(output, "sbom.cdx.json"))
	got := map[string]bool{}
	for _, v := range sbom["components"].([]any) {
		got[v.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"busybox", "libz1", "libssl3"} {
		if !got[want] {
			t.Errorf("%s missing", want)
		}
	}
	for _, never := range []string{"quilt-native", "not-in-image", "core-image-minimal-qemux86-64.rootfs"} {
		if got[never] {
			t.Errorf("%s must not be a component", never)
		}
	}
	root := sbom["metadata"].(map[string]any)["component"].(map[string]any)
	if root["name"] != "core-image-minimal-qemux86-64.rootfs" || root["version"] != "1.0" {
		t.Fatalf("product: %v", root)
	}
	want := map[string]string{
		"CVE-2023-42364 busybox": "resolved", "CVE-2023-42363 busybox": "not_affected",
		"CVE-2024-0727 libssl3": "exploitable", "CVE-2022-37434 libz1": "resolved",
	}
	if facts := vexFacts(t, output); len(facts) != len(want) {
		t.Fatalf("VEX facts %v", facts)
	} else {
		for k, v := range want {
			if facts[k] != v {
				t.Errorf("%s: %q, want %q", k, facts[k], v)
			}
		}
	}
	vex, _ := os.ReadFile(filepath.Join(output, yoctoVEXFile))
	if !bytes.Contains(vex, []byte(`"justification": "code_not_present"`)) || bytes.Contains(vex, []byte("CVE-2023-45853")) || bytes.Contains(vex, []byte("Applet disabled")) {
		t.Fatal("justification, withdrawal or free-text handling is wrong")
	}
	prov := readJSON(t, filepath.Join(output, "provenance.json"))
	ext := prov["extensions"].(map[string]any)["yocto"].(map[string]any)
	if ext["native_skipped"].(float64) != 1 || prov["extra_outputs"] == nil {
		t.Fatalf("provenance: %v", ext)
	}
}

func TestYoctoSPDX2DocumentSetAndCvesFixed(t *testing.T) {
	output, _ := yoctoRun(t, filepath.Join("fixtures", "yocto", "spdx2"))
	facts := vexFacts(t, output)
	for _, cve := range []string{"CVE-2022-28391", "CVE-2022-30065", "CVE-2023-42364"} {
		if facts[cve+" busybox"] != "resolved" {
			t.Errorf("%s not resolved for busybox: %v", cve, facts)
		}
	}
	if len(facts) != 3 {
		t.Fatalf("unexpected VEX facts %v", facts)
	}
	sbom := readJSON(t, filepath.Join(output, "sbom.cdx.json"))
	if n := len(sbom["components"].([]any)); n != 2 {
		t.Fatalf("components: %d", n)
	}
	if sbom["metadata"].(map[string]any)["component"].(map[string]any)["name"] != "core-image-minimal-qemux86-64" {
		t.Fatal("product name from the image document")
	}
}

// fakeZstd "decompresses" by copying the archive: the tests feed a plain tar.
func fakeZstd(t *testing.T) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "zstd")
	if os.WriteFile(file, []byte("#!/bin/sh\n[ \"$1 $2 $3 $4\" = '-q -d -c --' ] || exit 9\nexec /bin/cat \"$5\"\n"), 0700) != nil {
		t.Fatal("fake zstd")
	}
	return file
}

func writeTar(t *testing.T, file string, entries []tar.Header, data map[string][]byte) {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, h := range entries {
		h := h
		body := data[h.Name]
		h.Size = int64(len(body))
		h.Mode = 0644
		if w.WriteHeader(&h) != nil {
			t.Fatal("tar header")
		}
		_, _ = w.Write(body)
	}
	_ = w.Close()
	if os.WriteFile(file, buf.Bytes(), 0600) != nil {
		t.Fatal("tar")
	}
}

func TestYoctoTarZstInputAndUnsafeEntries(t *testing.T) {
	zstd := fakeZstd(t)
	docs := map[string][]byte{}
	headers := []tar.Header{}
	entries, _ := os.ReadDir(filepath.Join("fixtures", "yocto", "spdx2"))
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join("fixtures", "yocto", "spdx2", e.Name()))
		name := "./" + e.Name()
		docs[name] = data
		headers = append(headers, tar.Header{Name: name, Typeflag: tar.TypeReg})
	}
	deploy := t.TempDir()
	writeTar(t, filepath.Join(deploy, "core-image-minimal-qemux86-64.spdx.tar.zst"), headers, docs)
	output, _ := yoctoRun(t, deploy, "--zstd", zstd)
	if facts := vexFacts(t, output); facts["CVE-2023-42364 busybox"] != "resolved" {
		t.Fatalf("tar.zst input: %v", facts)
	}
	for name, bad := range map[string]tar.Header{
		"symlink":   {Name: "image.spdx.json", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		"traversal": {Name: "../escape.spdx.json", Typeflag: tar.TypeReg},
		"absolute":  {Name: "/abs.spdx.json", Typeflag: tar.TypeReg},
		"device":    {Name: "dev.spdx.json", Typeflag: tar.TypeChar},
	} {
		dir := t.TempDir()
		writeTar(t, filepath.Join(dir, "x.spdx.tar.zst"), []tar.Header{bad}, map[string][]byte{bad.Name: []byte("{}")})
		if _, err := collectYoctoSPDX(context.Background(), dir, zstd, ""); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	two := t.TempDir()
	_ = os.WriteFile(filepath.Join(two, "a.spdx.tar.zst"), nil, 0600)
	_ = os.WriteFile(filepath.Join(two, "b.spdx.tar.zst"), nil, 0600)
	if _, err := collectYoctoSPDX(context.Background(), two, zstd, ""); err == nil || !strings.Contains(err.Error(), "--yocto-image") {
		t.Fatalf("two archives: %v", err)
	}
}

func TestYoctoDirectoryRules(t *testing.T) {
	v3 := filepath.Join("fixtures", "yocto", "spdx3", "core-image-minimal-qemux86-64.rootfs.spdx.json")
	root, _ := os.ReadFile(v3)
	// The timestamped root and the IMAGE_LINK_NAME link count once.
	deploy := t.TempDir()
	_ = os.WriteFile(filepath.Join(deploy, "img-20261101.rootfs.spdx.json"), root, 0600)
	_ = os.Symlink("img-20261101.rootfs.spdx.json", filepath.Join(deploy, "img.rootfs.spdx.json"))
	set, err := collectYoctoSPDX(context.Background(), deploy, "", "")
	if err != nil || len(set.docs) != 1 || !set.spdx3 || set.docs[0].name != "img-20261101.rootfs.spdx.json" {
		t.Fatalf("link alias: %v %+v", err, set)
	}
	outside := t.TempDir()
	_ = os.Symlink(filepath.Join(deploy, "img-20261101.rootfs.spdx.json"), filepath.Join(outside, "img.rootfs.spdx.json"))
	if _, err := collectYoctoSPDX(context.Background(), outside, "", ""); err == nil || !strings.Contains(err.Error(), "unsafe symlink") {
		t.Fatalf("outside link: %v", err)
	}
	twoRoots := t.TempDir()
	_ = os.WriteFile(filepath.Join(twoRoots, "a.rootfs.spdx.json"), root, 0600)
	_ = os.WriteFile(filepath.Join(twoRoots, "b.rootfs.spdx.json"), root, 0600)
	if _, err := collectYoctoSPDX(context.Background(), twoRoots, "", ""); err == nil {
		t.Fatal("two roots accepted")
	}
	if set, err := collectYoctoSPDX(context.Background(), twoRoots, "", "b"); err != nil || set.docs[0].name != "b.rootfs.spdx.json" {
		t.Fatalf("--yocto-image selection: %v", err)
	}
	mixed := t.TempDir()
	copyTree(t, filepath.Join("fixtures", "yocto", "spdx2"), mixed)
	_ = os.WriteFile(filepath.Join(mixed, "x.rootfs.spdx.json"), root, 0600)
	if _, err := collectYoctoSPDX(context.Background(), mixed, "", ""); err == nil || !strings.Contains(err.Error(), "mixed") {
		t.Fatalf("mixed versions: %v", err)
	}
	v31 := t.TempDir()
	_ = os.WriteFile(filepath.Join(v31, "x.rootfs.spdx.json"), []byte(`{"@context":"https://spdx.org/rdf/3.1.0/spdx-context.jsonld","@graph":[{"type":"CreationInfo","specVersion":"3.1.0"}]}`), 0600)
	if _, err := collectYoctoSPDX(context.Background(), v31, "", ""); err == nil || !strings.Contains(err.Error(), "3.1.0") {
		t.Fatalf("SPDX 3.1: %v", err)
	}
	empty := t.TempDir()
	if _, err := collectYoctoSPDX(context.Background(), empty, "", ""); err == nil {
		t.Fatal("empty input accepted")
	}
}

func TestYoctoFlagsBelongToYoctoOnly(t *testing.T) {
	args, _ := cliFixture(t)
	if _, err := parseOptions(append(args[1:], "--yocto-image", "img")); err == nil {
		t.Fatal("--yocto-image accepted for rootfs")
	}
	dir := t.TempDir()
	syft := filepath.Join(dir, "syft")
	_ = os.WriteFile(syft, []byte("x"), 0700)
	base := []string{"--target-type", "yocto", "--target", dir, "--target-id", "y", "--output", filepath.Join(dir, "o"), "--syft", syft}
	for _, bad := range [][]string{{"--zstd", "zstd"}, {"--yocto-image", "../x"}} {
		if _, err := parseOptions(append(append([]string{}, base...), bad...)); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestYoctoNativeNames(t *testing.T) {
	for name, want := range map[string]bool{"quilt-native": true, "nativesdk-openssl": true, "gcc-cross-x86_64": true, "gcc-crosssdk-x86_64": true, "busybox": false, "native-utils": false} {
		if yoctoNative(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}

func TestYoctoDeployLinkAndDatedArchiveCountOnce(t *testing.T) {
	zstd := fakeZstd(t)
	docs := map[string][]byte{}
	headers := []tar.Header{}
	entries, _ := os.ReadDir(filepath.Join("fixtures", "yocto", "spdx2"))
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join("fixtures", "yocto", "spdx2", e.Name()))
		docs[e.Name()] = data
		headers = append(headers, tar.Header{Name: e.Name(), Typeflag: tar.TypeReg})
	}
	deploy := t.TempDir()
	dated := "core-image-minimal-qemux86-64.rootfs-20261118093000.spdx.tar.zst"
	writeTar(t, filepath.Join(deploy, dated), headers, docs)
	if os.Symlink(dated, filepath.Join(deploy, "core-image-minimal-qemux86-64.rootfs.spdx.tar.zst")) != nil {
		t.Fatal("link")
	}
	for _, image := range []string{"", "core-image-minimal-qemux86-64.rootfs"} {
		set, err := collectYoctoSPDX(context.Background(), deploy, zstd, image)
		if err != nil || set.inputKind != "spdx-tar-zst" {
			t.Fatalf("image %q: %v", image, err)
		}
	}
	// Two different builds still need a choice.
	writeTar(t, filepath.Join(deploy, "core-image-minimal-qemux86-64.rootfs-20261119093000.spdx.tar.zst"), headers, docs)
	if _, err := collectYoctoSPDX(context.Background(), deploy, zstd, ""); err == nil {
		t.Fatal("two real archives accepted")
	}
	// A dated SPDX 3 rootfs file and its link are one root.
	v3 := t.TempDir()
	root, _ := os.ReadFile(filepath.Join("fixtures", "yocto", "spdx3", "core-image-minimal-qemux86-64.rootfs.spdx.json"))
	_ = os.WriteFile(filepath.Join(v3, "img.rootfs-20261118093000.spdx.json"), root, 0600)
	_ = os.Symlink("img.rootfs-20261118093000.spdx.json", filepath.Join(v3, "img.rootfs.spdx.json"))
	if set, err := collectYoctoSPDX(context.Background(), v3, "", ""); err != nil || len(set.docs) != 1 {
		t.Fatalf("dated SPDX 3 root: %v", err)
	}
}

func fixtureSet(t *testing.T, dir string) *yoctoSet {
	t.Helper()
	set, err := collectYoctoSPDX(context.Background(), dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestCrackenUploadIsTheNativeSPDXUnchanged(t *testing.T) {
	src := filepath.Join("fixtures", "yocto", "spdx2")
	data, facts, err := buildCrackenUpload(fixtureSet(t, src))
	if err != nil {
		t.Fatal(err)
	}
	again, _, _ := buildCrackenUpload(fixtureSet(t, src))
	if !bytes.Equal(data, again) {
		t.Fatal("upload ZIP is not deterministic")
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"busybox.spdx.json", "core-image-minimal-qemux86-64.spdx.json", "libz1.spdx.json", "recipe-busybox.spdx.json", "recipe-zlib.spdx.json"}
	if len(zr.File) != len(want) || facts.Documents != len(want) {
		t.Fatalf("entries: %d", len(zr.File))
	}
	for i, f := range zr.File {
		if f.Name != want[i] {
			t.Fatalf("entry %d: %s", i, f.Name)
		}
		rc, _ := f.Open()
		got, _ := io.ReadAll(rc)
		rc.Close()
		orig, _ := os.ReadFile(filepath.Join(src, f.Name))
		if !bytes.Equal(got, orig) {
			t.Fatalf("%s changed", f.Name)
		}
	}
	// SPDX 3: the one rootfs document.
	data, facts, err = buildCrackenUpload(fixtureSet(t, filepath.Join("fixtures", "yocto", "spdx3")))
	if err != nil || facts.Documents != 1 {
		t.Fatalf("SPDX 3 upload: %v", err)
	}
	if validSidecars("sbom.cdx.json", []OutputFile{{Name: crackenUploadFile, Data: data}}) != nil {
		t.Fatal("upload ZIP must be an allowed extra output")
	}
	if validSidecars("sbom.cdx.json", []OutputFile{{Name: crackenUploadFile, Data: []byte("not a zip")}}) == nil {
		t.Fatal("a non-ZIP cracken-upload.zip was accepted")
	}
	if validSidecars("sbom.cdx.json", []OutputFile{{Name: "other.zip", Data: data}}) == nil {
		t.Fatal("other binary names must stay refused")
	}
}

func TestCrackenUploadRefusals(t *testing.T) {
	src := filepath.Join("fixtures", "yocto", "spdx2")
	set := func(t *testing.T) *yoctoSet { return fixtureSet(t, src) }
	restore := func(p *int, v int) func() { old := *p; *p = v; return func() { *p = old } }
	for name, tc := range map[string]struct {
		limit *int
		value int
		want  string
	}{
		"entries":      {&uploadEntryLimit, 3, "limit of 3 files"},
		"unpacked":     {&uploadUncompressedLimit, 1024, "unpacked"},
		"compressed":   {&uploadCompressedLimit, 512, "ZIP"},
		"spdx3 single": {&uploadSPDX3Limit, 10, ""},
	} {
		t.Run(name, func(t *testing.T) {
			defer restore(tc.limit, tc.value)()
			s := set(t)
			if name == "spdx3 single" {
				s = fixtureSet(t, filepath.Join("fixtures", "yocto", "spdx3"))
			}
			if _, _, err := buildCrackenUpload(s); err == nil || !strings.Contains(err.Error(), "no upload file was written") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
	// A missing recipe document: no upload file.
	partial := t.TempDir()
	copyTree(t, src, partial)
	_ = os.Remove(filepath.Join(partial, "recipe-zlib.spdx.json"))
	if _, _, err := buildCrackenUpload(fixtureSet(t, partial)); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing recipe: %v", err)
	}
	// Two documents with one file name (from different folders).
	dup := t.TempDir()
	copyTree(t, src, dup)
	copyTree(t, src, filepath.Join(dup, "again"))
	if _, _, err := buildCrackenUpload(fixtureSet(t, dup)); err == nil || !strings.Contains(err.Error(), "share the file name") {
		t.Fatalf("duplicate names: %v", err)
	}
	// generate: a warning by default, an error with --strict-upload.
	output, _ := yoctoRun(t, partial)
	if _, err := os.Stat(filepath.Join(output, crackenUploadFile)); err == nil {
		t.Fatal("upload file written for a partial set")
	}
	q, _ := os.ReadFile(filepath.Join(output, "quality.json"))
	if !bytes.Contains(q, []byte("cracken-upload.zip was not written")) {
		t.Fatal("missing upload not reported")
	}
	dir := t.TempDir()
	syft := filepath.Join(dir, "syft")
	_ = os.WriteFile(syft, []byte("x"), 0700)
	o, err := parseOptions([]string{"--target-type", "yocto", "--target", partial, "--target-id", "y", "--output", filepath.Join(dir, "o"), "--syft", syft, "--strict-upload"})
	if err != nil {
		t.Fatal(err)
	}
	if err := RunGenerate(context.Background(), o, Env{Engine: &fakeConvertEngine{}, Now: fixedNow, Stdout: &bytes.Buffer{}}); err == nil || !strings.Contains(err.Error(), "cracken-upload.zip") {
		t.Fatalf("strict upload: %v", err)
	}
}

// Attacker-shaped SPDX: small inputs whose derived size explodes.

func TestRecipeWideVEXExpansionIsCapped(t *testing.T) {
	defer func(a, b int) { maxVEXStatements, maxVEXPairs = a, b }(maxVEXStatements, maxVEXPairs)
	maxVEXPairs = 2000
	var g strings.Builder
	g.WriteString(`{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[`)
	g.WriteString(`{"type":"CreationInfo","@id":"_:c","specVersion":"3.0.1"},{"type":"SpdxDocument","spdxId":"d","rootElement":["r"]},{"type":"software_Package","spdxId":"r","name":"img","software_primaryPurpose":"filesystemImage"},{"type":"software_Package","spdxId":"recipe","name":"x","software_primaryPurpose":"source"}`)
	pkgs := []string{}
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("p%d", i)
		pkgs = append(pkgs, `"`+id+`"`)
		fmt.Fprintf(&g, `,{"type":"software_Package","spdxId":"%s","name":"pkg%d","software_packageVersion":"1","software_primaryPurpose":"install"}`, id, i)
	}
	fmt.Fprintf(&g, `,{"type":"Relationship","spdxId":"c","from":"r","to":[%s],"relationshipType":"contains"}`, strings.Join(pkgs, ","))
	fmt.Fprintf(&g, `,{"type":"Relationship","spdxId":"g","from":"recipe","to":[%s],"relationshipType":"generates"}`, strings.Join(pkgs, ","))
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&g, `,{"type":"security_Vulnerability","spdxId":"v%d","externalIdentifier":[{"externalIdentifierType":"cve","identifier":"CVE-2026-%04d"}]}`, i, 1000+i)
		fmt.Fprintf(&g, `,{"type":"security_VexFixedVulnAssessmentRelationship","spdxId":"a%d","from":"v%d","to":["recipe"],"relationshipType":"fixedIn"}`, i, i)
	}
	g.WriteString(`]}`)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "img.rootfs.spdx.json"), []byte(g.String()), 0600)
	set := fixtureSet(t, dir)
	_, err := convertYoctoSPDX3(context.Background(), set.docs[0], t.TempDir(), "syft", &fakeConvertEngine{})
	if err == nil || !strings.Contains(err.Error(), "affected-component pairs") {
		t.Fatalf("50 CVEs x 100 packages must hit the pair cap: %v", err)
	}
	maxVEXPairs = 1 << 20
	maxVEXStatements = 10
	if _, err := convertYoctoSPDX3(context.Background(), set.docs[0], t.TempDir(), "syft", &fakeConvertEngine{}); err == nil || !strings.Contains(err.Error(), "statements") {
		t.Fatalf("statement cap: %v", err)
	}
}

func spdx2Attack(t *testing.T, packages, cpes int) string {
	t.Helper()
	dir := t.TempDir()
	refs := []any{}
	for i := 0; i < cpes; i++ {
		refs = append(refs, map[string]any{"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": fmt.Sprintf("cpe:2.3:a:v%d:p:1:*:*:*:*:*:*:*", i)})
	}
	write := func(name string, doc map[string]any) {
		data, _ := json.Marshal(doc)
		_ = os.WriteFile(filepath.Join(dir, name), data, 0600)
	}
	write("recipe-r.spdx.json", map[string]any{"spdxVersion": "SPDX-2.2", "documentNamespace": "ns-recipe", "packages": []any{map[string]any{"SPDXID": "SPDXRef-Recipe-r", "name": "r", "externalRefs": refs}}})
	pkgs := []any{}
	rels := []any{}
	imgRels := []any{}
	for i := 0; i < packages; i++ {
		id := fmt.Sprintf("SPDXRef-PACKAGE-p%d", i)
		pkgs = append(pkgs, map[string]any{"SPDXID": id, "name": fmt.Sprintf("p%d", i), "versionInfo": "1"})
		rels = append(rels, map[string]any{"spdxElementId": id, "relatedSpdxElement": "DocumentRef-recipe-r:SPDXRef-Recipe-r", "relationshipType": "GENERATED_FROM"})
		imgRels = append(imgRels, map[string]any{"spdxElementId": "SPDXRef-Image", "relatedSpdxElement": "DocumentRef-pkgs:" + id, "relationshipType": "CONTAINS"})
	}
	write("pkgs.spdx.json", map[string]any{"spdxVersion": "SPDX-2.2", "documentNamespace": "ns-pkgs", "packages": pkgs, "relationships": rels,
		"externalDocumentRefs": []any{map[string]any{"externalDocumentId": "DocumentRef-recipe-r", "spdxDocument": "ns-recipe"}}})
	write("image.spdx.json", map[string]any{"spdxVersion": "SPDX-2.2", "documentNamespace": "ns-image", "packages": []any{map[string]any{"SPDXID": "SPDXRef-Image", "name": "img"}}, "relationships": imgRels,
		"externalDocumentRefs": []any{map[string]any{"externalDocumentId": "DocumentRef-pkgs", "spdxDocument": "ns-pkgs"}}})
	return dir
}

func TestRecipeCPEPropagationIsCapped(t *testing.T) {
	defer func(a int) { maxYoctoCPEPairs = a }(maxYoctoCPEPairs)
	maxYoctoCPEPairs = 5000
	set := fixtureSet(t, spdx2Attack(t, 200, 50))
	_, err := convertYoctoSPDX2(context.Background(), set.docs, t.TempDir(), "syft", &fakeConvertEngine{})
	if err == nil || !strings.Contains(err.Error(), "recipe CPEs") {
		t.Fatalf("200 packages x 50 CPEs must hit the cap: %v", err)
	}
}

func TestSPDX2ResolutionIsIndexedAndCancellable(t *testing.T) {
	set := fixtureSet(t, spdx2Attack(t, 20000, 1))
	start := time.Now()
	if _, err := convertYoctoSPDX2(context.Background(), set.docs, t.TempDir(), "syft", &fakeConvertEngine{}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("20,000 packages took %v; resolution must be indexed", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := convertYoctoSPDX2(ctx, set.docs, t.TempDir(), "syft", &fakeConvertEngine{}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestRejectedArchiveStopsDecompression(t *testing.T) {
	// The fake zstd prints an unsafe tar entry, then an endless stream.
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape.spdx.json", Typeflag: tar.TypeReg, Size: 2, Mode: 0644})
	_, _ = tw.Write([]byte("{}"))
	_ = tw.Close()
	head := filepath.Join(dir, "head.tar")
	_ = os.WriteFile(head, buf.Bytes(), 0600)
	_ = os.WriteFile(filepath.Join(dir, "x.spdx.tar.zst"), []byte("x"), 0600)
	zstd := filepath.Join(t.TempDir(), "zstd")
	_ = os.WriteFile(zstd, []byte("#!/bin/sh\n/bin/cat '"+head+"'\nexec /bin/cat /dev/zero\n"), 0700)
	start := time.Now()
	if _, err := collectYoctoSPDX(context.Background(), dir, zstd, ""); err == nil {
		t.Fatal("unsafe entry accepted")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("decompression kept running for %v after the rejection", d)
	}
}

func TestDocumentLinkToFIFOIsRefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skip("mkfifo unavailable")
	}
	_ = os.Symlink("pipe", filepath.Join(dir, "img.rootfs.spdx.json"))
	done := make(chan error, 1)
	go func() { _, err := collectYoctoSPDX(context.Background(), dir, "", ""); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
