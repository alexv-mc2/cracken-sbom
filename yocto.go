// Yocto Project target: native SPDX from the build, converted to CycloneDX 1.6
// with the pinned Syft (`syft convert`), plus a separate CycloneDX VEX 1.6 file
// for the CVEs the build already patched or assessed.
//
// The input stage is a Go port of yocto-pack.sh from alexv-mc2/cracken-action
// (Apache-2.0, same authors): safe archive paths, symlink rules, the SPDX 2 / 3
// split, exactly one *.rootfs.spdx.json for SPDX 3, and read limits.

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const yoctoTargetType = "yocto"

// Read limits from yocto-pack.sh: candidate SPDX bytes and entry count.
const yoctoReadLimit = 128 << 20
const yoctoMaxEntries = 10000

var yoctoExtension = Extension{
	Name:    "yocto",
	Targets: []TargetHandler{yoctoTarget{}},
}

func init() { Register(yoctoExtension) }

type yoctoTarget struct{}

func (yoctoTarget) Type() string     { return yoctoTargetType }
func (yoctoTarget) Kind() TargetKind { return TargetDirectory }
func (yoctoTarget) Flags() []ExtraFlag {
	return []ExtraFlag{
		{Name: "zstd", Usage: "absolute path to zstd, to unpack a .spdx.tar.zst (yocto only; default: zstd on PATH)"},
		{Name: "yocto-image", Usage: "image name prefix when the directory holds several images (yocto only)"},
		{Name: "strict-upload", Bool: true, Usage: "fail when cracken-upload.zip cannot be written (yocto only)"},
	}
}
func (yoctoTarget) ConfigDigest() string { return configurationDigest(yoctoTargetType) }

var yoctoImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

func (yoctoTarget) CheckOptions(o *generateOptions) error {
	if z := o.extra["zstd"]; z != "" && !filepath.IsAbs(z) {
		return errors.New("--zstd must be an absolute path")
	}
	if img := o.extra["yocto-image"]; img != "" && !yoctoImagePattern.MatchString(img) {
		return errors.New("--yocto-image must be an image name, not a path")
	}
	return nil
}

func (yoctoTarget) ResolvePaths(o *generateOptions) error {
	z := o.extra["zstd"]
	if z == "" {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(z)
	if err != nil {
		return errors.New("cannot resolve --zstd")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return errors.New("--zstd must be an existing executable")
	}
	o.extra["zstd"] = resolved
	return nil
}

func (yoctoTarget) Prepare(ctx context.Context, o generateOptions, env Env) (*Prepared, func(), error) {
	noop := func() {}
	set, err := collectYoctoSPDX(ctx, o.target, o.extra["zstd"], o.extra["yocto-image"])
	if err != nil {
		return nil, noop, err
	}
	work, err := os.MkdirTemp(filepath.Dir(o.output), ".cracken-sbom-yocto-")
	if err != nil {
		return nil, noop, errors.New("cannot create private Yocto workspace beside the output")
	}
	cleanup := func() { _ = os.RemoveAll(work) }
	conv, err := convertYoctoSet(ctx, set, work, o.syft, env.Engine)
	if err != nil {
		return nil, cleanup, err
	}
	p := &Prepared{
		RawCDX: conv.raw, ScanType: yoctoTargetType, Graph: GraphPartial,
		Root: RootHint{Type: "firmware", Executable: true, Archive: true, Structured: true,
			DefaultName: conv.imageName, DefaultVersion: conv.imageVersion},
		Warnings: conv.warnings,
		Provenance: map[string]any{
			"spdx_version": conv.spdxVersion, "documents": len(set.docs),
			"input": set.inputKind, "native_skipped": conv.nativeSkipped,
		},
	}
	refs, err := predictComponentRefs(conv.raw)
	if err != nil {
		return nil, cleanup, err
	}
	statements := conv.vex
	if len(statements) > 0 {
		vex, n, err := buildVEX(statements, refs, env.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return nil, cleanup, err
		}
		if n > 0 {
			p.Sidecars = []OutputFile{{Name: yoctoVEXFile, Data: vex}}
			p.Provenance["vex_statements"] = n
		}
	}
	if len(p.Sidecars) == 0 {
		p.Warnings = append(p.Warnings, "The Yocto SPDX holds no patched-CVE or VEX data for the selected packages; no VEX file was written.")
	}
	// The file for crAcken: the native SPDX, unchanged.
	upload, facts, uerr := buildCrackenUpload(set)
	if uerr == nil && conv.missing > 0 {
		uerr = fmt.Errorf("%d package(s) the image lists are missing from the input; no upload file was written", conv.missing)
	}
	if uerr != nil {
		if o.extra["strict-upload"] == "true" {
			return nil, cleanup, errors.New("cracken-upload.zip: " + uerr.Error())
		}
		p.Warnings = append(p.Warnings, "cracken-upload.zip was not written: "+uerr.Error())
		p.Notices = append(p.Notices, "cracken-upload.zip was NOT written: "+uerr.Error()+" (see quality.json; --strict-upload makes this an error).")
	} else {
		p.Sidecars = append(p.Sidecars, OutputFile{Name: crackenUploadFile, Data: upload})
		p.Provenance["cracken_upload"] = map[string]any{"documents": facts.Documents, "bytes": facts.Bytes, "sha256": facts.SHA256}
	}
	return p, cleanup, nil
}

// yoctoDoc is one SPDX JSON document of the build.
type yoctoDoc struct {
	name string // slash path inside the input, never written to outputs
	data []byte
}

type yoctoSet struct {
	docs      []yoctoDoc
	spdx3     bool
	inputKind string // "directory" or "spdx-tar-zst"
}

func yoctoCandidate(name string) bool {
	return strings.HasSuffix(name, ".spdx.json") || strings.HasSuffix(name, ".spdx.index.json")
}

func yoctoSafeName(name string) (string, error) {
	if strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return "", errors.New("unsafe archive path in the Yocto SPDX input")
	}
	parts := strings.Split(name, "/")
	if len(parts) > 0 && strings.Contains(parts[0], ":") {
		return "", errors.New("unsafe archive path in the Yocto SPDX input")
	}
	for _, p := range parts {
		if p == ".." {
			return "", errors.New("unsafe archive path in the Yocto SPDX input")
		}
	}
	return path.Clean(name), nil
}

type yoctoCollector struct {
	docs  []yoctoDoc
	seen  map[string]bool
	bytes int64
}

func (c *yoctoCollector) reserve(size int64) error {
	if size > yoctoReadLimit-c.bytes {
		return errors.New("Yocto SPDX files exceed the 128 MiB read limit; pass the image's deploy directory or a directory with only that image's documents")
	}
	c.bytes += size
	return nil
}

func (c *yoctoCollector) add(name string, data []byte) error {
	name, err := yoctoSafeName(name)
	if err != nil {
		return err
	}
	if !yoctoCandidate(name) {
		return nil
	}
	if c.seen[name] {
		return errors.New("duplicate SPDX document path in the Yocto input")
	}
	if len(c.docs) >= yoctoMaxEntries {
		return errors.New("the Yocto SPDX input has more than 10,000 documents")
	}
	c.seen[name] = true
	c.docs = append(c.docs, yoctoDoc{name: name, data: data})
	return nil
}

// collectYoctoSPDX reads the SPDX documents of one image from a deploy
// directory: its single .spdx.tar.zst, or the unpacked *.spdx.json files.
func collectYoctoSPDX(ctx context.Context, dir, zstd, image string) (*yoctoSet, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, errors.New("cannot resolve the Yocto input directory")
	}
	c := &yoctoCollector{seen: map[string]bool{}}
	set := &yoctoSet{inputKind: "directory"}
	archives, err := filepath.Glob(filepath.Join(root, "*.spdx.tar.zst"))
	if err != nil {
		return nil, errors.New("cannot list the Yocto input directory")
	}
	archives, err = uniqueArchives(root, filterImage(archives, image))
	if err != nil {
		return nil, err
	}
	if len(archives) > 1 {
		return nil, fmt.Errorf("%d .spdx.tar.zst image archives found; choose one with --yocto-image", len(archives))
	}
	if len(archives) == 1 {
		archive := archives[0]
		set.inputKind = "spdx-tar-zst"
		if err := readZstdTar(ctx, archive, zstd, c); err != nil {
			return nil, err
		}
	} else if err := walkYoctoDir(ctx, root, c); err != nil {
		return nil, err
	}
	if len(c.docs) == 0 {
		return nil, errors.New("no SPDX JSON documents found in the Yocto input; enable create-spdx and pass tmp/deploy/images/<machine>")
	}
	return finishYoctoSet(set, c.docs, image)
}

// uniqueArchives resolves links (IMAGE_LINK_NAME points at the dated archive)
// and counts each real archive once. Links must stay inside the directory.
func uniqueArchives(root string, paths []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range paths {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || !within(root, real) {
			return nil, errors.New("unsafe symlink in the Yocto input: a .spdx.tar.zst points outside the directory")
		}
		if info, err := os.Stat(real); err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("a .spdx.tar.zst in the Yocto input is not a regular file")
		}
		if !seen[real] {
			seen[real] = true
			out = append(out, real)
		}
	}
	sort.Strings(out)
	return out, nil
}

func filterImage(paths []string, image string) []string {
	if image == "" {
		return paths
	}
	out := []string{}
	for _, p := range paths {
		if strings.HasPrefix(filepath.Base(p), image) {
			out = append(out, p)
		}
	}
	return out
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// walkYoctoDir collects candidate files without following directory links;
// file links must resolve inside the directory and count once, under the
// real file's name.
func walkYoctoDir(ctx context.Context, root string, c *yoctoCollector) error {
	byReal := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.New("cannot read the Yocto input directory")
		}
		if ctx.Err() != nil {
			return errors.New("generation cancelled")
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		name := filepath.ToSlash(rel)
		if !yoctoCandidate(name) {
			return nil
		}
		isLink := d.Type()&fs.ModeSymlink != 0
		if d.Type()&fs.ModeSymlink == 0 && !d.Type().IsRegular() {
			return nil
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil || !within(root, real) {
			return errors.New("unsafe symlink in the Yocto input: " + name)
		}
		info, err := os.Stat(real)
		if err != nil || info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			// A FIFO or device would block the read below.
			return errors.New("a Yocto SPDX document is not a regular file: " + name)
		}
		// Prefer the real file's name over a link to it (IMAGE_LINK_NAME).
		if _, ok := byReal[real]; !ok || !isLink {
			byReal[real] = name
		}
		return nil
	})
	if err != nil {
		return err
	}
	reals := make([]string, 0, len(byReal))
	for r := range byReal {
		reals = append(reals, r)
	}
	sort.Strings(reals)
	for _, real := range reals {
		f, err := os.Open(real)
		if err != nil {
			return errors.New("cannot read a Yocto SPDX document")
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return errors.New("cannot read a Yocto SPDX document")
		}
		if err := c.reserve(info.Size()); err != nil {
			f.Close()
			return err
		}
		data, err := io.ReadAll(io.LimitReader(f, info.Size()+1))
		f.Close()
		if err != nil || int64(len(data)) != info.Size() {
			return errors.New("a Yocto SPDX document changed while it was read")
		}
		if err := c.add(byReal[real], data); err != nil {
			return err
		}
	}
	return nil
}

// readZstdTar streams a .spdx.tar.zst through the external zstd binary.
// Links and special entries are refused, as in yocto-pack.sh.
func readZstdTar(ctx context.Context, archive, zstd string, c *yoctoCollector) error {
	if zstd == "" {
		found, err := exec.LookPath("zstd")
		if err != nil {
			return errors.New("zstd is required to unpack the .spdx.tar.zst; install it or pass --zstd, or pass a directory with the unpacked *.spdx.json files")
		}
		zstd = found
	}
	cmd := exec.CommandContext(ctx, zstd, "-q", "-d", "-c", "--", archive)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stderr = io.Discard
	out, err := cmd.StdoutPipe()
	if err != nil {
		return errors.New("cannot start zstd")
	}
	if err := cmd.Start(); err != nil {
		return errors.New("cannot start zstd")
	}
	readErr := func() error {
		tr := tar.NewReader(out)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return errors.New("the .spdx.tar.zst is not a valid tar archive")
			}
			name, err := yoctoSafeName(strings.TrimPrefix(h.Name, "./"))
			if err != nil {
				return err
			}
			switch h.Typeflag {
			case tar.TypeSymlink, tar.TypeLink:
				return errors.New("unsafe link in the .spdx.tar.zst: " + name)
			case tar.TypeDir:
				continue
			case tar.TypeReg:
			default:
				return errors.New("unsafe entry in the .spdx.tar.zst: " + name)
			}
			if !yoctoCandidate(name) {
				continue
			}
			if err := c.reserve(h.Size); err != nil {
				return err
			}
			data, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
			if err != nil || int64(len(data)) != h.Size {
				return errors.New("cannot read the .spdx.tar.zst")
			}
			if err := c.add(name, data); err != nil {
				return err
			}
		}
	}()
	if readErr != nil {
		// Stop decompressing at once: a rejected archive may still have a
		// large, highly compressed tail.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return readErr
	}
	_, _ = io.Copy(io.Discard, out)
	waitErr := cmd.Wait()
	if waitErr != nil {
		return errors.New("zstd could not decompress the .spdx.tar.zst")
	}
	return nil
}

// The image's SPDX 3 file: <image>-<machine>.rootfs.spdx.json, or the dated
// file IMAGE_LINK_NAME points at, <image>-<machine>.rootfs-<DATETIME>.spdx.json.
var yoctoRootfsName = regexp.MustCompile(`\.rootfs(-[0-9]{8,14})?\.spdx\.json$`)

var spdx3ContextPattern = regexp.MustCompile(`(?i)^https?://spdx\.org/rdf/3\.0\.[01]/spdx-context\.jsonld$`)
var spdx3AnyContextPattern = regexp.MustCompile(`(?i)spdx\.org/rdf/3`)

// supportedSPDX3Context mirrors crAcken's context allowlist.
func supportedSPDX3Context(v any) bool {
	entries := []string{}
	type item struct {
		v     any
		depth int
	}
	pending := []item{{v, 0}}
	for len(pending) > 0 {
		it := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if it.depth > 4 {
			return false
		}
		switch x := it.v.(type) {
		case string:
			entries = append(entries, x)
		case map[string]any:
			for _, e := range x {
				pending = append(pending, item{e, it.depth + 1})
			}
		case []any:
			for _, e := range x {
				pending = append(pending, item{e, it.depth + 1})
			}
		}
	}
	found := false
	for _, e := range entries {
		if spdx3AnyContextPattern.MatchString(e) {
			found = true
			if !spdx3ContextPattern.MatchString(e) {
				return false
			}
		}
	}
	return found
}

// spdxVersions returns every spdxVersion/specVersion value in a document.
func spdxVersions(v any, out map[string]bool, depth int) {
	if depth > 64 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && (k == "spdxVersion" || k == "specVersion") {
				out[strings.TrimPrefix(s, "SPDX-")] = true
			}
			spdxVersions(e, out, depth+1)
		}
	case []any:
		for _, e := range x {
			spdxVersions(e, out, depth+1)
		}
	}
}

func finishYoctoSet(set *yoctoSet, docs []yoctoDoc, image string) (*yoctoSet, error) {
	families := map[string]bool{}
	roots := []yoctoDoc{}
	for _, d := range docs {
		var doc any
		dec := json.NewDecoder(bytes.NewReader(d.data))
		if dec.Decode(&doc) != nil {
			return nil, errors.New("invalid SPDX JSON in the Yocto input")
		}
		versions := map[string]bool{}
		spdxVersions(doc, versions, 0)
		spdx3 := false
		for v := range versions {
			switch {
			case strings.HasPrefix(v, "2."):
				families["2"] = true
			case v == "3.0.0" || v == "3.0.1":
				families["3"] = true
				spdx3 = true
			case strings.HasPrefix(v, "3."):
				return nil, errors.New("SPDX " + v + " is not supported; use SPDX 3.0.0 or 3.0.1")
			}
		}
		if spdx3 {
			m, _ := doc.(map[string]any)
			if m == nil || !supportedSPDX3Context(m["@context"]) {
				return nil, errors.New("SPDX 3 requires a supported 3.0.0 or 3.0.1 @context")
			}
			base := path.Base(d.name)
			if yoctoRootfsName.MatchString(base) && (image == "" || strings.HasPrefix(base, image)) {
				roots = append(roots, d)
			}
		}
	}
	if len(families) > 1 {
		return nil, errors.New("mixed SPDX 2 and SPDX 3 documents are not supported")
	}
	switch {
	case families["3"]:
		if len(roots) != 1 {
			return nil, fmt.Errorf("SPDX 3 requires exactly one complete *.rootfs.spdx.json; found %d (use --yocto-image to choose)", len(roots))
		}
		set.docs, set.spdx3 = roots, true
	case families["2"]:
		set.docs = docs
	default:
		return nil, errors.New("no supported SPDX 2 or SPDX 3 version found in the Yocto input")
	}
	return set, nil
}
