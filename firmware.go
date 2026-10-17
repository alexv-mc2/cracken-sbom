package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	firmwareTargetType   = "firmware-image"
	extractorTimeout     = 2 * time.Hour
	maxListedEntries     = 100
	maxListedCandidates  = 20
	maxUnsafeListedBytes = 4096
)

// FirmwareInfo records how a binary firmware image became a root filesystem
// tree. It describes the local extraction only; it never proves that the
// extraction was complete.
type FirmwareInfo struct {
	ImageName           string
	ImageSize           int64
	ImageSHA256         string
	ExtractorKind       string
	ExtractorVersion    string
	ExtractorSHA256     string
	ExtractedAt         string
	RootPath            string // slash-separated, relative to the extraction directory
	ExtractedFiles      int
	UnusedEntries       []string // entries beside the selected root, relative paths
	UnusedEntriesTotal  int
	OtherRootCandidates []string
	ExtractorReported   bool // the extractor exited with an error status
}

var extractorVersionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+_-]{0,63}$`)
var versionInOutput = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)+(?:[-+][0-9A-Za-z.]+)?`)
var safePropertyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+ /-]{0,199}$`)

// firmwarePropertyValue keeps image and extraction names out of the uploadable
// SBOM when they contain characters the privacy checks treat as unsafe. The
// local provenance file still carries the exact value.
func firmwarePropertyValue(v string) string {
	if !safePropertyPattern.MatchString(v) || suspiciousString(v) || strings.Contains(v, "..") {
		return "withheld-unsafe-characters"
	}
	return v
}

func validateFirmware(fw *FirmwareInfo) (*FirmwareInfo, error) {
	if fw.ExtractorKind != "unblob" && fw.ExtractorKind != "binwalk" {
		return nil, errors.New("invalid firmware extractor kind")
	}
	if !extractorVersionPattern.MatchString(fw.ExtractorVersion) {
		return nil, errors.New("invalid firmware extractor version")
	}
	if !digestPattern.MatchString(fw.ImageSHA256) || !digestPattern.MatchString(fw.ExtractorSHA256) {
		return nil, errors.New("invalid firmware digest")
	}
	if fw.ImageSize < 0 || fw.ExtractedFiles < 0 || fw.ImageName == "" || fw.RootPath == "" {
		return nil, errors.New("invalid firmware provenance")
	}
	t, err := time.Parse(time.RFC3339, fw.ExtractedAt)
	if err != nil {
		return nil, errors.New("invalid firmware extraction timestamp")
	}
	out := *fw
	out.ExtractedAt = t.UTC().Format(time.RFC3339)
	return &out, nil
}

// firmwareProperties are the facts the app can read without the sidecars.
// They contain no file lists and no paths of the user's machine.
func firmwareProperties(fw *FirmwareInfo) [][2]string {
	return [][2]string{
		{"cracken:firmware:source-type", firmwareTargetType},
		{"cracken:firmware:image-name", firmwarePropertyValue(fw.ImageName)},
		{"cracken:firmware:image-size-bytes", fmt.Sprint(fw.ImageSize)},
		{"cracken:firmware:image-sha256", fw.ImageSHA256},
		{"cracken:firmware:extractor", fw.ExtractorKind},
		{"cracken:firmware:extractor-version", fw.ExtractorVersion},
		{"cracken:firmware:extracted-at", fw.ExtractedAt},
		{"cracken:firmware:selected-root", firmwarePropertyValue(fw.RootPath)},
		{"cracken:firmware:extracted-file-count", fmt.Sprint(fw.ExtractedFiles)},
		{"cracken:firmware:unused-entry-count", fmt.Sprint(fw.UnusedEntriesTotal)},
		{"cracken:firmware:other-root-candidates", fmt.Sprint(len(fw.OtherRootCandidates))},
		{"cracken:firmware:extractor-reported-errors", fmt.Sprint(fw.ExtractorReported)},
	}
}

func firmwareProvenance(fw *FirmwareInfo) map[string]any {
	unused, others := fw.UnusedEntries, fw.OtherRootCandidates
	if unused == nil {
		unused = []string{}
	}
	if others == nil {
		others = []string{}
	}
	return map[string]any{
		"source_type":  firmwareTargetType,
		"image":        map[string]any{"file_name": fw.ImageName, "size_bytes": fw.ImageSize, "sha256": fw.ImageSHA256},
		"extractor":    map[string]string{"kind": fw.ExtractorKind, "version": fw.ExtractorVersion, "executable_sha256": fw.ExtractorSHA256},
		"extracted_at": fw.ExtractedAt, "selected_root": fw.RootPath, "extracted_file_count": fw.ExtractedFiles,
		"unused_entries": unused, "unused_entry_count": fw.UnusedEntriesTotal,
		"unused_entries_truncated":  fw.UnusedEntriesTotal > len(unused),
		"other_root_candidates":     others,
		"extractor_reported_errors": fw.ExtractorReported,
	}
}

func detectExtractorKind(given, canonical, explicit string) (string, error) {
	if explicit != "" {
		if explicit != "unblob" && explicit != "binwalk" {
			return "", errors.New("extractor kind must be unblob or binwalk")
		}
		return explicit, nil
	}
	for _, p := range []string{given, canonical} {
		switch strings.TrimSuffix(strings.ToLower(filepath.Base(p)), ".exe") {
		case "unblob":
			return "unblob", nil
		case "binwalk":
			return "binwalk", nil
		}
	}
	return "", errors.New("cannot tell the extractor kind from its file name; add --extractor-kind unblob or binwalk")
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Extractors need the user's PATH to find helpers such as 7z, and on macOS the
// library path to find libmagic. Everything else is isolated, and network use
// is pointed at a closed local port.
func extractorEnvironment(dir, binary string) []string {
	path := filepath.Dir(binary)
	if p := os.Getenv("PATH"); p != "" {
		path += string(os.PathListSeparator) + p
	}
	env := []string{
		"PATH=" + path, "HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_CACHE_HOME=" + dir, "TMPDIR=" + dir,
		"LANG=C", "LC_ALL=C",
		"HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "ALL_PROXY=http://127.0.0.1:1", "NO_PROXY=",
	}
	for _, name := range []string{"DYLD_FALLBACK_LIBRARY_PATH", "LD_LIBRARY_PATH"} {
		if v := os.Getenv(name); v != "" {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// Extractors start helper processes, so the whole process group is stopped on
// cancellation or timeout; otherwise helpers could keep writing into a directory
// that is being deleted.
func extractorCommand(ctx context.Context, binary, work string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = work, extractorEnvironment(work, binary)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	return cmd
}

func extractorVersion(ctx context.Context, binary, work string) (string, error) {
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := extractorCommand(vctx, binary, work, "--version")
	out := &cappedBuffer{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil || out.overflow {
		return "", errors.New("cannot run the extractor to read its version")
	}
	v := versionInOutput.FindString(out.String())
	if !extractorVersionPattern.MatchString(v) {
		return "", errors.New("cannot read the extractor version from its --version output")
	}
	return v, nil
}

// runExtractor reports whether the extractor exited with an error status. Real
// images often contain one chunk that cannot be unpacked, so partial output is
// kept and the problem is recorded instead of hiding or failing everything.
func runExtractor(ctx context.Context, kind, binary, image, extractDir, work string) (reportedErrors bool, err error) {
	var args []string
	switch kind {
	case "unblob":
		// Randomness analysis only draws entropy charts; it is not needed here.
		args = []string{"--extract-dir", extractDir, "--log", filepath.Join(work, "unblob.log"), "--randomness-depth", "0", image}
	case "binwalk":
		// -M descends into extracted containers; without it a squashfs inside
		// an update wrapper would stay packed.
		args = []string{"--extract", "--matryoshka", "--quiet", "--directory", extractDir, image}
	default:
		return false, errors.New("unsupported extractor kind")
	}
	ectx, cancel := context.WithTimeout(ctx, extractorTimeout)
	defer cancel()
	cmd := extractorCommand(ectx, binary, work, args...)
	// Child diagnostics can carry paths and file names from the image; they are
	// never returned.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if ectx.Err() != nil {
			return false, errors.New("firmware extraction timed out or was cancelled")
		}
		if !errors.As(err, &exit) {
			return false, errors.New("cannot start the extractor")
		}
		reportedErrors = true
	}
	if info, err := os.Lstat(extractDir); err != nil || !info.IsDir() {
		return reportedErrors, errors.New("firmware extraction failed and produced no output; check the extractor installation and its helper tools (for unblob: unblob --show-external-dependencies)")
	}
	return reportedErrors, nil
}

// A directory looks like a root filesystem when it has the usual top-level
// layout or a known package database. Symlinked bin or lib (merged /usr) count.
func looksLikeRootFS(dir string) bool {
	exists := func(rel string) bool {
		_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
		return err == nil
	}
	markers, hasEtc := 0, exists("etc")
	if hasEtc {
		markers++
	}
	for _, m := range []string{"bin", "sbin", "lib", "usr"} {
		if exists(m) {
			markers++
		}
	}
	if (hasEtc && markers >= 2) || markers >= 3 {
		return true
	}
	for _, db := range []string{"var/lib/dpkg/status", "lib/apk/db/installed", "var/lib/opkg/status", "usr/lib/opkg/status", "usr/lib/sysimage/rpm", "var/lib/rpm"} {
		if exists(db) {
			return true
		}
	}
	return false
}

func countNonDirs(ctx context.Context, root string) (int, error) {
	n := 0
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtrees are skipped, not followed
		}
		if cerr := contextError(ctx); cerr != nil {
			return cerr
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	return n, err
}

type rootCandidate struct {
	rel   string
	files int
}

// selectRootFS chooses the candidate tree with the most files; ties go to the
// lexicographically first path so the choice is reproducible.
func selectRootFS(ctx context.Context, extractDir string) (string, []string, error) {
	var found []rootCandidate
	err := filepath.WalkDir(extractDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if cerr := contextError(ctx); cerr != nil {
			return cerr
		}
		if looksLikeRootFS(p) {
			rel, relErr := filepath.Rel(extractDir, p)
			if relErr != nil {
				return nil
			}
			n, cerr := countNonDirs(ctx, p)
			if cerr != nil {
				return cerr
			}
			found = append(found, rootCandidate{filepath.ToSlash(rel), n})
			return filepath.SkipDir // nested trees belong to this root
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if len(found) == 0 {
		return "", nil, errNoRootFS
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].files != found[j].files {
			return found[i].files > found[j].files
		}
		return found[i].rel < found[j].rel
	})
	var others []string
	for _, c := range found[1:] {
		if len(others) < maxListedCandidates {
			others = append(others, c.rel)
		}
	}
	return found[0].rel, others, nil
}

var errNoRootFS = errors.New("no root filesystem found")

// topLevelListing lists the entries of the extraction directory (one wrapper
// level is unwrapped), so a failed run can say what was extracted.
func topLevelListing(extractDir string) string {
	entries, err := os.ReadDir(extractDir)
	if err == nil && len(entries) == 1 && entries[0].IsDir() {
		if inner, e := os.ReadDir(filepath.Join(extractDir, entries[0].Name())); e == nil {
			entries = inner
		}
	}
	names := []string{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() {
			n += "/"
		}
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "(nothing was extracted)"
	}
	shown, more := names, 0
	if len(shown) > 30 {
		shown, more = shown[:30], len(names)-30
	}
	text := strings.Join(shown, ", ")
	if more > 0 {
		text += fmt.Sprintf(" … and %d more", more)
	}
	if len(text) > maxUnsafeListedBytes {
		text = text[:maxUnsafeListedBytes] + "…"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, text)
}

// entriesBeside lists, level by level along the path to the selected root, the
// entries that were extracted next to it and therefore not scanned.
func entriesBeside(extractDir, rootRel string) (listed []string, total int) {
	parts := strings.Split(rootRel, "/")
	dir, prefix := extractDir, ""
	for _, part := range parts {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if e.Name() == part {
					continue
				}
				total++
				if len(listed) < maxListedEntries {
					listed = append(listed, prefix+e.Name())
				}
			}
		}
		dir = filepath.Join(dir, part)
		prefix += part + "/"
	}
	return listed, total
}

// forceRemove deletes an extraction tree even if the image carried
// directories without write permission.
func forceRemove(path string) {
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if d != nil && d.IsDir() {
			_ = os.Chmod(p, 0700)
		}
		return nil
	})
	_ = os.RemoveAll(path)
}

// extractFirmware runs the whole firmware step: hash the image, extract it into
// a private directory beside the future output, select the root filesystem and
// describe what happened. The returned cleanup must always be called.
func extractFirmware(ctx context.Context, o generateOptions, now func() time.Time) (root string, info *FirmwareInfo, cleanup func(), err error) {
	cleanup = func() {}
	if err = contextError(ctx); err != nil {
		return
	}
	kind, err := detectExtractorKind(o.extractorGiven, o.extractor, o.extractorKind)
	if err != nil {
		return
	}
	extractorHash, _, err := hashFile(o.extractor)
	if err != nil {
		err = errors.New("cannot read the extractor binary")
		return
	}
	imageHash, imageSize, err := hashFile(o.target)
	if err != nil {
		err = errors.New("cannot read the firmware image")
		return
	}
	if err = contextError(ctx); err != nil {
		return
	}
	tmp, err := os.MkdirTemp(filepath.Dir(o.output), ".cracken-sbom-extract-")
	if err != nil {
		err = errors.New("cannot create private extraction workspace beside the output directory")
		return
	}
	cleanup = func() { forceRemove(tmp) }
	if tmp, err = filepath.EvalSymlinks(tmp); err != nil {
		err = errors.New("cannot resolve extraction workspace")
		return
	}
	work, extractDir := filepath.Join(tmp, "work"), filepath.Join(tmp, "extract")
	if err = os.Mkdir(work, 0700); err != nil {
		err = errors.New("cannot prepare extraction workspace")
		return
	}
	version, err := extractorVersion(ctx, o.extractor, work)
	if err != nil {
		return
	}
	reportedErrors, err := runExtractor(ctx, kind, o.extractor, o.target, extractDir, work)
	if err != nil {
		return
	}
	extractedAt := now().UTC().Format(time.RFC3339)
	rootRel, others, err := selectRootFS(ctx, extractDir)
	if errors.Is(err, errNoRootFS) {
		hint := ""
		if reportedErrors {
			hint = " The extractor reported errors, so a missing helper tool may be the cause (for unblob: unblob --show-external-dependencies)."
		}
		err = fmt.Errorf("the image was extracted but no root filesystem (a directory with etc, bin, lib or a package database) was found. Extracted top-level entries: %s.%s Unpack the filesystem yourself and use --target-type rootfs", topLevelListing(extractDir), hint)
		return
	}
	if err != nil {
		return
	}
	root = filepath.Join(extractDir, filepath.FromSlash(rootRel))
	if st, lerr := os.Lstat(root); lerr != nil || !st.IsDir() {
		err = errors.New("selected root filesystem is not a plain directory")
		return
	}
	files, err := countNonDirs(ctx, extractDir)
	if err != nil {
		return
	}
	// binwalk stores a copy of the image next to its results; it is not extracted data.
	if st, serr := os.Lstat(filepath.Join(extractDir, filepath.Base(o.target))); serr == nil && st.Mode().IsRegular() && st.Size() == imageSize && files > 0 {
		files--
	}
	unused, unusedTotal := entriesBeside(extractDir, rootRel)
	info = &FirmwareInfo{
		ImageName: filepath.Base(o.target), ImageSize: imageSize, ImageSHA256: imageHash,
		ExtractorKind: kind, ExtractorVersion: version, ExtractorSHA256: extractorHash,
		ExtractedAt: extractedAt, RootPath: rootRel, ExtractedFiles: files,
		UnusedEntries: unused, UnusedEntriesTotal: unusedTotal, OtherRootCandidates: others, ExtractorReported: reportedErrors,
	}
	return root, info, cleanup, nil
}
