package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Release builds bind this value to their exact tag with -ldflags -X.
var toolVersion = "0.1.0"
const maxUploadBytes = 10 << 20

type generateOptions struct {
	targetType, target, targetID, output, syft string
	allowIncomplete                            bool
}

func main() {
	ctx, stop := signalContext(context.Background())
	defer stop()
	if err := runCLI(ctx, os.Args[1:], os.Stdout, runEngine, time.Now); err != nil {
		fmt.Fprintln(os.Stderr, "cracken-sbom:", err)
		os.Exit(1)
	}
}

func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

func parseOptions(args []string) (generateOptions, error) {
	var o generateOptions
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // flag errors otherwise echo supplied values.
	fs.StringVar(&o.targetType, "target-type", "", "local target type")
	fs.StringVar(&o.target, "target", "", "local existing path")
	fs.StringVar(&o.targetID, "target-id", "", "release, commit or image digest")
	fs.StringVar(&o.output, "output", "", "new output directory")
	fs.StringVar(&o.syft, "syft", "", "absolute path to verified Syft binary")
	fs.BoolVar(&o.allowIncomplete, "allow-incomplete", false, "acknowledge incomplete metadata")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return o, errors.New("invalid flags; use generate --target-type TYPE --target PATH --target-id ID --output NEW-DIR --syft ABSOLUTE-BINARY [--allow-incomplete]")
	}
	if o.target == "" || o.targetID == "" || o.output == "" || !filepath.IsAbs(o.syft) {
		return o, errors.New("required flags are missing or engine path is not absolute")
	}
	switch o.targetType {
	case "rootfs", "npm", "python", "oci-archive", "docker-archive":
	default:
		return o, errors.New("target type must be rootfs, npm, python, oci-archive or docker-archive")
	}
	return o, nil
}

func canonicalExisting(path string) (string, os.FileInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, errors.New("invalid local path")
	}
	info, err := os.Lstat(abs)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.New("local input must exist and must not be a symbolic link")
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", nil, errors.New("cannot resolve local input")
	}
	return canonical, info, nil
}

func validatePaths(o *generateOptions) error {
	// Selectors, URLs and bare image references are never interpreted as paths.
	if strings.Contains(o.target, "://") || strings.HasPrefix(o.target, "-") || strings.Contains(o.target, "\x00") {
		return errors.New("target must be a local filesystem path")
	}
	target, info, err := canonicalExisting(o.target)
	if err != nil {
		return err
	}
	wantDir := o.targetType == "rootfs" || o.targetType == "npm" || o.targetType == "python"
	if (wantDir && !info.IsDir()) || (!wantDir && !info.Mode().IsRegular()) {
		return errors.New("target filesystem type does not match declared target type")
	}
	engine, engineInfo, err := canonicalExisting(o.syft)
	if err != nil || !engineInfo.Mode().IsRegular() || engineInfo.Mode()&0111 == 0 {
		return errors.New("engine must be an existing regular executable")
	}
	outAbs, err := filepath.Abs(o.output)
	if err != nil || filepath.Clean(outAbs) == string(filepath.Separator) {
		return errors.New("invalid output directory")
	}
	// Canonicalize the parent once, including OS aliases such as /tmp on macOS.
	// The final output itself must remain absent, including dangling symlinks.
	parent, err := filepath.EvalSymlinks(filepath.Dir(outAbs))
	if err != nil {
		return errors.New("output parent must be an existing local directory")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return errors.New("output parent must be an existing local directory")
	}
	out := filepath.Join(parent, filepath.Base(outAbs))
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		return errors.New("output already exists; overwriting is forbidden")
	}
	rel, err := filepath.Rel(target, out)
	if wantDir && err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("output directory must be outside the scanned target")
	}
	o.target, o.syft, o.output = target, engine, out
	return nil
}

func runCLI(ctx context.Context, args []string, stdout io.Writer, runner engineRunner, now func() time.Time) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "version" {
		_, err := fmt.Fprintf(stdout, "cracken-sbom %s (Syft %s)\n", toolVersion, engineVersion)
		return err
	}
	if len(args) == 0 || args[0] != "generate" {
		return errors.New("use version or generate --target-type TYPE --target PATH --target-id ID --output NEW-DIR --syft ABSOLUTE-BINARY [--allow-incomplete]")
	}
	o, err := parseOptions(args[1:])
	if err != nil {
		return err
	}
	if err = validatePaths(&o); err != nil {
		return err
	}
	provenanceCtx := ProvenanceContext{
		ToolVersion: toolVersion, EngineVersion: engineVersion,
		ConfigDigest: configurationDigest(o.targetType), TargetType: o.targetType,
		TargetIdentifier: o.targetID, GeneratedAt: now().UTC().Format(time.RFC3339),
	}
	// Validate asserted provenance before spending time scanning or reading input.
	if _, err := createProvenance([]byte("{}"), provenanceCtx, Quality{}); err != nil {
		return errors.New("target identifier or provenance metadata is invalid")
	}
	raw, err := runner(ctx, o.syft, o.target, o.targetType)
	if err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	sbom, quality, err := normalizeSBOM(raw, provenanceCtx)
	if err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if len(sbom) > maxUploadBytes {
		return errors.New("minimized SBOM exceeds the 10 MiB upload limit; inventory was not truncated")
	}
	if quality.MissingVersions > 0 && !o.allowIncomplete {
		return fmt.Errorf("inventory requires acknowledgement: %d packages, %d missing versions. Inspect the target and explicitly use --allow-incomplete", quality.EmittedComponents, quality.MissingVersions)
	}
	provenance, err := createProvenance(sbom, provenanceCtx, quality)
	if err != nil {
		return err
	}
	qualityJSON, err := json.MarshalIndent(quality, "", "  ")
	if err != nil {
		return errors.New("cannot serialize quality summary")
	}
	if err := publishOutputs(ctx, o.output, sbom, provenance, append(qualityJSON, '\n')); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "Generated sbom.cdx.json, provenance.json and quality.json. Review the SBOM before manual upload; provenance remains customer-held.")
	return nil
}

// Build all files privately, then reserve a new destination exclusively and
// atomically replace only that reservation. No existing directory is replaced.
func contextError(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.New("generation cancelled")
	}
	return nil
}

func publishOutputs(ctx context.Context, output string, sbom, provenance, quality []byte) error {
	stage, err := os.MkdirTemp(filepath.Dir(output), ".cracken-sbom-output-")
	if err != nil {
		return errors.New("cannot create private output workspace")
	}
	defer os.RemoveAll(stage)
	for name, data := range map[string][]byte{"sbom.cdx.json": sbom, "provenance.json": provenance, "quality.json": quality} {
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(stage, name), data, 0600); err != nil {
			return errors.New("cannot prepare output files")
		}
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if os.Mkdir(output, 0700) != nil {
		return errors.New("cannot reserve new output directory; overwriting is forbidden")
	}
	reservation, err := os.Lstat(output)
	if err != nil {
		return errors.New("cannot verify output reservation")
	}
	current, err := os.Lstat(output)
	if err != nil || !os.SameFile(reservation, current) || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 {
		return errors.New("output reservation changed; no files published")
	}
	if err := contextError(ctx); err != nil {
		_ = os.Remove(output) // Remove only the empty reservation created above.
		return err
	}
	// Go's os.Rename precheck rejects any existing destination directory; the
	// supported POSIX platforms permit replacement of an empty reservation.
	if syscall.Rename(stage, output) != nil {
		_ = os.Remove(output) // Remove only an empty reservation, never recursively.
		return errors.New("cannot publish output directory")
	}
	return nil
}
