package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const usage = "generate --target-type TYPE --target PATH --target-id ID --output NEW-DIR [--syft ABSOLUTE-BINARY] [--allow-incomplete] [--zip] [--extractor ABSOLUTE-BINARY [--extractor-kind unblob|binwalk] [--work-dir ABSOLUTE-DIR]] " +
	"[--product-name NAME --product-version VERSION --product-license SPDX-EXPRESSION] [--manufacturer-name NAME --manufacturer-email EMAIL|--manufacturer-url URL] [--metadata FILE.json] [--artifact FILE] [--conclude-licenses] [--component-contacts]; " +
	"--zip or automatic ZIP for SBOMs over 10 MiB: crAcken web app's SPDX upload method (ZIP archive) or public API (application/zip)"

// errHelpRequested is returned by a subcommand's flag parsing for -h/--help;
// runCLI prints that command's help and exits successfully.
var errHelpRequested = errors.New("help requested")

var flagNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,40}$`)

// flagError turns a flag package error into a message that names the flag but
// never echoes a supplied value (values can be tokens or private paths).
func flagError(command string, err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return errHelpRequested
	}
	msg, name := err.Error(), ""
	text := "invalid flags"
	for _, p := range []struct{ prefix, text string }{
		{"flag provided but not defined: -", "unknown flag --%s"},
		{"flag needs an argument: -", "flag --%s needs a value"},
	} {
		if strings.HasPrefix(msg, p.prefix) {
			name, text = strings.TrimPrefix(msg, p.prefix), p.text
		}
	}
	if strings.HasPrefix(msg, "invalid ") {
		if i := strings.Index(msg, " for flag -"); i >= 0 {
			name, text = msg[i+len(" for flag -"):], "invalid value for flag --%s"
			if j := strings.Index(name, ":"); j >= 0 {
				name = name[:j]
			}
		}
	}
	if strings.HasPrefix(msg, "bad flag syntax") {
		text = "bad flag syntax"
	}
	name = strings.TrimPrefix(name, "-")
	if strings.Contains(text, "%s") {
		if !flagNamePattern.MatchString(name) {
			text, name = strings.ReplaceAll(text, " --%s", ""), ""
		} else {
			text = fmt.Sprintf(text, name)
		}
	}
	return fmt.Errorf("%s; run cracken-sbom %s --help", text, command)
}

func generateHelp() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: cracken-sbom %s\n\n", strings.SplitN(usage, ";", 2)[0])
	fmt.Fprintf(&b, "Target types: %s.\n", joinChoices(defaultRegistry.targetTypes()))
	fmt.Fprintln(&b, "--syft may be omitted when the pinned Syft is next to cracken-sbom, in PATH or in the cache folder.")
	fmt.Fprintln(&b, "--zip, or automatic ZIP for SBOMs over 10 MiB: use the crAcken web app's SPDX upload method \"ZIP archive\" or the public API with Content-Type: application/zip.")
	fmt.Fprintln(&b, "Not sure which target type? Run cracken-sbom detect PATH; it tells you and runs the right command.")
	return b.String()
}

func topHelp() string {
	var b strings.Builder
	fmt.Fprintln(&b, "cracken-sbom builds a CycloneDX 1.6 SBOM on this computer with the pinned Syft "+engineVersion+". Nothing is uploaded.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Usage:")
	if d, ok := defaultRegistry.defaultSubcommand(); ok {
		fmt.Fprintf(&b, "  cracken-sbom                 same as: cracken-sbom %s .\n", d.Name)
	}
	for _, ext := range defaultRegistry.extensions() {
		for _, c := range ext.Subcommands {
			fmt.Fprintf(&b, "  cracken-sbom %-15s %s\n", c.Name, c.Summary)
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Run cracken-sbom COMMAND --help for the flags of one command.")
	return b.String()
}

// Release builds bind this value to their exact tag with -ldflags -X.
var toolVersion = "1.1.0"

const maxUploadBytes = 10 << 20
const maxZipBytes = 16 << 20

type generateOptions struct {
	targetType, target, targetID, output, syft string
	allowIncomplete, zipOutput                 bool
	// Firmware images only: the extractor as given and as resolved, and its kind.
	extractor, extractorGiven, extractorKind, workDir string
	// BSI TR-03183-2 product and SBOM-creator facts asserted by the user.
	tr trOptions
	// Values of target-owned flags (ExtraFlag), by flag name.
	extra map[string]string
}

// Flags parsed by generate itself; extensions may not reuse these names.
var builtinFlagNames = map[string]bool{
	"target-type": true, "target": true, "target-id": true, "output": true, "syft": true,
	"zip": true, "allow-incomplete": true, "extractor": true, "extractor-kind": true, "work-dir": true,
	"product-name": true, "product-version": true, "product-license": true,
	"manufacturer-name": true, "manufacturer-email": true, "manufacturer-url": true,
	"metadata": true, "artifact": true, "conclude-licenses": true, "component-contacts": true,
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

func joinChoices(values []string) string {
	if len(values) < 2 {
		return strings.Join(values, "")
	}
	return strings.Join(values[:len(values)-1], ", ") + " or " + values[len(values)-1]
}

func parseOptions(args []string) (generateOptions, error) {
	o := generateOptions{extra: map[string]string{}}
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // flag errors otherwise echo supplied values.
	fs.StringVar(&o.targetType, "target-type", "", "local target type")
	fs.StringVar(&o.target, "target", "", "local existing path")
	fs.StringVar(&o.targetID, "target-id", "", "release, commit or image digest")
	fs.StringVar(&o.output, "output", "", "new output directory")
	fs.StringVar(&o.syft, "syft", "", "absolute path to verified Syft binary")
	fs.BoolVar(&o.zipOutput, "zip", false, "package the SBOM as ZIP for the crAcken web app (SPDX upload method: ZIP archive) or public API (application/zip)")
	fs.BoolVar(&o.allowIncomplete, "allow-incomplete", false, "acknowledge incomplete metadata")
	fs.StringVar(&o.extractor, "extractor", "", "absolute path to unblob or binwalk (firmware-image only)")
	fs.StringVar(&o.extractorKind, "extractor-kind", "", "unblob or binwalk (firmware-image only)")
	fs.StringVar(&o.workDir, "work-dir", "", "absolute directory for the private extraction folder (firmware-image only)")
	bindTRFlags(fs, &o.tr)
	extraFlags := defaultRegistry.allExtraFlags()
	extraBool := map[string]*bool{}
	extraString := map[string]*string{}
	for name, e := range extraFlags {
		if e.Flag.Bool {
			extraBool[name] = fs.Bool(name, false, e.Flag.Usage)
		} else {
			extraString[name] = fs.String(name, "", e.Flag.Usage)
		}
	}
	if err := fs.Parse(args); err != nil {
		return o, flagError("generate", err)
	}
	if fs.NArg() != 0 {
		// The value itself is not echoed: it can be a token or a private path.
		return o, fmt.Errorf("generate takes no positional arguments (%d given); every value needs its flag, for example --target PATH; run cracken-sbom generate --help", fs.NArg())
	}
	var extraErr error
	fs.Visit(func(f *flag.Flag) {
		e, ok := extraFlags[f.Name]
		if !ok {
			return
		}
		if e.Owner != o.targetType {
			extraErr = fmt.Errorf("--%s is only valid with --target-type %s", f.Name, e.Owner)
			return
		}
		if p := extraBool[f.Name]; p != nil {
			o.extra[f.Name] = strconv.FormatBool(*p)
		} else {
			o.extra[f.Name] = *extraString[f.Name]
		}
	})
	if extraErr != nil {
		return o, extraErr
	}
	if o.syft == "" {
		for _, locate := range defaultRegistry.engineLocators() {
			if path, ok := locate(); ok {
				o.syft = path
				break
			}
		}
	}
	missing := []string{}
	for _, f := range []struct{ name, value string }{{"--target-type", o.targetType}, {"--target", o.target}, {"--target-id", o.targetID}, {"--output", o.output}} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return o, fmt.Errorf("missing %s; run cracken-sbom generate --help, or cracken-sbom detect PATH to choose them for you", strings.Join(missing, ", "))
	}
	if o.syft == "" {
		return o, engineNotFoundError()
	}
	if !filepath.IsAbs(o.syft) {
		return o, errors.New("--syft must be an absolute path to the Syft binary")
	}
	handler, ok := defaultRegistry.target(o.targetType)
	if !ok {
		return o, errors.New("target type must be " + joinChoices(defaultRegistry.targetTypes()))
	}
	if o.targetType != firmwareTargetType && (o.extractor != "" || o.extractorKind != "" || o.workDir != "") {
		return o, errors.New("--extractor, --extractor-kind and --work-dir are only valid with --target-type firmware-image")
	}
	if err := handler.CheckOptions(&o); err != nil {
		return o, err
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
		return errors.New("--target: " + err.Error())
	}
	handler, ok := defaultRegistry.target(o.targetType)
	if !ok {
		return errors.New("unsupported target type")
	}
	wantDir := handler.Kind() == TargetDirectory
	if (wantDir && !info.IsDir()) || (!wantDir && !info.Mode().IsRegular()) {
		want := "a folder"
		if !wantDir {
			want = "a regular file"
		}
		return fmt.Errorf("--target must be %s for --target-type %s", want, o.targetType)
	}
	engine, engineInfo, err := canonicalExisting(o.syft)
	if err != nil || !engineInfo.Mode().IsRegular() || engineInfo.Mode()&0111 == 0 {
		return errors.New("--syft: the engine must be an existing regular executable, not a symbolic link")
	}
	outAbs, err := filepath.Abs(o.output)
	if err != nil || filepath.Clean(outAbs) == string(filepath.Separator) {
		return errors.New("--output: invalid output directory")
	}
	// Canonicalize the parent once, including OS aliases such as /tmp on macOS.
	// The final output itself must remain absent, including dangling symlinks.
	parent, err := filepath.EvalSymlinks(filepath.Dir(outAbs))
	if err != nil {
		return errors.New("--output: the parent folder must be an existing local directory")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return errors.New("--output: the parent folder must be an existing local directory")
	}
	out := filepath.Join(parent, filepath.Base(outAbs))
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		return errors.New("--output already exists; choose a new folder (existing output is never overwritten)")
	}
	rel, err := filepath.Rel(target, out)
	if wantDir && err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("--output must be outside the scanned --target folder")
	}
	o.target, o.syft, o.output = target, engine, out
	return handler.ResolvePaths(o)
}

func runCLI(ctx context.Context, args []string, stdout io.Writer, runner engineRunner, now func() time.Time) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	env := Env{Engine: engines{scan: runner, convert: runConvert}, Now: now, Stdout: stdout}
	run := func(command Subcommand, rest []string) error {
		err := command.Run(ctx, rest, env)
		if errors.Is(err, errHelpRequested) {
			text := command.Summary + "\n"
			if command.Name == "generate" {
				text = generateHelp()
			}
			_, err = io.WriteString(stdout, text)
		}
		return err
	}
	defaultCommand, hasDefault := defaultRegistry.defaultSubcommand()
	switch {
	case len(args) == 0 && hasDefault:
		return run(defaultCommand, nil)
	case len(args) == 0:
	case args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help":
		if len(args) == 2 {
			if command, ok := defaultRegistry.subcommand(args[1]); ok {
				return run(command, []string{"--help"})
			}
		}
		_, err := io.WriteString(stdout, topHelp())
		return err
	case args[0] == "--version" || args[0] == "-version":
		args = append([]string{"version"}, args[1:]...)
	}
	if len(args) > 0 {
		if command, ok := defaultRegistry.subcommand(args[0]); ok {
			return run(command, args[1:])
		}
		// cracken-sbom --dry-run or cracken-sbom ./some/path run the default command.
		if _, err := os.Lstat(args[0]); hasDefault && (strings.HasPrefix(args[0], "-") || err == nil) {
			return run(defaultCommand, args)
		}
		if registryNamePattern.MatchString(args[0]) {
			return fmt.Errorf("unknown command %q; use %s, or run cracken-sbom --help", args[0], joinChoices(defaultRegistry.subcommandNames()))
		}
	}
	return errors.New("use " + joinChoices(defaultRegistry.subcommandNames()) + "; run cracken-sbom --help")
}

func contextError(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.New("generation cancelled")
	}
	return nil
}

func zipSBOM(sbom []byte) ([]byte, error) {
	if len(sbom) > maxZipBytes {
		return nil, errors.New("SBOM exceeds the 16 MiB uncompressed ZIP limit")
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("sbom.cdx.json")
	if err != nil {
		return nil, errors.New("cannot create SBOM ZIP")
	}
	if _, err = f.Write(sbom); err != nil {
		return nil, errors.New("cannot write SBOM ZIP")
	}
	if err = w.Close(); err != nil {
		return nil, errors.New("cannot finish SBOM ZIP")
	}
	if buf.Len() > maxZipBytes {
		return nil, errors.New("SBOM ZIP exceeds the 16 MiB upload limit")
	}
	return buf.Bytes(), nil
}

func publishOutputs(ctx context.Context, output string, sbom, provenance, quality []byte) error {
	return publishNamedOutputs(ctx, output, "sbom.cdx.json", sbom, provenance, quality)
}

var sidecarNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}\.json$`)

// validSidecars rejects names that could collide with the core outputs or
// leave the output directory.
func validSidecars(name string, sidecars []OutputFile) error {
	seen := map[string]bool{name: true, "provenance.json": true, "quality.json": true, "sbom.cdx.json": true, "sbom.cdx.zip": true}
	for _, s := range sidecars {
		if seen[s.Name] {
			return errors.New("invalid extra output file")
		}
		// The one binary extra output: the native SPDX upload ZIP for crAcken.
		if s.Name == crackenUploadFile {
			if _, err := zip.NewReader(bytes.NewReader(s.Data), int64(len(s.Data))); err != nil {
				return errors.New("invalid extra output file")
			}
		} else if !sidecarNamePattern.MatchString(s.Name) || !json.Valid(s.Data) {
			return errors.New("invalid extra output file")
		}
		seen[s.Name] = true
	}
	return nil
}

// crackenUploadFile is the native Yocto SPDX, unchanged, packed for upload to
// crAcken. It is not minimized; the privacy profile does not apply to it.
const crackenUploadFile = "cracken-upload.zip"

// Build all files privately, then reserve a new destination exclusively and
// atomically replace only that reservation. No existing directory is replaced.
func publishNamedOutputs(ctx context.Context, output, name string, sbom, provenance, quality []byte, sidecars ...OutputFile) error {
	if err := validSidecars(name, sidecars); err != nil {
		return err
	}
	files := map[string][]byte{name: sbom, "provenance.json": provenance, "quality.json": quality}
	for _, s := range sidecars {
		files[s.Name] = s.Data
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".cracken-sbom-output-")
	if err != nil {
		return errors.New("cannot create private output workspace")
	}
	defer os.RemoveAll(stage)
	for name, data := range files {
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
