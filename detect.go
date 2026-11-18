package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// detect: `cracken-sbom` with no arguments, or `cracken-sbom detect PATH`.
// It looks at a local folder or file without any network access, says in
// plain words what it found and which generate command fits, and then runs
// that command through the same pipeline as generate.

var detectExtension = Extension{
	Name: "detect",
	Subcommands: []Subcommand{{
		Name: "detect", Default: true,
		Summary: "look at a folder or file, say what it is, and build the right SBOM (default)",
		Run:     runDetectCommand,
	}},
	EngineLocators: []EngineLocator{locatePinnedEngine},
}

func init() { Register(detectExtension) }

const detectHelp = `Usage: cracken-sbom [detect] [PATH] [flags]

Looks at PATH (default: the current folder) on this computer, without any
network access, says what it is and which command fits, and builds the SBOM:

  project folder with lockfiles   generate --target-type npm or dir
  installed Python packages       generate --target-type python
  unpacked root file system       generate --target-type rootfs
  docker save / OCI image .tar    generate --target-type docker-archive / oci-archive
  firmware image (.bin, .img)     generate --target-type firmware-image (needs unblob or binwalk)
  Yocto build or deploy folder    generate --target-type yocto (reads the image SPDX)
  Dockerfile                      explains how to save the image and scan that

Flags:
  --dry-run              say what would run, build nothing
  --output NEW-DIR       default: a new folder next to PATH, named <name>-sbom-<time>
  --target-id ID         release, commit or image digest; default: the git commit, else local-<time>
  --syft ABSOLUTE-PATH   default: the pinned Syft next to cracken-sbom, in PATH or in the cache folder
  --extractor ABSOLUTE-PATH, --extractor-kind unblob|binwalk, --work-dir ABSOLUTE-DIR (firmware images)
  --allow-incomplete, --zip and the BSI TR-03183-2 flags (--product-name, --manufacturer-name, ...)
                         are passed to generate unchanged; see cracken-sbom generate --help
`

// Flags detect itself uses; all others are forwarded to generate.
var detectOwnFlags = map[string]bool{"dry-run": true}

func runDetectCommand(ctx context.Context, args []string, env Env) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "")
	var fwd generateOptions
	fs.StringVar(&fwd.output, "output", "", "")
	fs.StringVar(&fwd.targetID, "target-id", "", "")
	fs.StringVar(&fwd.syft, "syft", "", "")
	fs.BoolVar(&fwd.allowIncomplete, "allow-incomplete", false, "")
	fs.BoolVar(&fwd.zipOutput, "zip", false, "")
	fs.StringVar(&fwd.extractor, "extractor", "", "")
	fs.StringVar(&fwd.extractorKind, "extractor-kind", "", "")
	fs.StringVar(&fwd.workDir, "work-dir", "", "")
	bindTRFlags(fs, &fwd.tr)
	// Accept the path before or after the flags.
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(flagError("detect", err), errHelpRequested) {
				_, werr := io.WriteString(env.Stdout, detectHelp)
				return werr
			}
			return flagError("detect", err)
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) > 1 {
		return fmt.Errorf("detect takes one PATH (%d given); run cracken-sbom detect --help", len(positional))
	}
	given := "."
	if len(positional) == 1 {
		given = positional[0]
	}
	target, info, err := detectTarget(given)
	if err != nil {
		return err
	}
	out := env.Stdout
	fmt.Fprintf(out, "cracken-sbom detect: looking at %s (on this computer, no network, nothing is uploaded)\n\n", target)
	plan, err := planForPath(ctx, target, info)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Found: %s\n", plan.What)
	for _, e := range plan.Evidence {
		fmt.Fprintf(out, "  - %s\n", e)
	}
	if plan.TargetType == "" {
		fmt.Fprintln(out)
		for _, g := range plan.Guidance {
			fmt.Fprintln(out, g)
		}
		if len(plan.Choices) > 0 {
			set := map[string]bool{}
			fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
			for _, choice := range plan.Choices {
				gen := append([]string{"--target-type", "yocto"}, choice...)
				gen = append(gen, completeGenerateArgs(target, info, env, fs, set)...)
				fmt.Fprintf(out, "  cracken-sbom generate %s\n", joinShell(gen))
			}
		}
		printNotes(out, plan.Notes)
		if plan.Unrecognised {
			return errors.New("no SBOM was written: detect found nothing it can list in " + shellQuote(target))
		}
		fmt.Fprintln(out, "\nNo SBOM was written.")
		return nil
	}
	if _, ok := defaultRegistry.target(plan.TargetType); !ok {
		return fmt.Errorf("target type %s is not available in this build", plan.TargetType)
	}

	// Build the generate command line from what was found and what was given.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	scanTarget := target
	if plan.Target != "" {
		scanTarget = plan.Target
	}
	gen := append([]string{"--target-type", plan.TargetType, "--target", scanTarget}, plan.Extra...)
	if !set["target-id"] {
		gen = append(gen, "--target-id", defaultTargetID(target, info, env))
	}
	if !set["output"] {
		output, err := defaultOutput(target, info, env)
		if err != nil {
			return err
		}
		gen = append(gen, "--output", output)
	}
	if !set["syft"] {
		for _, locate := range defaultRegistry.engineLocators() {
			if p, ok := locate(); ok {
				gen = append(gen, "--syft", p)
				break
			}
		}
	}
	if plan.TargetType == firmwareTargetType && !set["extractor"] {
		if p, kind, ok := locateExtractor(); ok {
			gen = append(gen, "--extractor", p)
			if !set["extractor-kind"] {
				gen = append(gen, "--extractor-kind", kind)
			}
		}
	}
	fs.Visit(func(f *flag.Flag) {
		if !detectOwnFlags[f.Name] {
			gen = append(gen, "--"+f.Name+"="+f.Value.String())
		}
	})
	fmt.Fprintf(out, "\nWhat I will do: build the SBOM with the %q target, because %s.\n", plan.TargetType, plan.Why)
	fmt.Fprintf(out, "Command: cracken-sbom generate %s\n", joinShell(gen))
	printNotes(out, plan.Notes)
	hasFlag := func(name string) bool {
		for _, a := range gen {
			if a == "--"+name || strings.HasPrefix(a, "--"+name+"=") {
				return true
			}
		}
		return false
	}
	if !hasFlag("syft") {
		return engineNotFoundError()
	}
	if plan.TargetType == firmwareTargetType && !hasFlag("extractor") {
		return extractorNotFoundError()
	}
	if *dryRun {
		fmt.Fprintln(out, "\nDry run: nothing was built. Run the same command without --dry-run to build the SBOM.")
		return nil
	}
	fmt.Fprintln(out)
	o, err := parseOptions(gen)
	if err != nil {
		return err
	}
	return RunGenerate(ctx, o, env)
}

// completeGenerateArgs adds what a printed generate command needs besides
// the target: target id, output, engine and the flags given to detect.
func completeGenerateArgs(target string, info os.FileInfo, env Env, fs *flag.FlagSet, set map[string]bool) []string {
	args := []string{}
	if !set["target-id"] {
		args = append(args, "--target-id", defaultTargetID(target, info, env))
	}
	if !set["output"] {
		if output, err := defaultOutput(target, info, env); err == nil {
			args = append(args, "--output", output)
		}
	}
	if !set["syft"] {
		for _, locate := range defaultRegistry.engineLocators() {
			if p, ok := locate(); ok {
				args = append(args, "--syft", p)
				break
			}
		}
	}
	fs.Visit(func(f *flag.Flag) {
		if !detectOwnFlags[f.Name] {
			args = append(args, "--"+f.Name+"="+f.Value.String())
		}
	})
	return args
}

func printNotes(out io.Writer, notes []string) {
	for _, n := range notes {
		fmt.Fprintf(out, "Note: %s\n", n)
	}
}

func joinShell(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		if name, value, ok := strings.Cut(a, "="); ok && strings.HasPrefix(a, "--") {
			quoted[i] = name + "=" + shellQuote(value)
		} else {
			quoted[i] = shellQuote(a)
		}
	}
	return strings.Join(quoted, " ")
}

// detectTarget checks the PATH argument. Unlike generate's flags, the path
// is named in errors: the person typed it to ask about exactly that path.
func detectTarget(given string) (string, os.FileInfo, error) {
	if strings.Contains(given, "://") || strings.Contains(given, "\x00") {
		return "", nil, fmt.Errorf("detect works on local paths only; %s looks like a URL. Save the image or download the file first", shellQuote(given))
	}
	abs, err := filepath.Abs(given)
	if err != nil {
		return "", nil, fmt.Errorf("cannot use the path %s", shellQuote(given))
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", nil, fmt.Errorf("%s does not exist; check the path (run cracken-sbom detect --help)", shellQuote(given))
	}
	if info.Mode()&os.ModeSymlink != 0 {
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return "", nil, fmt.Errorf("%s is a symbolic link to a path that does not exist", shellQuote(given))
		}
		return "", nil, fmt.Errorf("%s is a symbolic link; run detect on the real path: %s", shellQuote(given), shellQuote(real))
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", nil, fmt.Errorf("cannot resolve %s", shellQuote(given))
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%s is neither a folder nor a regular file", shellQuote(given))
	}
	return canonical, info, nil
}

func timeStamp(env Env) string {
	return env.Now().UTC().Format("20060102-150405")
}

// defaultOutput is a new folder next to the target (it must be outside a
// scanned folder), e.g. /work/app -> /work/app-sbom-20261118-235500.
func defaultOutput(target string, info os.FileInfo, env Env) (string, error) {
	parent := filepath.Dir(target)
	if parent == target {
		return "", errors.New("cannot place the output next to the file system root; pass --output NEW-DIR")
	}
	base := filepath.Base(target)
	if !info.IsDir() {
		base = strings.TrimSuffix(base, filepath.Ext(base))
	}
	stem := filepath.Join(parent, base+"-sbom-"+timeStamp(env))
	for i := 1; i < 100; i++ {
		candidate := stem
		if i > 1 {
			candidate = fmt.Sprintf("%s-%d", stem, i)
		}
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate, nil
		}
	}
	return "", errors.New("cannot find a new output folder name; pass --output NEW-DIR")
}

var (
	gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	gitRefPattern = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]{1,200}$`)
)

// defaultTargetID uses the folder's git commit when there is one (read from
// .git without running git), otherwise local-<UTC time>.
func defaultTargetID(target string, info os.FileInfo, env Env) string {
	if info.IsDir() {
		if sha, ok := gitHead(filepath.Join(target, ".git")); ok {
			return sha
		}
	}
	return "local-" + timeStamp(env)
}

func readSmall(p string, limit int64) (string, bool) {
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return "", false
	}
	data, err := os.ReadFile(p)
	return string(data), err == nil
}

func gitHead(gitDir string) (string, bool) {
	if !isDir(gitDir) {
		return "", false
	}
	head, ok := readSmall(filepath.Join(gitDir, "HEAD"), 512)
	if !ok {
		return "", false
	}
	head = strings.TrimSpace(head)
	if gitSHAPattern.MatchString(head) {
		return head, true
	}
	ref, found := strings.CutPrefix(head, "ref: ")
	if !found || !gitRefPattern.MatchString(ref) || strings.Contains(ref, "..") {
		return "", false
	}
	if sha, ok := readSmall(filepath.Join(gitDir, filepath.FromSlash(ref)), 512); ok && gitSHAPattern.MatchString(strings.TrimSpace(sha)) {
		return strings.TrimSpace(sha), true
	}
	packed, ok := readSmall(filepath.Join(gitDir, "packed-refs"), 8<<20)
	if !ok {
		return "", false
	}
	for _, line := range strings.Split(packed, "\n") {
		if sha, name, ok := strings.Cut(strings.TrimSpace(line), " "); ok && name == ref && gitSHAPattern.MatchString(sha) {
			return sha, true
		}
	}
	return "", false
}
