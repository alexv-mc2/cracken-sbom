package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The built-in extension: the seven local target types, generate and version.
var builtinExtension = Extension{
	Name: "builtin",
	Targets: []TargetHandler{
		syftTarget{name: "dir", kind: TargetDirectory, root: RootHint{Type: "application", Executable: true, Archive: true, Structured: true}},
		syftTarget{name: "rootfs", kind: TargetDirectory, root: RootHint{Type: "firmware", Executable: true, Archive: true, Structured: true}},
		syftTarget{name: "npm", kind: TargetDirectory, root: RootHint{Type: "application", Executable: true, Archive: true, Structured: true}},
		syftTarget{name: "python", kind: TargetDirectory, root: RootHint{Type: "application", Executable: true, Archive: true, Structured: true}},
		// Container images are structured archives (TR-03183-2 §8.1.6).
		syftTarget{name: "oci-archive", kind: TargetFile, root: RootHint{Type: "container", Archive: true, Structured: true}},
		syftTarget{name: "docker-archive", kind: TargetFile, root: RootHint{Type: "container", Archive: true, Structured: true}},
		firmwareTarget{},
	},
	Subcommands: []Subcommand{
		{Name: "generate", Summary: "generate an SBOM for one local target", Run: runGenerateCommand},
		{Name: "version", Summary: "print the tool and engine versions", Run: runVersionCommand},
	},
}

func init() { Register(builtinExtension) }

func runVersionCommand(_ context.Context, args []string, env Env) error {
	if len(args) != 0 {
		return errors.New("version takes no arguments")
	}
	_, err := fmt.Fprintf(env.Stdout, "cracken-sbom %s (Syft %s)\n", toolVersion, engineVersion)
	return err
}

func runGenerateCommand(ctx context.Context, args []string, env Env) error {
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
	return RunGenerate(ctx, o, env)
}

// syftTarget scans a local directory or archive directly with Syft.
type syftTarget struct {
	name string
	kind TargetKind
	root RootHint
}

func (t syftTarget) Type() string                          { return t.name }
func (t syftTarget) Kind() TargetKind                      { return t.kind }
func (t syftTarget) Flags() []ExtraFlag                    { return nil }
func (t syftTarget) ConfigDigest() string                  { return configurationDigest(t.name) }
func (t syftTarget) CheckOptions(o *generateOptions) error { return nil }
func (t syftTarget) ResolvePaths(o *generateOptions) error { return nil }

func (t syftTarget) Prepare(ctx context.Context, o generateOptions, env Env) (*Prepared, func(), error) {
	raw, err := env.Engine.Scan(ctx, o.syft, o.target, t.name)
	if err != nil {
		return nil, func() {}, err
	}
	p := &Prepared{RawCDX: raw, ScanType: t.name, Root: t.root, Graph: GraphPartial}
	if t.kind == TargetDirectory {
		p.ScanRoot = o.target
	} else {
		p.Root.ArtifactPath = o.target
	}
	if t.name == "npm" {
		// Syft builds the npm graph from package-lock.json v2/v3 (or
		// npm-shrinkwrap.json); only such a lockfile states the whole graph.
		p.Graph = GraphPartial
		if name, version, ok := npmLockfileProject(o.target); ok {
			p.Graph = GraphLockfile
			p.Root.DefaultName, p.Root.DefaultVersion = name, version
		}
	}
	return p, func() {}, nil
}

// npmLockfileProject reports whether the target has a lockfile v2/v3 and
// returns its project name and version when they are safe component values.
func npmLockfileProject(dir string) (name, version string, ok bool) {
	for _, lock := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
		path := filepath.Join(dir, lock)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxLockfileBytes {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var doc struct {
			Name            any            `json:"name"`
			Version         any            `json:"version"`
			LockfileVersion int            `json:"lockfileVersion"`
			Packages        map[string]any `json:"packages"`
		}
		if json.Unmarshal(data, &doc) != nil || doc.LockfileVersion < 2 || doc.Packages == nil {
			continue
		}
		if n, err := cleanString(doc.Name, "name", true); err == nil {
			name = n
		}
		if v, err := cleanString(doc.Version, "version", false); err == nil {
			version = v
		}
		return name, version, true
	}
	return "", "", false
}

// firmwareTarget extracts an image with unblob or binwalk and scans the
// largest root filesystem candidate as a rootfs.
type firmwareTarget struct{}

func (firmwareTarget) Type() string         { return firmwareTargetType }
func (firmwareTarget) Kind() TargetKind     { return TargetFile }
func (firmwareTarget) Flags() []ExtraFlag   { return nil }
func (firmwareTarget) ConfigDigest() string { return configurationDigest(firmwareTargetType) }

func (firmwareTarget) CheckOptions(o *generateOptions) error {
	if !filepath.IsAbs(o.extractor) {
		return errors.New("firmware-image requires --extractor with an absolute path to unblob or binwalk")
	}
	o.extractorGiven = o.extractor
	if o.workDir != "" && !filepath.IsAbs(o.workDir) {
		return errors.New("--work-dir must be an absolute path")
	}
	return nil
}

func (firmwareTarget) ResolvePaths(o *generateOptions) error {
	// Package managers such as pipx expose the extractor through a symbolic
	// link, so the link is resolved here instead of being rejected.
	extractor, err := filepath.EvalSymlinks(o.extractor)
	if err != nil {
		return errors.New("cannot resolve the extractor")
	}
	extractorInfo, err := os.Stat(extractor)
	if err != nil || !extractorInfo.Mode().IsRegular() || extractorInfo.Mode()&0111 == 0 {
		return errors.New("extractor must be an existing regular executable")
	}
	o.extractor = extractor
	if o.workDir != "" {
		work, err := filepath.EvalSymlinks(o.workDir)
		if err != nil {
			return errors.New("--work-dir must be an existing local directory")
		}
		workInfo, err := os.Stat(work)
		if err != nil || !workInfo.IsDir() {
			return errors.New("--work-dir must be an existing local directory")
		}
		o.workDir = work
	}
	return nil
}

func (firmwareTarget) Prepare(ctx context.Context, o generateOptions, env Env) (*Prepared, func(), error) {
	root, firmware, cleanup, err := extractFirmware(ctx, o, env.Now)
	if err != nil {
		return nil, cleanup, err
	}
	// The extracted tree goes through the unchanged rootfs flow.
	raw, err := env.Engine.Scan(ctx, o.syft, root, "rootfs")
	if err != nil {
		return nil, cleanup, err
	}
	// A firmware image is executable and unstructured (TR-03183-2 Table 7).
	return &Prepared{
		RawCDX: raw, ScanType: "rootfs", ScanRoot: root, Firmware: firmware, Graph: GraphPartial,
		Root: RootHint{Type: "firmware", ArtifactPath: o.target, Executable: true},
	}, cleanup, nil
}
