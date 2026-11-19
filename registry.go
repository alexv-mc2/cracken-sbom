package main

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

// Extension points. Target types, subcommands and engine locators live in
// extensions that register themselves from an init function in their own
// file, for example:
//
//	func init() { Register(yoctoExtension) }
//
// This file is the only registry; extensions never edit it or main.go.
// Lookups sort by extension name, so file and init order never matter.

// Extension groups what one feature adds to the CLI.
type Extension struct {
	Name           string
	Targets        []TargetHandler
	Subcommands    []Subcommand
	EngineLocators []EngineLocator
}

// TargetKind is the filesystem type a --target must have.
type TargetKind int

const (
	TargetDirectory TargetKind = iota
	TargetFile
)

// ExtraFlag is a generate flag owned by one target type. Its value reaches
// the handler through generateOptions.extra[Name]; the flag is rejected for
// every other target type.
type ExtraFlag struct {
	Name  string
	Usage string
	Bool  bool
}

// TargetHandler implements one generate --target-type.
type TargetHandler interface {
	Type() string
	Kind() TargetKind
	Flags() []ExtraFlag
	// ConfigDigest binds the engine policy used for this target type.
	ConfigDigest() string
	// CheckOptions validates flags before any path is resolved.
	CheckOptions(o *generateOptions) error
	// ResolvePaths runs after the common target, engine and output checks.
	ResolvePaths(o *generateOptions) error
	// Prepare produces the engine's CycloneDX 1.6 JSON. The returned cleanup
	// function is always non-nil and is called once, also on error.
	Prepare(ctx context.Context, o generateOptions, env Env) (*Prepared, func(), error)
}

// GraphSource says where the dependency graph in RawCDX comes from.
type GraphSource int

const (
	// GraphUnknown: the engine had no dependency graph for this target.
	GraphUnknown GraphSource = iota
	// GraphPartial: the engine reported edges, but nothing proves they are all.
	GraphPartial
	// GraphLockfile: a lockfile states the whole graph; only then may the TR
	// layer write compositions aggregate "complete".
	GraphLockfile
)

// RootHint describes the product (metadata.component) for the TR layer.
type RootHint struct {
	// CycloneDX component type: application, firmware, container, operating-system.
	Type string
	// ArtifactPath is a local regular file whose SHA-512 is the deployable
	// hash of the product (image, archive, firmware). Empty when unknown.
	ArtifactPath                    string
	Executable, Archive, Structured bool
	// DefaultName is used when no --product-name is given (already validated
	// by the handler as a safe component name). May be empty.
	DefaultName, DefaultVersion string
}

// OutputFile is an extra output published next to the SBOM, e.g. a separate
// CycloneDX VEX file. Its content is never merged into the SBOM.
type OutputFile struct {
	Name string
	Data []byte
}

// Prepared is what a handler hands to the shared pipeline.
type Prepared struct {
	RawCDX []byte
	// ScanType "rootfs" turns on embedded version-string detection.
	ScanType string
	// ScanRoot is the local directory the engine scanned, when there is one.
	// The TR layer reads lockfiles and hashes cataloged binaries below it.
	ScanRoot string
	Root     RootHint
	Graph    GraphSource
	// SerialNumber, when set (urn:uuid:...), becomes the SBOM's serialNumber,
	// so a sidecar can point into the SBOM with a BOM-Link.
	SerialNumber string
	Sidecars     []OutputFile
	// Firmware is set only by the firmware-image handler.
	Firmware *FirmwareInfo
	// Provenance is recorded under provenance.json "extensions"[target type].
	Provenance map[string]any
	// Warnings are copied into quality.json.
	Warnings []string
	// Notices are printed on the console after the output is written.
	Notices []string
}

// Env is what handlers and subcommands get from the CLI.
type Env struct {
	Engine EngineRunner
	Now    func() time.Time
	Stdout io.Writer
}

// EngineRunner runs the authenticated, pinned Syft binary.
type EngineRunner interface {
	// Scan runs syft scan <source>:<target> and returns CycloneDX 1.6 JSON.
	Scan(ctx context.Context, binary, target, source string) ([]byte, error)
	// Convert runs syft convert <inputFile> and returns CycloneDX 1.6 JSON.
	Convert(ctx context.Context, binary, inputFile string) ([]byte, error)
}

// Subcommand is one cracken-sbom <name>. Default marks the one that runs
// when cracken-sbom is called without arguments; at most one may exist.
type Subcommand struct {
	Name    string
	Default bool
	Summary string
	Run     func(ctx context.Context, args []string, env Env) error
}

// EngineLocator finds a Syft binary when --syft is omitted. The result is
// still copied and verified against engine-manifest.json before use.
type EngineLocator func() (path string, ok bool)

var registryNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type extensionRegistry struct {
	byName map[string]Extension
}

var defaultRegistry = &extensionRegistry{byName: map[string]Extension{}}

// Register adds an extension. Call it only from init functions. It panics on
// an invalid or duplicate extension, target type or subcommand name, or on a
// second default subcommand: these are programming errors.
func Register(ext Extension) {
	if err := defaultRegistry.register(ext); err != nil {
		panic(err)
	}
}

func (r *extensionRegistry) register(ext Extension) error {
	if !registryNamePattern.MatchString(ext.Name) {
		return fmt.Errorf("invalid extension name %q", ext.Name)
	}
	if _, exists := r.byName[ext.Name]; exists {
		return fmt.Errorf("duplicate extension %q", ext.Name)
	}
	targets, commands, flags := map[string]bool{}, map[string]bool{}, map[string]bool{}
	hasDefault := false
	for _, existing := range r.byName {
		for _, t := range existing.Targets {
			targets[t.Type()] = true
			for _, f := range t.Flags() {
				flags[f.Name] = true
			}
		}
		for _, c := range existing.Subcommands {
			commands[c.Name] = true
			hasDefault = hasDefault || c.Default
		}
	}
	for _, t := range ext.Targets {
		if t == nil || !registryNamePattern.MatchString(t.Type()) || targets[t.Type()] {
			return fmt.Errorf("invalid or duplicate target type in extension %q", ext.Name)
		}
		targets[t.Type()] = true
		for _, f := range t.Flags() {
			if !registryNamePattern.MatchString(f.Name) || flags[f.Name] || builtinFlagNames[f.Name] {
				return fmt.Errorf("invalid or duplicate flag %q in extension %q", f.Name, ext.Name)
			}
			flags[f.Name] = true
		}
	}
	for _, c := range ext.Subcommands {
		if !registryNamePattern.MatchString(c.Name) || commands[c.Name] || c.Run == nil {
			return fmt.Errorf("invalid or duplicate subcommand in extension %q", ext.Name)
		}
		commands[c.Name] = true
		if c.Default {
			if hasDefault {
				return fmt.Errorf("second default subcommand in extension %q", ext.Name)
			}
			hasDefault = true
		}
	}
	for _, l := range ext.EngineLocators {
		if l == nil {
			return fmt.Errorf("nil engine locator in extension %q", ext.Name)
		}
	}
	r.byName[ext.Name] = ext
	return nil
}

// extensions returns all registered extensions sorted by name.
func (r *extensionRegistry) extensions() []Extension {
	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Extension, 0, len(names))
	for _, name := range names {
		out = append(out, r.byName[name])
	}
	return out
}

func (r *extensionRegistry) target(name string) (TargetHandler, bool) {
	for _, ext := range r.extensions() {
		for _, t := range ext.Targets {
			if t.Type() == name {
				return t, true
			}
		}
	}
	return nil, false
}

func (r *extensionRegistry) targetTypes() []string {
	out := []string{}
	for _, ext := range r.extensions() {
		for _, t := range ext.Targets {
			out = append(out, t.Type())
		}
	}
	sort.Strings(out)
	return out
}

func (r *extensionRegistry) subcommand(name string) (Subcommand, bool) {
	for _, ext := range r.extensions() {
		for _, c := range ext.Subcommands {
			if c.Name == name {
				return c, true
			}
		}
	}
	return Subcommand{}, false
}

func (r *extensionRegistry) defaultSubcommand() (Subcommand, bool) {
	for _, ext := range r.extensions() {
		for _, c := range ext.Subcommands {
			if c.Default {
				return c, true
			}
		}
	}
	return Subcommand{}, false
}

func (r *extensionRegistry) subcommandNames() []string {
	out := []string{}
	for _, ext := range r.extensions() {
		for _, c := range ext.Subcommands {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (r *extensionRegistry) engineLocators() []EngineLocator {
	out := []EngineLocator{}
	for _, ext := range r.extensions() {
		out = append(out, ext.EngineLocators...)
	}
	return out
}

// allExtraFlags lists every target-owned flag with the target type owning it.
func (r *extensionRegistry) allExtraFlags() map[string]struct {
	Owner string
	Flag  ExtraFlag
} {
	out := map[string]struct {
		Owner string
		Flag  ExtraFlag
	}{}
	for _, ext := range r.extensions() {
		for _, t := range ext.Targets {
			for _, f := range t.Flags() {
				out[f.Name] = struct {
					Owner string
					Flag  ExtraFlag
				}{t.Type(), f}
			}
		}
	}
	return out
}
