package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// testTarget is registered from init below, exactly as PR2/PR3 extensions
// register themselves from their own files.
type testTarget struct{}

const testVEX = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"vulnerabilities":[{"id":"CVE-2026-0001","analysis":{"state":"resolved"}}]}`

func (testTarget) Type() string                        { return "zz-test-target" }
func (testTarget) Kind() TargetKind                    { return TargetDirectory }
func (testTarget) Flags() []ExtraFlag                  { return []ExtraFlag{{Name: "zz-test-flag", Usage: "test only"}} }
func (testTarget) ConfigDigest() string                { return strings.Repeat("b", 64) }
func (testTarget) CheckOptions(*generateOptions) error { return nil }
func (testTarget) ResolvePaths(*generateOptions) error { return nil }
func (testTarget) Prepare(ctx context.Context, o generateOptions, env Env) (*Prepared, func(), error) {
	raw, err := env.Engine.Scan(ctx, o.syft, o.target, "dir")
	if err != nil {
		return nil, func() {}, err
	}
	return &Prepared{
		RawCDX: raw, ScanRoot: o.target, Graph: GraphPartial,
		Root:       RootHint{Type: "application", DefaultName: "zz-product", DefaultVersion: o.extra["zz-test-flag"]},
		Sidecars:   []OutputFile{{Name: "sbom.vex.cdx.json", Data: []byte(testVEX)}},
		Provenance: map[string]any{"flag": o.extra["zz-test-flag"]},
	}, func() {}, nil
}

var testInitCommandRan bool

func init() {
	Register(Extension{
		Name:    "zz-registry-test",
		Targets: []TargetHandler{testTarget{}},
		Subcommands: []Subcommand{{Name: "zz-test-cmd", Summary: "test only", Run: func(context.Context, []string, Env) error {
			testInitCommandRan = true
			return nil
		}}},
	})
}

func TestRegistrationFromInitIsVisibleAndSorted(t *testing.T) {
	if _, ok := defaultRegistry.target("zz-test-target"); !ok {
		t.Fatal("target registered from init is not visible")
	}
	if _, ok := defaultRegistry.target("rootfs"); !ok {
		t.Fatal("built-in target missing")
	}
	names := []string{}
	for _, ext := range defaultRegistry.extensions() {
		names = append(names, ext.Name)
	}
	if !reflect.DeepEqual(names, []string{"builtin", "zz-registry-test"}) {
		t.Fatalf("extensions not sorted by name: %v", names)
	}
	types := defaultRegistry.targetTypes()
	want := []string{"dir", "docker-archive", "firmware-image", "npm", "oci-archive", "python", "rootfs", "zz-test-target"}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("target types %v", types)
	}
	if err := runCLI(context.Background(), []string{"zz-test-cmd"}, &bytes.Buffer{}, nil, fixedNow); err != nil || !testInitCommandRan {
		t.Fatal("subcommand registered from init was not dispatched")
	}
}

func TestRegistryRejectsDuplicatesAndOrderIsIndependentOfRegistration(t *testing.T) {
	run := func(context.Context, []string, Env) error { return nil }
	a := Extension{Name: "alpha", Subcommands: []Subcommand{{Name: "one", Run: run}}}
	b := Extension{Name: "beta", Subcommands: []Subcommand{{Name: "two", Run: run, Default: true}}}
	forward, backward := &extensionRegistry{byName: map[string]Extension{}}, &extensionRegistry{byName: map[string]Extension{}}
	for _, r := range []struct {
		reg  *extensionRegistry
		exts []Extension
	}{{forward, []Extension{a, b}}, {backward, []Extension{b, a}}} {
		for _, ext := range r.exts {
			if err := r.reg.register(ext); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !reflect.DeepEqual(forward.subcommandNames(), backward.subcommandNames()) || forward.extensions()[0].Name != "alpha" || backward.extensions()[0].Name != "alpha" {
		t.Fatal("lookup order depends on registration order")
	}
	r := forward
	for name, ext := range map[string]Extension{
		"duplicate extension":  {Name: "alpha"},
		"duplicate subcommand": {Name: "gamma", Subcommands: []Subcommand{{Name: "one", Run: run}}},
		"second default":       {Name: "delta", Subcommands: []Subcommand{{Name: "three", Run: run, Default: true}}},
		"invalid name":         {Name: "Bad Name"},
		"nil run":              {Name: "eps", Subcommands: []Subcommand{{Name: "four"}}},
		"nil locator":          {Name: "zeta", EngineLocators: []EngineLocator{nil}},
		"duplicate target":     {Name: "eta", Targets: []TargetHandler{testTarget{}, testTarget{}}},
		"builtin flag name":    {Name: "theta", Targets: []TargetHandler{flagTarget{name: "syft"}}},
	} {
		if r.register(ext) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Register did not panic on a duplicate")
		}
	}()
	Register(builtinExtension)
}

type flagTarget struct {
	testTarget
	name string
}

func (f flagTarget) Type() string       { return "flag-target" }
func (f flagTarget) Flags() []ExtraFlag { return []ExtraFlag{{Name: f.name}} }

func TestDefaultSubcommandRunsWithoutArguments(t *testing.T) {
	old := defaultRegistry
	defer func() { defaultRegistry = old }()
	defaultRegistry = &extensionRegistry{byName: map[string]Extension{}}
	if err := runCLI(context.Background(), nil, &bytes.Buffer{}, nil, fixedNow); err == nil {
		t.Fatal("no arguments without a default subcommand must fail")
	}
	ran := false
	if err := defaultRegistry.register(Extension{Name: "detectish", Subcommands: []Subcommand{{Name: "detectish", Default: true, Run: func(_ context.Context, args []string, _ Env) error {
		ran = len(args) == 0
		return nil
	}}}}); err != nil {
		t.Fatal(err)
	}
	if err := runCLI(context.Background(), nil, &bytes.Buffer{}, nil, fixedNow); err != nil || !ran {
		t.Fatal("default subcommand did not run without arguments")
	}
}

func TestEngineLocatorFillsMissingSyftPath(t *testing.T) {
	old := defaultRegistry
	defer func() { defaultRegistry = old }()
	defaultRegistry = &extensionRegistry{byName: map[string]Extension{}}
	_ = defaultRegistry.register(builtinExtension)
	args, _ := cliFixture(t)
	withoutSyft := args[:len(args)-2]
	if _, err := parseOptions(withoutSyft[1:]); err == nil {
		t.Fatal("missing --syft accepted without a locator")
	}
	located := args[len(args)-1]
	_ = defaultRegistry.register(Extension{Name: "locator", EngineLocators: []EngineLocator{func() (string, bool) { return located, true }}})
	o, err := parseOptions(withoutSyft[1:])
	if err != nil || o.syft != located {
		t.Fatalf("locator not used: %v", err)
	}
}

func TestExtensionTargetFlagsSidecarsAndProvenance(t *testing.T) {
	args, output := cliFixture(t)
	args[2] = "zz-test-target"
	args = append(args, "--zz-test-flag", "7.1")
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	vex, err := os.ReadFile(filepath.Join(output, "sbom.vex.cdx.json"))
	if err != nil || string(vex) != testVEX {
		t.Fatal("sidecar not published unchanged")
	}
	sbom, _ := os.ReadFile(filepath.Join(output, "sbom.cdx.json"))
	if bytes.Contains(sbom, []byte("vulnerabilities")) || bytes.Contains(sbom, []byte("CVE-2026-0001")) {
		t.Fatal("sidecar content reached the SBOM")
	}
	var doc map[string]any
	_ = json.Unmarshal(sbom, &doc)
	root := doc["metadata"].(map[string]any)["component"].(map[string]any)
	if root["name"] != "zz-product" || root["version"] != "7.1" {
		t.Fatalf("extension flag or root hint lost: %v", root)
	}
	var p map[string]any
	data, _ := os.ReadFile(filepath.Join(output, "provenance.json"))
	_ = json.Unmarshal(data, &p)
	outputs, _ := p["extra_outputs"].([]any)
	if len(outputs) != 1 || outputs[0].(map[string]any)["sha256"] != sha256Hex([]byte(testVEX)) {
		t.Fatal("provenance does not bind the sidecar")
	}
	if p["extensions"].(map[string]any)["zz-test-target"].(map[string]any)["flag"] != "7.1" {
		t.Fatal("extension provenance missing")
	}
	// The flag belongs to its target type only.
	other, _ := cliFixture(t)
	if runCLI(context.Background(), append(other, "--zz-test-flag", "x"), &bytes.Buffer{}, successRunner, fixedNow) == nil {
		t.Fatal("target-owned flag accepted for another target type")
	}
}

func TestSidecarNamesCannotEscapeOrCollide(t *testing.T) {
	for _, name := range []string{"sbom.cdx.json", "quality.json", "../x.json", "a/b.json", "x.txt", ".hidden.json"} {
		if validSidecars("sbom.cdx.json", []OutputFile{{Name: name, Data: []byte("{}")}}) == nil {
			t.Errorf("sidecar name %q accepted", name)
		}
	}
	if validSidecars("sbom.cdx.json", []OutputFile{{Name: "sbom.vex.cdx.json", Data: []byte("not json")}}) == nil {
		t.Error("invalid JSON sidecar accepted")
	}
}
