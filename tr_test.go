package main

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func trDocument(t *testing.T, raw string) (map[string]any, map[string]*componentHints, Quality) {
	t.Helper()
	doc, hints, q, err := normalizeDocument([]byte(raw), testContext())
	if err != nil {
		t.Fatal(err)
	}
	return doc, hints, q
}

const trGraphRaw = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"bom-ref":"a","type":"library","name":"app","version":"1","licenses":[{"license":{"id":"MIT"}}],"author":"Jane Doe <jane@example.org> (https://example.org/jane)"},
 {"bom-ref":"b","type":"library","name":"lib","version":"2","licenses":[{"expression":"MIT OR Apache-2.0"}]},
 {"bom-ref":"c","type":"library","name":"leaf","version":"3"},
 {"bom-ref":"d","type":"library","name":"loop1","version":"1"},
 {"bom-ref":"e","type":"library","name":"loop2","version":"1"}],
 "dependencies":[{"ref":"a","dependsOn":["b"]},{"ref":"b","dependsOn":["c"]},{"ref":"d","dependsOn":["e"]},{"ref":"e","dependsOn":["d"]}]}`

func componentsByName(doc map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, v := range doc["components"].([]any) {
		c := v.(map[string]any)
		out[c["name"].(string)] = c
	}
	return out
}

func dependencyMap(doc map[string]any) map[string][]string {
	out := map[string][]string{}
	for _, v := range doc["dependencies"].([]any) {
		d := v.(map[string]any)
		edges := []string{}
		for _, e := range d["dependsOn"].([]any) {
			edges = append(edges, e.(string))
		}
		out[d["ref"].(string)] = edges
	}
	return out
}

func TestTRDependenciesCoverEveryComponentAndReachCycles(t *testing.T) {
	doc, hints, q := trDocument(t, trGraphRaw)
	if err := applyTR(doc, hints, &Prepared{Graph: GraphPartial, Root: RootHint{Type: "application"}}, generateOptions{targetID: "r1"}, &q); err != nil {
		t.Fatal(err)
	}
	byName := componentsByName(doc)
	ref := func(n string) string { return byName[n]["bom-ref"].(string) }
	deps := dependencyMap(doc)
	// app is the only component nothing depends on; the cycle is reached too.
	if !reflect.DeepEqual(deps[productRef], []string{ref("app"), ref("loop1")}) {
		t.Fatalf("product direct dependencies: %v", deps[productRef])
	}
	if edges, ok := deps[ref("leaf")]; !ok || len(edges) != 0 {
		t.Fatal("leaf needs an empty dependency entry")
	}
	comp := doc["compositions"].([]any)[0].(map[string]any)
	if comp["aggregate"] != "incomplete" || q.GraphCompleteness != "incomplete" {
		t.Fatal("engine graph without lockfile must be incomplete")
	}
}

func TestTRCompositionAggregates(t *testing.T) {
	for graph, want := range map[GraphSource]string{GraphLockfile: "complete", GraphPartial: "incomplete", GraphUnknown: "unknown"} {
		doc, hints, q := trDocument(t, trGraphRaw)
		if err := applyTR(doc, hints, &Prepared{Graph: graph, Root: RootHint{Type: "application"}}, generateOptions{targetID: "r1"}, &q); err != nil {
			t.Fatal(err)
		}
		if got := doc["compositions"].([]any)[0].(map[string]any)["aggregate"]; got != want {
			t.Errorf("graph %d: aggregate %v, want %s", graph, got, want)
		}
	}
	// A lockfile claim without any engine graph is downgraded to unknown.
	doc, hints, q := trDocument(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"x","version":"1"}]}`)
	if err := applyTR(doc, hints, &Prepared{Graph: GraphLockfile}, generateOptions{targetID: "r1"}, &q); err != nil {
		t.Fatal(err)
	}
	if doc["compositions"].([]any)[0].(map[string]any)["aggregate"] != "unknown" {
		t.Fatal("complete claimed without a graph")
	}
}

func TestTRLicencesCreatorsAndProductFacts(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "product-1.0.bin")
	if os.WriteFile(artifact, []byte("deployable"), 0600) != nil {
		t.Fatal("artifact")
	}
	sum := sha512.Sum512([]byte("deployable"))
	for _, conclude := range []bool{false, true} {
		doc, hints, q := trDocument(t, trGraphRaw)
		o := generateOptions{targetID: "r1", tr: trOptions{
			ProductName: "product", ProductVersion: "1.0", ProductLicense: "Apache-2.0",
			ManufacturerName: "Example GmbH", ManufacturerEmail: "sbom@example.com",
			Artifact: artifact, ConcludeLicenses: conclude, ComponentContacts: conclude,
		}}
		if err := applyTR(doc, hints, &Prepared{Graph: GraphPartial, Root: RootHint{Type: "firmware", Executable: true}}, o, &q); err != nil {
			t.Fatal(err)
		}
		want := map[bool]string{false: "declared", true: "concluded"}[conclude]
		byName := componentsByName(doc)
		if byName["app"]["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)["acknowledgement"] != want ||
			byName["lib"]["licenses"].([]any)[0].(map[string]any)["acknowledgement"] != want {
			t.Fatalf("acknowledgement must be %s", want)
		}
		creator := byName["app"]["manufacturer"].(map[string]any)
		if creator["name"] != "Jane Doe" {
			t.Fatalf("creator name: %v", creator)
		}
		if _, hasContact := creator["contact"]; hasContact != conclude {
			t.Fatal("creator contacts must follow --component-contacts")
		}
		meta := doc["metadata"].(map[string]any)
		if !reflect.DeepEqual(meta["manufacturer"], map[string]any{"name": "Example GmbH", "contact": []any{map[string]any{"email": "sbom@example.com"}}}) {
			t.Fatalf("SBOM creator: %v", meta["manufacturer"])
		}
		root := meta["component"].(map[string]any)
		ext := root["externalReferences"].([]any)[0].(map[string]any)
		if root["name"] != "product" || ext["url"] != "product-1.0.bin" || ext["hashes"].([]any)[0].(map[string]any)["content"] != hex.EncodeToString(sum[:]) {
			t.Fatalf("product root: %v", root)
		}
		if root["licenses"].([]any)[0].(map[string]any)["acknowledgement"] != "concluded" {
			t.Fatal("product licence must be concluded")
		}
		if !strings.HasPrefix(doc["serialNumber"].(string), "urn:uuid:") || doc["specVersion"] != "1.6" {
			t.Fatal("serial number or spec version")
		}
		for _, c := range append([]map[string]any{root}, byName["app"], byName["leaf"]) {
			counts := map[string]int{}
			for _, p := range c["properties"].([]any) {
				counts[p.(map[string]any)["name"].(string)]++
			}
			if counts[bsiExecutable] != 1 || counts[bsiArchive] != 1 || counts[bsiStructured] != 1 || counts[bsiFilename] > 1 {
				t.Fatalf("BSI properties must occur exactly once: %v", counts)
			}
		}
	}
}

func TestTRHashesCatalogedBinaryInsideRootOnly(t *testing.T) {
	root := t.TempDir()
	if os.MkdirAll(filepath.Join(root, "bin"), 0700) != nil || os.WriteFile(filepath.Join(root, "bin", "busybox"), []byte("ELF"), 0700) != nil {
		t.Fatal("fixture")
	}
	outside := filepath.Join(t.TempDir(), "host-binary")
	_ = os.WriteFile(outside, []byte("host"), 0700)
	_ = os.Symlink(outside, filepath.Join(root, "bin", "escape"))
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
	 {"type":"application","name":"busybox","version":"1.36.1","properties":[{"name":"syft:package:foundBy","value":"binary-classifier-cataloger"},{"name":"syft:location:0:path","value":"/bin/busybox"}]},
	 {"type":"application","name":"escape","version":"1","properties":[{"name":"syft:package:foundBy","value":"binary-classifier-cataloger"},{"name":"syft:location:0:path","value":"/bin/escape"}]},
	 {"type":"library","name":"traversal","version":"1","properties":[{"name":"syft:package:foundBy","value":"binary-classifier-cataloger"},{"name":"syft:location:0:path","value":"/../host-binary"}]}]}`
	doc, hints, q := trDocument(t, raw)
	if err := applyTR(doc, hints, &Prepared{ScanRoot: root, Root: RootHint{Type: "firmware"}}, generateOptions{targetID: "r1"}, &q); err != nil {
		t.Fatal(err)
	}
	byName := componentsByName(doc)
	sum := sha512.Sum512([]byte("ELF"))
	refs, _ := byName["busybox"]["externalReferences"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["hashes"].([]any)[0].(map[string]any)["content"] != hex.EncodeToString(sum[:]) {
		t.Fatal("cataloged binary SHA-512 missing")
	}
	for _, name := range []string{"escape", "traversal"} {
		if _, has := byName[name]["externalReferences"]; has {
			t.Fatalf("%s: file outside the scanned root was hashed", name)
		}
	}
	filename := ""
	for _, p := range byName["busybox"]["properties"].([]any) {
		if p.(map[string]any)["name"] == bsiFilename {
			filename = p.(map[string]any)["value"].(string)
		}
	}
	if filename != "busybox" {
		t.Fatalf("binary file name: %q", filename)
	}
	if q.SHA512Components != 1 || q.FilenameComponents != 1 {
		t.Fatalf("quality counts: %+v", q)
	}
}

func TestTROptionsValidation(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "meta.json")
	_ = os.WriteFile(meta, []byte(`{"product":{"name":"p","version":"1"},"manufacturer":{"email":"a@example.com"}}`), 0600)
	got, err := resolveTROptions(trOptions{MetadataFile: meta, ProductVersion: "2"})
	if err != nil || got.ProductName != "p" || got.ProductVersion != "2" || got.ManufacturerEmail != "a@example.com" {
		t.Fatalf("metadata merge: %+v %v", got, err)
	}
	unknown := filepath.Join(dir, "unknown.json")
	_ = os.WriteFile(unknown, []byte(`{"product":{"name":"p"},"token":"x"}`), 0600)
	for name, o := range map[string]trOptions{
		"unknown metadata field": {MetadataFile: unknown},
		"bad email":              {ManufacturerEmail: "not-an-email"},
		"url with credentials":   {ManufacturerURL: "https://user:pw@example.com"},
		"url with query":         {ManufacturerURL: "https://example.com/?token=1"},
		"non-http url":           {ManufacturerURL: "ftp://example.com"},
		"path as product name":   {ProductName: "/home/alex/secret"},
		"bad licence":            {ProductLicense: "see LICENSE file"},
		"missing artifact":       {Artifact: filepath.Join(dir, "missing.bin")},
	} {
		if _, err := resolveTROptions(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseCreator(t *testing.T) {
	for in, want := range map[string]creatorFacts{
		"Jane Doe <jane@example.org> (https://example.org)": {Name: "Jane Doe", Email: "jane@example.org", URL: "https://example.org"},
		"Debian Maintainers <debian@lists.example>":         {Name: "Debian Maintainers", Email: "debian@lists.example"},
		"solo@example.com":                  {Email: "solo@example.com"},
		"Bad (https://user:pw@example.com)": {Name: "Bad"},
		"/home/alex/path <x@y.zz>":          {Email: "x@y.zz"},
	} {
		if got := parseCreator(in); got != want {
			t.Errorf("parseCreator(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestBSIClassificationFollowsTable7(t *testing.T) {
	for name, tc := range map[string]struct {
		componentType, foundBy string
		want                   [3]bool
	}{
		"rpm-like package":   {"library", "dpkg-db-cataloger", [3]bool{false, true, true}},
		"classified binary":  {"application", "binary-classifier-cataloger", [3]bool{true, false, false}},
		"embedded library":   {"library", "cracken-embedded-version-detector", [3]bool{true, false, false}},
		"go build info":      {"library", "go-module-binary-cataloger", [3]bool{true, false, true}},
		"java archive":       {"library", "java-archive-cataloger", [3]bool{true, true, true}},
		"operating system":   {"operating-system", "", [3]bool{false, false, true}},
		"npm lockfile entry": {"library", "javascript-lock-cataloger", [3]bool{false, true, true}},
	} {
		e, a, s := bsiClassification(tc.componentType, &componentHints{FoundBy: tc.foundBy})
		if [3]bool{e, a, s} != tc.want {
			t.Errorf("%s: got %v", name, [3]bool{e, a, s})
		}
	}
}

func TestValidSPDXExpression(t *testing.T) {
	for _, ok := range []string{"MIT", "Apache-2.0 OR MIT", "(MIT AND BSD-3-Clause) OR GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0+", "LicenseRef-acme-proprietary"} {
		if !validSPDXExpression(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"see LICENSE file", "MIT MIT", "MIT AND", "(MIT", "MIT)", "AND MIT", "Proprietary"} {
		if validSPDXExpression(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
