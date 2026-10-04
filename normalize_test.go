package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func testContext() ProvenanceContext {
	return ProvenanceContext{ToolVersion: "0.1.0", EngineVersion: "1.54.0", ConfigDigest: strings.Repeat("a", 64), TargetType: "rootfs", TargetIdentifier: "firmware-2026.10", GeneratedAt: "2026-10-04T13:14:15+02:00"}
}

func encodeTest(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testDocument(components ...any) map[string]any {
	return map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
}
func testPackage(name string) map[string]any {
	return map[string]any{"type": "library", "name": name, "version": "1.2.3", "licenses": []any{map[string]any{"license": map[string]any{"id": "MIT"}}}}
}

func TestNormalizeEmptyEngineDocumentWithoutComponents(t *testing.T) {
	input := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)
	output, _, err := normalizeSBOM(input, testContext())
	if err == nil || !strings.Contains(err.Error(), "empty_sbom") || output != nil {
		t.Fatal("valid empty engine document must fail as empty_sbom")
	}
}

func TestNormalizeMixedLicenseChoicesDisclosesEveryOmission(t *testing.T) {
	c := testPackage("licensed-package")
	c["licenses"] = []any{map[string]any{"license": map[string]string{"id": "MIT"}}, map[string]any{"license": map[string]string{"name": "Proprietary"}}}
	out, quality, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
	if err != nil || len(out) == 0 || quality.AmbiguousLicenses != 1 {
		t.Fatalf("mixed license choices were not identified: %+v, %v", quality, err)
	}
	if !strings.Contains(strings.Join(quality.Warnings, " "), "license choice") {
		t.Fatal("a surviving SPDX identifier must not hide an omitted choice")
	}
	if strings.Contains(string(out), "Proprietary") {
		t.Fatal("free-text license retained")
	}
}

func TestNormalizePreservesNewerSPDXIDsOutsideOutputSchemaAsExpressions(t *testing.T) {
	for _, id := range []string{"Unicode-3.0", "FSL-1.1-MIT", "BSD-3-Clause-OpenWebUI"} {
		c := testPackage("licensed-package")
		c["licenses"] = []any{map[string]any{"license": map[string]string{"id": id}}}
		out, quality, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
		if err != nil || out == nil || quality.ConvertedLicenseIDs != 1 {
			t.Fatalf("safe newer SPDX identifier was not retained: quality=%+v err=%v", quality, err)
		}
		var result map[string]any
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatal(err)
		}
		licenses := result["components"].([]any)[0].(map[string]any)["licenses"].([]any)
		if licenses[0].(map[string]any)["expression"] != id {
			t.Fatalf("newer SPDX identifier not preserved as an expression: %v", licenses)
		}
		if !strings.Contains(strings.Join(quality.Warnings, " "), "preserved as a license expression") {
			t.Fatal("SPDX identifier conversion was not disclosed")
		}
	}
}

func TestNormalizeKeepsCycloneDXLicenseChoicesSchemaCompatible(t *testing.T) {
	cases := []struct {
		name            string
		choices         []any
		wantLicenses    []any
		convertedIDs    int
		omittedChoices  int
		missingLicenses int
	}{
		{
			name: "multiple newer identifiers are omitted",
			choices: []any{
				map[string]any{"license": map[string]string{"id": "Unicode-3.0"}},
				map[string]any{"license": map[string]string{"id": "FSL-1.1-MIT"}},
			},
			convertedIDs: 0, omittedChoices: 2, missingLicenses: 1,
		},
		{
			name: "multiple expressions are omitted",
			choices: []any{
				map[string]string{"expression": "MIT"},
				map[string]string{"expression": "Apache-2.0"},
			},
			convertedIDs: 0, omittedChoices: 2, missingLicenses: 1,
		},
		{
			name: "known license survives newer identifier",
			choices: []any{
				map[string]any{"license": map[string]string{"id": "MIT"}},
				map[string]any{"license": map[string]string{"id": "Unicode-3.0"}},
			},
			wantLicenses: []any{map[string]any{"license": map[string]any{"id": "MIT"}}},
			convertedIDs: 0, omittedChoices: 1, missingLicenses: 0,
		},
		{
			name: "known license survives explicit expression",
			choices: []any{
				map[string]any{"license": map[string]string{"id": "MIT"}},
				map[string]string{"expression": "Apache-2.0"},
			},
			wantLicenses: []any{map[string]any{"license": map[string]any{"id": "MIT"}}},
			convertedIDs: 0, omittedChoices: 1, missingLicenses: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testPackage("license-choices")
			c["licenses"] = tc.choices
			out, quality, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}
			got := result["components"].([]any)[0].(map[string]any)["licenses"]
			if tc.wantLicenses == nil {
				if got != nil {
					t.Fatalf("incompatible license choices were not omitted: %v", got)
				}
			} else if !reflect.DeepEqual(got, tc.wantLicenses) {
				t.Fatalf("known license choice was not preserved: got %v, want %v", got, tc.wantLicenses)
			}
			if quality.ConvertedLicenseIDs != tc.convertedIDs || quality.OmittedLicenseChoices != tc.omittedChoices || quality.MissingLicenses != tc.missingLicenses {
				t.Fatalf("incorrect license quality counts: %+v", quality)
			}
			if tc.omittedChoices > 0 && !strings.Contains(strings.Join(quality.Warnings, " "), "omitted") {
				t.Fatal("omitted license choices were not disclosed")
			}
		})
	}
}

func TestNormalizeReportsMissingLicenseCoverageWithoutRejectingPackage(t *testing.T) {
	c := testPackage("license-missing")
	delete(c, "licenses")
	out, quality, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
	if err != nil || len(out) == 0 || quality.MissingLicenses != 1 {
		t.Fatalf("missing license coverage should be advisory: quality=%+v err=%v", quality, err)
	}
	if !strings.Contains(strings.Join(quality.Warnings, " "), "license coverage is incomplete") {
		t.Fatal("missing license coverage was not disclosed")
	}
}

func TestNormalizeSupportsPackageNamespacesWithoutLocalPaths(t *testing.T) {
	for _, name := range []string{"github.com/example/module", "symfony/console", "@scope/name", "@scope/name/child"} {
		out, _, err := normalizeSBOM(encodeTest(t, testDocument(testPackage(name))), testContext())
		if err != nil || !strings.Contains(string(out), name) {
			t.Fatalf("valid package namespace rejected: %v", err)
		}
	}
	for _, name := range []string{"home/customer/x", "Users/customer/x", "usr/bin/app", "tmp/work/pkg", "scope/@secret/package"} {
		out, _, err := normalizeSBOM(encodeTest(t, testDocument(testPackage(name))), testContext())
		if err == nil || out != nil {
			t.Fatal("local path accepted as package namespace")
		}
	}
}

func TestNormalizeFlattenPrivacyAndGraph(t *testing.T) {
	parent := testPackage("@scope/parent")
	parent["bom-ref"] = "/Users/private/token=canary-parent"
	child := testPackage("child")
	child["bom-ref"] = "/home/customer/child"
	child["purl"] = "pkg:npm/%40scope/child@1.2.3?arch=arm64&download_url=https%3A%2F%2Fsecret.invalid%2Ftoken%3Dcanary&file_path=%2Fhome%2Fcustomer"
	child["supplier"] = map[string]any{"name": "Package Author", "url": []string{"https://canary.invalid"}, "contact": []any{map[string]string{"email": "canary@example.invalid"}}}
	child["hashes"] = []any{map[string]string{"alg": "SHA-256", "content": strings.Repeat("b", 64)}}
	child["properties"] = []any{map[string]string{"name": "token", "value": "canary-arbitrary-property"}}
	child["evidence"] = map[string]any{"occurrences": []any{map[string]string{"location": "/canary/location"}}}
	parent["components"] = []any{child, map[string]string{"type": "file", "name": "/canary/file", "bom-ref": "file-ref"}}
	doc := testDocument(parent)
	doc["metadata"] = map[string]any{"component": map[string]string{"name": "canary-root"}, "properties": []any{map[string]string{"name": "canary", "value": "secret"}}}
	doc["dependencies"] = []any{map[string]any{"ref": parent["bom-ref"], "dependsOn": []string{child["bom-ref"].(string), "file-ref", "missing"}}, map[string]any{"ref": child["bom-ref"], "dependsOn": []string{}}}
	out, q, err := normalizeSBOM(encodeTest(t, doc), testContext())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "canary") || strings.Contains(string(out), "/Users/") || strings.Contains(string(out), "/home/") || strings.Contains(string(out), "download_url") {
		t.Fatalf("private data survived: %s", out)
	}
	if q.InputComponents != 3 || q.EmittedComponents != 2 || q.RemovedFiles != 1 {
		t.Fatalf("wrong counts: %+v", q)
	}
	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	cs := result["components"].([]any)
	c := cs[1].(map[string]any)
	if _, exists := cs[0].(map[string]any)["components"]; exists {
		t.Fatal("output is nested")
	}
	if c["purl"] != "pkg:npm/%40scope/child@1.2.3?arch=arm64" {
		t.Fatalf("bad purl: %v", c["purl"])
	}
	if c["supplier"].(map[string]any)["name"] != "Package Author" || c["hashes"] == nil {
		t.Fatal("identity evidence lost")
	}
	deps := result["dependencies"].([]any)[0].(map[string]any)
	if deps["ref"] != "component-1" || len(deps["dependsOn"].([]any)) != 1 || deps["dependsOn"].([]any)[0] != "component-2" {
		t.Fatalf("bad graph: %+v", deps)
	}
	if !strings.Contains(strings.Join(q.Warnings, " "), "graph coverage") {
		t.Fatal("unresolved graph not disclosed")
	}
	if result["metadata"].(map[string]any)["timestamp"] != "2026-10-04T11:14:15Z" {
		t.Fatal("timestamp not UTC")
	}
}

func TestNormalizePreservesLicenseExpressionAndUnknownVersion(t *testing.T) {
	c := testPackage("package")
	delete(c, "version")
	c["licenses"] = []any{map[string]string{"expression": "MIT OR Apache-2.0"}}
	out, q, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
	if err != nil {
		t.Fatal(err)
	}
	if q.MissingVersions != 1 || q.AmbiguousLicenses != 0 || strings.Contains(string(out), `"version": "UNKNOWN"`) || !strings.Contains(string(out), "MIT OR Apache-2.0") {
		t.Fatalf("version or licenses changed: %s %+v", out, q)
	}
	c["licenses"] = []any{map[string]any{"license": map[string]string{"id": "MIT"}}, map[string]any{"license": map[string]string{"id": "Apache-2.0"}}}
	_, q, err = normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
	if err != nil || q.AmbiguousLicenses != 1 {
		t.Fatalf("ambiguity not flagged: %+v %v", q, err)
	}
}

func TestNormalizeRejectsMalformedAndSecrets(t *testing.T) {
	cases := map[string][]byte{"json": []byte("{"), "trailing": []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]} {}`), "empty": encodeTest(t, testDocument()), "unsupported": []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`), "bad_inventory": []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":{}}`)}
	for _, field := range []string{"name", "group", "version", "cpe"} {
		c := testPackage("good")
		c[field] = "https://user:token-canary@host.invalid/path"
		cases[field] = encodeTest(t, testDocument(c))
	}
	for _, name := range []string{"/home/customer/private", "../private", `C:\private\file`, "password=canary-secret", "good\u202Eprivate"} {
		c := testPackage(name)
		cases[name] = encodeTest(t, testDocument(c))
	}
	for _, purl := range []string{"pkg:npm/user:canary-secret@private", "pkg:generic/%2Fhome%2Fcustomer", "pkg:generic/home/customer", "pkg:npm/name@1?arch=%2Fhome%2Fcustomer", "https://token-canary@host.invalid", "pkg:npm/name@1#home/customer"} {
		c := testPackage("good")
		c["purl"] = purl
		cases[purl] = encodeTest(t, testDocument(c))
	}
	c := testPackage("good")
	delete(c, "name")
	cases["missing_name"] = encodeTest(t, testDocument(c))
	c = testPackage("good")
	c["hashes"] = []any{map[string]string{"alg": "SHA-256", "content": "token-canary"}}
	cases["bad_hash"] = encodeTest(t, testDocument(c))
	a, b := testPackage("a"), testPackage("b")
	a["bom-ref"] = "duplicate"
	b["bom-ref"] = "duplicate"
	cases["duplicate_ref"] = encodeTest(t, testDocument(a, b))
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := normalizeSBOM(input, testContext())
			if err == nil {
				t.Fatal("unsafe input accepted")
			}
			if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "/home/") {
				t.Fatal("error leaked rejected value")
			}
		})
	}
}

func TestNormalizePreservesCPEAndPURLNamespaces(t *testing.T) {
	for _, purl := range []string{"pkg:maven/org.example/library@2.0?type=jar", "pkg:deb/debian/libc6@2.36?arch=arm64&distro=debian-12", "pkg:pypi/requests@2.32.0", "pkg:golang/github.com/example/package@1.0", "pkg:deb/debian/libc6@2.36?arch=arm64&upstream=glibc"} {
		c := testPackage("good")
		c["purl"] = purl
		c["cpe"] = "cpe:2.3:a:example:good:1.2.3:*:*:*:*:*:*:*"
		if _, _, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext()); err != nil {
			t.Fatalf("valid identity rejected %s: %v", purl, err)
		}
	}
}

func TestNormalizePreservesSafeUpstreamPURLQualifier(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{
			input: "pkg:deb/debian/libc6@2.36?arch=arm64&upstream=glibc",
			want:  "pkg:deb/debian/libc6@2.36?arch=arm64&upstream=glibc",
		},
		{
			input: "pkg:deb/debian/libc6@2.36?upstream=glibc%402.36",
			want:  "pkg:deb/debian/libc6@2.36?upstream=glibc%402.36",
		},
		{
			input: "pkg:deb/debian/libc6@2.36?upstream=glibc%401%3A2.36-1~deb12u1",
			want:  "pkg:deb/debian/libc6@2.36?upstream=glibc%401%3A2.36-1~deb12u1",
		},
	} {
		c := testPackage("libc6")
		c["purl"] = tc.input
		out, _, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
		if err != nil {
			t.Fatalf("safe upstream qualifier rejected: %v", err)
		}
		var result map[string]any
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatal(err)
		}
		got := result["components"].([]any)[0].(map[string]any)["purl"]
		if got != tc.want {
			t.Fatalf("upstream qualifier changed: got %v, want %s", got, tc.want)
		}
	}
}

func TestNormalizeRejectsUnsafeUpstreamAndNonUpstreamQualifiers(t *testing.T) {
	for _, purl := range []string{
		"pkg:deb/debian/libc6@2.36?upstream=glibc@",
		"pkg:deb/debian/libc6@2.36?upstream=%402.36",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%40%402.36",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%40C%3Aprivate",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%401%3A",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%402.36%2Fetc",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%402..36",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%40https%3A%2F%2Fsecret.invalid",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%40password%3Dcanary",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%402.36%3Fprivate",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%402.36%0Aprivate",
		"pkg:deb/debian/libc6@2.36?upstream=glibc%402.36%252Fetc",
		"pkg:deb/debian/libc6@2.36?upstream=source%2Fpath%402.36",
		"pkg:deb/debian/libc6@2.36?arch=arm64%40private&upstream=glibc",
		"pkg:deb/debian/libc6@2.36?arch=arm64%3Fprivate&upstream=glibc",
	} {
		c := testPackage("libc6")
		c["purl"] = purl
		if _, _, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext()); err == nil {
			t.Fatalf("unsafe qualifier accepted: %s", purl)
		}
	}
}

func TestNormalizeRootfsDebianEpochAndTildeVersions(t *testing.T) {
	for _, tc := range []struct{ name, version, purl string }{
		{"busybox", "1:1.35.0-4+b3", "pkg:deb/debian/busybox@1%3A1.35.0-4%2Bb3?arch=arm64&distro=debian-12"},
		{"libssl3", "3.0.11-1~deb12u2", "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=arm64&distro=debian-12"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testPackage(tc.name)
			c["version"], c["purl"] = tc.version, tc.purl
			out, q, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			got := doc["components"].([]any)[0].(map[string]any)
			if got["version"] != tc.version || got["purl"] != tc.purl || q.MissingVersions != 0 {
				t.Fatalf("rootfs package identity changed: %+v, quality %+v", got, q)
			}
		})
	}
	for _, unsafe := range []string{`C:\private\file`, "C:/private/file", "C:private", "%43%3Aprivate", "%43%3A%2Fprivate"} {
		c := testPackage("busybox")
		c["version"] = unsafe
		if _, _, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext()); err == nil {
			t.Fatal("Windows drive version was accepted")
		}
	}
}

func TestNormalizePreservesEscapedRootfsCPEs(t *testing.T) {
	for _, cpe := range []string{
		`cpe:2.3:a:auth0:jsonwebtoken:9.0.2:*:*:*:*:*:*:*`,
		`cpe:2.3:a:busybox:busybox:1\:1.35.0-4\+b3:*:*:*:*:*:*:*`,
		`cpe:2.3:a:libssl3:libssl3:3.0.11-1\~deb12u2:*:*:*:*:*:*:*`,
		`cpe:/a:busybox:busybox:1%3a1.35.0-4%2bb3`,
	} {
		c := testPackage("rootfs-package")
		c["cpe"] = cpe
		out, _, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext())
		if err != nil {
			t.Fatalf("valid CPE rejected: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		if got := doc["components"].([]any)[0].(map[string]any)["cpe"]; got != cpe {
			t.Fatalf("escaped CPE changed: %v", got)
		}
	}
	for _, cpe := range []string{
		`cpe:2.3:a:vendor:product:/home/private:*:*:*:*:*:*:*`,
		`cpe:2.3:a:vendor:product:\/home\/private:*:*:*:*:*:*:*`,
		`cpe:2.3:a:vendor:product:C\:\\private:*:*:*:*:*:*:*`,
		`cpe:2.3:a:vendor:product:token\=canary-secret:*:*:*:*:*:*:*`,
		`cpe:2.3:a:auth0:jsonwebtoken:token\=canary-secret:*:*:*:*:*:*:*`,
		`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*`,
		`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*:extra`,
		`cpe:/a:vendor:product:%2Fhome%2Fprivate`,
		`cpe:/a:vendor:product:%68%74%74%70%3A%2F%2Fsecret.invalid`,
	} {
		c := testPackage("rootfs-package")
		c["cpe"] = cpe
		if _, _, err := normalizeSBOM(encodeTest(t, testDocument(c)), testContext()); err == nil {
			t.Fatal("unsafe or malformed CPE accepted")
		}
	}
}

func TestNormalizeInventoryAndByteLimits(t *testing.T) {
	components := make([]any, maxComponents+1)
	for i := range components {
		components[i] = testPackage("pkg")
	}
	if _, _, err := normalizeSBOM(encodeTest(t, testDocument(components...)), testContext()); err == nil || !strings.Contains(err.Error(), "50000") {
		t.Fatalf("inventory limit not enforced: %v", err)
	}
	components = components[:12000]
	for i := range components {
		c := testPackage(strings.Repeat("a", 1000))
		components[i] = c
	}
	if _, _, err := normalizeSBOM(encodeTest(t, testDocument(components...)), testContext()); err == nil || !strings.Contains(err.Error(), "10 MiB") {
		t.Fatalf("byte limit not enforced: %v", err)
	}
}
