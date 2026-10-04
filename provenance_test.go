package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProvenanceBindsExactFinalBytes(t *testing.T) {
	out, q, err := normalizeSBOM(encodeTest(t, testDocument(testPackage("hello"))), testContext())
	if err != nil {
		t.Fatal(err)
	}
	p, err := createProvenance(out, testContext(), q)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(p, &got); err != nil {
		t.Fatal(err)
	}
	if got["sbom_sha256"] != sha256Hex(out) || got["sbom_sha256"] == sha256Hex(out[:len(out)-1]) {
		t.Fatal("digest not bound to exact output bytes")
	}
	if strings.Contains(string(out), sha256Hex(out)) {
		t.Fatal("self-referential digest in SBOM")
	}
	if got["generated_at"] != "2026-10-04T11:14:15Z" || got["provenance_status"] != "customer_asserted_local" {
		t.Fatal("false provenance claim or time")
	}
	ctx := testContext()
	ctx.ConfigDigest = strings.Repeat("b", 64)
	changed, _, err := normalizeSBOM(encodeTest(t, testDocument(testPackage("hello"))), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sha256Hex(changed) == sha256Hex(out) {
		t.Fatal("configuration not bound to output")
	}
}

func TestProvenanceCarriesLicenseCoverageQuality(t *testing.T) {
	quality := Quality{MissingLicenses: 2, ConvertedLicenseIDs: 1, OmittedLicenseChoices: 3}
	p, err := createProvenance([]byte("{}\n"), testContext(), quality)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Quality Quality `json:"quality"`
	}
	if err := json.Unmarshal(p, &got); err != nil {
		t.Fatal(err)
	}
	if got.Quality.MissingLicenses != 2 || got.Quality.ConvertedLicenseIDs != 1 || got.Quality.OmittedLicenseChoices != 3 {
		t.Fatalf("license coverage quality missing from provenance: %+v", got.Quality)
	}
}

func TestContextCannotLeakPathsOrCredentials(t *testing.T) {
	for _, id := range []string{"/home/customer/secret", "https://user:canary@host.invalid", "password=canary", "../../root", "C:\\private", "release\nsecret"} {
		ctx := testContext()
		ctx.TargetIdentifier = id
		if _, err := createProvenance([]byte("{}"), ctx, Quality{}); err == nil {
			t.Fatalf("unsafe target accepted: %q", id)
		}
		if _, _, err := normalizeSBOM(encodeTest(t, testDocument(testPackage("hello"))), ctx); err == nil {
			t.Fatal("unsafe embedded target accepted")
		}
	}
	ctx := testContext()
	ctx.ConfigDigest = "not-a-digest"
	if _, err := createProvenance([]byte("{}"), ctx, Quality{}); err == nil {
		t.Fatal("invalid config accepted")
	}
	ctx = testContext()
	ctx.EngineVersion = "https://canary.invalid"
	if _, err := createProvenance([]byte("{}"), ctx, Quality{}); err == nil {
		t.Fatal("unsafe version accepted")
	}
	ctx = testContext()
	ctx.GeneratedAt = "yesterday"
	if _, err := createProvenance([]byte("{}"), ctx, Quality{}); err == nil {
		t.Fatal("invalid timestamp accepted")
	}
}
