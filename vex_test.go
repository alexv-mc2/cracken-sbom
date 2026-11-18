package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestExtractCvesFixedMatchesCrAcken(t *testing.T) {
	for in, want := range map[string][]string{
		"CVEs fixed: CVE-2022-28391 CVE-2022-30065":        {"CVE-2022-28391", "CVE-2022-30065"},
		"Patched. CVE fixed: cve-2023-1234, CVE-2023-5678": {"CVE-2023-1234", "CVE-2023-5678"},
		"no fixed CVEs recorded":                           nil,
		"CVEs fixed: CVE-20-1":                             {},
		"":                                                 nil,
	} {
		if got := extractCvesFixed(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

func TestPredictComponentRefsMatchesNormalization(t *testing.T) {
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
	 {"bom-ref":"a","type":"library","name":"a","version":"1"},
	 {"bom-ref":"f","type":"file","name":"/x"},
	 {"bom-ref":"b","type":"library","name":"b","version":"2","components":[{"bom-ref":"c","type":"library","name":"c","version":"3"}]},
	 {"bom-ref":"d","type":"library","name":"d","version":"4"}]}`
	refs, err := predictComponentRefs([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	doc, _, _, err := normalizeDocument([]byte(raw), testContext())
	if err != nil {
		t.Fatal(err)
	}
	actual := map[string]string{}
	for _, v := range doc["components"].([]any) {
		c := v.(map[string]any)
		actual[c["name"].(string)] = c["bom-ref"].(string)
	}
	for key, target := range refs {
		if actual[key] != target.Ref {
			t.Errorf("%s predicted %s, normalized %s", key, target.Ref, actual[key])
		}
	}
	if len(refs) != 4 {
		t.Fatalf("file component must not be numbered: %v", refs)
	}
}

func TestBuildVEXGroupsAndSkipsUnknownTargets(t *testing.T) {
	refs := map[string]vexTarget{"p1": {Ref: "component-1", Name: "busybox", Version: "1.36.1"}, "p2": {Ref: "component-2", Name: "zlib", Version: "1.3"}}
	statements := []vexStatement{
		{CVE: "CVE-2024-0002", State: vexNotAffected, Justification: "code_not_present", Targets: []string{"p1"}, Source: "s"},
		{CVE: "CVE-2024-0001", State: vexFixed, Targets: []string{"p1", "p2", "gone"}, Source: "s"},
		{CVE: "CVE-2024-0003", State: vexAffected, Targets: []string{"gone"}, Source: "s"},
	}
	data, n, err := buildVEX(statements, refs, "2026-11-18T00:00:00Z")
	if err != nil || n != 2 {
		t.Fatalf("buildVEX: %d %v", n, err)
	}
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	vulns := doc["vulnerabilities"].([]any)
	first := vulns[0].(map[string]any)
	if first["id"] != "CVE-2024-0001" || first["analysis"].(map[string]any)["state"] != "resolved" || len(first["affects"].([]any)) != 2 {
		t.Fatalf("first: %v", first)
	}
	second := vulns[1].(map[string]any)
	if second["analysis"].(map[string]any)["justification"] != "code_not_present" || second["analysis"].(map[string]any)["state"] != "not_affected" {
		t.Fatalf("second: %v", second)
	}
	if strings.Contains(string(data), "CVE-2024-0003") || doc["components"] != nil {
		t.Fatal("statement without an SBOM component, or an inventory, in the VEX")
	}
	if _, n, _ := buildVEX(nil, refs, "x"); n != 0 {
		t.Fatal("empty VEX must not be written")
	}
}
