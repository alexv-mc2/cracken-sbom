package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The separate CycloneDX VEX 1.6 file written next to the SBOM.
const yoctoVEXFile = "sbom.vex.cdx.json"

// vexTarget is a final SBOM component a statement refers to.
type vexTarget struct {
	Ref, Name, Version string
}

var cycloneDXStates = map[vexState]string{vexFixed: "resolved", vexNotAffected: "not_affected", vexAffected: "exploitable"}
var versionStatus = map[vexState]string{vexFixed: "unaffected", vexNotAffected: "unaffected", vexAffected: "affected"}

// buildVEX writes one vulnerability per CVE and state. affects[].ref names
// the bom-ref of the component in sbom.cdx.json; versions repeats the
// component version so the file stays readable on its own. The document has
// no component inventory of its own.
func buildVEX(statements []vexStatement, refs map[string]vexTarget, timestamp string) ([]byte, int, error) {
	type key struct {
		cve           string
		state         vexState
		justification string
	}
	grouped := map[key]map[string]vexTarget{}
	sources := map[string]bool{}
	if len(statements) > maxVEXStatements {
		return nil, 0, vexCapError("statements", maxVEXStatements)
	}
	pairs := 0
	for _, s := range statements {
		if pairs += len(s.Targets); pairs > maxVEXPairs {
			return nil, 0, vexCapError("affected-component pairs", maxVEXPairs)
		}
		k := key{s.CVE, s.State, s.Justification}
		for _, t := range s.Targets {
			target, ok := refs[t]
			if !ok {
				continue
			}
			if grouped[k] == nil {
				grouped[k] = map[string]vexTarget{}
			}
			grouped[k][target.Ref] = target
			sources[s.Source] = true
		}
	}
	entries := 0
	for _, targets := range grouped {
		entries += len(targets)
	}
	// About 160 bytes per indented affects entry: refuse before encoding.
	if entries*160 > maxVEXBytes {
		return nil, 0, fmt.Errorf("the VEX file would exceed %d MiB; refused to protect memory, the input looks malformed", maxVEXBytes>>20)
	}
	keys := make([]key, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].cve != keys[j].cve {
			return keys[i].cve < keys[j].cve
		}
		if keys[i].state != keys[j].state {
			return keys[i].state < keys[j].state
		}
		return keys[i].justification < keys[j].justification
	})
	vulnerabilities := []any{}
	for i, k := range keys {
		targets := make([]vexTarget, 0, len(grouped[k]))
		for _, t := range grouped[k] {
			targets = append(targets, t)
		}
		sort.Slice(targets, func(a, b int) bool { return targets[a].Ref < targets[b].Ref })
		affects := []any{}
		for _, t := range targets {
			entry := map[string]any{"ref": t.Ref}
			if t.Version != "" {
				entry["versions"] = []any{map[string]any{"version": t.Version, "status": versionStatus[k.state]}}
			}
			affects = append(affects, entry)
		}
		analysis := map[string]any{"state": cycloneDXStates[k.state]}
		if k.justification != "" && k.state == vexNotAffected {
			analysis["justification"] = k.justification
		}
		switch k.state {
		case vexFixed:
			analysis["detail"] = "Fixed in the build: the Yocto build records this CVE as patched."
		case vexNotAffected:
			analysis["detail"] = "The Yocto build assesses this CVE as not affecting the package."
		case vexAffected:
			analysis["detail"] = "The Yocto build assesses this CVE as affecting the package."
		}
		vulnerabilities = append(vulnerabilities, map[string]any{
			"bom-ref":  fmt.Sprintf("vex-%d", i+1),
			"id":       k.cve,
			"source":   map[string]any{"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/" + k.cve},
			"analysis": analysis,
			"affects":  affects,
		})
	}
	if len(vulnerabilities) == 0 {
		return nil, 0, nil
	}
	serial, err := newSerialNumber()
	if err != nil {
		return nil, 0, err
	}
	sourceList := make([]string, 0, len(sources))
	for s := range sources {
		sourceList = append(sourceList, s)
	}
	sort.Strings(sourceList)
	doc := map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": serial, "version": 1,
		"metadata": map[string]any{
			"timestamp": timestamp,
			"tools":     []any{map[string]any{"name": "cracken-sbom", "version": toolVersion}},
			"properties": []any{
				map[string]any{"name": "cracken:vex:sbom", "value": "sbom.cdx.json"},
				map[string]any{"name": "cracken:vex:source", "value": strings.Join(sourceList, ",")},
			},
		},
		"vulnerabilities": vulnerabilities,
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, 0, errors.New("cannot encode the VEX file")
	}
	if len(out) > maxVEXBytes {
		return nil, 0, fmt.Errorf("the VEX file would exceed %d MiB; refused to protect memory, the input looks malformed", maxVEXBytes>>20)
	}
	return append(out, '\n'), len(vulnerabilities), nil
}
