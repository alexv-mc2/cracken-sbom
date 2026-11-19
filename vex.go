// Patched-CVE and VEX facts from native Yocto SPDX, using the same rules as
// crAcken's parsers (sbom-to-cra parse-sbom/spdx/enricher.ts extractCvesFixed
// and parse-sbom/spdx3/mod.ts), so the generator and crAcken read the same
// data. The SPDX 3 VEX mapping was checked against JPEWdev/spdx3toopenvex
// (MIT, see NOTICE). The facts go only into a separate CycloneDX VEX file;
// an SBOM must not contain vulnerability information (TR-03183-2 §3.1).

package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

type vexState string

const (
	vexFixed       vexState = "fixed"
	vexNotAffected vexState = "not_affected"
	vexAffected    vexState = "affected"
)

// vexStatement is one assessment of one CVE for some SPDX elements.
type vexStatement struct {
	CVE           string
	State         vexState
	Justification string   // CycloneDX justification, may be empty
	Targets       []string // component keys (see componentKey)
	Source        string
}

var cvesFixedPattern = regexp.MustCompile(`(?i)CVEs?\s+fixed:\s*(CVE-[\d-]+(?:[\s,]+CVE-[\d-]+)*)`)
var cveIDPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+`)
var cveStrictPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// extractCvesFixed parses "CVEs fixed: CVE-xxxx-yyyy CVE-aaaa-bbbb" from an
// SPDX 2 recipe's sourceInfo, exactly as crAcken does.
func extractCvesFixed(sourceInfo string) []string {
	m := cvesFixedPattern.FindStringSubmatch(sourceInfo)
	if m == nil {
		return nil
	}
	out := []string{}
	for _, s := range regexp.MustCompile(`[\s,]+`).Split(m[1], -1) {
		if cveIDPattern.MatchString(s) {
			cve := strings.ToUpper(s)
			if cveStrictPattern.MatchString(cve) {
				out = append(out, cve)
			}
		}
	}
	return out
}

// SPDX 3 justification types mapped to CycloneDX analysis justifications.
// Types without a clear counterpart are left out rather than guessed.
var spdx3Justifications = map[string]string{
	"componentNotPresent":            "code_not_present",
	"vulnerableCodeNotPresent":       "code_not_present",
	"vulnerableCodeNotInExecutePath": "code_not_reachable",
	"inlineMitigationsAlreadyExist":  "protected_by_mitigating_control",
}

var spdx3TimePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)

// spdx3VEX reads security_Vex*VulnAssessmentRelationship elements. An
// assessment on a recipe applies to the selected packages it generates; one
// on a package applies to that package. Assessments withdrawn in the past are
// skipped; an invalid withdrawal time keeps the assessment.
// Caps for attacker-shaped VEX data: statements (CVE x assessment), affected
// (statement, component) pairs, and the bytes of the VEX file.
var maxVEXStatements = 50000
var maxVEXPairs = 200000
var maxVEXBytes = 16 << 20

func vexCapError(what string, limit int) error {
	return fmt.Errorf("the Yocto SPDX holds more than %d VEX %s; refused to protect memory, the input looks malformed", limit, what)
}

func spdx3VEX(g *spdx3Graph, selected map[string]bool, generatedBy map[string][]string) ([]vexStatement, error) {
	generates := map[string][]string{}
	for pkg, recipes := range generatedBy {
		for _, r := range recipes {
			generates[r] = append(generates[r], pkg)
		}
	}
	out := []vexStatement{}
	pairs := 0
	for _, r := range g.relations {
		var state vexState
		switch {
		case spdx3HasType(r, "security_VexFixedVulnAssessmentRelationship") && r["relationshipType"] == "fixedIn":
			state = vexFixed
		case spdx3HasType(r, "security_VexNotAffectedVulnAssessmentRelationship") && r["relationshipType"] == "doesNotAffect":
			state = vexNotAffected
		case spdx3HasType(r, "security_VexAffectedVulnAssessmentRelationship") && r["relationshipType"] == "affects":
			state = vexAffected
		default:
			continue
		}
		if w, ok := r["security_withdrawnTime"].(string); ok && spdx3TimePattern.MatchString(w) {
			if t, err := time.Parse(time.RFC3339Nano, w); err == nil && !t.After(time.Now()) {
				continue
			}
		}
		from, _ := r["from"].(string)
		vuln := g.byID[from]
		if vuln == nil || !spdx3HasType(vuln, "security_Vulnerability") {
			continue
		}
		cves := []string{}
		if ids, ok := vuln["externalIdentifier"].([]any); ok {
			for _, v := range ids {
				if m, ok := v.(map[string]any); ok && m["externalIdentifierType"] == "cve" {
					if s, ok := m["identifier"].(string); ok && cveStrictPattern.MatchString(strings.ToUpper(s)) {
						cves = append(cves, strings.ToUpper(s))
					}
				}
			}
		}
		targets := []string{}
		for _, t := range spdx3Refs(r["to"]) {
			if selected[t] {
				targets = append(targets, t)
			}
			for _, pkg := range generates[t] {
				if selected[pkg] {
					targets = append(targets, pkg)
				}
			}
		}
		targets = uniqueStrings(targets)
		if len(targets) == 0 {
			continue
		}
		cves = uniqueStrings(cves)
		if len(out)+len(cves) > maxVEXStatements {
			return nil, vexCapError("statements", maxVEXStatements)
		}
		if pairs += len(cves) * len(targets); pairs > maxVEXPairs {
			return nil, vexCapError("affected-component pairs", maxVEXPairs)
		}
		justification := ""
		if j, ok := r["security_justificationType"].(string); ok {
			justification = spdx3Justifications[j]
		}
		for _, cve := range cves {
			out = append(out, vexStatement{CVE: cve, State: state, Justification: justification, Targets: targets, Source: "yocto-spdx3-vex"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out, nil
}
