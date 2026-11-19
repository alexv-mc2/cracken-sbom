package main

import (
	"bytes"
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
	if len(keys) == 0 {
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
		"vulnerabilities": []any{},
	}
	// The encoding is built from its parts so that its exact size is known
	// before the next part is materialised: the document with an empty
	// vulnerabilities list, then each vulnerability indented as it appears.
	enc := newVEXEncoder(doc)
	if enc == nil {
		return nil, 0, errors.New("cannot encode the VEX file")
	}
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
		if err := enc.add(map[string]any{
			"bom-ref":  fmt.Sprintf("vex-%d", i+1),
			"id":       k.cve,
			"source":   map[string]any{"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/" + k.cve},
			"analysis": analysis,
			"affects":  affects,
		}); err != nil {
			return nil, 0, err
		}
	}
	return enc.bytes(), len(keys), nil
}

// vexEncoder produces exactly json.MarshalIndent(doc, "", "  ") plus a final
// newline, where doc's "vulnerabilities" list is filled element by element.
// size() is the exact length of the file so far; add refuses an element that
// would take it above maxVEXBytes, before keeping it.
type vexEncoder struct {
	head, tail []byte // around the "[]" of the empty vulnerabilities list
	elems      [][]byte
	size       int
}

const vexElemPrefix = "    " // the vulnerabilities array sits at depth 1

func newVEXEncoder(doc map[string]any) *vexEncoder {
	base, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil
	}
	marker := []byte(`"vulnerabilities": []`)
	i := bytes.LastIndex(base, marker)
	if i < 0 {
		return nil
	}
	cut := i + len(marker) - 2
	e := &vexEncoder{head: base[:cut], tail: base[cut+2:]}
	e.size = len(e.head) + len("[]") + len(e.tail) + 1
	return e
}

// growth is what one more element adds: "[\n    " + elem + "\n  ]" for the
// first one (replacing "[]"), ",\n    " + elem for each further one.
func (e *vexEncoder) growth(elem []byte) int {
	if len(e.elems) == 0 {
		return len("\n"+vexElemPrefix) + len(elem) + len("\n  ")
	}
	return len(",\n"+vexElemPrefix) + len(elem)
}

func (e *vexEncoder) add(v any) error {
	elem, err := json.MarshalIndent(v, vexElemPrefix, "  ")
	if err != nil {
		return errors.New("cannot encode the VEX file")
	}
	if e.size+e.growth(elem) > maxVEXBytes {
		return fmt.Errorf("the VEX file would exceed %d MiB; refused to protect memory, the input looks malformed", maxVEXBytes>>20)
	}
	e.size += e.growth(elem)
	e.elems = append(e.elems, elem)
	return nil
}

func (e *vexEncoder) bytes() []byte {
	out := make([]byte, 0, e.size)
	out = append(out, e.head...)
	out = append(out, '[')
	for i, elem := range e.elems {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, "\n"+vexElemPrefix...)
		out = append(out, elem...)
	}
	if len(e.elems) > 0 {
		out = append(out, "\n  "...)
	}
	out = append(out, ']')
	out = append(out, e.tail...)
	return append(out, '\n')
}
