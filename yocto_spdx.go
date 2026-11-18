package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// yoctoConversion is the converted image inventory and the facts the VEX
// writer and the product root need.
type yoctoConversion struct {
	raw                     []byte
	imageName, imageVersion string
	spdxVersion             string
	nativeSkipped           int
	warnings                []string
	vex                     []vexStatement
}

// Recipes built for the build host or an SDK are never part of the image.
var yoctoNativePattern = regexp.MustCompile(`(-native|-cross(-[A-Za-z0-9_]+)?|-crosssdk(-[A-Za-z0-9_]+)?|-cross-canadian(-[A-Za-z0-9_]+)?)$|^nativesdk-`)

func yoctoNative(name string) bool { return yoctoNativePattern.MatchString(name) }

func convertYoctoSet(ctx context.Context, set *yoctoSet, work, syft string, engine EngineRunner) (*yoctoConversion, error) {
	if set.spdx3 {
		return convertYoctoSPDX3(ctx, set.docs[0], work, syft, engine)
	}
	return convertYoctoSPDX2(ctx, set.docs, work, syft, engine)
}

// componentKey identifies a converted component by the SPDX element it came
// from: Syft writes SPDX 3 ids as the package-id qualifier of the bom-ref (or
// as the bom-ref itself) and SPDX 2 ids without the "SPDXRef-" prefix.
func componentKey(bomRef string) string {
	if i := strings.Index(bomRef, "package-id="); i >= 0 {
		value := bomRef[i+len("package-id="):]
		if j := strings.IndexByte(value, '&'); j >= 0 {
			value = value[:j]
		}
		if unescaped, err := url.QueryUnescape(value); err == nil {
			return unescaped
		}
		return value
	}
	return bomRef
}

// filterConverted keeps only the selected components of a Syft conversion.
func filterConverted(raw []byte, keep func(key, name string) bool) ([]byte, int, error) {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil, 0, errors.New("the engine conversion is not valid CycloneDX JSON")
	}
	list, _ := doc["components"].([]any)
	kept := []any{}
	keptRefs := map[string]bool{}
	dropped := 0
	for _, v := range list {
		c, ok := v.(map[string]any)
		if !ok {
			return nil, 0, errors.New("malformed converted component")
		}
		ref, _ := c["bom-ref"].(string)
		name, _ := c["name"].(string)
		if keep(componentKey(ref), name) {
			kept = append(kept, c)
			keptRefs[ref] = true
		} else {
			dropped++
		}
	}
	doc["components"] = kept
	if deps, ok := doc["dependencies"].([]any); ok {
		pruned := []any{}
		for _, v := range deps {
			d, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if ref, _ := d["ref"].(string); !keptRefs[ref] {
				continue
			}
			edges := []any{}
			for _, e := range spdx3Refs(d["dependsOn"]) {
				if keptRefs[e] {
					edges = append(edges, e)
				}
			}
			d["dependsOn"] = edges
			pruned = append(pruned, d)
		}
		doc["dependencies"] = pruned
	}
	delete(doc, "metadata")
	out, err := json.Marshal(doc)
	return out, dropped, err
}

// predictComponentRefs reproduces normalizeDocument's bom-ref numbering
// (depth-first, file components skipped) so the separate VEX file can point
// at the final SBOM's bom-refs. tests/e2e/yocto.sh checks every reference.
func predictComponentRefs(raw []byte) (map[string]vexTarget, error) {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil, errors.New("the engine conversion is not valid CycloneDX JSON")
	}
	list, _ := doc["components"].([]any)
	out := map[string]vexTarget{}
	n := 0
	stack := [][]any{list}
	for len(stack) > 0 {
		top := len(stack) - 1
		if len(stack[top]) == 0 {
			stack = stack[:top]
			continue
		}
		c, _ := stack[top][0].(map[string]any)
		stack[top] = stack[top][1:]
		if c == nil {
			continue
		}
		if c["type"] != "file" {
			n++
			ref, _ := c["bom-ref"].(string)
			version, _ := c["version"].(string)
			name, _ := c["name"].(string)
			out[componentKey(ref)] = vexTarget{Ref: fmt.Sprintf("component-%d", n), Name: name, Version: version}
		}
		if children, ok := c["components"].([]any); ok {
			stack = append(stack, children)
		}
	}
	return out, nil
}

func writeWorkFile(work, name string, data []byte) (string, error) {
	file := filepath.Join(work, name)
	if err := os.WriteFile(file, data, 0600); err != nil {
		return "", errors.New("cannot write the Yocto conversion input")
	}
	return file, nil
}

// ---- SPDX 3 (Yocto 5.1+ and 6.0: one complete *.rootfs.spdx.json) ----

type spdx3Graph struct {
	byID      map[string]map[string]any
	nodes     []map[string]any
	relations []map[string]any
}

func spdx3ID(n map[string]any) string {
	if s, ok := n["spdxId"].(string); ok {
		return s
	}
	s, _ := n["@id"].(string)
	return s
}

func spdx3HasType(n map[string]any, want string) bool {
	for _, key := range []string{"type", "@type"} {
		switch t := n[key].(type) {
		case string:
			if t == want {
				return true
			}
		case []any:
			for _, e := range t {
				if e == want {
					return true
				}
			}
		}
	}
	return false
}

func spdx3Refs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := []string{}
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func parseSPDX3(data []byte) (*spdx3Graph, error) {
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return nil, errors.New("invalid SPDX 3 JSON")
	}
	list, ok := doc["@graph"].([]any)
	if !ok {
		return nil, errors.New("the SPDX 3 document has no @graph")
	}
	g := &spdx3Graph{byID: map[string]map[string]any{}}
	for _, v := range list {
		n, ok := v.(map[string]any)
		if !ok {
			continue
		}
		g.nodes = append(g.nodes, n)
		if id := spdx3ID(n); id != "" {
			g.byID[id] = n
		}
		if _, ok := n["relationshipType"].(string); ok {
			g.relations = append(g.relations, n)
		}
	}
	return g, nil
}

func (g *spdx3Graph) targets(from, kind string) []string {
	out := []string{}
	for _, r := range g.relations {
		if r["relationshipType"] == kind && r["from"] == from {
			out = append(out, spdx3Refs(r["to"])...)
		}
	}
	return out
}

func convertYoctoSPDX3(ctx context.Context, d yoctoDoc, work, syft string, engine EngineRunner) (*yoctoConversion, error) {
	g, err := parseSPDX3(d.data)
	if err != nil {
		return nil, err
	}
	conv := &yoctoConversion{spdxVersion: "3.0"}
	// Roots: the document's rootElement, through an Sbom's rootElement.
	roots := []string{}
	for _, n := range g.nodes {
		if spdx3HasType(n, "SpdxDocument") {
			for _, r := range spdx3Refs(n["rootElement"]) {
				if node := g.byID[r]; node != nil && spdx3HasType(node, "software_Sbom") {
					roots = append(roots, spdx3Refs(node["rootElement"])...)
				} else {
					roots = append(roots, r)
				}
			}
		}
	}
	isRoot := map[string]bool{}
	for _, r := range roots {
		isRoot[r] = true
	}
	for _, r := range roots {
		if n := g.byID[r]; n != nil && conv.imageName == "" {
			if name, err := cleanString(n["name"], "name", true); err == nil {
				conv.imageName = name
			}
			if v, err := cleanString(n["software_packageVersion"], "version", false); err == nil {
				conv.imageVersion = v
			}
		}
	}
	// What the image ships: reachable from the roots through contains,
	// dependsOn and hasInput, including builds whose output is reachable.
	reachable := map[string]bool{}
	queue := append([]string{}, roots...)
	for _, r := range roots {
		reachable[r] = true
	}
	enqueue := func(id string) {
		if !reachable[id] {
			reachable[id] = true
			queue = append(queue, id)
		}
	}
	for i := 0; i < len(queue); i++ {
		id := queue[i]
		for _, kind := range []string{"contains", "dependsOn", "hasInput"} {
			for _, t := range g.targets(id, kind) {
				enqueue(t)
			}
		}
		for _, r := range g.relations {
			if r["relationshipType"] == "hasOutput" {
				for _, t := range spdx3Refs(r["to"]) {
					if t == id {
						if from, ok := r["from"].(string); ok {
							enqueue(from)
						}
					}
				}
			}
		}
	}
	generatedBy := map[string][]string{}
	for _, r := range g.relations {
		if r["relationshipType"] == "generates" {
			if from, ok := r["from"].(string); ok {
				for _, t := range spdx3Refs(r["to"]) {
					generatedBy[t] = append(generatedBy[t], from)
				}
			}
		}
	}
	selected := map[string]bool{}
	for _, n := range g.nodes {
		if !spdx3HasType(n, "software_Package") {
			continue
		}
		id := spdx3ID(n)
		purpose, _ := n["software_primaryPurpose"].(string)
		if isRoot[id] || purpose == "specification" || purpose == "source" || purpose == "patch" {
			continue
		}
		if len(roots) > 0 && !reachable[id] {
			continue
		}
		name, _ := n["name"].(string)
		native := yoctoNative(name)
		for _, recipe := range generatedBy[id] {
			if rn, _ := g.byID[recipe]["name"].(string); yoctoNative(rn) {
				native = true
			}
		}
		if native {
			conv.nativeSkipped++
			continue
		}
		selected[id] = true
	}
	if len(roots) == 0 {
		conv.warnings = append(conv.warnings, "The Yocto SPDX 3 document does not name the image; every listed package was included.")
	}
	input, err := writeWorkFile(work, "rootfs.spdx.json", d.data)
	if err != nil {
		return nil, err
	}
	raw, err := engine.Convert(ctx, syft, input)
	if err != nil {
		return nil, err
	}
	conv.raw, _, err = filterConverted(raw, func(key, _ string) bool { return selected[key] })
	if err != nil {
		return nil, err
	}
	conv.vex = spdx3VEX(g, selected, generatedBy)
	return conv, nil
}

// ---- SPDX 2.2 (Yocto Scarthgap 5.0 and earlier: a document set) ----

type spdx2Doc struct {
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	ExternalRefs      []struct {
		ID       string `json:"externalDocumentId"`
		Document string `json:"spdxDocument"`
	} `json:"externalDocumentRefs"`
	Packages      []map[string]any `json:"packages"`
	Relationships []struct {
		From string `json:"spdxElementId"`
		To   string `json:"relatedSpdxElement"`
		Type string `json:"relationshipType"`
	} `json:"relationships"`
}

type spdx2Set struct {
	byNamespace map[string]*spdx2Doc
}

func (s *spdx2Set) resolve(from *spdx2Doc, element string) (*spdx2Doc, map[string]any) {
	doc, local := from, element
	if strings.HasPrefix(element, "DocumentRef-") {
		i := strings.Index(element, ":")
		if i < 0 {
			return nil, nil
		}
		ref, id := element[:i], element[i+1:]
		doc = nil
		for _, e := range from.ExternalRefs {
			if e.ID == ref {
				doc = s.byNamespace[e.Document]
			}
		}
		local = id
	}
	if doc == nil {
		return nil, nil
	}
	for _, p := range doc.Packages {
		if p["SPDXID"] == local {
			return doc, p
		}
	}
	return doc, nil
}

func convertYoctoSPDX2(ctx context.Context, docs []yoctoDoc, work, syft string, engine EngineRunner) (*yoctoConversion, error) {
	set := &spdx2Set{byNamespace: map[string]*spdx2Doc{}}
	parsed := []*spdx2Doc{}
	names := map[*spdx2Doc]string{}
	for _, d := range docs {
		if strings.HasSuffix(d.name, ".spdx.index.json") {
			continue
		}
		doc := &spdx2Doc{}
		if json.Unmarshal(d.data, doc) != nil {
			return nil, errors.New("invalid SPDX 2 JSON in the Yocto input")
		}
		if doc.DocumentNamespace != "" {
			set.byNamespace[doc.DocumentNamespace] = doc
		}
		parsed = append(parsed, doc)
		names[doc] = d.name
	}
	// The image document CONTAINS packages of other documents.
	images := []*spdx2Doc{}
	for _, doc := range parsed {
		for _, r := range doc.Relationships {
			if r.Type == "CONTAINS" && strings.HasPrefix(r.To, "DocumentRef-") {
				images = append(images, doc)
				break
			}
		}
	}
	if len(images) != 1 {
		return nil, fmt.Errorf("expected exactly one Yocto image document (an SPDX 2 document that CONTAINS packages of other documents), found %d; pass the image's .spdx.tar.zst or its deploy directory", len(images))
	}
	image := images[0]
	conv := &yoctoConversion{spdxVersion: "2.2"}
	var imagePkg map[string]any
	containsFrom := map[string]bool{}
	for _, r := range image.Relationships {
		if r.Type == "CONTAINS" && strings.HasPrefix(r.To, "DocumentRef-") {
			containsFrom[r.From] = true
		}
	}
	for _, p := range image.Packages {
		if id, _ := p["SPDXID"].(string); containsFrom[id] {
			imagePkg = p
			break
		}
	}
	if imagePkg != nil {
		if name, err := cleanString(imagePkg["name"], "name", true); err == nil {
			conv.imageName = name
		}
		if v, err := cleanString(imagePkg["versionInfo"], "version", false); err == nil {
			conv.imageVersion = v
		}
	}
	merged := []any{}
	relationships := []any{map[string]any{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Image", "relationshipType": "DESCRIBES"}}
	merged = append(merged, map[string]any{"SPDXID": "SPDXRef-Image", "name": "yocto-image", "downloadLocation": "NOASSERTION", "filesAnalyzed": false})
	seen := map[string]bool{}
	missing := 0
	for _, r := range image.Relationships {
		if r.Type != "CONTAINS" || !strings.HasPrefix(r.To, "DocumentRef-") || seen[r.To] {
			continue
		}
		seen[r.To] = true
		pkgDoc, pkg := set.resolve(image, r.To)
		if pkg == nil {
			missing++
			continue
		}
		name, _ := pkg["name"].(string)
		if yoctoNative(name) {
			conv.nativeSkipped++
			continue
		}
		key := fmt.Sprintf("P%d", len(merged))
		out := map[string]any{"SPDXID": "SPDXRef-" + key, "downloadLocation": "NOASSERTION", "filesAnalyzed": false}
		for _, field := range []string{"name", "versionInfo", "supplier", "originator", "licenseDeclared", "licenseConcluded", "externalRefs"} {
			if v, ok := pkg[field]; ok {
				out[field] = v
			}
		}
		// The recipe carries the CPEs and the "CVEs fixed" list.
		var cves []string
		for _, rel := range pkgDoc.Relationships {
			if rel.Type != "GENERATED_FROM" || rel.From != pkg["SPDXID"] {
				continue
			}
			if _, recipe := set.resolve(pkgDoc, rel.To); recipe != nil {
				if rn, _ := recipe["name"].(string); yoctoNative(rn) {
					name = rn
				}
				out["externalRefs"] = mergeCPERefs(out["externalRefs"], recipe["externalRefs"])
				if info, ok := recipe["sourceInfo"].(string); ok {
					cves = append(cves, extractCvesFixed(info)...)
				}
			}
		}
		if yoctoNative(name) {
			conv.nativeSkipped++
			continue
		}
		merged = append(merged, out)
		relationships = append(relationships, map[string]any{"spdxElementId": "SPDXRef-Image", "relatedSpdxElement": "SPDXRef-" + key, "relationshipType": "CONTAINS"})
		for _, cve := range uniqueStrings(cves) {
			conv.vex = append(conv.vex, vexStatement{CVE: cve, State: vexFixed, Targets: []string{key}, Source: "yocto-spdx2-cves-fixed"})
		}
	}
	if missing > 0 {
		conv.warnings = append(conv.warnings, fmt.Sprintf("%d package(s) the Yocto image document lists were not found in the input; pass the image's complete .spdx.tar.zst.", missing))
	}
	sum := sha256.Sum256([]byte(names[image]))
	doc := map[string]any{
		"spdxVersion": "SPDX-2.2", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
		"name": "yocto-image", "documentNamespace": "https://cracken.local/yocto/" + hex.EncodeToString(sum[:8]),
		"creationInfo":      map[string]any{"created": "1970-01-01T00:00:00Z", "creators": []any{"Tool: cracken-sbom"}},
		"documentDescribes": []any{"SPDXRef-Image"}, "packages": merged, "relationships": relationships,
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, errors.New("cannot build the merged Yocto SPDX document")
	}
	input, err := writeWorkFile(work, "image.spdx.json", data)
	if err != nil {
		return nil, err
	}
	raw, err := engine.Convert(ctx, syft, input)
	if err != nil {
		return nil, err
	}
	conv.raw, _, err = filterConverted(raw, func(key, _ string) bool { return key != "Image" })
	return conv, err
}

func mergeCPERefs(own, recipe any) any {
	list, _ := own.([]any)
	have := map[string]bool{}
	for _, v := range list {
		if m, ok := v.(map[string]any); ok {
			if s, ok := m["referenceLocator"].(string); ok {
				have[s] = true
			}
		}
	}
	extra, _ := recipe.([]any)
	for _, v := range extra {
		m, ok := v.(map[string]any)
		if !ok || m["referenceCategory"] != "SECURITY" {
			continue
		}
		t, _ := m["referenceType"].(string)
		loc, _ := m["referenceLocator"].(string)
		if (path.Base(t) == "cpe23Type" || path.Base(t) == "cpe22Type") && loc != "" && !have[loc] {
			list = append(list, map[string]any{"referenceCategory": "SECURITY", "referenceType": path.Base(t), "referenceLocator": loc})
			have[loc] = true
		}
	}
	if list == nil {
		return nil
	}
	return list
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
