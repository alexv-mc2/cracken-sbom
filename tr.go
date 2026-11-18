package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The BSI TR-03183-2 v2.1.0 layer: product root, SBOM creator, component
// creators, licence acknowledgement, deployable SHA-512, file names, the BSI
// taxonomy flags, a dependency entry for every component, and compositions.
// Every value is either asserted by the user, read from the engine output or
// a lockfile, or computed from a local file; nothing is guessed.

const productRef = "cracken-product"

type trOptions struct {
	ProductName, ProductVersion, ProductLicense          string
	ManufacturerName, ManufacturerEmail, ManufacturerURL string
	MetadataFile, Artifact                               string
	ConcludeLicenses, ComponentContacts                  bool
}

func bindTRFlags(fs *flag.FlagSet, t *trOptions) {
	fs.StringVar(&t.ProductName, "product-name", "", "product (primary component) name")
	fs.StringVar(&t.ProductVersion, "product-version", "", "product version")
	fs.StringVar(&t.ProductLicense, "product-license", "", "SPDX licence expression the product is distributed under (written as concluded)")
	fs.StringVar(&t.ManufacturerName, "manufacturer-name", "", "SBOM creator and product manufacturer name")
	fs.StringVar(&t.ManufacturerEmail, "manufacturer-email", "", "SBOM creator contact e-mail (TR-03183-2 §5.2.1)")
	fs.StringVar(&t.ManufacturerURL, "manufacturer-url", "", "SBOM creator https URL, used when there is no e-mail")
	fs.StringVar(&t.MetadataFile, "metadata", "", "JSON file with product and manufacturer facts; flags override it")
	fs.StringVar(&t.Artifact, "artifact", "", "local deployable file of the product (SHA-512 and file name)")
	fs.BoolVar(&t.ConcludeLicenses, "conclude-licenses", false, "assert that detected component licences are the distribution licences (acknowledgement concluded)")
	fs.BoolVar(&t.ComponentContacts, "component-contacts", false, "keep component creator e-mail and URL from package metadata")
}

var emailPattern = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)

// validHTTPURL accepts absolute http(s) URLs without credentials, query or
// fragment: a creator home page, never a signed or private link.
func validHTTPURL(s string) bool {
	if len(s) > 512 || strings.TrimSpace(s) != s || strings.ContainsAny(s, " \\\x00") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return !credentialPattern.MatchString(s)
}

const maxMetadataBytes = 64 << 10

// resolveTROptions loads --metadata, applies flag overrides and validates
// every user-asserted value before any scan starts.
func resolveTROptions(t trOptions) (trOptions, error) {
	if t.MetadataFile != "" {
		file, info, err := canonicalExisting(t.MetadataFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxMetadataBytes {
			return t, errors.New("--metadata must be an existing regular JSON file of at most 64 KiB")
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return t, errors.New("cannot read --metadata file")
		}
		var meta struct {
			Product struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				License string `json:"license"`
			} `json:"product"`
			Manufacturer struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				URL   string `json:"url"`
			} `json:"manufacturer"`
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if dec.Decode(&meta) != nil || dec.Decode(new(any)) != io.EOF {
			return t, errors.New("--metadata must be one JSON object with only product{name,version,license} and manufacturer{name,email,url}")
		}
		fill := func(dst *string, v string) {
			if *dst == "" {
				*dst = v
			}
		}
		fill(&t.ProductName, meta.Product.Name)
		fill(&t.ProductVersion, meta.Product.Version)
		fill(&t.ProductLicense, meta.Product.License)
		fill(&t.ManufacturerName, meta.Manufacturer.Name)
		fill(&t.ManufacturerEmail, meta.Manufacturer.Email)
		fill(&t.ManufacturerURL, meta.Manufacturer.URL)
	}
	if t.ProductName != "" {
		if _, err := cleanString(t.ProductName, "name", true); err != nil {
			return t, errors.New("--product-name is not a safe component name")
		}
	}
	if t.ProductVersion != "" {
		if _, err := cleanString(t.ProductVersion, "version", false); err != nil {
			return t, errors.New("--product-version is not a safe version")
		}
	}
	if t.ProductLicense != "" && !validSPDXExpression(t.ProductLicense) {
		return t, errors.New("--product-license must be an SPDX licence expression")
	}
	if t.ManufacturerName != "" {
		if _, err := cleanString(t.ManufacturerName, "manufacturer name", false); err != nil {
			return t, errors.New("--manufacturer-name is not a safe name")
		}
	}
	if t.ManufacturerEmail != "" && !emailPattern.MatchString(t.ManufacturerEmail) {
		return t, errors.New("--manufacturer-email is not an e-mail address")
	}
	if t.ManufacturerURL != "" && !validHTTPURL(t.ManufacturerURL) {
		return t, errors.New("--manufacturer-url must be an http(s) URL without credentials, query or fragment")
	}
	if t.Artifact != "" {
		file, info, err := canonicalExisting(t.Artifact)
		if err != nil || !info.Mode().IsRegular() {
			return t, errors.New("--artifact must be an existing regular file")
		}
		t.Artifact = file
	}
	return t, nil
}

var licenseRefPattern = regexp.MustCompile(`^(DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$`)

// validSPDXExpression accepts SPDX licence expressions whose identifiers are
// on the CycloneDX 1.6 SPDX list (optionally with "+") or are LicenseRef-s,
// combined with AND, OR, WITH and parentheses.
func validSPDXExpression(expr string) bool {
	if expr == "" || len(expr) > 1024 || !licenseExpressionPattern.MatchString(expr) || suspiciousString(expr) || strings.Contains(expr, "..") {
		return false
	}
	tokens := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(expr))
	depth, expectOperand := 0, true
	for _, tok := range tokens {
		switch {
		case tok == "(":
			if !expectOperand {
				return false
			}
			depth++
		case tok == ")":
			if expectOperand || depth == 0 {
				return false
			}
			depth--
		case tok == "AND" || tok == "OR" || tok == "WITH":
			if expectOperand {
				return false
			}
			expectOperand = true
		default:
			if !expectOperand || !(supportedSPDXIDs[strings.TrimSuffix(tok, "+")] || licenseRefPattern.MatchString(tok)) {
				return false
			}
			expectOperand = false
		}
	}
	return depth == 0 && !expectOperand
}

// creatorFacts is a component creator taken from package metadata.
type creatorFacts struct {
	Name, Email, URL string
}

var creatorEmailPattern = regexp.MustCompile(`<([^<>\s]+)>`)
var creatorURLPattern = regexp.MustCompile(`\((https?://[^()\s]+)\)`)

// parseCreator reads "Name <email> (url)" as written in npm, PyPI and Debian
// metadata. Unsafe parts are dropped individually.
func parseCreator(s string) creatorFacts {
	var c creatorFacts
	if len(s) > 1024 {
		return c
	}
	if m := creatorEmailPattern.FindStringSubmatch(s); m != nil && emailPattern.MatchString(m[1]) {
		c.Email = m[1]
	}
	if m := creatorURLPattern.FindStringSubmatch(s); m != nil && validHTTPURL(m[1]) {
		c.URL = m[1]
	}
	name := s
	if i := strings.IndexAny(name, "<("); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	if emailPattern.MatchString(name) {
		if c.Email == "" {
			c.Email = name
		}
		name = ""
	}
	if n, err := cleanString(name, "creator name", false); err == nil {
		c.Name = n
	}
	return c
}

// componentCreator prefers the engine's manufacturer, then authors, author,
// publisher, and finally the supplier name.
func componentCreator(c map[string]any) creatorFacts {
	if m, ok := c["manufacturer"].(map[string]any); ok {
		var f creatorFacts
		if n, ok := m["name"].(string); ok {
			f = parseCreator(n)
		}
		if contacts, ok := m["contact"].([]any); ok {
			for _, v := range contacts {
				if contact, ok := v.(map[string]any); ok {
					if e, ok := contact["email"].(string); ok && emailPattern.MatchString(e) && f.Email == "" {
						f.Email = e
					}
				}
			}
		}
		if urls, ok := m["url"].([]any); ok && len(urls) > 0 {
			if u, ok := urls[0].(string); ok && validHTTPURL(u) && f.URL == "" {
				f.URL = u
			}
		}
		if f != (creatorFacts{}) {
			return f
		}
	}
	if authors, ok := c["authors"].([]any); ok {
		for _, v := range authors {
			a, ok := v.(map[string]any)
			if !ok {
				continue
			}
			var f creatorFacts
			if n, ok := a["name"].(string); ok {
				f = parseCreator(n)
			}
			if e, ok := a["email"].(string); ok && emailPattern.MatchString(e) {
				f.Email = e
			}
			if f != (creatorFacts{}) {
				return f
			}
		}
	}
	for _, field := range []string{"author", "publisher"} {
		if s, ok := c[field].(string); ok {
			if f := parseCreator(s); f != (creatorFacts{}) {
				return f
			}
		}
	}
	if s, ok := c["supplier"].(map[string]any); ok {
		if n, ok := s["name"].(string); ok {
			return parseCreator(n)
		}
	}
	return creatorFacts{}
}

// organizationalEntity renders a CycloneDX 1.6 organizationalEntity.
func organizationalEntity(name, email, link string) map[string]any {
	if name == "" && email == "" && link == "" {
		return nil
	}
	entity := map[string]any{}
	if name != "" {
		entity["name"] = name
	}
	if link != "" {
		entity["url"] = []any{link}
	}
	if email != "" {
		entity["contact"] = []any{map[string]any{"email": email}}
	}
	return entity
}

func newSerialNumber() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("cannot create SBOM serial number")
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func distributionReference(filename, publicURL, sha512 string) map[string]any {
	ref := publicURL
	if ref == "" {
		// The file name as a relative IRI reference: the deployable file the
		// hash describes, without revealing a local path or a private host.
		ref = url.PathEscape(filename)
	}
	return map[string]any{"type": "distribution", "url": ref, "hashes": []any{map[string]any{"alg": "SHA-512", "content": sha512}}}
}

func setAcknowledgement(component map[string]any, ack string) {
	list, ok := component["licenses"].([]any)
	if !ok {
		return
	}
	for _, v := range list {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if lic, ok := entry["license"].(map[string]any); ok {
			lic["acknowledgement"] = ack
		} else if _, ok := entry["expression"]; ok {
			entry["acknowledgement"] = ack
		}
	}
}

func appendProperties(component map[string]any, props []any) {
	existing, _ := component["properties"].([]any)
	component["properties"] = append(existing, props...)
}

func addGap(quality *Quality, gap string) {
	for _, g := range quality.TRGaps {
		if g == gap {
			return
		}
	}
	quality.TRGaps = append(quality.TRGaps, gap)
}

// applyTR adds the TR-03183-2 layer to a minimized document in place.
func applyTR(doc map[string]any, hints map[string]*componentHints, p *Prepared, o generateOptions, quality *Quality) error {
	if _, exists := doc["vulnerabilities"]; exists {
		return errors.New("an SBOM must not contain vulnerability information (TR-03183-2 §3.1)")
	}
	components, ok := doc["components"].([]any)
	if !ok || len(components) == 0 {
		return errors.New("empty_sbom: no package components")
	}
	tr := o.tr
	serial, err := newSerialNumber()
	if err != nil {
		return err
	}
	doc["specVersion"] = "1.6"
	doc["serialNumber"] = serial
	ack := "declared"
	if tr.ConcludeLicenses {
		ack = "concluded"
	}

	// Components: creator, licence acknowledgement, deployable hash, file
	// name and the taxonomy flags.
	locks := loadLockIndexes(p.ScanRoot, hints)
	var hashedTotal int64
	refs := make([]string, 0, len(components))
	missingCreator, missingHash, missingFilename := 0, 0, 0
	for _, v := range components {
		component, ok := v.(map[string]any)
		if !ok {
			return errors.New("malformed minimized component")
		}
		ref, _ := component["bom-ref"].(string)
		refs = append(refs, ref)
		h := hints[ref]
		if h == nil {
			h = &componentHints{}
		}
		setAcknowledgement(component, ack)
		creator := h.Creator
		if !tr.ComponentContacts {
			creator.Email, creator.URL = "", ""
		}
		if entity := organizationalEntity(creator.Name, creator.Email, creator.URL); entity != nil {
			component["manufacturer"] = entity
			quality.ManufacturerComponents++
		}
		if creator.Email == "" && creator.URL == "" {
			missingCreator++
		}
		var digest, filename, publicURL string
		if idx, ok := locks[h.Location]; ok && h.PkgType == "npm" {
			key := h.Name
			if h.Group != "" {
				key = h.Group + "/" + h.Name
			}
			if e, ok := idx[lockKey(key, h.Version)]; ok {
				digest, filename, publicURL = e.SHA512, e.Filename, e.URL
			}
		} else if fileComponentCatalogers[h.FoundBy] && p.ScanRoot != "" {
			if file, ok := insideRoot(p.ScanRoot, h.Location); ok && hashedTotal < maxHashedTotalBytes {
				if sum, n, err := sha512File(file, maxHashedFileBytes); err == nil {
					hashedTotal += n
					digest, filename = sum, safeFilename(path.Base(h.Location))
				}
			}
		}
		if digest != "" && filename != "" {
			component["externalReferences"] = []any{distributionReference(filename, publicURL, digest)}
			quality.SHA512Components++
		} else {
			missingHash++
			filename = ""
		}
		if filename != "" {
			quality.FilenameComponents++
		} else {
			missingFilename++
		}
		componentType, _ := component["type"].(string)
		executable, archive, structured := bsiClassification(componentType, h)
		appendProperties(component, bsiProperties(executable, archive, structured, filename))
	}

	// Product root (metadata.component) and SBOM creator (metadata.manufacturer).
	metadata, ok := doc["metadata"].(map[string]any)
	if !ok {
		return errors.New("malformed minimized metadata")
	}
	manufacturer := organizationalEntity(tr.ManufacturerName, tr.ManufacturerEmail, tr.ManufacturerURL)
	if manufacturer != nil {
		metadata["manufacturer"] = manufacturer
	}
	if tr.ManufacturerEmail == "" && tr.ManufacturerURL == "" {
		addGap(quality, "SBOM creator: no --manufacturer-email or --manufacturer-url (TR-03183-2 §5.2.1).")
	}
	root := map[string]any{"bom-ref": productRef, "type": p.Root.Type}
	if root["type"] == "" {
		root["type"] = "application"
	}
	name := tr.ProductName
	if name == "" {
		name = p.Root.DefaultName
	}
	if name == "" {
		name = safeFilename(filepath.Base(o.target))
		addGap(quality, "Product name: no --product-name; the target's file or folder name is used.")
	}
	if name == "" {
		name = "unnamed-product"
	}
	version := tr.ProductVersion
	if version == "" {
		version = p.Root.DefaultVersion
	}
	if version == "" {
		version = o.targetID
		addGap(quality, "Product version: no --product-version; the --target-id is used.")
	}
	root["name"], root["version"] = name, version
	if manufacturer != nil {
		root["manufacturer"] = manufacturer
	}
	if tr.ProductLicense != "" {
		// The manufacturer states the product's distribution licence.
		root["licenses"] = []any{map[string]any{"expression": tr.ProductLicense, "acknowledgement": "concluded"}}
	} else {
		addGap(quality, "Product licence: no --product-license (distribution licence, TR-03183-2 §5.2.2).")
	}
	artifact := tr.Artifact
	if artifact == "" {
		artifact = p.Root.ArtifactPath
	}
	rootFilename := ""
	if artifact != "" {
		sum, _, err := sha512File(artifact, 1<<40)
		if err != nil {
			return errors.New("cannot hash the product's deployable file")
		}
		rootFilename = safeFilename(filepath.Base(artifact))
		reference := rootFilename
		if reference == "" {
			// Like the firmware properties, an unsafe local name is withheld.
			reference = "withheld-unsafe-characters"
			addGap(quality, "Product file name: withheld because it contains unsafe characters.")
		}
		root["externalReferences"] = []any{distributionReference(reference, "", sum)}
	} else {
		addGap(quality, "Product deployable hash: no --artifact for a directory target (TR-03183-2 §5.2.2).")
	}
	root["properties"] = bsiProperties(p.Root.Executable, p.Root.Archive, p.Root.Structured, rootFilename)
	metadata["component"] = root
	graph := p.Graph
	deps, _ := doc["dependencies"].([]any)
	if len(deps) == 0 && graph != GraphUnknown {
		graph = GraphUnknown
	}
	if graph == GraphLockfile && quality.graphUnresolved {
		graph = GraphPartial
	}
	source := map[GraphSource]string{GraphUnknown: "none", GraphPartial: "engine", GraphLockfile: "lockfile"}[graph]
	props, _ := metadata["properties"].([]any)
	metadata["properties"] = append(props,
		map[string]any{"name": "cracken:tr:profile", "value": trProfile},
		map[string]any{"name": "cracken:tr:licence-acknowledgement", "value": ack},
		map[string]any{"name": "cracken:tr:graph-source", "value": source},
	)

	// Dependencies: every component gets an entry (an empty one for leaves);
	// the product depends on every component nothing else depends on, and on
	// any component a cycle would otherwise leave unreachable.
	entries := map[string][]string{}
	inDegree := map[string]int{}
	for _, v := range deps {
		d, ok := v.(map[string]any)
		if !ok {
			return errors.New("malformed minimized dependency")
		}
		ref, _ := d["ref"].(string)
		edges := []string{}
		if list, ok := d["dependsOn"].([]any); ok {
			for _, e := range list {
				if s, ok := e.(string); ok {
					edges = append(edges, s)
					inDegree[s]++
				}
			}
		}
		entries[ref] = edges
	}
	direct := []string{}
	for _, ref := range refs {
		if _, ok := entries[ref]; !ok {
			entries[ref] = []string{}
		}
		if inDegree[ref] == 0 {
			direct = append(direct, ref)
		}
	}
	reached := map[string]bool{}
	var visit func(string)
	visit = func(ref string) {
		if reached[ref] {
			return
		}
		reached[ref] = true
		for _, e := range entries[ref] {
			visit(e)
		}
	}
	for _, ref := range direct {
		visit(ref)
	}
	for _, ref := range refs {
		if !reached[ref] {
			direct = append(direct, ref)
			visit(ref)
		}
	}
	sort.Strings(direct)
	dependencies := []any{map[string]any{"ref": productRef, "dependsOn": toAnySlice(direct)}}
	for _, ref := range refs {
		dependencies = append(dependencies, map[string]any{"ref": ref, "dependsOn": toAnySlice(entries[ref])})
	}
	doc["dependencies"] = dependencies

	// Compositions: "complete" only for components a root lockfile lists and
	// whose dependencies it lists too. Everything else, and the product unless
	// every component is covered, is incomplete (engine graph) or unknown.
	rest := map[GraphSource]string{GraphUnknown: "unknown", GraphPartial: "incomplete", GraphLockfile: "incomplete"}[graph]
	covered := map[string]bool{}
	if graph == GraphLockfile {
		covered = lockfileCoverage(p.ScanRoot, refs, hints, entries)
	}
	complete, other := []string{}, []string{}
	for _, ref := range refs {
		if covered[ref] {
			complete = append(complete, ref)
		} else {
			other = append(other, ref)
		}
	}
	productComplete := graph == GraphLockfile && len(other) == 0
	if productComplete {
		complete = append([]string{productRef}, complete...)
	} else {
		other = append([]string{productRef}, other...)
	}
	compositions := []any{}
	if len(complete) > 0 {
		compositions = append(compositions, map[string]any{"aggregate": "complete", "dependencies": toAnySlice(complete)})
	}
	if len(other) > 0 {
		compositions = append(compositions, map[string]any{"aggregate": rest, "dependencies": toAnySlice(other)})
	}
	doc["compositions"] = compositions
	quality.GraphCompleteness = rest
	if productComplete {
		quality.GraphCompleteness = "complete"
	}
	switch {
	case graph != GraphLockfile:
		addGap(quality, "Dependency completeness is "+rest+": no lockfile states the whole graph for this target.")
	case !productComplete:
		addGap(quality, fmt.Sprintf("Dependency completeness: %d of %d components are listed in the root lockfile and marked complete; the others and the product are %s.", len(complete), len(refs), rest))
	}

	total := len(components)
	if !tr.ConcludeLicenses {
		addGap(quality, "Component distribution licences are written as declared; use --conclude-licenses only if you have concluded them (TR-03183-2 §5.2.2).")
	}
	if missingCreator > 0 {
		hint := ""
		if !tr.ComponentContacts {
			hint = " Package metadata contacts are kept only with --component-contacts."
		}
		addGap(quality, fmt.Sprintf("Component creator e-mail or URL: missing for %d of %d components.%s", missingCreator, total, hint))
	}
	if missingHash > 0 {
		addGap(quality, fmt.Sprintf("Deployable SHA-512: missing for %d of %d components (known only from npm/yarn/bun lockfiles and cataloged binary files).", missingHash, total))
	}
	if missingFilename > 0 {
		addGap(quality, fmt.Sprintf("bsi:component:filename: missing for %d of %d components.", missingFilename, total))
	}
	if _, exists := doc["vulnerabilities"]; exists {
		return errors.New("an SBOM must not contain vulnerability information (TR-03183-2 §3.1)")
	}
	return nil
}

// lockfileCoverage returns the components a root npm lockfile v2/v3 lists:
// npm packages Syft located in that lockfile. A component stays covered only
// while all of its dependencies are covered, so "complete" never reaches a
// subgraph the lockfile does not describe (a Python environment, a nested
// project with another package manager or another lockfile).
func lockfileCoverage(root string, refs []string, hints map[string]*componentHints, entries map[string][]string) map[string]bool {
	covered := map[string]bool{}
	if root == "" {
		return covered
	}
	lockfiles := map[string]bool{}
	for _, name := range npmGraphLockfiles {
		if _, ok := readNPMGraphLockfile(root, name); ok {
			lockfiles["/"+name] = true
		}
	}
	for _, ref := range refs {
		if h := hints[ref]; h != nil && h.PkgType == "npm" && lockfiles[h.Location] {
			covered[ref] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, ref := range refs {
			if !covered[ref] {
				continue
			}
			for _, dep := range entries[ref] {
				if !covered[dep] {
					delete(covered, ref)
					changed = true
					break
				}
			}
		}
	}
	return covered
}

func toAnySlice(values []string) []any {
	out := make([]any, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	return out
}
