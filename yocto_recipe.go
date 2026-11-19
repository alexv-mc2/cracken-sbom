package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// One CycloneDX component per Yocto recipe. The recipe is the upstream
// software that CVE_PRODUCT names, so it alone carries the CPEs: the first in
// `cpe`, the others as `evidence.identity[]` entries with field "cpe". The
// binary packages it generates carry no CPE; each links to its recipe with
// the property cracken:yocto:recipe = the recipe's bom-ref. A CVE is then
// matched and assessed once per recipe instead of once per package.

const yoctoRecipeProperty = "cracken:yocto:recipe"

// Cap for attacker-shaped input: CPEs kept on recipe components in total.
var maxYoctoRecipeCPEs = 100000

type yoctoRecipe struct {
	ref                     string // bom-ref in the engine conversion
	name, version, supplier string
	license, purl           string
	cpes                    []string
	cpesRead, ownCPEs       bool // ownCPEs: the recipe names CPEs itself
	seenCPE                 map[string]bool
}

type yoctoRecipes struct {
	list    []*yoctoRecipe
	byID    map[string]*yoctoRecipe
	invalid map[string]bool     // recipes without a usable name
	links   map[string][]string // package key -> recipe bom-refs
	cpes    int
	dropped int // CPEs refused by the CycloneDX CPE checks
}

func newYoctoRecipes() *yoctoRecipes {
	return &yoctoRecipes{byID: map[string]*yoctoRecipe{}, invalid: map[string]bool{}, links: map[string][]string{}}
}

// get returns the recipe for id, building it on first use. created reports a
// first use. A recipe whose name is unusable yields nil: its packages keep
// their own identity.
func (s *yoctoRecipes) get(id string, build func() *yoctoRecipe) (*yoctoRecipe, bool, error) {
	if r := s.byID[id]; r != nil {
		return r, false, nil
	}
	if s.invalid[id] {
		return nil, false, nil
	}
	r := build()
	name, err := cleanString(r.name, "name", true)
	if err != nil {
		s.invalid[id] = true
		return nil, false, nil
	}
	r.name = name
	if v, err := cleanString(r.version, "version", false); err == nil && !strings.EqualFold(v, "NOASSERTION") {
		r.version = v
	} else {
		r.version = ""
	}
	if r.purl != "" {
		if p, err := cleanPURL(r.purl); err == nil {
			r.purl = p
		} else {
			r.purl = ""
		}
	}
	if len(s.list) >= maxComponents {
		return nil, false, errors.New("component inventory exceeds 50000 entries")
	}
	r.ref = fmt.Sprintf("cracken-yocto-recipe-%d", len(s.list)+1)
	r.seenCPE = map[string]bool{}
	s.byID[id] = r
	s.list = append(s.list, r)
	return r, true, nil
}

// link records that the package (by component key) comes from the recipe.
// The recipe's own CPEs win; a recipe without any takes the CPEs its
// packages carried, so no identity is lost when they are removed there.
func (s *yoctoRecipes) link(pkgKey string, r *yoctoRecipe, recipeCPEs, packageCPEs []string) error {
	for _, ref := range s.links[pkgKey] {
		if ref == r.ref {
			return nil
		}
	}
	s.links[pkgKey] = append(s.links[pkgKey], r.ref)
	if !r.cpesRead {
		r.cpesRead = true
		if len(recipeCPEs) > 0 {
			r.ownCPEs = true
			return s.addCPEs(r, recipeCPEs)
		}
	}
	if !r.ownCPEs {
		return s.addCPEs(r, packageCPEs)
	}
	return nil
}

func (s *yoctoRecipes) addCPEs(r *yoctoRecipe, cpes []string) error {
	for _, c := range cpes {
		clean, err := cleanCPE(c)
		if err != nil {
			s.dropped++
			continue
		}
		if r.seenCPE[clean] {
			continue
		}
		if s.cpes++; s.cpes > maxYoctoRecipeCPEs {
			return fmt.Errorf("the Yocto SPDX names more than %d recipe CPEs; refused to protect memory, the input looks malformed", maxYoctoRecipeCPEs)
		}
		r.seenCPE[clean] = true
		r.cpes = append(r.cpes, clean)
	}
	return nil
}

func (s *yoctoRecipes) warnings() []string {
	if s.dropped == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d recipe CPE(s) that are not valid CPE 2.2/2.3 strings were left out.", s.dropped)}
}

func (r *yoctoRecipe) component() map[string]any {
	c := map[string]any{"type": "library", "bom-ref": r.ref, "name": r.name}
	if r.version != "" {
		c["version"] = r.version
	}
	if len(r.cpes) > 0 {
		c["cpe"] = r.cpes[0]
		if len(r.cpes) > 1 {
			identity := make([]any, 0, len(r.cpes)-1)
			for _, alias := range r.cpes[1:] {
				identity = append(identity, map[string]any{"field": "cpe", "concludedValue": alias})
			}
			c["evidence"] = map[string]any{"identity": identity}
		}
	}
	if r.purl != "" {
		c["purl"] = r.purl
	}
	if r.supplier != "" {
		c["supplier"] = map[string]any{"name": r.supplier}
	}
	if r.license != "" {
		c["licenses"] = []any{map[string]any{"expression": r.license}}
	}
	return c
}

// inject adds the recipe components to the engine conversion and turns each
// linked package's CPE into a link to its recipe.
func (s *yoctoRecipes) inject(raw []byte) ([]byte, error) {
	if len(s.list) == 0 {
		return raw, nil
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil, errors.New("the engine conversion is not valid CycloneDX JSON")
	}
	list, _ := doc["components"].([]any)
	for _, v := range list {
		c, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("malformed converted component")
		}
		ref, _ := c["bom-ref"].(string)
		links := s.links[componentKey(ref)]
		if len(links) == 0 {
			continue
		}
		delete(c, "cpe")
		props, _ := c["properties"].([]any)
		kept := []any{}
		for _, p := range props {
			// Syft writes further CPEs as syft:cpe23 properties.
			if m, ok := p.(map[string]any); ok && m["name"] == "syft:cpe23" {
				continue
			}
			kept = append(kept, p)
		}
		for _, l := range links {
			kept = append(kept, map[string]any{"name": yoctoRecipeProperty, "value": l})
		}
		c["properties"] = kept
	}
	for _, r := range s.list {
		list = append(list, r.component())
	}
	doc["components"] = list
	return json.Marshal(doc)
}

// spdxAgentName reads the name of an SPDX 2 agent string such as
// "Organization: OpenEmbedded ()" or "Person: Jane Doe (jane@example.com)".
// The e-mail part is never kept. Unusable values yield "".
func spdxAgentName(s string) string {
	for _, prefix := range []string{"Organization:", "Person:"} {
		if strings.HasPrefix(s, prefix) {
			name := strings.TrimSpace(strings.TrimPrefix(s, prefix))
			if strings.HasSuffix(name, ")") {
				if i := strings.LastIndex(name, "("); i >= 0 {
					name = strings.TrimSpace(name[:i])
				}
			}
			if clean, err := cleanString(name, "supplier name", false); err == nil {
				return clean
			}
			return ""
		}
	}
	return ""
}

// recipeLicense keeps a declared licence expression only when the minimizer
// will accept it, so a recipe can never fail the run for its licence.
func recipeLicense(expr string) string {
	if expr == "" || expr == "NOASSERTION" || expr == "NONE" {
		return ""
	}
	check, _ := rewriteDocumentLicenseRefs(expr)
	if len(check) > 1024 || !licenseExpressionPattern.MatchString(check) || suspiciousString(check) || strings.Contains(check, "..") {
		return ""
	}
	return expr
}

// recipeTargets maps an SPDX element named by a VEX assessment to the
// components it applies to: a recipe to its component; a package to its
// recipes, or to itself when it has none.
func (s *yoctoRecipes) recipeTargets(id string, selected bool) []string {
	if r := s.byID[id]; r != nil {
		return []string{r.ref}
	}
	if !selected {
		return nil
	}
	if links := s.links[id]; len(links) > 0 {
		return links
	}
	return []string{id}
}
