package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const maxComponents = 50000
const maxSBOMBytes = 10 * 1024 * 1024

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]*$`)
var purlQualifierVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_~:-]*$`)
var licenseExpressionPattern = regexp.MustCompile(`^[A-Za-z0-9(][A-Za-z0-9.+_() -]*$`)
var credentialPattern = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|credential|authorization)\s*[:=]`)

// The output's exact CycloneDX 1.5 schema, not the engine's newer SPDX list,
// decides which license.id values are valid. This is data, not a scanner.
//
//go:embed tests/schema/spdx.schema.json
var spdxSchemaJSON []byte

var supportedSPDXIDs = func() map[string]bool {
	var schema struct {
		Enum []string `json:"enum"`
	}
	if json.Unmarshal(spdxSchemaJSON, &schema) != nil || len(schema.Enum) == 0 {
		panic("invalid embedded SPDX identifier schema")
	}
	ids := make(map[string]bool, len(schema.Enum))
	for _, id := range schema.Enum {
		ids[id] = true
	}
	return ids
}()

// These checks deliberately do not echo the rejected value: engine output may
// contain credentials or local paths. Omitted fields never reach this function.
func suspiciousString(s string) bool {
	if strings.Contains(s, "://") || strings.Contains(s, "\\") || strings.Contains(s, "~/") || credentialPattern.MatchString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func cleanString(v any, field string, allowScope bool) (string, error) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) != s || s == "" || len(s) > 1024 || suspiciousString(s) {
		return "", fmt.Errorf("unsafe or malformed component %s", field)
	}
	decoded, err := url.PathUnescape(s)
	if err != nil || suspiciousString(decoded) {
		return "", fmt.Errorf("unsafe component %s", field)
	}
	check := decoded
	if field == "cpe" && strings.HasPrefix(check, "cpe:/") {
		check = strings.TrimPrefix(check, "cpe:/")
	}
	if strings.Contains(check, "/") {
		parts := strings.Split(check, "/")
		if !allowScope || len(parts) < 2 {
			return "", fmt.Errorf("unsafe component %s", field)
		}
		for i, part := range parts {
			if i == 0 {
				part = strings.TrimPrefix(part, "@")
			}
			if !identifierPattern.MatchString(part) {
				return "", fmt.Errorf("unsafe component %s", field)
			}
		}
		switch strings.ToLower(parts[0]) {
		case "home", "users", "tmp", "private", "var", "etc", "usr", "root":
			return "", fmt.Errorf("local path in component %s", field)
		}
	}
	// A Debian epoch such as 1:1.35.0-4+b3 is package identity. A letter
	// followed by a colon remains a Windows drive prefix, even when encoded.
	if strings.Contains(check, "..") || strings.HasPrefix(check, ".") || (len(check) > 2 && ((check[0] >= 'a' && check[0] <= 'z') || (check[0] >= 'A' && check[0] <= 'Z')) && check[1] == ':' && field != "cpe") {
		return "", fmt.Errorf("unsafe component %s", field)
	}
	return s, nil
}

func cleanPURL(v any) (string, error) {
	s, ok := v.(string)
	if !ok || len(s) > 4096 || !strings.HasPrefix(s, "pkg:") {
		return "", errors.New("invalid component purl")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "pkg" || u.Host != "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("unsafe component purl")
	}
	identity, err := url.PathUnescape(u.Opaque)
	if err != nil || suspiciousString(identity) || strings.Contains(identity, "..") || strings.HasPrefix(identity, "/") || strings.ContainsAny(identity, " ?#") {
		return "", errors.New("unsafe component purl")
	}
	parts := strings.SplitN(identity, "/", 2)
	if len(parts) != 2 || !identifierPattern.MatchString(parts[0]) || parts[1] == "" || strings.HasPrefix(parts[1], "/") || strings.Contains(parts[1], "//") {
		return "", errors.New("invalid component purl identity")
	}
	for _, prefix := range []string{"home/", "Users/", "tmp/", "private/", "var/", "etc/"} {
		if strings.HasPrefix(parts[1], prefix) {
			return "", errors.New("local path in component purl identity")
		}
	}
	if colon := strings.Index(parts[1], ":"); colon >= 0 {
		// Epochs may occur after the version separator; user:password@... is unsafe.
		if at := strings.LastIndex(parts[1], "@"); at < 0 || colon < at {
			return "", errors.New("unsafe component purl identity")
		}
	}
	// A PURL namespace is ecosystem identity, not a filesystem path. Local path
	// qualifiers and unknown qualifiers are removed; clean ecosystem metadata stays.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("invalid component purl qualifiers")
	}
	clean := url.Values{}
	allowed := map[string]bool{"arch": true, "distro": true, "epoch": true, "type": true, "classifier": true, "extension": true, "os": true, "upstream": true}
	for key, vals := range q {
		if !allowed[key] {
			continue
		}
		if len(vals) != 1 {
			return "", errors.New("ambiguous component purl qualifier")
		}
		val := vals[0]
		if key == "upstream" {
			val, err = cleanUpstreamQualifier(val)
		} else {
			val, err = cleanString(val, "purl qualifier", false)
		}
		if err != nil || strings.Contains(val, "?") || (key != "upstream" && strings.Contains(val, "@")) {
			return "", errors.New("unsafe component purl qualifier")
		}
		clean.Set(key, val)
	}
	u.RawQuery = clean.Encode()
	return u.String(), nil
}

func cleanUpstreamQualifier(value string) (string, error) {
	if value == "" || len(value) > 1024 || strings.TrimSpace(value) != value || suspiciousString(value) || strings.ContainsAny(value, "/\\?#") || strings.Contains(value, "..") {
		return "", errors.New("unsafe component purl upstream qualifier")
	}
	parts := strings.Split(value, "@")
	if len(parts) > 2 || !identifierPattern.MatchString(parts[0]) {
		return "", errors.New("invalid component purl upstream qualifier")
	}
	if len(parts) == 2 {
		version := parts[1]
		if !purlQualifierVersionPattern.MatchString(version) || strings.HasPrefix(version, ".") {
			return "", errors.New("invalid component purl upstream version")
		}
		if colon := strings.IndexByte(version, ':'); colon >= 0 {
			if colon == 0 || colon == len(version)-1 || strings.IndexByte(version[colon+1:], ':') >= 0 {
				return "", errors.New("invalid component purl upstream version")
			}
			for _, r := range version[:colon] {
				if r < '0' || r > '9' {
					return "", errors.New("invalid component purl upstream version")
				}
			}
		}
	}
	return value, nil
}

// CPE formatted strings use backslash escapes as syntax, unlike ordinary
// package fields. Parse the attributes before applying the privacy checks so
// valid escaped version punctuation is preserved rather than treated as a path.
func cleanCPE(v any) (string, error) {
	s, ok := v.(string)
	if !ok || len(s) > 1024 || strings.TrimSpace(s) != s {
		return "", errors.New("invalid component cpe")
	}
	unsafe := func(value string) bool {
		return suspiciousString(value) || strings.Contains(value, "/") || strings.Contains(value, "..")
	}
	if strings.HasPrefix(s, "cpe:2.3:") {
		body := strings.TrimPrefix(s, "cpe:2.3:")
		attributes := []string{}
		var value strings.Builder
		for i := 0; i < len(body); i++ {
			ch := body[i]
			switch {
			case ch == ':':
				attributes = append(attributes, value.String())
				value.Reset()
			case ch == '\\':
				if i+1 >= len(body) {
					return "", errors.New("invalid component cpe escape")
				}
				i++
				// A literal slash/backslash is never needed for package CPE evidence;
				// it would reintroduce a path. Other escaped punctuation is valid.
				if !strings.ContainsRune(`!"#$%&'()+,-.:;<=>@[]^_`+"`"+`{|}~?*`, rune(body[i])) {
					return "", errors.New("unsafe component cpe escape")
				}
				value.WriteByte(body[i])
			case ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("_-.?*", rune(ch)):
				value.WriteByte(ch)
			default:
				return "", errors.New("invalid component cpe attribute")
			}
		}
		attributes = append(attributes, value.String())
		if len(attributes) != 11 || !(attributes[0] == "a" || attributes[0] == "h" || attributes[0] == "o" || attributes[0] == "*" || attributes[0] == "-") {
			return "", errors.New("invalid component cpe attributes")
		}
		for _, attr := range attributes {
			if attr == "" || unsafe(attr) {
				return "", errors.New("unsafe component cpe attribute")
			}
		}
		return s, nil
	}
	if strings.HasPrefix(s, "cpe:/") {
		attributes := strings.Split(strings.TrimPrefix(s, "cpe:/"), ":")
		if len(attributes) > 7 || !(attributes[0] == "a" || attributes[0] == "h" || attributes[0] == "o") {
			return "", errors.New("invalid component cpe attributes")
		}
		for _, raw := range attributes {
			attr, err := url.PathUnescape(raw)
			if err != nil || unsafe(attr) {
				return "", errors.New("unsafe component cpe attribute")
			}
			for _, ch := range raw {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("._-*~+%!", ch)) {
					return "", errors.New("invalid component cpe attribute")
				}
			}
		}
		return s, nil
	}
	return "", errors.New("invalid component cpe")
}

func normalizeComponent(c map[string]any, ref string, quality *Quality) (map[string]any, error) {
	typeName, ok := c["type"].(string)
	allowedTypes := map[string]bool{"application": true, "framework": true, "library": true, "container": true, "operating-system": true, "device": true, "firmware": true}
	if !ok || !allowedTypes[typeName] {
		return nil, errors.New("unsupported component type")
	}
	name, err := cleanString(c["name"], "name", true)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"type": typeName, "name": name, "bom-ref": ref}
	for _, field := range []string{"group", "version", "cpe"} {
		v, present := c[field]
		if !present || v == nil || v == "" {
			if field == "version" {
				quality.MissingVersions++
			}
			continue
		}
		var s string
		var err error
		if field == "cpe" {
			s, err = cleanCPE(v)
		} else {
			s, err = cleanString(v, field, false)
		}
		if err != nil {
			return nil, err
		}
		if field == "version" && strings.EqualFold(s, "UNKNOWN") {
			quality.MissingVersions++
			continue
		}
		out[field] = s
	}
	if v, exists := c["purl"]; exists {
		purl, err := cleanPURL(v)
		if err != nil {
			return nil, err
		}
		out["purl"] = purl
	}
	if v, exists := c["supplier"]; exists {
		supplier, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("malformed component supplier")
		}
		if n, exists := supplier["name"]; exists {
			name, err := cleanString(n, "supplier name", false)
			if err != nil {
				return nil, err
			}
			out["supplier"] = map[string]string{"name": name}
		}
	}
	hasLicense := false
	if v, exists := c["licenses"]; exists {
		list, ok := v.([]any)
		if !ok {
			return nil, errors.New("malformed component licenses")
		}
		if len(list) > 1 {
			quality.AmbiguousLicenses++
		}
		knownLicenses := []any{}
		expressionChoices := []string{}
		convertedIDs := 0
		for _, v := range list {
			entry, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("malformed component license entry")
			}
			if expr, exists := entry["expression"]; exists {
				s, ok := expr.(string)
				if !ok || len(s) > 1024 || !licenseExpressionPattern.MatchString(s) || suspiciousString(s) || strings.Contains(s, "..") {
					return nil, errors.New("unsafe license expression")
				}
				expressionChoices = append(expressionChoices, s)
			} else if lic, ok := entry["license"].(map[string]any); ok {
				// Keep identifiers only. License names/free text may embed source paths.
				if id, exists := lic["id"]; exists {
					s, ok := id.(string)
					if !ok || !identifierPattern.MatchString(s) {
						return nil, errors.New("unsafe license identifier")
					}
					if !supportedSPDXIDs[s] {
						expressionChoices = append(expressionChoices, s)
						convertedIDs++
						continue
					}
					knownLicenses = append(knownLicenses, map[string]any{"license": map[string]string{"id": s}})
				} else {
					quality.OmittedLicenseChoices++
					addWarning(quality, "A license choice without an SPDX identifier was omitted; license coverage is incomplete.")
				}
			} else {
				return nil, errors.New("malformed component license")
			}
		}
		licenses := knownLicenses
		switch {
		case len(knownLicenses) == 0 && len(expressionChoices) == 1:
			licenses = append(licenses, map[string]string{"expression": expressionChoices[0]})
			if convertedIDs == 1 {
				quality.ConvertedLicenseIDs++
				addWarning(quality, "An SPDX identifier outside the CycloneDX 1.5 identifier list was preserved as a license expression.")
			}
		case len(expressionChoices) > 0:
			quality.OmittedLicenseChoices += len(expressionChoices)
			if convertedIDs > 0 {
				addWarning(quality, "Unsupported SPDX identifiers were omitted because CycloneDX 1.5 cannot combine identifier expressions with other license choices.")
			}
			if len(expressionChoices) > convertedIDs {
				addWarning(quality, "License expressions were omitted because CycloneDX 1.5 permits only one expression and cannot combine it with license entries.")
			}
		}
		if len(licenses) > 0 {
			out["licenses"] = licenses
			hasLicense = true
		}
	}
	if !hasLicense {
		quality.MissingLicenses++
		addWarning(quality, "Package license identifiers are missing; license coverage is incomplete.")
	}
	if v, exists := c["hashes"]; exists {
		list, ok := v.([]any)
		if !ok {
			return nil, errors.New("malformed component hashes")
		}
		lengths := map[string]int{"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128, "SHA3-256": 64, "SHA3-384": 96, "SHA3-512": 128, "BLAKE2b-256": 64, "BLAKE2b-384": 96, "BLAKE2b-512": 128, "BLAKE3": 64}
		hashes := []any{}
		for _, v := range list {
			h, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("malformed component hash")
			}
			alg, a := h["alg"].(string)
			content, b := h["content"].(string)
			if !a || !b || lengths[alg] == 0 || len(content) != lengths[alg] {
				return nil, errors.New("invalid component hash")
			}
			for _, r := range content {
				if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
					return nil, errors.New("invalid component hash")
				}
			}
			hashes = append(hashes, map[string]string{"alg": alg, "content": content})
		}
		if len(hashes) > 0 {
			out["hashes"] = hashes
		}
	}
	return out, nil
}

func addWarning(quality *Quality, warning string) {
	for _, existing := range quality.Warnings {
		if existing == warning {
			return
		}
	}
	quality.Warnings = append(quality.Warnings, warning)
}

func normalizeSBOM(input []byte, ctx ProvenanceContext) ([]byte, Quality, error) {
	quality := Quality{Warnings: []string{}}
	ctx, err := validateContext(ctx)
	if err != nil {
		return nil, quality, err
	}
	var root map[string]any
	dec := json.NewDecoder(strings.NewReader(string(input)))
	if err := dec.Decode(&root); err != nil {
		return nil, quality, errors.New("malformed CycloneDX JSON")
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, quality, errors.New("trailing CycloneDX JSON data")
	}
	if root["bomFormat"] != "CycloneDX" || root["specVersion"] != "1.5" {
		return nil, quality, errors.New("only CycloneDX 1.5 is supported")
	}
	// CycloneDX permits omitting components entirely. Syft uses that valid
	// representation for an empty target; it must fail as empty, never clean.
	if _, exists := root["components"]; !exists {
		return nil, quality, errors.New("empty_sbom: no package components")
	}
	list, ok := root["components"].([]any)
	if !ok {
		return nil, quality, errors.New("missing or malformed component inventory")
	}
	components := []any{}
	refs := map[string]string{}
	seenRefs := map[string]bool{}
	// Iterative traversal mirrors the current extractor's depth-first inventory.
	stack := [][]any{list}
	for len(stack) > 0 {
		top := len(stack) - 1
		if len(stack[top]) == 0 {
			stack = stack[:top]
			continue
		}
		v := stack[top][0]
		stack[top] = stack[top][1:]
		c, ok := v.(map[string]any)
		if !ok {
			return nil, quality, errors.New("malformed component entry")
		}
		quality.InputComponents++
		if quality.InputComponents > maxComponents {
			return nil, quality, errors.New("component inventory exceeds 50000 entries")
		}
		oldRef := ""
		if r, exists := c["bom-ref"]; exists {
			oldRef, ok = r.(string)
			if !ok || oldRef == "" || seenRefs[oldRef] {
				return nil, quality, errors.New("invalid or duplicate component reference")
			}
			seenRefs[oldRef] = true
		}
		if c["type"] == "file" {
			quality.RemovedFiles++
		} else {
			ref := fmt.Sprintf("component-%d", len(components)+1)
			out, err := normalizeComponent(c, ref, &quality)
			if err != nil {
				return nil, quality, err
			}
			components = append(components, out)
			if oldRef != "" {
				refs[oldRef] = ref
			}
		}
		if children, exists := c["components"]; exists {
			children, ok := children.([]any)
			if !ok {
				return nil, quality, errors.New("malformed nested component inventory")
			}
			stack = append(stack, children)
		}
	}
	quality.EmittedComponents = len(components)
	if len(components) == 0 {
		return nil, quality, errors.New("empty_sbom: no package components")
	}
	if quality.MissingVersions > 0 {
		quality.Warnings = append(quality.Warnings, "Package versions are missing; inventory coverage is incomplete.")
	}
	if quality.AmbiguousLicenses > 0 {
		quality.Warnings = append(quality.Warnings, "Multiple license entries have ambiguous combined meaning; no operator was invented.")
	}
	dependencies := []any{}
	unresolved := false
	if v, exists := root["dependencies"]; exists {
		list, ok := v.([]any)
		if !ok {
			return nil, quality, errors.New("malformed dependency graph")
		}
		seenNodes := map[string]bool{}
		for _, v := range list {
			dep, ok := v.(map[string]any)
			if !ok {
				return nil, quality, errors.New("malformed dependency entry")
			}
			r, ok := dep["ref"].(string)
			if !ok {
				return nil, quality, errors.New("malformed dependency reference")
			}
			ref, exists := refs[r]
			if !exists {
				unresolved = true
				continue
			}
			if seenNodes[ref] {
				return nil, quality, errors.New("duplicate dependency node")
			}
			seenNodes[ref] = true
			edges := []string{}
			if v, exists := dep["dependsOn"]; exists {
				list, ok := v.([]any)
				if !ok {
					return nil, quality, errors.New("malformed dependency edges")
				}
				seen := map[string]bool{}
				for _, v := range list {
					r, ok := v.(string)
					if !ok {
						return nil, quality, errors.New("malformed dependency edge reference")
					}
					if rewritten, exists := refs[r]; exists {
						if !seen[rewritten] {
							edges = append(edges, rewritten)
							seen[rewritten] = true
						}
					} else {
						unresolved = true
					}
				}
			}
			sort.Strings(edges)
			dependencies = append(dependencies, map[string]any{"ref": ref, "dependsOn": edges})
		}
	}
	if unresolved {
		quality.Warnings = append(quality.Warnings, "Unresolved or removed dependency references were omitted; graph coverage is incomplete.")
	}
	properties := []any{}
	for _, p := range [][2]string{{"cracken:generator", "cracken-sbom"}, {"cracken:generator:version", ctx.ToolVersion}, {"cracken:engine", "syft"}, {"cracken:engine:version", ctx.EngineVersion}, {"cracken:configuration:sha256", ctx.ConfigDigest}, {"cracken:target:type", ctx.TargetType}, {"cracken:target:identifier", ctx.TargetIdentifier}, {"cracken:privacy:profile", privacyProfile}, {"cracken:provenance:status", "customer_asserted_local"}} {
		properties = append(properties, map[string]string{"name": p[0], "value": p[1]})
	}
	out := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components,
		"metadata": map[string]any{"timestamp": ctx.GeneratedAt, "tools": []any{map[string]string{"name": "cracken-sbom", "version": ctx.ToolVersion}, map[string]string{"name": "syft", "version": ctx.EngineVersion}}, "properties": properties}}
	if len(dependencies) > 0 {
		out["dependencies"] = dependencies
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, quality, errors.New("cannot encode minimized SBOM")
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxSBOMBytes {
		return nil, quality, errors.New("minimized SBOM exceeds 10 MiB upload limit")
	}
	return encoded, quality, nil
}
