// Lockfile SHA-512 extraction for the BSI TR-03183-2 deployable hash.
//
// Adapted from kunnus-scanner (https://github.com/think-ahead-technologies/kunnus-scanner,
// commit 31e1bf9dcc2c3d87de9fe00569a451d7c12bbcb0, internal/ecosystem/npm.go,
// npm_packagelock.go, npm_yarnlock.go and npm_bunlock.go), Copyright the
// kunnus-scanner authors, licensed under the Apache License, Version 2.0.
// Changes: standard library only (bun.lock comments and trailing commas are
// stripped by a small scanner instead of tidwall/jsonc); keys are name@version
// instead of purls; yarn berry "checksum" values are not used because they
// hash Yarn's cache archive, not the published tarball; the registry download
// URL is kept only for the public npm registry. See NOTICE.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path"
	"strings"
)

const maxLockfileBytes = 64 << 20

// lockEntry is the published tarball of one npm package version.
type lockEntry struct {
	SHA512   string // lowercase hex
	Filename string // tarball file name, e.g. left-pad-1.3.0.tgz
	URL      string // set only for the public registry
}

type lockIndex map[string]lockEntry

func lockKey(name, version string) string { return name + "@" + version }

// decodeSRI turns "sha512-<base64>" into lowercase hex.
func decodeSRI(sri string) (string, error) {
	sri = strings.TrimSpace(sri)
	// An SRI value may list several hashes; use the first SHA-512 one.
	for _, part := range strings.Fields(sri) {
		if !strings.HasPrefix(part, "sha512-") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(part, "sha512-"))
		if err != nil || len(raw) != sha512.Size {
			return "", errors.New("invalid sha512 integrity")
		}
		return hex.EncodeToString(raw), nil
	}
	return "", errors.New("integrity is not sha512")
}

var publicNPMRegistries = map[string]bool{"registry.npmjs.org": true, "registry.yarnpkg.com": true}

// tarballFacts derives the file name from a resolved URL and keeps the URL
// only when it points at a public registry without credentials or query.
func tarballFacts(resolved, name, version string) (filename, publicURL string) {
	if u, err := url.Parse(resolved); err == nil && u.Path != "" {
		filename = safeFilename(path.Base(u.Path))
		if u.Scheme == "https" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && publicNPMRegistries[u.Host] && filename != "" {
			publicURL = "https://" + u.Host + u.EscapedPath()
		}
	}
	if filename == "" || !strings.HasSuffix(filename, ".tgz") {
		// npm's own tarball naming for unscoped and scoped packages.
		base := name
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		filename = safeFilename(base + "-" + version + ".tgz")
		publicURL = ""
	}
	return filename, publicURL
}

func (idx lockIndex) add(name, version, integrity, resolved string) {
	if name == "" || version == "" || integrity == "" {
		return
	}
	digest, err := decodeSRI(integrity)
	if err != nil {
		return
	}
	filename, publicURL := tarballFacts(resolved, name, version)
	idx[lockKey(name, version)] = lockEntry{SHA512: digest, Filename: filename, URL: publicURL}
}

// parseNPMLock reads package-lock.json / npm-shrinkwrap.json v1, v2 and v3.
func parseNPMLock(data []byte, idx lockIndex) error {
	type v1Dep struct {
		Version      string           `json:"version"`
		Resolved     string           `json:"resolved"`
		Integrity    string           `json:"integrity"`
		Dependencies map[string]v1Dep `json:"dependencies"`
	}
	var lock struct {
		Packages map[string]struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
			Link      bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]v1Dep `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return errors.New("malformed npm lockfile")
	}
	for installPath, entry := range lock.Packages {
		const marker = "node_modules/"
		i := strings.LastIndex(installPath, marker)
		if installPath == "" || entry.Link || i < 0 {
			continue
		}
		name := entry.Name
		if name == "" {
			name = installPath[i+len(marker):]
		}
		idx.add(name, entry.Version, entry.Integrity, entry.Resolved)
	}
	var walk func(map[string]v1Dep, int)
	walk = func(deps map[string]v1Dep, depth int) {
		if depth > 64 {
			return
		}
		for name, entry := range deps {
			idx.add(name, entry.Version, entry.Integrity, entry.Resolved)
			walk(entry.Dependencies, depth+1)
		}
	}
	walk(lock.Dependencies, 0)
	return nil
}

// parseYarnV1Lock reads yarn.lock v1 blocks ("integrity sha512-...").
func parseYarnV1Lock(data []byte, idx lockIndex) error {
	var header, version, integrity, resolved string
	flush := func() {
		if header == "" {
			return
		}
		spec := strings.TrimSpace(strings.SplitN(strings.TrimSuffix(header, ":"), ",", 2)[0])
		spec = strings.Trim(spec, `"`)
		if name, _, ok := splitNPMSpec(spec); ok {
			idx.add(name, version, integrity, resolved)
		}
		header, version, integrity, resolved = "", "", "", ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "":
			flush()
		case !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t"):
			flush()
			header = strings.TrimSpace(line)
		default:
			body := strings.TrimSpace(line)
			unquote := func(s string) string { return strings.Trim(strings.TrimSpace(s), `"`) }
			switch {
			case strings.HasPrefix(body, "version "):
				version = unquote(strings.TrimPrefix(body, "version "))
			case strings.HasPrefix(body, "integrity "):
				integrity = unquote(strings.TrimPrefix(body, "integrity "))
			case strings.HasPrefix(body, "resolved "):
				resolved = strings.SplitN(unquote(strings.TrimPrefix(body, "resolved ")), "#", 2)[0]
			}
		}
	}
	flush()
	return scanner.Err()
}

// splitNPMSpec splits "name@range" and "@scope/name@range".
func splitNPMSpec(spec string) (name, rest string, ok bool) {
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	i := strings.Index(spec[start:], "@")
	if i < 0 {
		return "", "", false
	}
	return spec[:start+i], spec[start+i+1:], spec[:start+i] != ""
}

// parseBunLock reads bun.lock: JSONC whose packages map holds tuples
// [ "<name>@<version>", "<resolution>", {<deps>}, "<integrity>" ].
func parseBunLock(data []byte, idx lockIndex) error {
	var lock struct {
		Packages map[string][]any `json:"packages"`
	}
	if err := json.Unmarshal(stripJSONC(data), &lock); err != nil {
		return errors.New("malformed bun lockfile")
	}
	for _, tuple := range lock.Packages {
		if len(tuple) < 4 {
			continue
		}
		spec, _ := tuple[0].(string)
		integrity, _ := tuple[3].(string)
		if name, version, ok := splitNPMSpec(spec); ok {
			idx.add(name, version, integrity, "")
		}
	}
	return nil
}

// stripJSONC removes // and /* */ comments and trailing commas outside strings.
func stripJSONC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++
		case c == ']' || c == '}':
			// Drop a trailing comma before the closing bracket.
			j := len(out) - 1
			for j >= 0 && (out[j] == ' ' || out[j] == '\n' || out[j] == '\r' || out[j] == '\t') {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// lockfileParsers maps lockfile names that Syft reports as package
// locations to their SHA-512 extractors. pnpm-lock.yaml is not read: it would
// need a YAML parser and this module stays dependency-free.
var lockfileParsers = map[string]func([]byte, lockIndex) error{
	"package-lock.json":   parseNPMLock,
	"npm-shrinkwrap.json": parseNPMLock,
	"yarn.lock":           parseYarnV1Lock,
	"bun.lock":            parseBunLock,
}

// loadLockIndexes parses each lockfile named by a component location once.
// Unreadable or malformed lockfiles are skipped: hashes are then missing and
// reported as a TR gap, never invented.
func loadLockIndexes(root string, hints map[string]*componentHints) map[string]lockIndex {
	out := map[string]lockIndex{}
	for _, h := range hints {
		if h == nil || h.Location == "" {
			continue
		}
		if _, done := out[h.Location]; done {
			continue
		}
		parser, ok := lockfileParsers[path.Base(h.Location)]
		if !ok {
			continue
		}
		idx := lockIndex{}
		out[h.Location] = idx
		file, ok := insideRoot(root, h.Location)
		if !ok {
			continue
		}
		info, err := os.Lstat(file)
		if err != nil || info.Size() > maxLockfileBytes {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		_ = parser(data, idx)
	}
	return out
}
