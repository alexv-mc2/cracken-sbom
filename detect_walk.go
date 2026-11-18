package main

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// The detect walker looks at file names only. It never follows symbolic
// links, never reads file contents, and stops at fixed depth and entry limits
// so a huge root filesystem or a mounted drive cannot stall detection.

type globKind int

const (
	globOther     globKind = iota // binaries and archives: never used to choose a target
	globOS                        // operating-system package database: a root filesystem
	globDeclared                  // project manifest or lockfile
	globInstalled                 // installed language packages
)

// detectGlob is one row of the table generated from the pinned Syft.
type detectGlob struct {
	Ecosystem string
	Cataloger string
	Kind      globKind
	Pattern   string
}

type walkLimits struct {
	MaxDepth   int
	MaxEntries int
}

var defaultWalkLimits = walkLimits{MaxDepth: 10, MaxEntries: 100000}

// Folders that only repeat what a lockfile already states, or hold version
// control data. Syft still scans them; detection does not need them.
var walkSkipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "node_modules": true}

type globHit struct {
	Glob detectGlob
	Rel  string // slash-separated path below the walked folder
}

type walkResult struct {
	Hits        []globHit
	Dockerfiles []string // relative paths
	TopFiles    []string // regular files directly in the folder
	Entries     int
	Truncated   bool
}

func walkFolder(ctx context.Context, root string, limits walkLimits, table []detectGlob) (walkResult, error) {
	var res walkResult
	errStop := errors.New("stop")
	// Index by the pattern's last segment so each file is compared only with
	// the patterns that can match its name.
	literal, wildcard := map[string][]detectGlob{}, []detectGlob{}
	for _, g := range table {
		last := g.Pattern[strings.LastIndex(g.Pattern, "/")+1:]
		if strings.ContainsAny(last, "*?[") {
			wildcard = append(wildcard, g)
		} else {
			literal[last] = append(literal[last], g)
		}
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			if p == root {
				return err
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir // unreadable folder: skip it, keep walking
			}
			return nil
		}
		if p == root {
			return nil
		}
		res.Entries++
		if res.Entries > limits.MaxEntries {
			res.Truncated = true
			return errStop
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		depth := strings.Count(rel, "/") + 1
		if d.IsDir() {
			if walkSkipDirs[d.Name()] || depth >= limits.MaxDepth {
				if depth >= limits.MaxDepth {
					res.Truncated = true
				}
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symbolic links, devices, sockets: never followed or read
		}
		if depth == 1 {
			res.TopFiles = append(res.TopFiles, rel)
		}
		if depth <= 3 && isDockerfileName(d.Name()) {
			res.Dockerfiles = append(res.Dockerfiles, rel)
		}
		for _, g := range literal[d.Name()] {
			if globMatch(g.Pattern, rel) {
				res.Hits = append(res.Hits, globHit{Glob: g, Rel: rel})
			}
		}
		for _, g := range wildcard {
			last := g.Pattern[strings.LastIndex(g.Pattern, "/")+1:]
			if ok, _ := path.Match(last, d.Name()); ok && globMatch(g.Pattern, rel) {
				res.Hits = append(res.Hits, globHit{Glob: g, Rel: rel})
			}
		}
		return nil
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	return res, err
}

// globMatch implements the doublestar subset Syft's capability globs use:
// "**" matches zero or more path segments; other segments use path.Match.
// A pattern without a slash is matched against the file name.
func globMatch(pattern, rel string) bool {
	if !strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, path.Base(rel))
		return ok
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchSegments(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			for i := 0; i <= len(segs); i++ {
				if matchSegments(rest, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], segs[0]); !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

func isDockerfileName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "dockerfile" || lower == "containerfile" ||
		strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile")
}
