package main

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Limits for hashing cataloged files below a scanned directory.
const maxHashedFileBytes = 2 << 30
const maxHashedTotalBytes = 16 << 30

// sha512File hashes a regular file. Symbolic links are not followed.
func sha512File(file string, limit int64) (string, int64, error) {
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() {
		return "", 0, errors.New("not a regular file")
	}
	if info.Size() > limit {
		return "", 0, errors.New("file exceeds the hashing limit")
	}
	f, err := os.Open(file)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha512.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n > limit {
		return "", 0, errors.New("cannot hash file")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// insideRoot maps an engine location such as "/usr/bin/busybox" to a regular
// file below root. Links may resolve only to targets inside root; anything
// else is ignored rather than followed.
func insideRoot(root, location string) (string, bool) {
	if root == "" || !strings.HasPrefix(location, "/") || strings.ContainsAny(location, "\\\x00") {
		return "", false
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	clean := path.Clean(location)
	if clean == "/" || strings.Contains(clean, "/../") || strings.HasSuffix(clean, "/..") {
		return "", false
	}
	full := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(clean, "/")))
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	info, err := os.Lstat(real)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return real, true
}

// safeFilename returns a file name (never a path) that passes the component
// string checks, or "".
func safeFilename(name string) string {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return ""
	}
	clean, err := cleanString(name, "filename", false)
	if err != nil {
		return ""
	}
	return clean
}
