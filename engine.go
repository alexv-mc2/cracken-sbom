package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const engineVersion = "1.54.0"

// All network enrichment is explicitly disabled. Remaining defaults are bound
// by the exact engine version and authenticated per-platform binary digest.
// Keep missing identities so normalization can fail or report incompleteness;
// never allow the engine to silently drop them or invent UNKNOWN versions.
const engineConfig = `check-for-app-update: false
enrich: [none]
parallelism: 4
scope: squashed
compliance:
  missing-name: keep
  missing-version: keep
cpp:
  vcpkg-allow-git-clone: false
golang:
  search-local-mod-cache-licenses: false
  search-local-vendor-licenses: false
  search-remote-licenses: false
  use-packages-lib: false
java:
  use-network: false
  use-maven-local-repository: false
  resolve-transitive-dependencies: false
javascript:
  search-remote-licenses: false
  include-dev-dependencies: true
python:
  search-remote-licenses: false
  guess-unpinned-requirements: false
file:
  metadata:
    selection: none
  content:
    globs: []
license:
  content: none
`

//go:embed engine-manifest.json
var engineManifestJSON []byte

type engineManifest struct {
	Version      string            `json:"version"`
	BinarySHA256 map[string]string `json:"binary_sha256"`
}

type engineRunner func(context.Context, string, string, string) ([]byte, error)

const maxEngineOutput = 64 << 20

// Canonical JSON binds the policy, engine-bound defaults, and non-path scan
// options. Local paths and the temporary execution environment are deliberately
// omitted; asserted target identity is recorded separately in provenance.
func configurationDigest(targetType string) string {
	source := targetType
	if source == "rootfs" || source == "npm" || source == "python" {
		source = "dir"
	}
	policy := struct {
		EngineVersion    string `json:"engine_version"`
		Configuration    string `json:"configuration"`
		OutputFormat     string `json:"output_format"`
		SourceKind       string `json:"source_kind"`
		Scope            string `json:"scope"`
		PrivacyProfile   string `json:"privacy_profile"`
		GeneratorVersion string `json:"generator_version"`
	}{engineVersion, engineConfig, "cyclonedx-json@1.5", source, "squashed", privacyProfile, toolVersion}
	data, _ := json.Marshal(policy)
	return sha256Hex(data)
}

// cappedBuffer bounds memory independently of the target or child process.
// Child diagnostics are intentionally never returned: they can contain paths,
// package metadata, source text or credentials from the scanned target.
type cappedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.overflow = true
		return 0, errors.New("engine output limit exceeded")
	}
	return b.Buffer.Write(p)
}

func isolatedEnvironment(dir string) []string {
	return []string{
		"PATH=/usr/bin:/bin", "HOME=" + dir, "XDG_CONFIG_HOME=" + dir,
		"XDG_CACHE_HOME=" + dir, "TMPDIR=" + dir, "LANG=C", "LC_ALL=C",
		"HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1",
		"ALL_PROXY=http://127.0.0.1:1", "NO_PROXY=",
		"GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local",
	}
}

func verifyEngine(path string, manifest engineManifest) error {
	if manifest.Version != engineVersion {
		return errors.New("invalid embedded engine manifest")
	}
	expected := manifest.BinarySHA256[runtime.GOOS+"_"+runtime.GOARCH]
	if len(expected) != 64 {
		return errors.New("unsupported engine platform")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return errors.New("invalid embedded engine digest")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open engine binary")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return errors.New("engine must be a regular executable file")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("engine binary digest does not match authenticated pin")
	}
	return nil
}

func runEngine(ctx context.Context, binary, target, targetType string) ([]byte, error) {
	var manifest engineManifest
	if json.Unmarshal(engineManifestJSON, &manifest) != nil {
		return nil, errors.New("invalid embedded engine manifest")
	}
	return runEngineWithManifest(ctx, binary, target, targetType, manifest)
}

func runEngineWithManifest(ctx context.Context, binary, target, targetType string, manifest engineManifest) ([]byte, error) {
	work, err := os.MkdirTemp("", "cracken-sbom-engine-")
	if err != nil {
		return nil, errors.New("cannot create isolated engine workspace")
	}
	defer os.RemoveAll(work)
	work, err = filepath.EvalSymlinks(work)
	if err != nil {
		return nil, errors.New("cannot resolve isolated engine workspace")
	}
	// Copy once into a private directory, authenticate the copy, and execute only
	// that copy. Replacement of the supplied path cannot change scanned code.
	input, err := os.Open(binary)
	if err != nil {
		return nil, errors.New("cannot open engine binary")
	}
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		input.Close()
		return nil, errors.New("engine must be a regular executable file")
	}
	privateBinary := filepath.Join(work, "syft")
	copyFile, err := os.OpenFile(privateBinary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		input.Close()
		return nil, errors.New("cannot isolate engine binary")
	}
	copied, copyErr := io.Copy(copyFile, io.LimitReader(input, 256<<20+1))
	closeErr := copyFile.Close()
	input.Close()
	if copyErr != nil || closeErr != nil || copied > 256<<20 {
		return nil, errors.New("cannot isolate engine binary within safety limit")
	}
	if err := verifyEngine(privateBinary, manifest); err != nil {
		return nil, err
	}
	binary = privateBinary
	config := filepath.Join(work, "config.yaml")
	if os.WriteFile(config, []byte(engineConfig), 0600) != nil {
		return nil, errors.New("cannot prepare isolated engine configuration")
	}
	versionCtx, cancelVersion := context.WithTimeout(ctx, 15*time.Second)
	defer cancelVersion()
	versionCmd := exec.CommandContext(versionCtx, binary, "version", "-o", "json", "--config", config)
	versionCmd.Dir, versionCmd.Env = work, isolatedEnvironment(work)
	versionOut := &cappedBuffer{limit: 64 << 10}
	versionCmd.Stdout, versionCmd.Stderr = versionOut, io.Discard
	versionCmd.WaitDelay = 2 * time.Second
	if versionCmd.Start() != nil {
		return nil, errors.New("cannot start isolated engine; ensure the temporary filesystem permits executable files (check noexec)")
	}
	if versionCmd.Wait() != nil || versionOut.overflow {
		return nil, errors.New("cannot verify pinned engine version")
	}
	var identity struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(versionOut.Bytes(), &identity) != nil || strings.TrimPrefix(identity.Version, "v") != engineVersion {
		return nil, errors.New("engine version does not match exact pin")
	}
	source := targetType
	switch targetType {
	case "rootfs", "npm", "python":
		source = "dir"
	case "oci-archive", "docker-archive":
	default:
		return nil, errors.New("unsupported local target type")
	}
	args := []string{"scan", source + ":" + target, "--config", config, "--output", "cyclonedx-json@1.5", "--quiet"}
	if source == "dir" {
		args = append(args, "--base-path", target)
	}
	scanCtx, cancelScan := context.WithTimeout(ctx, 10*time.Minute)
	defer cancelScan()
	cmd := exec.CommandContext(scanCtx, binary, args...)
	cmd.Dir, cmd.Env = work, isolatedEnvironment(work)
	out := &cappedBuffer{limit: maxEngineOutput}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if scanCtx.Err() != nil {
			return nil, errors.New("engine scan timed out or was cancelled")
		}
		if out.overflow {
			return nil, errors.New("engine output exceeds 64 MiB safety limit")
		}
		return nil, errors.New("engine scan failed; no output was published")
	}
	return out.Bytes(), nil
}
