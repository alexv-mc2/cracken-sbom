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

const engineVersion = "1.55.0"

// BSI TR-03183-2 v2.1.0 requires CycloneDX 1.6 or later. Syft's default is
// newer (1.7), which crAcken's VEX import refuses, so the version is pinned.
const engineOutputFormat = "cyclonedx-json@1.6"

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

// engines adapts the scan function (replaceable in tests) and the convert
// function to the EngineRunner interface extensions use.
type engines struct {
	scan    engineRunner
	convert func(context.Context, string, string) ([]byte, error)
}

func (e engines) Scan(ctx context.Context, binary, target, source string) ([]byte, error) {
	if e.scan == nil {
		return nil, errors.New("engine scan is not available")
	}
	return e.scan(ctx, binary, target, source)
}

func (e engines) Convert(ctx context.Context, binary, inputFile string) ([]byte, error) {
	if e.convert == nil {
		return nil, errors.New("engine convert is not available")
	}
	return e.convert(ctx, binary, inputFile)
}

const maxEngineOutput = 64 << 20

// Canonical JSON binds the policy, engine-bound defaults, and non-path scan
// options. Local paths and the temporary execution environment are deliberately
// omitted; asserted target identity is recorded separately in provenance.
func configurationDigest(targetType string) string {
	source := targetType
	if source == "rootfs" || source == "npm" || source == "python" || source == firmwareTargetType {
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
	}{engineVersion, engineConfig, engineOutputFormat, source, "squashed", privacyProfile, toolVersion}
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
	source := targetType
	switch targetType {
	case "dir", "rootfs", "npm", "python":
		source = "dir"
	case "oci-archive", "docker-archive":
	default:
		return nil, errors.New("unsupported local target type")
	}
	args := []string{"scan", source + ":" + target, "--output", engineOutputFormat, "--quiet"}
	if source == "dir" {
		args = append(args, "--base-path", target)
	}
	return runIsolatedEngine(ctx, binary, manifest, args, "engine scan")
}

// runConvert converts a local SBOM file (SPDX 2.x or 3.0 JSON, or another
// format Syft decodes) to CycloneDX 1.6 with the same authenticated engine.
func runConvert(ctx context.Context, binary, inputFile string) ([]byte, error) {
	var manifest engineManifest
	if json.Unmarshal(engineManifestJSON, &manifest) != nil {
		return nil, errors.New("invalid embedded engine manifest")
	}
	return runConvertWithManifest(ctx, binary, inputFile, manifest)
}

func runConvertWithManifest(ctx context.Context, binary, inputFile string, manifest engineManifest) ([]byte, error) {
	if !filepath.IsAbs(inputFile) || strings.HasPrefix(filepath.Base(inputFile), "-") {
		return nil, errors.New("convert input must be an absolute local file path")
	}
	info, err := os.Lstat(inputFile)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("convert input must be an existing regular file")
	}
	return runIsolatedEngine(ctx, binary, manifest, []string{"convert", inputFile, "--output", engineOutputFormat, "--quiet"}, "engine convert")
}

// runIsolatedEngine copies the engine into a private directory, authenticates
// the copy, verifies its exact version and runs it with the fixed policy.
func runIsolatedEngine(ctx context.Context, binary string, manifest engineManifest, args []string, what string) ([]byte, error) {
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
	// The subcommand and its first operand stay first; the fixed configuration
	// follows so that test doubles can check positional arguments.
	full := append([]string{args[0], args[1], "--config", config}, args[2:]...)
	runCtx, cancelRun := context.WithTimeout(ctx, 10*time.Minute)
	defer cancelRun()
	cmd := exec.CommandContext(runCtx, binary, full...)
	cmd.Dir, cmd.Env = work, isolatedEnvironment(work)
	out := &cappedBuffer{limit: maxEngineOutput}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if runCtx.Err() != nil {
			return nil, errors.New(what + " timed out or was cancelled")
		}
		if out.overflow {
			return nil, errors.New("engine output exceeds 64 MiB safety limit")
		}
		return nil, errors.New(what + " failed; no output was published")
	}
	return out.Bytes(), nil
}
