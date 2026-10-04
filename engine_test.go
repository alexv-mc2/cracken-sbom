package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func mockEngine(t *testing.T, script string) (string, engineManifest) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "syft")
	data := []byte("#!/bin/sh\n" + script)
	if err := os.WriteFile(file, data, 0700); err != nil {
		t.Fatal(err)
	}
	return file, engineManifest{Version: engineVersion, BinarySHA256: map[string]string{runtime.GOOS + "_" + runtime.GOARCH: sha256Hex(data)}}
}

func TestEngineIgnoresAmbientConfigurationAndCredentials(t *testing.T) {
	t.Setenv("SYFT_CHECK_FOR_APP_UPDATE", "true")
	t.Setenv("SYFT_JAVA_USE_NETWORK", "true")
	t.Setenv("SYFT_CONFIG", "/private/ambient.yaml")
	t.Setenv("GITHUB_TOKEN", "do-not-inherit")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "do-not-inherit")
	t.Setenv("HOME", "/private/ambient-home")
	file, manifest := mockEngine(t, `
test -z "$SYFT_CHECK_FOR_APP_UPDATE$SYFT_JAVA_USE_NETWORK$SYFT_CONFIG$GITHUB_TOKEN$AWS_SECRET_ACCESS_KEY" || exit 22
test "$HOME" = "$PWD" || exit 23
test "$HTTPS_PROXY" = "http://127.0.0.1:1" || exit 24
if [ "$1" = "version" ]; then
  printf '{"version":"1.54.0"}'
  exit 0
fi
test "$1" = "scan" || exit 25
test "$2" = 'dir:/local/rootfs' || exit 26
test "$3" = '--config' || exit 27
grep -q 'check-for-app-update: false' "$4" || exit 28
grep -q 'vcpkg-allow-git-clone: false' "$4" || exit 29
grep -q 'missing-version: keep' "$4" || exit 30
test "$5" = '--output' || exit 31
test "$6" = 'cyclonedx-json@1.5' || exit 32
test "$8" = '--base-path' || exit 33
test "$9" = '/local/rootfs' || exit 34
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}'
`)
	out, err := runEngineWithManifest(context.Background(), file, "/local/rootfs", "rootfs", manifest)
	if err != nil || !bytes.Contains(out, []byte("CycloneDX")) {
		t.Fatalf("isolated engine: %v", err)
	}
}

func TestEngineEnforcesAuthenticatedBinaryAndExactVersion(t *testing.T) {
	file, manifest := mockEngine(t, `printf '{"version":"1.54.1"}'`)
	if _, err := runEngineWithManifest(context.Background(), file, "/fixture", "rootfs", manifest); err == nil {
		t.Fatal("different version accepted")
	}
	manifest.BinarySHA256[runtime.GOOS+"_"+runtime.GOARCH] = strings.Repeat("0", 64)
	if err := verifyEngine(file, manifest); err == nil {
		t.Fatal("untrusted binary accepted")
	}
	manifest.Version = "latest"
	if err := verifyEngine(file, manifest); err == nil {
		t.Fatal("unpinned manifest accepted")
	}
}

func TestEngineCancellationAndDiagnosticsAreSafe(t *testing.T) {
	file, manifest := mockEngine(t, `
if [ "$1" = "version" ]; then printf '{"version":"1.54.0"}'; exit 0; fi
echo 'token=do-not-print /private/local/source' >&2
exec sleep 5
`)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := runEngineWithManifest(ctx, file, "/fixture", "rootfs", manifest)
	if err == nil || strings.Contains(err.Error(), "do-not-print") || strings.Contains(err.Error(), "/private") {
		t.Fatal("unsafe timeout diagnostics")
	}
}

func TestCappedEngineOutputNeverGrowsPastBound(t *testing.T) {
	b := &cappedBuffer{limit: 8}
	if _, err := b.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("56789")); err == nil || !b.overflow || b.Len() > 8 {
		t.Fatal("engine output memory is unbounded")
	}
}

func TestLocalArchivesUseExplicitSourceWithoutDaemon(t *testing.T) {
	for _, targetType := range []string{"oci-archive", "docker-archive"} {
		t.Run(targetType, func(t *testing.T) {
			file, manifest := mockEngine(t, "if [ \"$1\" = \"version\" ]; then printf '{\"version\":\"1.54.0\"}'; exit 0; fi\n"+
				"test \"$2\" = '"+targetType+":/fixture.tar' || exit 1\n"+"printf '{}'\n")
			if _, err := runEngineWithManifest(context.Background(), file, "/fixture.tar", targetType, manifest); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfigurationDigestBindsPolicyAndSourceKind(t *testing.T) {
	firstDigest := configurationDigest("rootfs")
	secondDigest := configurationDigest("rootfs")
	if firstDigest != secondDigest {
		t.Fatal("configuration digest is not deterministic")
	}
	if configurationDigest("rootfs") == configurationDigest("oci-archive") || configurationDigest("oci-archive") == configurationDigest("docker-archive") {
		t.Fatal("configuration digest does not bind explicit source kind")
	}
	if configurationDigest("rootfs") == sha256Hex([]byte(engineConfig)) {
		t.Fatal("configuration digest omits non-path format and engine options")
	}
}

func TestEngineStartFailureUsesSafeExecutableFilesystemHint(t *testing.T) {
	const canary = "private-engine-canary-do-not-print"
	privateDir := t.TempDir()
	file := filepath.Join(privateDir, "syft")
	data := []byte("#!" + filepath.Join(privateDir, canary) + "\nexit 0\n")
	if err := os.WriteFile(file, data, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := engineManifest{Version: engineVersion, BinarySHA256: map[string]string{runtime.GOOS + "_" + runtime.GOARCH: sha256Hex(data)}}
	_, err := runEngineWithManifest(context.Background(), file, "/private/target-canary", "rootfs", manifest)
	const expected = "cannot start isolated engine; ensure the temporary filesystem permits executable files (check noexec)"
	if err == nil || err.Error() != expected {
		t.Fatal("engine start failure did not return the static executable-filesystem hint")
	}
	for _, forbidden := range []string{privateDir, file, canary, "target-canary", "cracken-sbom-engine-"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatal("engine start failure exposed a private path or canary")
		}
	}
}

func TestEngineVersionProcessFailureRemainsDistinctFromStartFailure(t *testing.T) {
	file, manifest := mockEngine(t, "echo 'private-version-canary /private/source' >&2\nexit 42\n")
	_, err := runEngineWithManifest(context.Background(), file, "/private/target", "rootfs", manifest)
	if err == nil || err.Error() != "cannot verify pinned engine version" {
		t.Fatal("started engine failure was not reported as version verification failure")
	}
}
