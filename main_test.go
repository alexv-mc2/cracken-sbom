package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const validRawSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"openssl","version":"3.0.1","purl":"pkg:generic/openssl@3.0.1","licenses":[{"license":{"id":"Apache-2.0"}}]}]}`

func cliFixture(t *testing.T) (args []string, output string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "rootfs")
	if os.Mkdir(target, 0700) != nil {
		t.Fatal("create fixture target")
	}
	binary := filepath.Join(dir, "syft")
	if os.WriteFile(binary, []byte("unused mock runner executable"), 0700) != nil {
		t.Fatal("create mock executable")
	}
	output = filepath.Join(dir, "new-output")
	return []string{"generate", "--target-type", "rootfs", "--target", target, "--target-id", "release-1.0", "--output", output, "--syft", binary}, output
}

func fixedNow() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }

func successRunner(_ context.Context, _, _, _ string) ([]byte, error) {
	return []byte(validRawSBOM), nil
}

func TestCLIPublishesExactDigestAndPrivateOutputs(t *testing.T) {
	args, output := cliFixture(t)
	var printed bytes.Buffer
	if err := runCLI(context.Background(), args, &printed, successRunner, fixedNow); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sbom.cdx.json", "provenance.json", "quality.json"} {
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private output %s: %v", name, err)
		}
	}
	sbom, _ := os.ReadFile(filepath.Join(output, "sbom.cdx.json"))
	provenance, _ := os.ReadFile(filepath.Join(output, "provenance.json"))
	var p map[string]any
	if json.Unmarshal(provenance, &p) != nil || p["sbom_sha256"] != sha256Hex(sbom) || p["configuration_sha256"] != configurationDigest("rootfs") {
		t.Fatal("provenance does not bind exact final bytes and configuration")
	}
	if strings.Contains(printed.String(), output) {
		t.Fatal("success output leaks local path")
	}
}

func TestCLIIncompleteRequiresAcknowledgementAndNeverPublishesOnFailure(t *testing.T) {
	args, output := cliFixture(t)
	runner := func(context.Context, string, string, string) ([]byte, error) {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"versionless"}]}`), nil
	}
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow); err == nil {
		t.Fatal("missing version was accepted without acknowledgement")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed generation published output")
	}
	args = append(args, "--allow-incomplete")
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow); err != nil {
		t.Fatal(err)
	}
}

func TestCLIMixedLicenseChoicesAreAdvisory(t *testing.T) {
	args, output := cliFixture(t)
	runner := func(context.Context, string, string, string) ([]byte, error) {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"licensed","version":"1.0","licenses":[{"license":{"id":"MIT"}},{"license":{"name":"Proprietary"}}]}]}`), nil
	}
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow); err != nil {
		t.Fatal(err)
	}
	quality, err := os.ReadFile(filepath.Join(output, "quality.json"))
	if err != nil || !bytes.Contains(quality, []byte(`"ambiguous_licenses": 1`)) || !bytes.Contains(quality, []byte("license")) {
		t.Fatal("license coverage was not reported as advisory quality information")
	}
}

func TestCLIMissingLicenseCoverageIsAdvisory(t *testing.T) {
	args, output := cliFixture(t)
	runner := func(context.Context, string, string, string) ([]byte, error) {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"unlicensed","version":"1.0"}]}`), nil
	}
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow); err != nil {
		t.Fatal(err)
	}
	quality, err := os.ReadFile(filepath.Join(output, "quality.json"))
	if err != nil || !bytes.Contains(quality, []byte(`"missing_licenses": 1`)) {
		t.Fatal("missing license coverage was not reported as advisory quality information")
	}
}

func TestCLIPreservesNewerSPDXIdentifierAsExpression(t *testing.T) {
	args, output := cliFixture(t)
	runner := func(context.Context, string, string, string) ([]byte, error) {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"licensed","version":"1.0","licenses":[{"license":{"id":"Unicode-3.0"}}]}]}`), nil
	}
	if err := runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow); err != nil {
		t.Fatal(err)
	}
	sbom, err := os.ReadFile(filepath.Join(output, "sbom.cdx.json"))
	var document map[string]any
	if err != nil || json.Unmarshal(sbom, &document) != nil {
		t.Fatal("newer SPDX identifier was not retained as an expression")
	}
	components, ok := document["components"].([]any)
	if !ok || len(components) != 1 {
		t.Fatal("newer SPDX identifier output has no component")
	}
	component, ok := components[0].(map[string]any)
	licenses, licensesOK := component["licenses"].([]any)
	if !ok || !licensesOK || len(licenses) != 1 {
		t.Fatal("newer SPDX identifier output has no license")
	}
	licenseEntry, ok := licenses[0].(map[string]any)
	_, hasLicense := licenseEntry["license"]
	if !ok || hasLicense || licenseEntry["expression"] != "Unicode-3.0" {
		t.Fatal("newer SPDX identifier was not retained as an expression")
	}
}

func TestCLIRejectsUnsafeInputsBeforeEngine(t *testing.T) {
	for _, name := range []string{"existing-output", "symlink-output", "symlink-target", "remote-target", "output-inside-target", "unsafe-identifier", "unknown-flags"} {
		t.Run(name, func(t *testing.T) {
			args, output := cliFixture(t)
			switch name {
			case "existing-output":
				_ = os.Mkdir(output, 0700)
				_ = os.WriteFile(filepath.Join(output, "sentinel"), []byte("preserve"), 0600)
			case "symlink-output":
				_ = os.Symlink(t.TempDir(), output)
			case "symlink-target":
				link := filepath.Join(filepath.Dir(output), "linked-rootfs")
				_ = os.Symlink(args[4], link)
				args[4] = link
			case "remote-target":
				args[4] = "https://credential@example.org/private"
			case "output-inside-target":
				args[8] = filepath.Join(args[4], "evidence")
			case "unsafe-identifier":
				args[6] = "https://token:secret@example.org/source"
			case "unknown-flags":
				args = append(args, "--upload-token", "secret-do-not-print")
			}
			called := false
			runner := func(context.Context, string, string, string) ([]byte, error) {
				called = true
				return []byte(validRawSBOM), nil
			}
			err := runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow)
			if err == nil || called {
				t.Fatal("unsafe input reached engine")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), filepath.Dir(output)) {
				t.Fatal("error exposes supplied secrets or local paths")
			}
			if name == "existing-output" {
				data, _ := os.ReadFile(filepath.Join(output, "sentinel"))
				if string(data) != "preserve" {
					t.Fatal("existing output modified")
				}
			}
		})
	}
}

func TestCLIFailureLeavesNoOutputOrStaging(t *testing.T) {
	args, output := cliFixture(t)
	runner := func(context.Context, string, string, string) ([]byte, error) { return nil, errors.New("engine failed") }
	if runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow) == nil {
		t.Fatal("engine failure accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("output left after failure")
	}
	entries, _ := filepath.Glob(filepath.Join(filepath.Dir(output), ".cracken-sbom-*"))
	if len(entries) != 0 {
		t.Fatal("private staging left after failure")
	}
}

func TestPublishOutputsCancelledContextLeavesNoStagingOrReservation(t *testing.T) {
	output := filepath.Join(t.TempDir(), "new-output")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := publishOutputs(ctx, output, []byte("sbom"), []byte("provenance"), []byte("quality")); err == nil {
		t.Fatal("cancelled publication succeeded")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("cancelled publication left output reservation")
	}
	entries, err := filepath.Glob(filepath.Join(filepath.Dir(output), ".cracken-sbom-output-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("cancelled publication left staging directory")
	}
}

func TestSignalNotifyContextCancelsAndCleansActualPrivateEngineCopy(t *testing.T) {
	if os.Getenv("CRACKEN_SBOM_SIGNAL_HELPER") == "1" {
		ctx, stop := signalContext(context.Background())
		defer stop()
		script := os.Getenv("CRACKEN_SBOM_SIGNAL_SYFT")
		target, output, marker := os.Getenv("CRACKEN_SBOM_SIGNAL_TARGET"), os.Getenv("CRACKEN_SBOM_SIGNAL_OUTPUT"), os.Getenv("CRACKEN_SBOM_SIGNAL_MARKER")
		data, err := os.ReadFile(script)
		if err != nil {
			t.Fatal("read mock engine")
		}
		manifest := engineManifest{Version: engineVersion, BinarySHA256: map[string]string{runtime.GOOS + "_" + runtime.GOARCH: sha256Hex(data)}}
		args := []string{"generate", "--target-type", "rootfs", "--target", target, "--target-id", "release-signal-test", "--output", output, "--syft", script}
		runner := func(ctx context.Context, binary, target, targetType string) ([]byte, error) {
			return runEngineWithManifest(ctx, binary, target, targetType, manifest)
		}
		if err := runCLI(ctx, args, &bytes.Buffer{}, runner, fixedNow); err == nil {
			t.Fatal("SIGINT-cancelled scan succeeded")
		}
		privatePath, err := os.ReadFile(marker)
		if err != nil {
			t.Fatal("mock engine did not record its private execution path")
		}
		if _, err := os.Stat(filepath.Dir(strings.TrimSpace(string(privatePath)))); !os.IsNotExist(err) {
			t.Fatal("actual private engine workspace survived cancellation")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("SIGINT-cancelled scan published output")
		}
		staging, _ := filepath.Glob(filepath.Join(filepath.Dir(output), ".cracken-sbom-*"))
		if len(staging) != 0 {
			t.Fatal("SIGINT-cancelled scan left private staging")
		}
		return
	}

	args, output := cliFixture(t)
	dir := filepath.Dir(output)
	marker := filepath.Join(dir, "scan-started")
	script := filepath.Join(dir, "mock-syft")
	scriptBody := "#!/bin/sh\nif [ \"$1\" = version ]; then printf '{\"version\":\"1.54.0\"}\\n'; exit 0; fi\nprintf '%s\\n' \"$0\" > '" + marker + "'\nexec /bin/sleep 60\n"
	if err := os.WriteFile(script, []byte(scriptBody), 0700); err != nil {
		t.Fatal("write authenticated mock engine")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSignalNotifyContextCancelsAndCleansActualPrivateEngineCopy$")
	cmd.Env = append(os.Environ(), "CRACKEN_SBOM_SIGNAL_HELPER=1", "CRACKEN_SBOM_SIGNAL_SYFT="+script, "CRACKEN_SBOM_SIGNAL_TARGET="+args[4], "CRACKEN_SBOM_SIGNAL_OUTPUT="+output, "CRACKEN_SBOM_SIGNAL_MARKER="+marker)
	var childOutput bytes.Buffer
	cmd.Stdout, cmd.Stderr = &childOutput, &childOutput
	childOutputSummary := func() string {
		const maxDiagnosticBytes = 4096
		out := childOutput.String()
		if len(out) > maxDiagnosticBytes {
			out = out[:maxDiagnosticBytes] + "..."
		}
		return out
	}
	if err := cmd.Start(); err != nil {
		t.Fatal("start signal helper process")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("signal helper exited before scan started: %v; output: %s", err, childOutputSummary())
		default:
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("timed out waiting for mock engine scan marker")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal("send SIGINT to signal helper")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("signal helper failed cleanup assertions: %v; output: %s", err, childOutputSummary())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("signal helper did not exit after SIGINT")
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatal("cancellation removed the caller's supplied engine")
	}
}

func TestCLIEmptySBOMAlwaysFailsEvenWithAcknowledgement(t *testing.T) {
	args, output := cliFixture(t)
	args = append(args, "--allow-incomplete")
	runner := func(context.Context, string, string, string) ([]byte, error) {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), nil
	}
	if runCLI(context.Background(), args, &bytes.Buffer{}, runner, fixedNow) == nil {
		t.Fatal("empty inventory accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("empty inventory published")
	}
}

func TestVersionDoesNotAccessEngine(t *testing.T) {
	var out bytes.Buffer
	if err := runCLI(context.Background(), []string{"version"}, &out, nil, nil); err != nil || !strings.Contains(out.String(), toolVersion) {
		t.Fatal("version command failed")
	}
}

func TestPublishOutputsNeverOverwritesExistingDirectory(t *testing.T) {
	output := t.TempDir()
	if publishOutputs(context.Background(), output, []byte("new"), []byte("new"), []byte("new")) == nil {
		t.Fatal("existing directory overwritten")
	}
	entries, _ := os.ReadDir(output)
	if len(entries) != 0 {
		t.Fatal("existing output modified")
	}
}
