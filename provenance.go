package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

const privacyProfile = "cracken-minimized-1"

type ProvenanceContext struct {
	ToolVersion      string
	EngineVersion    string
	ConfigDigest     string
	TargetType       string
	TargetIdentifier string
	GeneratedAt      string
	// Set only for the firmware-image target type.
	Firmware *FirmwareInfo
	// Extra outputs next to the SBOM; provenance binds each by SHA-256.
	Sidecars []OutputFile
	// Facts a target handler records under "extensions".
	Extension map[string]any
}

type Quality struct {
	InputComponents         int `json:"input_components"`
	EmittedComponents       int `json:"emitted_components"`
	VersionStringComponents int `json:"version_string_components"`
	RemovedFiles            int `json:"removed_files"`
	MissingVersions         int `json:"missing_versions"`
	MissingLicenses         int `json:"missing_licenses"`
	ConvertedLicenseIDs     int `json:"converted_license_ids"`
	OmittedLicenseChoices   int `json:"omitted_license_choices"`
	AmbiguousLicenses       int `json:"ambiguous_licenses"`
	// BSI TR-03183-2 coverage of the emitted components.
	SHA512Components       int      `json:"tr_sha512_components"`
	FilenameComponents     int      `json:"tr_filename_components"`
	ManufacturerComponents int      `json:"tr_manufacturer_components"`
	GraphCompleteness      string   `json:"tr_graph_completeness"`
	TRGaps                 []string `json:"tr_gaps"`
	Warnings               []string `json:"warnings"`
	// The engine graph named components that minimization removed.
	graphUnresolved bool
}

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var targetPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]{0,199}$`)

func validateContext(ctx ProvenanceContext) (ProvenanceContext, error) {
	if !versionPattern.MatchString(ctx.ToolVersion) || !versionPattern.MatchString(ctx.EngineVersion) {
		return ctx, errors.New("invalid generator or engine version")
	}
	if !digestPattern.MatchString(ctx.ConfigDigest) {
		return ctx, errors.New("invalid configuration digest")
	}
	if _, ok := defaultRegistry.target(ctx.TargetType); !ok {
		return ctx, errors.New("unsupported target type")
	}
	if ctx.Firmware != nil {
		if ctx.TargetType != firmwareTargetType {
			return ctx, errors.New("firmware facts belong only to firmware-image")
		}
		fw, err := validateFirmware(ctx.Firmware)
		if err != nil {
			return ctx, err
		}
		ctx.Firmware = fw
	}
	if !targetPattern.MatchString(ctx.TargetIdentifier) || suspiciousString(ctx.TargetIdentifier) || strings.Contains(ctx.TargetIdentifier, "..") {
		return ctx, errors.New("unsafe target identifier; use a release identifier or digest")
	}
	t, err := time.Parse(time.RFC3339, ctx.GeneratedAt)
	if err != nil {
		return ctx, errors.New("invalid generation timestamp")
	}
	ctx.GeneratedAt = t.UTC().Format(time.RFC3339)
	return ctx, nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func createProvenance(sbom []byte, ctx ProvenanceContext, quality Quality) ([]byte, error) {
	ctx, err := validateContext(ctx)
	if err != nil {
		return nil, err
	}
	// The pre-check validates the context before extraction; a final record of a
	// firmware image without its extraction facts is never valid.
	if ctx.TargetType == firmwareTargetType && ctx.Firmware == nil {
		return nil, errors.New("firmware provenance is missing")
	}
	if !json.Valid(sbom) || len(sbom) == 0 {
		return nil, errors.New("invalid final SBOM")
	}
	// The digest binds the exact output bytes, including its trailing newline.
	result := map[string]any{
		"schema_version": "1", "generator": map[string]string{"name": "cracken-sbom", "version": ctx.ToolVersion},
		"engine":               map[string]string{"name": "syft", "version": ctx.EngineVersion},
		"configuration_sha256": ctx.ConfigDigest, "target": map[string]string{"type": ctx.TargetType, "identifier": ctx.TargetIdentifier},
		"generated_at": ctx.GeneratedAt, "privacy_profile": privacyProfile,
		"sbom_sha256": sha256Hex(sbom), "quality": quality,
		"provenance_status": "customer_asserted_local", "timestamp_source": "local_machine_clock",
	}
	if ctx.Firmware != nil {
		result["firmware"] = firmwareProvenance(ctx.Firmware)
	}
	if len(ctx.Sidecars) > 0 {
		outputs := []any{}
		for _, s := range ctx.Sidecars {
			entry := map[string]any{"name": s.Name, "sha256": sha256Hex(s.Data), "role": "separate-json", "privacy_profile_applies": true}
			switch {
			case s.Name == crackenUploadFile:
				entry["role"], entry["privacy_profile_applies"] = "cracken-upload", false
			case strings.HasSuffix(s.Name, ".vex.cdx.json"):
				entry["role"] = "vex"
			}
			outputs = append(outputs, entry)
		}
		result["extra_outputs"] = outputs
	}
	if len(ctx.Extension) > 0 {
		result["extensions"] = map[string]any{ctx.TargetType: ctx.Extension}
	}
	out, err := json.MarshalIndent(result, "", "  ")
	return append(out, '\n'), err
}
