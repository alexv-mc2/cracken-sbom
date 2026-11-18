package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RunGenerate is the one generate path for every target type. Subcommands
// such as detect build generateOptions and call it; it validates everything
// itself before the engine runs.
func RunGenerate(ctx context.Context, o generateOptions, env Env) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	handler, ok := defaultRegistry.target(o.targetType)
	if !ok {
		return errors.New("target type must be " + joinChoices(defaultRegistry.targetTypes()))
	}
	if o.extra == nil {
		o.extra = map[string]string{}
	}
	if err := validatePaths(&o); err != nil {
		return err
	}
	tr, err := resolveTROptions(o.tr)
	if err != nil {
		return err
	}
	o.tr = tr
	provenanceCtx := ProvenanceContext{
		ToolVersion: toolVersion, EngineVersion: engineVersion,
		ConfigDigest: handler.ConfigDigest(), TargetType: o.targetType,
		TargetIdentifier: o.targetID, GeneratedAt: env.Now().UTC().Format(time.RFC3339),
	}
	// Validate asserted provenance before spending time scanning or reading input.
	if _, err := validateContext(provenanceCtx); err != nil {
		return errors.New("target identifier or provenance metadata is invalid")
	}
	prepared, cleanup, err := handler.Prepare(ctx, o, env)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	if prepared == nil {
		return errors.New("target handler produced no inventory")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	provenanceCtx.Firmware = prepared.Firmware
	raw := prepared.RawCDX
	if prepared.ScanType == "rootfs" && prepared.ScanRoot != "" {
		raw, err = detectEmbedded(ctx, prepared.ScanRoot, raw, defaultEmbeddedLimits)
		if err != nil {
			return err
		}
	}
	doc, hints, quality, err := normalizeDocument(raw, provenanceCtx)
	if err != nil {
		return err
	}
	for _, w := range prepared.Warnings {
		addWarning(&quality, w)
	}
	if err := applyTR(doc, hints, prepared, o, &quality); err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	sbom, err := encodeSBOM(doc)
	if err != nil {
		return err
	}
	if len(sbom) > maxZipBytes {
		return errors.New("minimized SBOM exceeds the 16 MiB uncompressed ZIP limit; inventory was not truncated")
	}
	if quality.MissingVersions > 0 && !o.allowIncomplete {
		return fmt.Errorf("inventory requires acknowledgement: %d packages, %d missing versions. Inspect the target and explicitly use --allow-incomplete", quality.EmittedComponents, quality.MissingVersions)
	}
	provenanceCtx.Sidecars = prepared.Sidecars
	provenanceCtx.Extension = prepared.Provenance
	provenance, err := createProvenance(sbom, provenanceCtx, quality)
	if err != nil {
		return err
	}
	qualityJSON, err := json.MarshalIndent(quality, "", "  ")
	if err != nil {
		return errors.New("cannot serialize quality summary")
	}
	outputName, outputBytes := "sbom.cdx.json", sbom
	if o.zipOutput || len(sbom) > maxUploadBytes {
		outputName = "sbom.cdx.zip"
		outputBytes, err = zipSBOM(sbom)
		if err != nil {
			return err
		}
	}
	if err := publishNamedOutputs(ctx, o.output, outputName, outputBytes, provenance, append(qualityJSON, '\n'), prepared.Sidecars...); err != nil {
		return err
	}
	stdout := env.Stdout
	_, _ = fmt.Fprintf(stdout, "Generated %s, provenance.json and quality.json. Review the SBOM before manual upload; provenance remains customer-held.\n", outputName)
	for _, s := range prepared.Sidecars {
		_, _ = fmt.Fprintf(stdout, "Also generated %s (a separate file; it is never part of the SBOM).\n", s.Name)
	}
	if outputName == "sbom.cdx.zip" {
		_, _ = fmt.Fprintln(stdout, "In the crAcken web app, select ZIP archive under SPDX upload method. The public API accepts Content-Type: application/zip (16 MiB compressed and unpacked; HTTP 413 archive_too_large for compressed size or archive_unpacked_too_large for unpacked size).")
	}
	if prepared.Firmware != nil {
		_, _ = fmt.Fprintln(stdout, "The inventory comes from a best-effort local extraction of the image; see the firmware block in provenance.json and the warnings in quality.json.")
	}
	if len(quality.TRGaps) > 0 {
		_, _ = fmt.Fprintf(stdout, "BSI TR-03183-2: %d gap(s) remain; see tr_gaps in quality.json.\n", len(quality.TRGaps))
	}
	return nil
}

func encodeSBOM(doc map[string]any) ([]byte, error) {
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, errors.New("cannot encode minimized SBOM")
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxSBOMBytes {
		return nil, errors.New("minimized SBOM exceeds 16 MiB uncompressed ZIP limit")
	}
	return encoded, nil
}
