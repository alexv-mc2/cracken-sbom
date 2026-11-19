package main

// cracken-upload.zip: the build's native SPDX, byte for byte and under the
// original file names, packed the way crAcken's "ZIP archive" upload reads
// it. crAcken applies the build's patched-CVE data only from native SPDX, so
// this file (not the CycloneDX SBOM and VEX) is the one to upload there.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// crAcken's ZIP limits (sbom-to-cra supabase/functions):
//   - parse-sbom/index.ts:105 MAX_ZIP_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
//   - parse-sbom/index.ts:106 MAX_ZIP_COMPRESSED_BYTES = EDGE_ZIP_MAX_BYTES,
//     _shared/extended-parse-limits.ts:6 EDGE_ZIP_MAX_BYTES = 16 * 1024 * 1024
//   - parse-sbom/index.ts:107 MAX_ZIP_ENTRIES = 10_000
//   - parse-sbom/spdx3-size.ts:5 MAX_SPDX3_DOCUMENT_BYTES = 16 * 1024 * 1024
//
// crAcken applies the uncompressed limit after it selects the image's
// documents; the generator applies it to every entry, which is stricter.
const (
	crackenZipCompressedLimit   = 16 * 1024 * 1024
	crackenZipUncompressedLimit = 16 * 1024 * 1024
	crackenZipEntryLimit        = 10000
	crackenSPDX3DocumentLimit   = 16 * 1024 * 1024
)

// Variables so tests can exercise the refusals with small inputs.
var uploadCompressedLimit = crackenZipCompressedLimit
var uploadUncompressedLimit = crackenZipUncompressedLimit
var uploadEntryLimit = crackenZipEntryLimit
var uploadSPDX3Limit = crackenSPDX3DocumentLimit

type uploadFacts struct {
	Documents int
	Bytes     int
	SHA256    string
}

// buildCrackenUpload packs the image's SPDX documents. An error means no
// upload file is written; the message says why in plain words.
func buildCrackenUpload(set *yoctoSet) ([]byte, uploadFacts, error) {
	var facts uploadFacts
	entries := []yoctoDoc{}
	names := map[string]bool{}
	total := 0
	for _, d := range set.docs {
		base := path.Base(d.name)
		// The index is not an SPDX document; crAcken does not read it.
		if base == "index.json" || strings.HasSuffix(base, ".spdx.index.json") || !strings.HasSuffix(base, ".spdx.json") {
			continue
		}
		if names[base] {
			return nil, facts, fmt.Errorf("two SPDX documents share the file name %s; crAcken finds documents by file name, so no upload file was written", base)
		}
		names[base] = true
		if set.spdx3 && len(d.data) > uploadSPDX3Limit {
			return nil, facts, fmt.Errorf("the SPDX 3 document is %d MiB, above crAcken's %d MiB limit for one SPDX 3 file; no upload file was written", len(d.data)>>20, uploadSPDX3Limit>>20)
		}
		total += len(d.data)
		entries = append(entries, yoctoDoc{name: base, data: d.data})
	}
	if len(entries) == 0 {
		return nil, facts, errors.New("no SPDX document to upload")
	}
	if len(entries) > uploadEntryLimit {
		return nil, facts, fmt.Errorf("%d SPDX documents, above crAcken's limit of %d files in a ZIP; no upload file was written", len(entries), uploadEntryLimit)
	}
	if total > uploadUncompressedLimit {
		return nil, facts, fmt.Errorf("the SPDX documents are %d MiB unpacked, above crAcken's %d MiB ZIP limit; no upload file was written", total>>20, uploadUncompressedLimit>>20)
	}
	if !set.spdx3 {
		if err := checkSPDX2Complete(entries); err != nil {
			return nil, facts, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fixed := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: fixed}
		h.SetMode(0644)
		f, err := w.CreateHeader(h)
		if err != nil {
			return nil, facts, errors.New("cannot write the upload ZIP")
		}
		if _, err := f.Write(e.data); err != nil {
			return nil, facts, errors.New("cannot write the upload ZIP")
		}
		if buf.Len() > uploadCompressedLimit {
			return nil, facts, fmt.Errorf("the upload ZIP would exceed crAcken's %d MiB limit; no upload file was written", uploadCompressedLimit>>20)
		}
	}
	if err := w.Close(); err != nil {
		return nil, facts, errors.New("cannot finish the upload ZIP")
	}
	if buf.Len() > uploadCompressedLimit {
		return nil, facts, fmt.Errorf("the upload ZIP is %d MiB, above crAcken's %d MiB limit; no upload file was written", buf.Len()>>20, uploadCompressedLimit>>20)
	}
	sum := sha256.Sum256(buf.Bytes())
	facts = uploadFacts{Documents: len(entries), Bytes: buf.Len(), SHA256: hex.EncodeToString(sum[:])}
	return buf.Bytes(), facts, nil
}

// checkSPDX2Complete requires exactly one image document and every document
// the image CONTAINS, and every recipe those packages are GENERATED_FROM, to
// be in the set. A partial set would upload a partial inventory.
func checkSPDX2Complete(entries []yoctoDoc) error {
	set := newSPDX2Set()
	parsed := []*spdx2Doc{}
	for _, e := range entries {
		doc := &spdx2Doc{}
		if json.Unmarshal(e.data, doc) != nil {
			return errors.New("invalid SPDX 2 JSON in the Yocto input; no upload file was written")
		}
		if doc.DocumentNamespace != "" {
			set.byNamespace[doc.DocumentNamespace] = doc
		}
		set.index(doc)
		parsed = append(parsed, doc)
	}
	images := []*spdx2Doc{}
	for _, doc := range parsed {
		for _, r := range doc.Relationships {
			if r.Type == "CONTAINS" && strings.HasPrefix(r.To, "DocumentRef-") {
				images = append(images, doc)
				break
			}
		}
	}
	if len(images) != 1 {
		return fmt.Errorf("expected exactly one image document for the upload file, found %d; no upload file was written", len(images))
	}
	image := images[0]
	missing := 0
	for _, r := range image.Relationships {
		if r.Type != "CONTAINS" || !strings.HasPrefix(r.To, "DocumentRef-") {
			continue
		}
		pkgDoc, pkg := set.resolve(image, r.To)
		if pkg == nil {
			missing++
			continue
		}
		id, _ := pkg["SPDXID"].(string)
		for _, to := range set.generatedFrom[pkgDoc][id] {
			if _, recipe := set.resolve(pkgDoc, to); recipe == nil {
				missing++
			}
		}
	}
	if missing > 0 {
		return fmt.Errorf("%d package or recipe document(s) the image refers to are missing; no upload file was written. Pass the image's complete .spdx.tar.zst", missing)
	}
	return nil
}
