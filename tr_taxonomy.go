package main

// BSI CycloneDX property taxonomy v0.1.2 (Apache-2.0, BSI-Bund/tr-03183-cyclonedx-property-taxonomy)
// for BSI TR-03183-2 v2.1.0. Names and values are the taxonomy's exact strings.
const (
	bsiExecutable = "bsi:component:executable"
	bsiArchive    = "bsi:component:archive"
	bsiStructured = "bsi:component:structured"
	bsiFilename   = "bsi:component:filename"

	bsiValueExecutable    = "executable"
	bsiValueNonExecutable = "non-executable"
	bsiValueArchive       = "archive"
	bsiValueNoArchive     = "no archive"
	bsiValueStructured    = "structured"
	bsiValueUnstructured  = "unstructured"
)

const trProfile = "BSI-TR-03183-2-v2.1.0"

// Catalogers whose component is the cataloged file itself: a compiled
// binary, kernel image or Java archive. Their Syft location is that file, so
// its SHA-512 and file name describe the deployable component.
var fileComponentCatalogers = map[string]bool{
	"binary-classifier-cataloger":          true,
	"elf-binary-package-cataloger":         true,
	"pe-binary-package-cataloger":          true,
	"dotnet-portable-executable-cataloger": true,
	"linux-kernel-cataloger":               true,
	"java-archive-cataloger":               true,
}

// bsiClassification maps an engine component to the taxonomy flags, following
// TR-03183-2 §8.1.4-8.1.7 (Table 7):
//   - binaries found by content (classifiers, ELF/PE notes, the kernel, and
//     libraries detected inside binaries) are executable, not archives, and
//     unstructured, because statically linked parts cannot be dissected;
//   - Go and Rust binaries carrying build information are "binaries with an
//     integrated SBOM": executable and structured;
//   - Java archives are executable, structured archives;
//   - package-manager packages (deb, rpm, apk, npm, PyPI, ...) are, like the
//     rpm package in Table 7, non-executable structured archives;
//   - the operating-system component is a logical component without a file.
func bsiClassification(componentType string, h *componentHints) (executable, archive, structured bool) {
	switch h.FoundBy {
	case "binary-classifier-cataloger", "elf-binary-package-cataloger", "pe-binary-package-cataloger",
		"dotnet-portable-executable-cataloger", "linux-kernel-cataloger", "cracken-embedded-version-detector":
		return true, false, false
	case "go-module-binary-cataloger", "cargo-auditable-binary-cataloger":
		return true, false, true
	case "java-archive-cataloger", "graalvm-native-image-cataloger":
		return true, true, true
	}
	if componentType == "operating-system" {
		return false, false, true
	}
	return false, true, true
}

func bsiProperties(executable, archive, structured bool, filename string) []any {
	pick := func(flag bool, yes, no string) string {
		if flag {
			return yes
		}
		return no
	}
	props := []any{
		map[string]any{"name": bsiExecutable, "value": pick(executable, bsiValueExecutable, bsiValueNonExecutable)},
		map[string]any{"name": bsiArchive, "value": pick(archive, bsiValueArchive, bsiValueNoArchive)},
		map[string]any{"name": bsiStructured, "value": pick(structured, bsiValueStructured, bsiValueUnstructured)},
	}
	if filename != "" {
		props = append(props, map[string]any{"name": bsiFilename, "value": filename})
	}
	return props
}
