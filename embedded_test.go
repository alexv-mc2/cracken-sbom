package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var embeddedCases = []struct{ name, path, version, banner string }{
	{"zlib", "usr/lib/libz.so.1.2.13", "1.2.13", "deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler"},
	{"dropbear", "usr/sbin/dropbear", "2022.83", "Dropbear sshd v2022.83"},
	{"openssh", "usr/sbin/sshd", "9.6p1", "OpenSSH_9.6p1"},
	{"dnsmasq", "usr/sbin/dnsmasq", "2.90", "Dnsmasq version 2.90"},
	{"hostapd", "usr/sbin/hostapd", "2.10", "hostapd v2.10"},
	{"wpa_supplicant", "usr/sbin/wpa_supplicant", "2.10", "wpa_supplicant v2.10"},
	{"u-boot", "boot/u-boot.bin", "2024.01", "U-Boot 2024.01"},
	{"mbedtls", "usr/lib/libmbedtls.so", "3.5.1", "mbed TLS 3.5.1"},
	{"wolfssl", "usr/lib/libwolfssl.so", "5.6.6", "wolfSSL 5.6.6"},
}

const emptyEmbeddedSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`

func embeddedStub(t *testing.T, root, path, banner string) {
	t.Helper()
	path = filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	data := append([]byte("\x7fELF\x02\x01\x01"+strings.Repeat("\x00", 57)), []byte("\x00"+banner+"\x00"+strings.Repeat("\x00", 512))...)
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
}

func embeddedInventory(t *testing.T, root string, raw []byte, limits embeddedLimits) ([]byte, []map[string]any) {
	t.Helper()
	out, err := detectEmbedded(context.Background(), root, raw, limits)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return out, doc.Components
}

func TestEmbeddedRules(t *testing.T) {
	for _, tc := range embeddedCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sample := range []struct {
				label, banner string
				want          bool
			}{
				{"present", tc.banner, true}, {"absent", "random executable data", false}, {"altered", strings.Replace(tc.banner, tc.version, "not-a-version", 1), false},
			} {
				t.Run(sample.label, func(t *testing.T) {
					root := t.TempDir()
					embeddedStub(t, root, tc.path, sample.banner)
					_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), embeddedLimits{maxFileBytes: 1 << 20, timeout: time.Second})
					if !sample.want {
						if len(components) != 0 {
							t.Fatalf("unexpected components: %#v", components)
						}
						return
					}
					if len(components) != 1 {
						t.Fatalf("got %d components: %#v", len(components), components)
					}
					c := components[0]
					if c["name"] != tc.name || c["version"] != tc.version || c["purl"] != "pkg:generic/"+tc.name+"@"+tc.version {
						t.Fatalf("incorrect identity: %#v", c)
					}
					if cpe, ok := c["cpe"].(string); !ok || !strings.HasPrefix(cpe, "cpe:2.3:") {
						t.Fatalf("missing CPE 2.3: %#v", c)
					}
				})
			}
		})
	}
}

func TestEmbeddedStaticLibraries(t *testing.T) {
	root := t.TempDir()
	banners := " deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler\x00mbed TLS 3.5.1\x00wolfSSL 5.6.6"
	for _, path := range []string{"usr/sbin/foo", "usr/bin/bar"} {
		embeddedStub(t, root, path, banners+"\x00"+banners)
	}
	limits := embeddedLimits{maxFileBytes: 1 << 20, timeout: time.Second}
	for _, tc := range []struct {
		name, raw string
		want      map[string]int
	}{
		{"distinct paths", emptyEmbeddedSBOM, map[string]int{"zlib@1.2.13": 2, "mbedtls@3.5.1": 2, "wolfssl@5.6.6": 2}},
		{"Syft duplicate", `{"components":[{"name":"zlib","version":"1.2.13","properties":[{"name":"syft:location:0:path","value":"/usr/sbin/foo"}]}]}`, map[string]int{"zlib@1.2.13": 2, "mbedtls@3.5.1": 2, "wolfssl@5.6.6": 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, components := embeddedInventory(t, root, []byte(tc.raw), limits)
			counts := map[string]int{}
			for _, c := range components {
				counts[c["name"].(string)+"@"+c["version"].(string)]++
			}
			if !reflect.DeepEqual(counts, tc.want) {
				t.Fatalf("incorrect per-file library inventory: got %v, want %v", counts, tc.want)
			}
		})
	}
}

func TestEmbeddedLibraryBinaryCandidates(t *testing.T) {
	const zlib = "deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler"
	const mbedTLS = "mbed TLS 3.5.1"
	const wolfSSL = "wolfSSL 5.6.6"
	for _, tc := range []struct {
		name, path, data, wantName, wantVersion string
	}{
		{"ELF app with zlib", "app", "\x7fELF\x00" + zlib + "\x00", "zlib", "1.2.13"},
		{"ELF app with mbed TLS", "app", "\x7fELF\x00" + mbedTLS + "\x00", "mbedtls", "3.5.1"},
		{"raw binary with zlib", "app", "\x00" + zlib + "\x00", "zlib", "1.2.13"},
		{"raw binary with mbed TLS", "app", "\x00" + mbedTLS + "\x00", "mbedtls", "3.5.1"},
		{"raw binary with wolfSSL", "app", "\x00" + wolfSSL + "\x00", "wolfssl", "5.6.6"},
		{"text with zlib", "app", "Library: " + zlib + "\n", "", ""},
		{"text file with zlib", "library.log", zlib + "\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, tc.path), []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), defaultEmbeddedLimits)
			if tc.wantName == "" {
				if len(components) != 0 {
					t.Fatalf("text produced components: %#v", components)
				}
				return
			}
			if len(components) != 1 || components[0]["name"] != tc.wantName || components[0]["version"] != tc.wantVersion {
				t.Fatalf("library not recognized: %#v", components)
			}
		})
	}
}

func TestEmbeddedLibraryBannerFalsePositives(t *testing.T) {
	for _, tc := range []struct{ name, path, banner string }{
		{"zlib fragment", "usr/lib/libz.so", "deflate 1.2"},
		{"zlib without copyright", "usr/lib/libz.so", "deflate 1.2.13"},
		{"zlib incomplete copyright", "usr/sbin/foo", "deflate 1.2.13 Copyright 1995-"},
		{"zlib unrelated copyright", "usr/sbin/foo", "deflate 1.2.13 Copyright 1995-2022 Example Corp"},
		{"mbedtls prefix", "usr/lib/libmbedtls.so", "notmbed TLS 3.5.1"},
		{"mbedtls version suffix", "usr/lib/libmbedtls.so", "mbed TLS 3.5.1garbage"},
		{"mbedtls extra version part", "usr/lib/libmbedtls.so", "mbed TLS 3.5.1.2"},
		{"wolfssl prefix", "usr/lib/libwolfssl.so", "notwolfSSL 5.6.6"},
		{"wolfssl version suffix", "usr/lib/libwolfssl.so", "wolfSSL 5.6.6garbage"},
		{"wolfssl extra version part", "usr/lib/libwolfssl.so", "wolfSSL 5.6.6.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			embeddedStub(t, root, tc.path, tc.banner)
			_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), defaultEmbeddedLimits)
			if len(components) != 0 {
				t.Fatalf("fragment produced components: %#v", components)
			}
		})
	}
}

func TestEmbeddedProgramRulesStillRequireName(t *testing.T) {
	root := t.TempDir()
	embeddedStub(t, root, "usr/sbin/foo", "Dropbear sshd v2022.83\x00OpenSSH_9.6p1\x00Dnsmasq version 2.90\x00hostapd v2.10\x00wpa_supplicant v2.10\x00U-Boot 2024.01")
	_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), defaultEmbeddedLimits)
	if len(components) != 0 {
		t.Fatalf("program rules lost their filename gates: %#v", components)
	}
}

func TestEmbeddedRawUBoot(t *testing.T) {
	const completeBanner = "U-Boot 2024.01 (Jan 01 2024 - 12:34:56 +0000)"
	for _, tc := range []struct {
		name, path, banner string
		maxBytes           int64
		want               bool
	}{
		{"raw named bootloader", "u-boot.bin", completeBanner, 1024, true},
		{"raw named bootloader short banner", "u-boot-spl.bin", "U-Boot 2024.01", 1024, true},
		{"boot partition", "boot/loader.bin", "U-Boot 2024.01", 1024, true},
		{"firmware partition", "partitions/firmware/loader.bin", "U-Boot 2024.01", 1024, true},
		{"complete banner without path hint", "image.bin", completeBanner, 1024, true},
		{"complete banner after fragment", "image.bin", "U-Boot 1999.01\x00" + completeBanner, 1024, true},
		{"complete vendor banner", "image.bin", "U-Boot 2024.01-board (Jan  1 2024 - 12:34:56)", 1024, true},
		{"random binary", "random.bin", "random binary data", 1024, false},
		{"path alone", "boot/loader.bin", "random binary data", 1024, false},
		{"short banner without path hint", "random.bin", "U-Boot 2024.01", 1024, false},
		{"incomplete date", "random.bin", "U-Boot 2024.01 (Jan 01", 1024, false},
		{"non-date parenthesis", "random.bin", "U-Boot 2024.01 (documentation)", 1024, false},
		{"similar directory", "reboot/loader.bin", "U-Boot 2024.01", 1024, false},
		{"boot text file", "boot/notes.txt", "U-Boot 2024.01", 1024, false},
		{"oversized named bootloader", "u-boot.bin", completeBanner, 16, false},
		{"oversized complete banner", "image.bin", completeBanner, 16, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("\x00\x01\x02\x03\x00"+tc.banner+"\x00"), 0600); err != nil {
				t.Fatal(err)
			}
			_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), embeddedLimits{maxFileBytes: tc.maxBytes, timeout: time.Second})
			if !tc.want {
				if len(components) != 0 {
					t.Fatalf("unexpected raw binary components: %#v", components)
				}
				return
			}
			if len(components) != 1 || components[0]["name"] != "u-boot" || components[0]["version"] != "2024.01" {
				t.Fatalf("raw U-Boot not recognized: %#v", components)
			}
		})
	}
}

func TestEmbeddedRawUBootBinaryCandidates(t *testing.T) {
	const banner = "U-Boot 2024.01 (Jan 01 2024 - 12:34:56 +0000)"
	textSample := banner + strings.Repeat(" ", (8<<10)-len(banner))
	type testCase struct {
		name, path, data string
		want             bool
	}
	cases := []testCase{
		{"serial console log", "boot.log", "Booting...\r\n" + banner + "\r\n", false},
		{"readme", "README", "Example output:\n" + banner + "\n", false},
		{"text with binary extension", "image.bin", banner + "\n", false},
		{"text with bootloader name", "u-boot.bin", banner + "\n", false},
		{"raw named bootloader", "u-boot.bin", "\x00" + banner + "\x00", true},
		{"raw image", "image.bin", "\x00" + banner + "\x00", true},
		{"95 percent printable", "image.bin", banner + strings.Repeat(" ", 190-len(banner)) + strings.Repeat("\x01", 10), false},
		{"below 95 percent printable", "image.bin", banner + strings.Repeat(" ", 189-len(banner)) + strings.Repeat("\x01", 11), true},
		{"whitespace is text", "README", banner + strings.Repeat("\t\n\v\f\r", 20), false},
		{"NUL inside sample", "image.bin", textSample[:len(textSample)-1] + "\x00", true},
		{"NUL outside sample", "image.bin", textSample + "\x00", false},
	}
	for _, ext := range []string{".txt", ".log", ".md", ".rst", ".html", ".conf", ".cfg", ".sh", ".LOG"} {
		cases = append(cases, testCase{"text extension " + ext, "notes" + ext, "\x00" + banner + "\x00", false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, tc.path), []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), defaultEmbeddedLimits)
			if !tc.want {
				if len(components) != 0 {
					t.Fatalf("text produced components: %#v", components)
				}
				return
			}
			if len(components) != 1 || components[0]["name"] != "u-boot" || components[0]["version"] != "2024.01" {
				t.Fatalf("raw U-Boot not recognized: %#v", components)
			}
		})
	}
}

func TestEmbeddedRootfsDeterministicAndSyftDuplicate(t *testing.T) {
	root := t.TempDir()
	// Copy the checked-in rootfs fixture without mutating it.
	err := filepath.WalkDir("fixtures/rootfs", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("fixtures/rootfs", path)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, rel)
		if entry.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0644)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range embeddedCases {
		embeddedStub(t, root, tc.path, tc.banner)
	}
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"application","name":"dropbear","version":"2022.83","bom-ref":"syft-dropbear","properties":[{"name":"syft:location:0:path","value":"/usr/sbin/dropbear"}]}]}`)
	limits := embeddedLimits{maxFileBytes: 1 << 20, timeout: 5 * time.Second}
	first, components := embeddedInventory(t, root, raw, limits)
	second, _ := embeddedInventory(t, root, raw, limits)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("non-deterministic output")
	}
	if len(components) != len(embeddedCases) {
		t.Fatalf("deduplication failed, got %d components: %#v", len(components), components)
	}
}

func TestEmbeddedRandomSizeAndTimeLimits(t *testing.T) {
	root := t.TempDir()
	embeddedStub(t, root, "usr/sbin/dropbear", "random binary data")
	_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), embeddedLimits{maxFileBytes: 1 << 20, timeout: time.Second})
	if len(components) != 0 {
		t.Fatalf("random binary produced components: %#v", components)
	}
	embeddedStub(t, root, "usr/sbin/dropbear", "Dropbear sshd v2022.83")
	_, components = embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), embeddedLimits{maxFileBytes: 16, timeout: time.Second})
	if len(components) != 0 {
		t.Fatalf("oversized file produced components: %#v", components)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := detectEmbedded(ctx, root, []byte(emptyEmbeddedSBOM), embeddedLimits{maxFileBytes: 1 << 20, timeout: time.Second}); err == nil {
		t.Fatal("cancelled scan succeeded")
	}
}

func TestEmbeddedDoesNotFollowOutsideSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	embeddedStub(t, outside, "dropbear", "Dropbear sshd v2022.83")
	if err := os.Symlink(filepath.Join(outside, "dropbear"), filepath.Join(root, "dropbear")); err != nil {
		t.Fatal(err)
	}
	_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), embeddedLimits{maxFileBytes: 1 << 20, timeout: time.Second})
	if len(components) != 0 {
		t.Fatalf("followed external symlink: %#v", components)
	}
}

func TestEmbeddedTimeout(t *testing.T) {
	root := t.TempDir()
	embeddedStub(t, root, "usr/sbin/dropbear", "Dropbear sshd v2022.83")
	if _, err := detectEmbedded(context.Background(), root, []byte(emptyEmbeddedSBOM), embeddedLimits{maxFileBytes: 1 << 20, timeout: time.Nanosecond}); err == nil {
		t.Fatal("expired scan succeeded")
	}
}

func TestEmbeddedUBootImage(t *testing.T) {
	root := t.TempDir()
	data := append([]byte{0x27, 0x05, 0x19, 0x56}, []byte("\x00U-Boot 2024.01\x00")...)
	if err := os.WriteFile(filepath.Join(root, "image.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	_, components := embeddedInventory(t, root, []byte(emptyEmbeddedSBOM), embeddedLimits{maxFileBytes: 1024, timeout: time.Second})
	if len(components) != 1 || components[0]["name"] != "u-boot" {
		t.Fatalf("U-Boot image not recognized: %#v", components)
	}
}
