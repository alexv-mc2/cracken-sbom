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
