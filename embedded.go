package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type embeddedRule struct {
	// An empty hint allows library banners in any binary candidate.
	name, hint, pattern, vendor, product string
	re                                   *regexp.Regexp
}

var embeddedRules = func() []embeddedRule {
	rules := []embeddedRule{
		{name: "zlib", pattern: `\bdeflate ([0-9]+\.[0-9]+(?:\.[0-9]+)*) Copyright 1995-[0-9]{4} Jean-loup Gailly and Mark Adler\b`, vendor: "zlib", product: "zlib"},
		{name: "dropbear", hint: "dropbear", pattern: `Dropbear sshd v([0-9]+\.[0-9]+(?:\.[0-9]+)*)`, vendor: "dropbear_ssh_project", product: "dropbear_ssh"},
		{name: "openssh", hint: "ssh", pattern: `OpenSSH_([0-9]+\.[0-9]+(?:p[0-9]+)?)`, vendor: "openbsd", product: "openssh"},
		{name: "dnsmasq", hint: "dnsmasq", pattern: `(?i)dnsmasq(?:-| version )([0-9]+\.[0-9]+(?:\.[0-9]+)*)`, vendor: "thekelleys", product: "dnsmasq"},
		{name: "hostapd", hint: "hostapd", pattern: `hostapd v([0-9]+\.[0-9]+(?:\.[0-9]+)*)`, vendor: "w1.fi", product: "hostapd"},
		{name: "wpa_supplicant", hint: "wpa_supplicant", pattern: `wpa_supplicant v([0-9]+\.[0-9]+(?:\.[0-9]+)*)`, vendor: "w1.fi", product: "wpa_supplicant"},
		{name: "u-boot", hint: "", pattern: `U-Boot ([0-9]{4}\.[0-9]{2}(?:\.[0-9]+)?)`, vendor: "denx", product: "u-boot"},
		{name: "mbedtls", pattern: `\bmbed TLS ([0-9]+\.[0-9]+\.[0-9]+)(?:$|[\x00[:space:]])`, vendor: "trustedfirmware", product: "mbed_tls"},
		{name: "wolfssl", pattern: `\bwolfSSL ([0-9]+\.[0-9]+\.[0-9]+)(?:$|[\x00[:space:]])`, vendor: "wolfssl", product: "wolfssl"},
	}
	for i := range rules {
		rules[i].re = regexp.MustCompile(rules[i].pattern)
	}
	return rules
}()

// Raw images without a bootloader path must carry the complete build banner.
var embeddedRawUBoot = regexp.MustCompile(`\bU-Boot ([0-9]{4}\.[0-9]{2}(?:\.[0-9]+)?)(?:[-+][[:alnum:]_.+-]+)? \((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +[0-9]{1,2} [0-9]{4} - [0-9]{2}:[0-9]{2}:[0-9]{2}(?: [^()\x00\r\n]+)?\)`)

func embeddedBootloaderPath(path string) bool {
	path = strings.ToLower(filepath.ToSlash(path))
	if strings.HasPrefix(filepath.Base(path), "u-boot") {
		return true
	}
	if filepath.Ext(path) != ".bin" {
		return false
	}
	for _, dir := range strings.Split(filepath.Dir(path), "/") {
		if dir == "boot" || dir == "firmware" {
			return true
		}
	}
	return false
}

func embeddedLooksLikeText(path string, data []byte) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".txt", ".log", ".md", ".rst", ".html", ".conf", ".cfg", ".sh":
		return true
	}
	// Only sample the prefix; raw binaries may contain long printable banners.
	data = data[:min(len(data), 8<<10)]
	if bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 0x20 && b <= 0x7e) || (b >= '\t' && b <= '\r') {
			printable++
		}
	}
	return printable*100 >= len(data)*95
}

type embeddedLimits struct {
	maxFileBytes int64
	timeout      time.Duration
}

var defaultEmbeddedLimits = embeddedLimits{maxFileBytes: 32 << 20, timeout: 2 * time.Minute}

// detectEmbedded keeps paths only while comparing Syft's location evidence.
func detectEmbedded(ctx context.Context, root string, raw []byte, limits embeddedLimits) ([]byte, error) {
	if limits.maxFileBytes <= 0 || limits.timeout <= 0 {
		return nil, errors.New("invalid embedded detector limits")
	}
	ctx, cancel := context.WithTimeout(ctx, limits.timeout)
	defer cancel()
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil, errors.New("malformed CycloneDX JSON")
	}
	list, ok := doc["components"].([]any)
	if !ok && doc["components"] != nil {
		return nil, errors.New("missing or malformed component inventory")
	}
	seen := map[string]bool{}
	key := func(name, version, path string) string {
		h := sha256.Sum256([]byte(filepath.ToSlash(strings.TrimPrefix(filepath.Clean("/"+path), "/"))))
		return strings.ToLower(name) + "\x00" + version + "\x00" + fmt.Sprintf("%x", h)
	}
	var index func([]any)
	index = func(cs []any) {
		for _, v := range cs {
			c, ok := v.(map[string]any)
			if !ok {
				continue
			}
			n, _ := c["name"].(string)
			ver, _ := c["version"].(string)
			if props, ok := c["properties"].([]any); ok {
				for _, v := range props {
					p, ok := v.(map[string]any)
					if !ok {
						continue
					}
					pn, _ := p["name"].(string)
					pv, _ := p["value"].(string)
					if strings.HasPrefix(pn, "syft:location:") && strings.HasSuffix(pn, ":path") {
						seen[key(n, ver, pv)] = true
					}
				}
			}
			if children, ok := c["components"].([]any); ok {
				index(children)
			}
		}
	}
	index(list)
	confined, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("cannot open embedded scan root")
	}
	defer confined.Close()
	var additions []map[string]any
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return errors.New("embedded detector timed out or was cancelled")
		}
		if walkErr != nil {
			return errors.New("cannot walk embedded scan root")
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return errors.New("cannot inspect embedded scan path")
		}
		f, err := confined.Open(rel)
		if err != nil {
			return errors.New("cannot open embedded scan file")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("cannot inspect embedded scan file")
		}
		if info.Size() > limits.maxFileBytes {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, limits.maxFileBytes+1))
		if err != nil {
			return errors.New("cannot read embedded scan file")
		}
		if int64(len(data)) > limits.maxFileBytes {
			return nil
		}
		if ctx.Err() != nil {
			return errors.New("embedded detector timed out or was cancelled")
		}
		elf := bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'})
		uboot := bytes.HasPrefix(data, []byte{0x27, 0x05, 0x19, 0x56})
		base := strings.ToLower(filepath.Base(rel))
		for _, rule := range embeddedRules {
			re := rule.re
			if rule.name == "u-boot" {
				if elf && !strings.Contains(base, "u-boot") {
					continue
				}
				if !elf && !uboot {
					if embeddedLooksLikeText(rel, data) {
						continue
					}
					if !embeddedBootloaderPath(rel) {
						re = embeddedRawUBoot
					}
				}
			} else if rule.hint == "" {
				if !elf && embeddedLooksLikeText(rel, data) {
					continue
				}
			} else if !elf || !strings.Contains(base, rule.hint) {
				continue
			}
			match := re.FindSubmatch(data)
			if len(match) < 2 {
				continue
			}
			version := string(match[1])
			k := key(rule.name, version, rel)
			if seen[k] {
				continue
			}
			seen[k] = true
			additions = append(additions, map[string]any{"type": "library", "name": rule.name, "version": version, "purl": "pkg:generic/" + rule.name + "@" + version, "cpe": "cpe:2.3:a:" + rule.vendor + ":" + rule.product + ":" + version + ":*:*:*:*:*:*:*", "properties": []any{map[string]any{"name": "syft:package:foundBy", "value": "cracken-embedded-version-detector"}}})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(additions, func(i, j int) bool {
		a, b := additions[i], additions[j]
		return a["name"].(string)+"\x00"+a["version"].(string) < b["name"].(string)+"\x00"+b["version"].(string)
	})
	for _, c := range additions {
		list = append(list, c)
	}
	if len(list) > 0 {
		doc["components"] = list
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, errors.New("cannot serialize embedded inventory")
	}
	return out, nil
}
