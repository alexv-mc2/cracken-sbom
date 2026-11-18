package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Integrity of left-pad@1.3.0 as published by the public npm registry.
const leftPadSRI = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
const leftPadHex = "5c8e4c3f354d0298c0ca1433a615fc06498ab0a5310f82ddc8adb88997901a29c137dc93413ddb165081cbf695c761eb35ca901ac768b7c821ae3cabbcc0a810"

func TestDecodeSRI(t *testing.T) {
	if got, err := decodeSRI(leftPadSRI); err != nil || got != leftPadHex {
		t.Fatalf("decodeSRI: %q %v", got, err)
	}
	if got, err := decodeSRI("sha1-abc sha512-" + leftPadSRI[len("sha512-"):]); err != nil || got != leftPadHex {
		t.Fatal("multi-hash SRI must use the SHA-512 entry")
	}
	for _, bad := range []string{"", "sha1-abcdefghijklmnopqrstuvwxyz12", "sha512-AAAA", "sha512-!!!"} {
		if _, err := decodeSRI(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseNPMLockV1AndV3(t *testing.T) {
	idx := lockIndex{}
	v3 := `{"lockfileVersion":3,"packages":{"":{"name":"root"},
	 "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"` + leftPadSRI + `"},
	 "node_modules/@corp/private":{"version":"1.0.0","resolved":"https://npm.corp.internal/@corp/private/-/private-1.0.0.tgz?token=x","integrity":"` + leftPadSRI + `"},
	 "node_modules/linked":{"link":true,"version":"1.0.0","integrity":"` + leftPadSRI + `"}}}`
	if err := parseNPMLock([]byte(v3), idx); err != nil {
		t.Fatal(err)
	}
	if e := idx[lockKey("left-pad", "1.3.0")]; e.SHA512 != leftPadHex || e.Filename != "left-pad-1.3.0.tgz" || e.URL != "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" {
		t.Fatalf("public entry: %+v", e)
	}
	// A private registry never leaves the machine: file name only, no URL.
	if e := idx[lockKey("@corp/private", "1.0.0")]; e.URL != "" || e.Filename != "private-1.0.0.tgz" {
		t.Fatalf("private entry: %+v", e)
	}
	if _, ok := idx[lockKey("linked", "1.0.0")]; ok {
		t.Fatal("linked workspace package must be skipped")
	}
	v1 := lockIndex{}
	if err := parseNPMLock([]byte(`{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","integrity":"`+leftPadSRI+`","dependencies":{"b":{"version":"2.0.0","integrity":"`+leftPadSRI+`"}}}}}`), v1); err != nil {
		t.Fatal(err)
	}
	if v1[lockKey("a", "1.0.0")].SHA512 != leftPadHex || v1[lockKey("b", "2.0.0")].Filename != "b-2.0.0.tgz" {
		t.Fatal("lockfile v1 nested dependencies")
	}
}

func TestParseYarnV1AndBunLocks(t *testing.T) {
	yarn := `# yarn lockfile v1

"left-pad@^1.3.0", left-pad@~1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc"
  integrity ` + leftPadSRI + `

"@scope/pkg@^2.0.0":
  version "2.0.0"
  integrity ` + leftPadSRI + `
`
	idx := lockIndex{}
	if err := parseYarnV1Lock([]byte(yarn), idx); err != nil {
		t.Fatal(err)
	}
	if e := idx[lockKey("left-pad", "1.3.0")]; e.SHA512 != leftPadHex || e.URL != "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz" {
		t.Fatalf("yarn entry: %+v", e)
	}
	if idx[lockKey("@scope/pkg", "2.0.0")].Filename != "pkg-2.0.0.tgz" {
		t.Fatal("yarn scoped entry")
	}
	bun := `{
	  // bun.lock is JSONC
	  "lockfileVersion": 1,
	  "packages": {
	    "left-pad": ["left-pad@1.3.0", "", {}, "` + leftPadSRI + `"], /* trailing comma follows */
	    "git-dep": ["git-dep@github:x/y", "", {}],
	  },
	}`
	b := lockIndex{}
	if err := parseBunLock([]byte(bun), b); err != nil {
		t.Fatal(err)
	}
	if b[lockKey("left-pad", "1.3.0")].SHA512 != leftPadHex || len(b) != 1 {
		t.Fatalf("bun entries: %+v", b)
	}
}

func TestLockIndexesReadOnlyLockfilesInsideRoot(t *testing.T) {
	root := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0","integrity":"` + leftPadSRI + `"}}}`
	if os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0600) != nil {
		t.Fatal("fixture")
	}
	hints := map[string]*componentHints{
		"component-1": {Location: "/package-lock.json", PkgType: "npm"},
		"component-2": {Location: "/../package-lock.json", PkgType: "npm"},
		"component-3": {Location: "/etc/passwd"},
	}
	idx := loadLockIndexes(root, hints)
	if idx["/package-lock.json"][lockKey("left-pad", "1.3.0")].SHA512 != leftPadHex {
		t.Fatal("lockfile below the root not read")
	}
	if _, ok := idx["/etc/passwd"]; ok {
		t.Fatal("non-lockfile location parsed")
	}
}
