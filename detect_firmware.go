package main

// Firmware and file-format magic numbers for local detection.
//
// The constants below are taken from the signature definitions of binwalk 3
// (https://github.com/ReFirmLabs/binwalk, src/signatures/*.rs, Copyright
// ReFirmLabs and contributors, MIT licence) and the handlers of unblob
// (https://github.com/onekey-sec/unblob, unblob/handlers/**, Copyright ONEKEY,
// MIT licence). Only the magic bytes and their offsets are used; no code from
// either project is included. See NOTICE. Extraction itself still runs the
// separately installed unblob or binwalk (firmware.go).

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type magicKind int

const (
	magicFirmware   magicKind = iota // file system or firmware container
	magicCompressed                  // compression stream: unpack first unless it is a firmware file
)

type magicSignature struct {
	Name   string
	Offset int64
	Magic  []byte
	Kind   magicKind
	// Weak signatures (two or three bytes) count only for files whose name
	// already says firmware (.bin, .img, ...).
	Weak bool
	// Scan: also searched at any offset in the first scan window of a
	// firmware-named file (binwalk-style), because vendor images often
	// put a header or bootloader in front of the root filesystem.
	Scan bool
}

var firmwareSignatures = []magicSignature{
	{Name: "SquashFS file system", Offset: 0, Magic: []byte("hsqs"), Scan: true},
	{Name: "SquashFS file system (big-endian)", Offset: 0, Magic: []byte("sqsh"), Scan: true},
	{Name: "UBI image", Offset: 0, Magic: []byte("UBI#"), Scan: true},
	{Name: "UBIFS file system", Offset: 0, Magic: []byte{0x31, 0x18, 0x10, 0x06}},
	{Name: "U-Boot uImage", Offset: 0, Magic: []byte{0x27, 0x05, 0x19, 0x56}, Scan: true},
	{Name: "flattened device tree or FIT image", Offset: 0, Magic: []byte{0xd0, 0x0d, 0xfe, 0xed}},
	{Name: "ext2/3/4 file system", Offset: 0x438, Magic: []byte{0x53, 0xef}},
	{Name: "EROFS file system", Offset: 0x400, Magic: []byte{0xe2, 0xe1, 0xf5, 0xe0}},
	{Name: "CramFS file system", Offset: 0, Magic: []byte{0x45, 0x3d, 0xcd, 0x28}},
	{Name: "romfs file system", Offset: 0, Magic: []byte("-rom1fs-"), Scan: true},
	{Name: "JFFS2 file system", Offset: 0, Magic: []byte{0x85, 0x19}, Weak: true},
	{Name: "JFFS2 file system (big-endian)", Offset: 0, Magic: []byte{0x19, 0x85}, Weak: true},
	{Name: "cpio archive", Offset: 0, Magic: []byte("070701")},
	{Name: "cpio archive (CRC)", Offset: 0, Magic: []byte("070702")},
	{Name: "TRX firmware header", Offset: 0, Magic: []byte("HDR0"), Scan: true},
	{Name: "Android sparse image", Offset: 0, Magic: []byte{0x3a, 0xff, 0x26, 0xed}},
	{Name: "Android boot image", Offset: 0, Magic: []byte("ANDROID!"), Scan: true},
	{Name: "gzip data", Offset: 0, Magic: []byte{0x1f, 0x8b, 0x08}, Kind: magicCompressed},
	{Name: "xz data", Offset: 0, Magic: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, Kind: magicCompressed},
	{Name: "Zstandard data", Offset: 0, Magic: []byte{0x28, 0xb5, 0x2f, 0xfd}, Kind: magicCompressed},
	{Name: "bzip2 data", Offset: 0, Magic: []byte("BZh"), Kind: magicCompressed},
	{Name: "LZ4 data", Offset: 0, Magic: []byte{0x04, 0x22, 0x4d, 0x18}, Kind: magicCompressed},
	{Name: "LZMA data", Offset: 0, Magic: []byte{0x5d, 0x00, 0x00}, Kind: magicCompressed, Weak: true},
}

// File names that say "firmware image" on their own.
var firmwareExtensions = map[string]bool{
	".bin": true, ".img": true, ".fw": true, ".trx": true, ".chk": true, ".ubi": true,
	".squashfs": true, ".sqfs": true, ".jffs2": true, ".uimage": true, ".itb": true,
	".fit": true, ".ext4": true, ".cpio": true, ".rom": true,
}

const firmwareScanWindow = 8 << 20

type firmwareSniff struct {
	Signature   *magicSignature
	At          int64
	Compressed  bool // only a compression stream was found
	FirmwareExt bool
}

// sniffFirmware reads at most the first scan window of a regular file.
func sniffFirmware(path string) (firmwareSniff, error) {
	var res firmwareSniff
	res.FirmwareExt = firmwareExtensions[strings.ToLower(filepath.Ext(path))]
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()
	head := make([]byte, firmwareScanWindow)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return res, err
	}
	head = head[:n]
	for i := range firmwareSignatures {
		s := &firmwareSignatures[i]
		end := s.Offset + int64(len(s.Magic))
		if end > int64(len(head)) || !bytes.Equal(head[s.Offset:end], s.Magic) {
			continue
		}
		if s.Weak && !res.FirmwareExt {
			continue
		}
		if s.Kind == magicCompressed {
			if res.Signature == nil {
				res.Signature, res.At, res.Compressed = s, s.Offset, true
			}
			continue
		}
		res.Signature, res.At, res.Compressed = s, s.Offset, false
		return res, nil
	}
	if !res.FirmwareExt {
		return res, nil
	}
	// binwalk-style: a firmware file whose root file system starts later.
	for i := range firmwareSignatures {
		s := &firmwareSignatures[i]
		if !s.Scan {
			continue
		}
		if at := bytes.Index(head, s.Magic); at > 0 {
			res.Signature, res.At, res.Compressed = s, int64(at), false
			return res, nil
		}
	}
	return res, nil
}
