// code in goelf.go is derived from the Go Programming Language
// source: github.com/golang/go.
// copyright belongs to The Go Authors.

package inspect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
)

func readGoVersionMod(exe *elf.File) (string, string) {
	infoSection := exe.Section(".go.buildinfo")
	if infoSection == nil {
		return "", ""
	}
	goinfo, err := ioutil.ReadAll(infoSection.Open())
	if err != nil {
		log.Fatalf("read go.buildinfo err: %s", err)
	}
	buildInfoMagic := []byte("\xff Go buildinf:")

	if !bytes.HasPrefix(goinfo, buildInfoMagic) {
		log.Printf("unexpected data in go.buildinfo")
		return "", ""
	}
	ptrSize := int(goinfo[14])
	bigEndian := goinfo[15] != 0
	var bo binary.ByteOrder
	if bigEndian {
		bo = binary.BigEndian
	} else {
		bo = binary.LittleEndian
	}

	var readPtr func([]byte) uint64
	if ptrSize == 4 {
		readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
	} else {
		readPtr = bo.Uint64
	}

	vers := readString(exe, ptrSize, readPtr, readPtr(goinfo[16:]))
	if vers == "" {
		return "", ""
	}
	mod := readString(exe, ptrSize, readPtr, readPtr(goinfo[16+ptrSize:]))
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		// Strip module framing.
		mod = mod[16 : len(mod)-16]
	} else {
		mod = ""
	}

	return vers, mod
}

func readString(f *elf.File, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := readData(f, addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := readData(f, dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}

func readData(f *elf.File, addr, size uint64) ([]byte, error) {
	for _, prog := range f.Progs {
		if prog.Vaddr <= addr && addr <= prog.Vaddr+prog.Filesz-1 {
			n := prog.Vaddr + prog.Filesz - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := prog.ReadAt(data, int64(addr-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}
