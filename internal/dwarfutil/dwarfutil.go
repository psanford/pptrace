package dwarfutil

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"path/filepath"
)

type Node struct {
	Entry     dwarf.Entry
	Children  []*Node
	OffsetMap map[dwarf.Offset]*Node
}

func Tree(r *dwarf.Reader) *Node {
	var (
		first = true
		stack = make([]*Node, 0)
		root  *Node
	)

	for {
		entry, err := r.Next()
		if err == io.EOF || entry == nil {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		if first {
			first = false
			root = &Node{
				Entry:     *entry,
				Children:  make([]*Node, 0),
				OffsetMap: make(map[dwarf.Offset]*Node),
			}

			stack = append(stack, root)
		}

		node := &Node{
			Entry: *entry,
		}

		root.OffsetMap[entry.Offset] = node

		// empty node denotes we're at the end of the parent's children
		if entry.Children == false && entry.Offset == 0 && entry.Tag == 0 {
			stack = stack[:len(stack)-1]
			continue
		}

		parent := stack[len(stack)-1]
		parent.Children = append(parent.Children, node)

		if entry.Children {
			stack = append(stack, node)
		}
	}

	return root
}

// FindDwarf returns the path to the elf containing debug
// symbols for the given path. If debug symbols are present
// in the original path, that path is returned.
//
// Logic based on https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
func FindDwarf(path string) (string, error) {
	e, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer e.Close()

	_, err = e.DWARF()
	if err == nil {
		return path, nil
	}

	buildID := readBuildID(e)

	pathsToCheck := make([]string, 0, 4)

	if buildID != "" {
		prefix := buildID[:2]
		suffix := buildID[2:] + ".debug"

		pathsToCheck = append(pathsToCheck, filepath.Join("/usr/lib/debug/.build-id", prefix, suffix))
	}

	dbgLink := readDebugLink(e)
	if dbgLink != nil {
		origDir := filepath.Dir(path)
		pathsToCheck = append(pathsToCheck,
			filepath.Join(origDir, dbgLink.name),
			filepath.Join(origDir, ".debug", dbgLink.name),
			filepath.Join("/usr/lib/debug", origDir, dbgLink.name),
		)
	}

	for _, p := range pathsToCheck {
		if existsAndHasDwarf(p) {
			return p, nil
		}
	}

	return "", fmt.Errorf("no debug symbols found")
}

func existsAndHasDwarf(p string) bool {
	debugElf, err := elf.Open(p)
	if err != nil {
		return false
	}
	defer debugElf.Close()
	_, err = debugElf.DWARF()
	return err == nil
}

func readDebugLink(e *elf.File) *debugLink {
	s := e.Section(".gnu_debuglink")
	if s == nil {
		return nil
	}

	r := bufio.NewReader(s.Open())
	name, err := r.ReadBytes(0)
	if err != nil {
		return nil
	}

	pad := len(name) % 4
	_, err = r.Discard(pad)
	if err != nil {
		return nil
	}

	crc32 := make([]byte, 4)
	_, err = io.ReadFull(r, crc32)
	if err != nil {
		return nil
	}

	return &debugLink{
		name: string(name[:len(name)-1]),
		crc:  crc32,
	}
}

type debugLink struct {
	name string
	crc  []byte
}

func readBuildID(e *elf.File) string {
	s := e.Section(".note.gnu.build-id")
	if s == nil {
		return ""
	}

	r := s.Open()
	var bh buildIDHeader

	err := binary.Read(r, binary.LittleEndian, bh)
	if err != nil {
		return ""
	}

	name := make([]byte, bh.Namesz)

	_, err = io.ReadFull(r, name)
	if err != nil {
		return ""
	}

	desc := make([]byte, bh.Descsz)
	_, err = io.ReadFull(r, desc)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(desc)
}

type buildIDHeader struct {
	Namesz uint32
	Descsz uint32
	Type   uint32
}
