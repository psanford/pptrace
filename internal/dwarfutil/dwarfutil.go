package dwarfutil

import (
	"debug/dwarf"
	"io"
	"log"
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
