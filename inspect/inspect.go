package inspect

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
	allFlag    bool
)

func Command() *cobra.Command {
	cmd := cobra.Command{
		Use:   "inspect",
		Short: "Inspect a binary or library",
	}

	cmd.AddCommand(infoCommand())
	cmd.AddCommand(listSectionsCommand())
	cmd.AddCommand(listSymbolsCommand())
	cmd.AddCommand(listFunctionsCommand())
	cmd.AddCommand(functionArgsCommand())

	return &cmd
}

func infoCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "info <file>",
		Short: "General information about elf",
		Run:   infoAction,
	}

	return &cmd
}

func infoAction(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		log.Fatalf("Usage: info <file>")
	}

	exe, err := elf.Open(args[0])
	if err != nil {
		log.Fatalf("Open elf err: %s", err)
	}

	defer exe.Close()

	var prettyType string

	switch exe.Type {
	case elf.ET_REL:
		prettyType = "Relocatable"
	case elf.ET_EXEC:
		prettyType = "Executable"
	case elf.ET_DYN:
		prettyType = "Shared object"
	case elf.ET_CORE:
		prettyType = "Core file"
	case elf.ET_LOOS:
		prettyType = "First operating system specific"
	case elf.ET_HIOS:
		prettyType = "Last operating system-specific"
	case elf.ET_LOPROC:
		prettyType = "First processor-specific"
	case elf.ET_HIPROC:
		prettyType = "Last processor-specific"
	case elf.ET_NONE:
		prettyType = "Unknown type"
	default:
		prettyType = "Unknown type"
	}

	fmt.Printf("Type: %s\n", prettyType)

	ver, modinfo := readGoVersionMod(exe)
	if ver != "" {
		fmt.Printf("Go version: %s\n", ver)
	}
	if modinfo != "" {
		modinfo = strings.ReplaceAll(modinfo, "\n", "\n\t")
		fmt.Printf("Go modules:\n\t%s\n", modinfo)
	}
}

func listSectionsCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "sections <file>",
		Short: "List sections",
		Run:   listSectionsAction,
	}

	cmd.Flags().BoolVarP(&jsonOutput, "json", "", false, "Show raw json ouput")

	return &cmd
}

func listSectionsAction(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		log.Fatalf("Usage: sections <file>")
	}

	jsonOut := json.NewEncoder(os.Stdout)
	jsonOut.SetIndent("", "  ")

	exe, err := elf.Open(args[0])
	if err != nil {
		log.Fatalf("Open elf err: %s", err)
	}

	defer exe.Close()

	for _, s := range exe.Sections {
		if jsonOutput {
			jsonOut.Encode(s)
		} else {
			fmt.Printf("%s %s\n", s.Type, s.Name)
		}
	}
}

func listSymbolsCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "symbols <file>",
		Short: "List symbols",
		Run:   listSymbolsAction,
	}

	return &cmd
}

func listSymbolsAction(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		log.Fatalf("Usage: symbols <file>")
	}

	exe, err := elf.Open(args[0])
	if err != nil {
		log.Fatalf("Open elf err: %s", err)
	}

	defer exe.Close()

	symbols, err := exe.Symbols()
	if err != nil {
		log.Fatalf("Get symbols err: %s", err)
	}
	for _, sym := range symbols {
		fmt.Printf("%+v\n", sym)
	}
}

func listFunctionsCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "functions <file> [filter]",
		Short: "List functions",
		Run:   listFunctionsAction,
	}

	return &cmd
}

func listFunctionsAction(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		log.Fatalf("Usage: functions <file> [filter]")
	}

	var filterString string
	if len(args) > 1 {
		filterString = args[1]
	}
	exe, err := elf.Open(args[0])
	if err != nil {
		log.Fatalf("Open elf err: %s", err)
	}

	defer exe.Close()

	symbols, errSym := exe.Symbols()
	dsyms, errDyn := exe.DynamicSymbols()

	if errSym != nil && errDyn != nil {
		log.Fatalf("Get symbols err: %s %s", errSym, errDyn)
	}

	symbols = append(symbols, dsyms...)

	for _, sym := range symbols {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		if len(filterString) == 0 || strings.Contains(sym.Name, filterString) {
			fmt.Printf("%016x %016x %s\n", sym.Value, sym.Size, sym.Name)
		}
	}
}

func functionArgsCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "args <file> [<function-name>|-all]",
		Short: "Show available function variables",
		Run:   funcArgsAction,
	}

	cmd.Flags().BoolVarP(&allFlag, "all", "", false, "Show all functions")

	return &cmd
}

func funcArgsAction(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		log.Fatalf("Usage: args <file> [<function>|-all]")
	}

	if len(args) < 2 && !allFlag {
		log.Fatalf("Usage: args <file> [<function>|-all]")
	}

	var matchFuncName string
	if !allFlag {
		matchFuncName = args[1]
	}

	exe, err := elf.Open(args[0])
	if err != nil {
		log.Fatalf("Open elf err: %s", err)
	}

	defer exe.Close()

	dwarfInfo, err := exe.DWARF()
	if err != nil {
		log.Fatalf("read dwarf err: %s", err)
	}

	// var inFuncDef bool

	r := dwarfInfo.Reader()

	var (
		first = true
		stack = make([]*dwarfNode, 0)
		root  *dwarfNode
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
			root = &dwarfNode{
				entry:    *entry,
				children: make([]*dwarfNode, 0),
			}
			stack = append(stack, root)
		}

		node := dwarfNode{
			entry: *entry,
		}

		// empty node denotes we're at the end of the parent's children
		if entry.Children == false && entry.Offset == 0 && entry.Tag == 0 {
			stack = stack[:len(stack)-1]
			continue
		}

		parent := stack[len(stack)-1]
		parent.children = append(parent.children, &node)

		if entry.Children {
			stack = append(stack, &node)
		}

	}

	r.Seek(0)
	for _, pkgs := range root.children {
		for _, pkgNode := range pkgs.children {
			// // function definition
			if pkgNode.entry.Tag == dwarf.TagSubprogram {
				var matchedName bool
				for _, field := range pkgNode.entry.Field {
					if field.Attr == dwarf.AttrName {
						funcName := field.Val.(string)
						if strings.Contains(funcName, matchFuncName) {
							fmt.Printf("%s\n", funcName)
							matchedName = true
						}
					}
				}

				if !matchedName {
					continue
				}

				for _, funcChild := range pkgNode.children {
					// function argument
					if funcChild.entry.Tag == dwarf.TagFormalParameter {
						var (
							name     string
							typeName string
						)

						for _, field := range funcChild.entry.Field {
							if field.Attr == dwarf.AttrName {
								name = field.Val.(string)
							}

							if field.Attr == dwarf.AttrType {
								r.Seek(field.Val.(dwarf.Offset))
								typeEntry, err := r.Next()
								if err != nil {
									log.Fatal(err)
								}
								for i := range typeEntry.Field {
									if typeEntry.Field[i].Attr == dwarf.AttrName {
										typeName = typeEntry.Field[i].Val.(string)
									}
								}
							}
						}

						fmt.Printf("\t%s %s\n", name, typeName)
					}
				}
			}
		}
	}
}

type dwarfNode struct {
	entry    dwarf.Entry
	children []*dwarfNode
}
