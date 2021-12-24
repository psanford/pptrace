package inspect

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
)

func Command() *cobra.Command {
	cmd := cobra.Command{
		Use:   "inspect",
		Short: "Inspect a binary or library",
	}

	cmd.AddCommand(listSymbolsCommand())
	cmd.AddCommand(infoCommand())
	cmd.AddCommand(listSectionsCommand())

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

	for _, s := range exe.Sections {
		fmt.Printf("section: %s %s\n", s.Name, s.Type)
		fmt.Printf("section: %+v\n", s)
	}
}
