package cmd

import (
	"github.com/psanford/ptrace/inspect"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "petrace",
	Short: "Peter's trace tool",
}

func Execute() error {

	rootCmd.AddCommand(inspect.Command())

	return rootCmd.Execute()
}
