package cmd

import (
	"github.com/psanford/pptrace/inspect"
	"github.com/psanford/pptrace/tracerstate"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pptrace",
	Short: "Peter's trace tool",
}

func Execute() error {

	rootCmd.AddCommand(inspect.Command())
	rootCmd.AddCommand(tracerstate.Command())

	return rootCmd.Execute()
}
