package tracerstate

import (
	"fmt"
	"log"

	"github.com/psanford/tracefs"
	"github.com/spf13/cobra"
)

func Command() *cobra.Command {
	cmd := cobra.Command{
		Use:   "tracer_state",
		Short: "Get tracefs state",
	}

	cmd.AddCommand(listTracersCommand())

	return &cmd
}

func listTracersCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "list_tracers",
		Short: "List tracer instances",
		Run:   listTracersAction,
	}

	return &cmd
}

func listTracersAction(cmd *cobra.Command, args []string) {
	insts, err := tracefs.ListInstances()
	if err != nil {
		log.Fatalf("list instances err: %s", err)
	}
	for _, inst := range insts {
		on, err := inst.On()
		if err != nil {
			log.Fatalf("get on state err for %s: %s", inst.Name(), err)
		}

		tracer, err := inst.CurrentTracer()
		if err != nil {
			log.Fatalf("get on CurrentTracer err for %s: %s", inst.Name(), err)
		}

		fmt.Printf("Instance: %s on=%t tracer=%s\n", inst.Name(), on, tracer)
	}
}
