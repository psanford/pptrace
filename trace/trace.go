package trace

import (
	"debug/elf"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/psanford/tracefs"
	"github.com/spf13/cobra"
)

var (
	dryRun  bool
	verbose bool
)

func Command() *cobra.Command {
	cmd := cobra.Command{
		Use:   "trace <binary> <function> [arg_expression...] [-- <binary> <function> [arg_expression...]]",
		Short: "Function tracer",
		RunE:  traceAction,
	}

	cmd.Flags().BoolVarP(&dryRun, "dry", "", false, "Show commands that would be run")
	cmd.Flags().BoolVarP(&verbose, "verbose", "", false, "Show commands as they are run")

	return &cmd
}

type traceTarget struct {
	binary         string
	function       string
	argExpressions []string

	targetName   string
	functionAddr uint64
	compiledArgs []string
}

func traceAction(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		log.Fatal("usage: trace <binary> <function> [arg_expression...] [-- <binary> <function> [arg_expression...]]")
	}
	var (
		targets   []*traceTarget
		curTarget *traceTarget
		seenName  bool
		seenFunc  bool
	)
	for _, arg := range args {
		if arg == "--" {
			if !seenName || !seenFunc {
				log.Fatal("Arg parse error: saw '--' without full trace defintion <binary> <function>")
			}
			targets = append(targets, curTarget)
			curTarget = nil
			seenName = false
			seenFunc = false
			continue
		}
		if curTarget == nil {
			curTarget = &traceTarget{}
		}

		if !seenName {
			seenName = true
			curTarget.binary = arg
			continue
		}

		if !seenFunc {
			seenFunc = true
			curTarget.function = arg
			continue
		}

		curTarget.argExpressions = append(curTarget.argExpressions, arg)
	}

	if curTarget != nil {
		if !seenName || !seenFunc {
			log.Fatal("Arg parse error: saw '--' without full trace defintion <binary> <function>")
		}
		targets = append(targets, curTarget)
		curTarget = nil
	}

	for i, t := range targets {
		err := t.Compile(i)
		if err != nil {
			return err
		}
	}

	inst := tracefs.DefaultInstance

	instPath := filepath.Join("/sys/kernel/tracing/")

	for _, t := range targets {
		evt := t.Uprobe()
		if dryRun || verbose {
			log.Printf("echo %q >> %s", evt.Rule(), filepath.Join(instPath, "uprobe_events"))
		}
		if !dryRun {
			err := inst.AddUprobeEvent(evt)
			if err != nil {
				return fmt.Errorf("add uprobe err: %s", err)
			}
		}

		defer inst.RemoveUprobeEvent(evt)
	}

	for _, t := range targets {
		evt := t.Uprobe()
		if dryRun || verbose {
			log.Printf("echo 1 > %s", inst.UprobeEnablePath(evt))
		}
		if !dryRun {
			err := inst.EnableUprobe(evt)
			if err != nil {
				return fmt.Errorf("enable uprobe err: %s", err)
			}
			defer inst.DisableUprobe(evt)
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	stop := make(chan struct{})
	go func() {
		<-sigChan
		close(stop)
	}()

	if dryRun || verbose {
		log.Printf("cat %s", filepath.Join(instPath, "trace_pipe"))
	}
	if !dryRun {
		p, err := inst.TracePipe()
		if err != nil {
			return err
		}
		defer p.Close()
		go func() {
			<-stop
			p.Close()
		}()
		io.Copy(os.Stdout, p)
	}

	return nil

}

func (t *traceTarget) Uprobe() *tracefs.UprobeEvent {
	e := tracefs.UprobeEvent{
		Group:  "pptrace",
		Event:  t.targetName,
		Path:   t.binary,
		Offset: t.functionAddr,
	}
	return &e
}

func (t *traceTarget) Compile(idx int) error {
	exe, err := elf.Open(t.binary)
	if err != nil {
		return fmt.Errorf("Open elf %s err: %s", t.binary, err)
	}

	defer exe.Close()

	symbols, errSym := exe.Symbols()
	dsyms, errDyn := exe.DynamicSymbols()

	if errSym != nil && errDyn != nil {
		log.Fatalf("Get symbols err: %s %s", errSym, errDyn)
	}

	symbols = append(symbols, dsyms...)

	var funcFound bool

	var addrOffset uint64
	for _, prog := range exe.Progs {
		if prog.Type == elf.PT_LOAD {
			addrOffset = prog.Vaddr
			break
		}
	}

	for _, sym := range symbols {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		if sym.Name == t.function {
			t.functionAddr = sym.Value - addrOffset
			funcFound = true
			break
		}
	}

	if !funcFound {
		return fmt.Errorf("function %s not found in %s", t.function, t.binary)
	}

	t.targetName = fmt.Sprintf("%s_%d", safeName(t.function), idx)

	return nil
}

func safeName(n string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'z' || r == '_' {
			return r
		}
		return -1
	}, n)

}
