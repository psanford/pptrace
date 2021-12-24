package main

import (
	"log"

	"github.com/psanford/ptrace/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
