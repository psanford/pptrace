package main

import (
	"log"

	"github.com/psanford/pptrace/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
