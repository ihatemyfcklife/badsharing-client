package main

import (
	"fmt"
	"os"

	"github.com/ihatemyfcklife/badsharing-client/internal/desktop"
	"github.com/ihatemyfcklife/badsharing-client/internal/lanfirewall"
)

func main() {
	if handled, err := lanfirewall.RunHelper(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	desktop.Run()
}
