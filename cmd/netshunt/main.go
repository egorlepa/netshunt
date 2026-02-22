package main

import (
	"fmt"
	"os"

	"github.com/egorlepa/netshunt/internal/cli"
)

var version = "dev"

func main() {
	cli.SetVersion(version)
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
