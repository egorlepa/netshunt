package main

import (
	"fmt"
	"os"

	"github.com/guras256/keenetic-split-tunnel/internal/cli"
)

var version = "dev"

func main() {
	cli.SetVersion(version)
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
