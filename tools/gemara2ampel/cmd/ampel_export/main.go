package main

import (
	"os"

	"gemara2ampel/go/cmd/ampel_export/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
