package main

import (
	"os"

	"github.com/wyh0626/cli-gateway/client/internal/app"
)

func main() {
	os.Exit(app.Run(app.Options{
		Args: os.Args[1:], Environ: os.Environ(),
		IO: app.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
	}))
}
