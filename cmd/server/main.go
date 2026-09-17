// Command eudi-api-management is the client-facing management API of the EUDI
// verifier.
package main

import (
	"os"

	"azugo.io/core/cli"
)

// Version is overridden at build time via -ldflags.
var Version = "0.1.0-dev"

func main() {
	if _, ok := os.LookupEnv("SERVER_URLS"); !ok {
		_ = os.Setenv("SERVER_URLS", "http://0.0.0.0:8080")
	}
	cli.Run(cli.Options{
		Use:     "eudi-api-management",
		Short:   "EUDI Wallet verifier management API (client-facing)",
		Version: Version,
	})
}
