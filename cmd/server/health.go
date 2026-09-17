package main

import (
	eudiapimanagement "github.com/dativa-lv/eudi-api-management"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Management API",
		AppVer:        Version,
		Configuration: eudiapimanagement.NewConfiguration(),
	}))
}
