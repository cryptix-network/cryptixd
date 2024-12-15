package main

import (
	"github.com/cryptix-network/cryptixd/infrastructure/logger"
	"github.com/cryptix-network/cryptixd/util/panics"
)

var (
	backendLog = logger.NewBackend()
	log        = backendLog.Logger("JSTT")
	spawn      = panics.GoroutineWrapperFunc(log)
)
