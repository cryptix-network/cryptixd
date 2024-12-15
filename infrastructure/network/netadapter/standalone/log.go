package standalone

import (
	"github.com/cryptix-network/cryptixd/infrastructure/logger"
	"github.com/cryptix-network/cryptixd/util/panics"
)

var log = logger.RegisterSubSystem("NTAR")
var spawn = panics.GoroutineWrapperFunc(log)
