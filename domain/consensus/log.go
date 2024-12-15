package consensus

import (
	"github.com/cryptix-network/cryptixd/infrastructure/logger"
	"github.com/cryptix-network/cryptixd/util/panics"
)

var log = logger.RegisterSubSystem("BDAG")
var spawn = panics.GoroutineWrapperFunc(log)
