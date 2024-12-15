package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cryptix-network/cryptixd/version"
)

func showVersion() {
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	fmt.Println(appName, "version", version.Version())
}
