package common

import (
	"fmt"
	"github.com/cryptix-network/cryptixd/domain/dagconfig"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
)

// RunCryptixdForTesting runs cryptixd for testing purposes
func RunCryptixdForTesting(t *testing.T, testName string, rpcAddress string) func() {
	appDir, err := TempDir(testName)
	if err != nil {
		t.Fatalf("TempDir: %s", err)
	}

	cryptixdRunCommand, err := StartCmd("CRYPTIXD",
		"cryptixd",
		NetworkCliArgumentFromNetParams(&dagconfig.DevnetParams),
		"--appdir", appDir,
		"--rpclisten", rpcAddress,
		"--loglevel", "debug",
	)
	if err != nil {
		t.Fatalf("StartCmd: %s", err)
	}
	t.Logf("Cryptixd started with --appdir=%s", appDir)

	isShutdown := uint64(0)
	go func() {
		err := cryptixdRunCommand.Wait()
		if err != nil {
			if atomic.LoadUint64(&isShutdown) == 0 {
				panic(fmt.Sprintf("Cryptixd closed unexpectedly: %s. See logs at: %s", err, appDir))
			}
		}
	}()

	return func() {
		err := cryptixdRunCommand.Process.Signal(syscall.SIGTERM)
		if err != nil {
			t.Fatalf("Signal: %s", err)
		}
		err = os.RemoveAll(appDir)
		if err != nil {
			t.Fatalf("RemoveAll: %s", err)
		}
		atomic.StoreUint64(&isShutdown, 1)
		t.Logf("Cryptixd stopped")
	}
}
