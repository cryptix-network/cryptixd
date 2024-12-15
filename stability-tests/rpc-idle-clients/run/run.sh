#!/bin/bash
rm -rf /tmp/cryptixd-temp

NUM_CLIENTS=128
cryptixd --devnet --appdir=/tmp/cryptixd-temp --profile=6061 --rpcmaxwebsockets=$NUM_CLIENTS &
CRYPTIXD_PID=$!
CRYPTIXD_KILLED=0
function killCryptixdIfNotKilled() {
  if [ $CRYPTIXD_KILLED -eq 0 ]; then
    kill $CRYPTIXD_PID
  fi
}
trap "killCryptixdIfNotKilled" EXIT

sleep 1

rpc-idle-clients --devnet --profile=7000 -n=$NUM_CLIENTS
TEST_EXIT_CODE=$?

kill $CRYPTIXD_PID

wait $CRYPTIXD_PID
CRYPTIXD_EXIT_CODE=$?
CRYPTIXD_KILLED=1

echo "Exit code: $TEST_EXIT_CODE"
echo "Cryptixd exit code: $CRYPTIXD_EXIT_CODE"

if [ $TEST_EXIT_CODE -eq 0 ] && [ $CRYPTIXD_EXIT_CODE -eq 0 ]; then
  echo "rpc-idle-clients test: PASSED"
  exit 0
fi
echo "rpc-idle-clients test: FAILED"
exit 1
