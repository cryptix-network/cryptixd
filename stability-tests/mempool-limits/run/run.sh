#!/bin/bash

APPDIR=/tmp/cryptixd-temp
CRYPTIXD_RPC_PORT=29587

rm -rf "${APPDIR}"

cryptixd --simnet --appdir="${APPDIR}" --rpclisten=0.0.0.0:"${CRYPTIXD_RPC_PORT}" --profile=6061 &
CRYPTIXD_PID=$!

sleep 1

RUN_STABILITY_TESTS=true go test ../ -v -timeout 86400s -- --rpc-address=127.0.0.1:"${CRYPTIXD_RPC_PORT}" --profile=7000
TEST_EXIT_CODE=$?

kill $CRYPTIXD_PID

wait $CRYPTIXD_PID
CRYPTIXD_EXIT_CODE=$?

echo "Exit code: $TEST_EXIT_CODE"
echo "Cryptixd exit code: $CRYPTIXD_EXIT_CODE"

if [ $TEST_EXIT_CODE -eq 0 ] && [ $CRYPTIXD_EXIT_CODE -eq 0 ]; then
  echo "mempool-limits test: PASSED"
  exit 0
fi
echo "mempool-limits test: FAILED"
exit 1
