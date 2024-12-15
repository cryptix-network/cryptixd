#!/bin/bash
rm -rf /tmp/cryptixd-temp

cryptixd --devnet --appdir=/tmp/cryptixd-temp --profile=6061 --loglevel=debug &
CRYPTIXD_PID=$!

sleep 1

rpc-stability --devnet -p commands.json --profile=7000
TEST_EXIT_CODE=$?

kill $CRYPTIXD_PID

wait $CRYPTIXD_PID
CRYPTIXD_EXIT_CODE=$?

echo "Exit code: $TEST_EXIT_CODE"
echo "Cryptixd exit code: $CRYPTIXD_EXIT_CODE"

if [ $TEST_EXIT_CODE -eq 0 ] && [ $CRYPTIXD_EXIT_CODE -eq 0 ]; then
  echo "rpc-stability test: PASSED"
  exit 0
fi
echo "rpc-stability test: FAILED"
exit 1
