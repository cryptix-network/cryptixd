#!/bin/bash
rm -rf /tmp/cryptixd-temp

cryptixd --devnet --appdir=/tmp/cryptixd-temp --profile=6061 &
CRYPTIXD_PID=$!

sleep 1

infra-level-garbage --devnet -alocalhost:19121 -m messages.dat --profile=7000
TEST_EXIT_CODE=$?

kill $CRYPTIXD_PID

wait $CRYPTIXD_PID
CRYPTIXD_EXIT_CODE=$?

echo "Exit code: $TEST_EXIT_CODE"
echo "Cryptixd exit code: $CRYPTIXD_EXIT_CODE"

if [ $TEST_EXIT_CODE -eq 0 ] && [ $CRYPTIXD_EXIT_CODE -eq 0 ]; then
  echo "infra-level-garbage test: PASSED"
  exit 0
fi
echo "infra-level-garbage test: FAILED"
exit 1
