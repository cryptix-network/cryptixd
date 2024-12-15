#!/bin/bash
rm -rf /tmp/cryptixd-temp

cryptixd --devnet --appdir=/tmp/cryptixd-temp --profile=6061 --loglevel=debug &
CRYPTIXD_PID=$!
CRYPTIXD_KILLED=0
function killCryptixdIfNotKilled() {
    if [ $CRYPTIXD_KILLED -eq 0 ]; then
      kill $CRYPTIXD_PID
    fi
}
trap "killCryptixdIfNotKilled" EXIT

sleep 1

application-level-garbage --devnet -alocalhost:19121 -b blocks.dat --profile=7000
TEST_EXIT_CODE=$?

kill $CRYPTIXD_PID

wait $CRYPTIXD_PID
CRYPTIXD_KILLED=1
CRYPTIXD_EXIT_CODE=$?

echo "Exit code: $TEST_EXIT_CODE"
echo "Cryptixd exit code: $CRYPTIXD_EXIT_CODE"

if [ $TEST_EXIT_CODE -eq 0 ] && [ $CRYPTIXD_EXIT_CODE -eq 0 ]; then
  echo "application-level-garbage test: PASSED"
  exit 0
fi
echo "application-level-garbage test: FAILED"
exit 1
