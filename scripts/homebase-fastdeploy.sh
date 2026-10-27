#!/bin/bash
# The Homebase half of `scripts/homebase.sh fastdeploy [lane ...]`, run from the unpacked
# ~/deploy-<stamp> folder. scripts/fastdeploy.py picks the tests and corpus lanes the change can
# affect (a change to the robot itself gets the whole suite and corpus, as `deploy`); then the
# swap, and a sweep at once instead of at the next cron minute. No new replay baseline: on release
# day a full replay would compete with the robot for the 2 cores and 1.9 GB.
# Env: DRY=1 stops before the swap; ALLOW_SLOWER=1 and SKIP_REPLAY=1 as for `deploy`.
set -euo pipefail
began=$(date +%s)
plan=$(python3 -I scripts/fastdeploy.py plan ~/src src tests "$@")
grep '^#' <<<"$plan" || true
mode=$(sed -n 's/^MODE=//p' <<<"$plan")
tests=$(sed -n 's/^TESTS=//p' <<<"$plan")
lanes=$(sed -n 's/^REPLAY=//p' <<<"$plan")
export HUNTRESS_LOCK=/tmp/deploy-test.lock PYTHONPATH=src
if [ "$mode" = full ]; then
  python3 -m unittest discover -s tests > test.log 2>&1 || status=$?
else
  # shellcheck disable=SC2086  # One test file per word.
  python3 scripts/fastdeploy.py test tests $tests > test.log 2>&1 || status=$?
fi
if [ "${status:-0}" != 0 ]; then
  tail -25 test.log; echo 'Tests failed on the VM; ~/src is unchanged.'; exit 1
fi
echo "tests ($mode, $(( $(date +%s) - began )) s): $(grep -E '^Ran ' test.log)"
replay() {  # One corpus lane, or the whole corpus without an argument.
  HUNTRESS_ALLOW_SLOWER="${ALLOW_SLOWER:-0}" HUNTRESS_STATE_DIR=~/.huntress \
    python3 scripts/replay.py --dry ${1:+--only "$1-day-"} >> replay.log 2>&1
}
if [ "${SKIP_REPLAY:-0}" != 1 ]; then
  failed=0
  if [ "$mode" = full ]; then
    replay || failed=1
  else
    for lane in $lanes; do replay "$lane" || failed=1; done
  fi
  if [ "$failed" = 1 ]; then
    grep -B1 -A3 -E 'REGRESSION|SLOWER|BROKE' replay.log | head -40
    echo 'Replay found regressions, slower or broken solvers; ~/src is unchanged (ALLOW_SLOWER=1 accepts slower solvers, SKIP_REPLAY=1 deploys anyway).'
    exit 1
  fi
  [ "$mode" = full ] && lanes="whole corpus"
  echo "replay (${lanes:-no lane}, $(( $(date +%s) - began )) s): $(grep -c ' answered |' replay.log 2>/dev/null || true) entries, no regression"
fi
if [ "${DRY:-0}" = 1 ]; then
  echo "DRY=1: checks passed in $(( $(date +%s) - began )) s; ~/src is unchanged."
  exit 0
fi
rm -rf ~/src.previous ~/src.new
cp -a src ~/src.new
mv ~/src ~/src.previous && mv ~/src.new ~/src  # ~/src is gone only between two renames, not for a copy.
install -m 755 scripts/homebase-day.sh ~/day.sh; install -m 755 scripts/homebase-hof.sh ~/hof.sh
install -m 755 scripts/replay.py ~/replay.py
# Sweep now: day.sh exits at once if a sweep holds day.lock, and the cron minute after it sees the new code.
setsid nohup ~/day.sh >> ~/day-auto.log 2>&1 < /dev/null &
echo "Deployed $(pwd) in $(( $(date +%s) - began )) s (previous code in ~/src.previous); a sweep was started."
