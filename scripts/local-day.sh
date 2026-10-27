#!/bin/bash
# Solve (and, with RACE=1, race) one release day from a player's own machine: homebase-day.sh for
# a checkout of this repo instead of the Homebase. Started by cron every minute (see the install
# lines below). Run by hand: scripts/local-day.sh [day]
#
# Before the release (09:00 New York) it sleeps until just before it; `daily --wait-release` then
# starts the moment the day is listed:
#   1. solves every challenge the robot can, untimed, families in parallel, and with --prove gives
#      each Time Trial/Mastery someone solved by hand one untimed run, so the robot holds its own
#      proof (a regular variant, never a ranked one);
#   2. with RACE=1 only, races each proven Time Trial and Mastery route once (run_for_time).
# Later cron runs sweep again only when src/, this script or hints.json changed since the last
# sweep, so a solver committed during the day scores (and races) within a minute.
# Logs: $ROBOT_LOGS/day-auto.log (summaries), dayNN-HHMM-untimed.log and dayNN-HHMM-timed.log.
#
# Differences from homebase-day.sh: the code is this checkout (PYTHONPATH=src), the Game Master is
# the direct API with the token from the checkout's git-ignored .env (cron has no shell profile),
# state lives in .huntress/ beside it, the default lanes leave Web out, MIN_DAY keeps it off older
# days, and the race gate allows the direct route's ~0.6 s per request.
#
# Only one robot may play a team's shared attempts: stop any other robot (a Homebase cron) first.
# Install (one line per crontab entry; RACE=1 lets it race ranked):
#   crontab -e, then add:
#     * * * * * MIN_DAY=27 RACE=1 /path/to/ai-tool/scripts/local-day.sh >> $HOME/robot-logs/day-auto.log 2>&1
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
day="${1:-$(TZ=America/New_York date +%-d)}"
[ "$day" -ge "${MIN_DAY:-1}" ] || exit 0
state="$root/.huntress"
logs="${ROBOT_LOGS:-$HOME/robot-logs}"
mkdir -p "$state" "$logs"
exec 9>"$state/day.lock"
flock -n 9 || exit 0  # A sweep is already running or waiting for the release.
if [ ! -f "$root/.env" ] && [ -z "${HUNTRESS_GM_TOKEN:-}" ]; then
  echo "$(date): no token: create $root/.env (HUNTRESS_GM_TOKEN=..., chmod 600); nothing was started."
  exit 0
fi
cd "$root"
export PYTHONPATH="$root/src"
lanes="${LANES:-warmups,metadata-forensics,mobile-android,script-analysis,binary-reverse-engineering}"
code() { { find "$root/src" -name '*.py' -type f -print0 | sort -z | xargs -0 sha1sum; cat "$0"; echo "$lanes ${RACE:-0}"; } | sha1sum; }
# While the last sweep left a Time Trial or Mastery waiting for its earlier mode, the day's solved
# flags count too: a mode a human finishes by hand starts the next one within a minute.
waiting() {
  last=$(ls -t "$logs"/day"$day"-*-untimed.log 2>/dev/null | head -1)
  [ -n "$last" ] && grep -q 'is not solved yet' "$last" || return 0
  python3 -m huntress_ctf list --day "$day" 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit()
items = data.get("challenges", data) if isinstance(data, dict) else data
print(sorted(str(c.get("id")) for c in items if isinstance(c, dict) and c.get("solved") is True))'
}
version() { { echo "$1"; cat "$state/hints.json" 2>/dev/null; waiting; } | sha1sum | cut -c1-16; }
swept="$state/day$day.swept"
[ -e "$swept" ] && [ "$(cat "$swept")" = "$(version "$(code)")" ] && exit 0  # Nothing new to try.
release=$(TZ=America/New_York date -d "08:59:30" +%s)
now=$(date +%s)
if [ "$now" -lt "$release" ]; then
  echo "$(date): day $day waits $(( (release - now) / 60 )) min for the release (09:00 New York)."
  sleep $(( release - now )) 9>&-  # fd 9 closed: a killed waiter frees day.lock (homebase-day.sh).
fi
robot() { python3 -m huntress_ctf --lock-wait 3600 "$@"; }
log="$logs/day$day-$(date +%H%M)"
started_code=$(code)
echo "== Day $day: untimed sweep (lanes $lanes), $(date)"
robot daily --day "$day" --lanes "$lanes" --wait-release 1800 --prove > "$log-untimed.log" 2>&1
sed -n '/===== Summary =====/,$p' "$log-untimed.log"
# A transport or server error (an overloaded release), or a sweep that died before its summary,
# gets another sweep next minute, at most 10 times, before any race (an errored Single Solve
# blocks its lane's later modes); unresolved and incorrect do not.
retries="$state/day$day.retries"
if { grep -q '"outcome": "error"' "$log-untimed.log" || ! grep -q '===== Summary =====' "$log-untimed.log"; } \
    && [ "$(cat "$retries" 2>/dev/null || echo 0)" -lt 10 ]; then
  echo $(( $(cat "$retries" 2>/dev/null || echo 0) + 1 )) > "$retries"
  echo "== Day $day: errors in the sweep; trying again next minute, races after, $(date)"
  exit 0
fi
if [ "${RACE:-0}" = "1" ]; then
  echo "== Day $day: timed races, $(date)"
  robot daily --day "$day" --lanes "$lanes" --timed --gate-ms "${GATE_MS:-1500}" --gate-wait 20 > "$log-timed.log" 2>&1
  sed -n '/===== Summary =====/,$p' "$log-timed.log"
else
  echo "== Day $day: no timed races (RACE=1 turns them on), $(date)"
fi
version "$started_code" > "$swept"
echo "== Day $day swept, $(date)"
