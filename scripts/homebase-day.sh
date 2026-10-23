#!/bin/bash
# Solve and race one release day on the Homebase that plays for the team. Started by cron
# every minute and at boot (see `crontab -l`). Run by hand: ~/day.sh [day]
#
# Before the release (09:00 New York = 15:00 in Sweden) it sleeps until just before it;
# `daily --wait-release` then starts the moment the day is listed:
#   1. solves every challenge the robot can, untimed, families in parallel (records
#      proven solvers in ~/.huntress/hints.json);
#   2. races each proven Time Trial and Mastery route once (hints.json keeps the best).
# Later cron runs sweep again only when the code in ~/src or hints.json changed since the
# last sweep (checking takes milliseconds), so a solver deployed during the day scores and
# races within a minute of `scripts/homebase.sh deploy`.
# Logs: ~/day-auto.log (summaries), ~/dayNN-HHMM-untimed.log and ~/dayNN-HHMM-timed.log.
# The robot holds ~/.huntress/robot.lock around every start, retry and submit, so a run
# by hand and this script never play at once: this script waits its turn (--lock-wait).
#
# Install on the one Homebase that plays for the team (teammates share attempts):
#   cp scripts/homebase-day.sh ~/day.sh && chmod +x ~/day.sh   (code in ~/src)
#   crontab -e, then add:
#     @reboot sleep 90 && /home/HuntressCTF/day.sh >> /home/HuntressCTF/day-auto.log 2>&1
#     * * * * * /home/HuntressCTF/day.sh >> /home/HuntressCTF/day-auto.log 2>&1
#     30 0-10/2 * * * /home/HuntressCTF/hof.sh >> /home/HuntressCTF/hof-auto.log 2>&1
set -u
day="${1:-$(TZ=America/New_York date +%-d)}"
state="$HOME/.huntress"
mkdir -p "$state"
exec 9>"$state/day.lock"
flock -n 9 || exit 0  # A sweep is already running or waiting for the release.
export PYTHONPATH="$HOME/src" HUNTRESS_GM_URL="http://10.0.0.219/huntress-ctf-proxy"
# What a sweep depends on: the solver code and this script (its lanes), then the proven
# solvers. The code is taken as the sweep starts, so a deploy during a sweep sweeps again.
code() { { find "$HOME/src" -name '*.py' -type f -print0 | sort -z | xargs -0 sha1sum; cat "$0"; } | sha1sum; }
version() { { echo "$1"; cat "$state/hints.json" 2>/dev/null; } | sha1sum | cut -c1-16; }
swept="$state/day$day.swept"
[ -e "$swept" ] && [ "$(cat "$swept")" = "$(version "$(code)")" ] && exit 0  # Nothing new to try.
release=$(TZ=America/New_York date -d "08:59:30" +%s)
now=$(date +%s)
if [ "$now" -lt "$release" ]; then
  echo "$(date): day $day waits $(( (release - now) / 60 )) min for the release (09:00 New York = 15:00 Sweden)."
  sleep $(( release - now ))
fi
cd "$HOME"
robot() { python3 -m huntress_ctf --lock-wait 3600 "$@"; }
# The robot's lanes only: teammates share attempts, and an untimed start of their Time
# Trial would block their timed race. Add a lane here once the robot has its solver.
# Android since day 22 (the puzzle-asset solver took all of day 21's variants). Script
# since day 22 too: its descriptor answers (54% of a day, all accepted on days 20 and
# 21) give the teammate who finishes Script a head start; a partial solve stays open.
# Since day 22 Script has script-rules (Ilse) and Binary binary-static-facts (David):
# both answered every question of the day 20 and 21 Single Solves offline.
lanes="warmups,metadata-forensics,mobile-android,script-analysis,binary-reverse-engineering,web-exploitation"
log="$HOME/day$day-$(date +%H%M)"
started_code=$(code)  # After the release wait: deploys while waiting are this sweep's code.
echo "== Day $day: untimed sweep, $(date)"
robot daily --day "$day" --lanes "$lanes" --wait-release 1800 > "$log-untimed.log" 2>&1
sed -n '/===== Summary =====/,$p' "$log-untimed.log"
echo "== Day $day: timed races, $(date)"
# A short gate: these races only set a first Hall of Fame time (flags came from the
# untimed sweep, and hof.sh improves times at night), and while they run they hold
# day.lock and the robot lock that a parser deployed minutes after the release needs.
robot daily --day "$day" --lanes "$lanes" --timed --gate-ms 600 --gate-wait 20 > "$log-timed.log" 2>&1
sed -n '/===== Summary =====/,$p' "$log-timed.log"
# A transport or server error in our lanes (an overloaded release), or a sweep that died
# before its summary (a failed list), gets another sweep next minute, at most 10 times;
# unresolved and incorrect do not, so a guess is never repeated.
retries="$state/day$day.retries"
if { grep -q '"outcome": "error"' "$log-untimed.log" || ! grep -q '===== Summary =====' "$log-untimed.log"; } \
    && [ "$(cat "$retries" 2>/dev/null || echo 0)" -lt 10 ]; then
  echo $(( $(cat "$retries" 2>/dev/null || echo 0) + 1 )) > "$retries"
  echo "== Day $day: errors in the sweep; trying again next minute, $(date)"
  exit 0
fi
version "$started_code" > "$swept"  # After the races, which add to hints.json themselves.
echo "== Day $day swept, $(date)"
