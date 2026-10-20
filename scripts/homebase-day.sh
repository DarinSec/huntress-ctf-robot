#!/bin/bash
# Solve and race one release day on the Homebase that plays for the team. Started by cron
# every 15 minutes and at boot (see `crontab -l`). Run by hand: ~/day.sh [day]
#
# Before the release (09:00 New York = 15:00 in Sweden) it sleeps until just before it;
# `daily --wait-release` then starts the moment the day is listed:
#   1. solves every challenge the robot can, untimed, families in parallel (records
#      proven solvers in ~/.huntress/hints.json);
#   2. races each proven Time Trial and Mastery route once (hints.json keeps the best).
# Later cron runs sweep again only when the code in ~/src or hints.json changed since the
# last sweep, so a solver deployed in the afternoon still scores and races the same day.
# Logs: ~/day-auto.log (summaries), ~/dayNN-HHMM-untimed.log and ~/dayNN-HHMM-timed.log.
# The robot holds ~/.huntress/robot.lock around every start, retry and submit, so a run
# by hand and this script never play at once: this script waits its turn (--lock-wait).
#
# Install on the one Homebase that plays for the team (teammates share attempts):
#   cp scripts/homebase-day.sh ~/day.sh && chmod +x ~/day.sh   (code in ~/src)
#   crontab -e, then add:
#     @reboot sleep 90 && /home/HuntressCTF/day.sh >> /home/HuntressCTF/day-auto.log 2>&1
#     */15 * * * * /home/HuntressCTF/day.sh >> /home/HuntressCTF/day-auto.log 2>&1
set -u
day="${1:-$(TZ=America/New_York date +%-d)}"
state="$HOME/.huntress"
mkdir -p "$state"
exec 9>"$state/day.lock"
flock -n 9 || exit 0  # A sweep is already running or waiting for the release.
export PYTHONPATH="$HOME/src" HUNTRESS_GM_URL="http://10.0.0.219/huntress-ctf-proxy"
# What a sweep depends on: the solver code and the proven solvers.
version() {
  { find "$HOME/src" -name '*.py' -type f -print0 | sort -z | xargs -0 sha1sum
    cat "$state/hints.json" 2>/dev/null; } | sha1sum | cut -c1-16
}
swept="$state/day$day.swept"
[ -e "$swept" ] && [ "$(cat "$swept")" = "$(version)" ] && exit 0  # Nothing new to try.
release=$(TZ=America/New_York date -d "08:59:30" +%s)
now=$(date +%s)
if [ "$now" -lt "$release" ]; then
  echo "$(date): day $day waits $(( (release - now) / 60 )) min for the release (09:00 New York = 15:00 Sweden)."
  sleep $(( release - now ))
fi
cd "$HOME"
robot() { python3 -m huntress_ctf --lock-wait 3600 "$@"; }
log="$HOME/day$day-$(date +%H%M)"
echo "== Day $day: untimed sweep, $(date)"
robot daily --day "$day" --wait-release 1800 > "$log-untimed.log" 2>&1
sed -n '/===== Summary =====/,$p' "$log-untimed.log"
echo "== Day $day: timed races, $(date)"
robot daily --day "$day" --timed --gate-ms 600 --gate-wait 300 > "$log-timed.log" 2>&1
sed -n '/===== Summary =====/,$p' "$log-timed.log"
version > "$swept"  # After the races, which add to hints.json themselves.
echo "== Day $day swept, $(date)"
