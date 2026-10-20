#!/bin/bash
# Solve and race one release day. Started automatically by cron (see `crontab -l`):
# when the VM boots, and daily around the release. Run by hand: ~/day.sh [day]
#
# Waits for the release (09:00 New York time = 15:00 in Sweden), then
#   1. solves every new challenge the robot can, untimed (records proven solvers);
#   2. races the proven Time Trial and Mastery routes when the server answers fast.
# Logs: ~/day-auto.log (summaries), ~/dayNN-untimed.log, ~/dayNN-timed.log.
# A day runs once (marker ~/.huntress/dayNN.done); a lock stops parallel runs of this
# script only: a robot started by hand at the same time still collides (20 Oct 2026).
#
# Install on the one Homebase that plays for the team (teammates share attempts):
#   cp scripts/homebase-day.sh ~/day.sh && chmod +x ~/day.sh   (code in ~/src)
#   crontab -e, then add:
#     @reboot sleep 90 && /home/HuntressCTF/day.sh >> /home/HuntressCTF/day-auto.log 2>&1
#     3 13,14 * * * /home/HuntressCTF/day.sh >> /home/HuntressCTF/day-auto.log 2>&1
set -u
day="${1:-$(TZ=America/New_York date +%-d)}"
marker="$HOME/.huntress/day$day.done"
mkdir -p "$HOME/.huntress"
exec 9>"$HOME/.huntress/day.lock"
if ! flock -n 9; then echo "$(date): another day.sh is running; exiting."; exit 0; fi
if [ -e "$marker" ]; then echo "$(date): day $day already done ($marker); exiting."; exit 0; fi
export PYTHONPATH="$HOME/src" HUNTRESS_GM_URL="http://10.0.0.219/huntress-ctf-proxy"
release=$(TZ=America/New_York date -d "09:02" +%s)
now=$(date +%s)
if [ "$now" -lt "$release" ]; then
  echo "$(date): day $day waits $(( (release - now) / 60 )) min for the release (09:00 New York = 15:00 Sweden)."
  sleep $(( release - now ))
fi
cd "$HOME"
echo "== Day $day: untimed solve, $(date)"
python3 -m huntress_ctf daily --day "$day" > "$HOME/day$day-untimed.log" 2>&1
sed -n '/===== Summary =====/,$p' "$HOME/day$day-untimed.log"
echo "== Day $day: timed races, $(date)"
python3 -m huntress_ctf daily --day "$day" --timed --gate-ms 600 --gate-wait 300 > "$HOME/day$day-timed.log" 2>&1
sed -n '/===== Summary =====/,$p' "$HOME/day$day-timed.log"
touch "$marker"
echo "== Day $day done, $(date)"
