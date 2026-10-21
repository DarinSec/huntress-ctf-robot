#!/bin/bash
# Hall of Fame re-races at night on the Homebase that plays for the team. Every fresh timed
# variant can lower the team's best time on a route, so this races each proven Warmups and
# Metadata route of every released day again: only while the server answers status within
# 250 ms (kept-alive median was 208 ms, p90 226 ms on 20 Oct 23:00 UTC; a slower server
# spends nothing) and never below 8 fresh variants per route (--reserve). The robot lock keeps it from overlapping day.sh or a run by hand.
# hints.json keeps each route's races and best_on_clock_ms.
# Logs: ~/hof-auto.log (one line per raced route), ~/hof-MMDD-HHMM-<lane>.log.
#
# Install next to ~/day.sh (scripts/homebase.sh deploy copies both), crontab -e:
#     30 0-10/2 * * * /home/HuntressCTF/hof.sh >> /home/HuntressCTF/hof-auto.log 2>&1
# (every two hours 00:30-10:30 UTC, far from the 13:00 UTC release; each run races a
# route once, and Hall of Fame keeps the team's best.)
set -u
export PYTHONPATH="$HOME/src" HUNTRESS_GM_URL="http://10.0.0.219/huntress-ctf-proxy"
# The last released day: today's once 09:00 New York has passed (00:30 UTC is 20:30 there).
day=$(TZ=America/New_York date +%-d); hour=$(TZ=America/New_York date +%-H)
last=$(( hour >= 9 ? day : day - 1 ))
[ "$last" -ge 1 ] || exit 0
cd "$HOME"
for lane in warmups metadata-forensics mobile-android; do
  log="$HOME/hof-$(date +%m%d-%H%M)-$lane.log"
  echo "== Hall of Fame $lane, days 1-$last, $(date)"
  python3 -m huntress_ctf --lock-wait 900 daily --days "1-$last" --lane "$lane" --timed --rerace \
    --reserve 8 --gate-ms 250 --gate-wait 60 > "$log" 2>&1
  python3 -I - "$log" <<'EOF'
import json, sys
text = open(sys.argv[1], encoding="utf-8").read().rpartition("===== Summary =====")[2]
try:
    summary = json.loads(text)
except ValueError:
    sys.exit(f"no summary in {sys.argv[1]}")
for entry in summary["challenges"]:
    if entry["outcome"] != "skipped":
        print(entry["challenge"], entry["outcome"], entry.get("best_on_clock_ms", entry.get("reason", "")))
EOF
done
echo "== Hall of Fame done, $(date)"
