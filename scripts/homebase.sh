#!/bin/bash
# The robot's Homebase chores from this computer, over SSH through the CTF VPN.
# Logs in with the key ~/.ssh/huntress_homebase when the VM accepts it; otherwise with the
# password from the macOS keychain (service huntress-homebase, account HuntressCTF), typed
# once by expect into a shared connection that stays open for 10 minutes.
#
#   scripts/homebase.sh run '<cmd>'  run one command there (PYTHONPATH and the proxy URL set)
#   scripts/homebase.sh deploy       test src/ and replay the corpus on the VM, then swap it into ~/src (keeps
#                                    ~/src.previous) and install day.sh and hof.sh; the
#                                    minute cron sweeps the day with the new code. A lost
#                                    answer, a solver over 2x slower (ALLOW_SLOWER=1 deploys
#                                    anyway) or one that broke stops it (SKIP_REPLAY=1 skips)
#   scripts/homebase.sh fastdeploy [lane ...]  release day: only the tests and corpus lanes the
#                                    change can reach (scripts/fastdeploy.py; a change to the robot
#                                    itself gets everything), then the swap and a sweep at once.
#                                    ~1 min for a Metadata parser instead of ~8.5. DRY=1 stops before
#                                    the swap; naming lanes replays only those
#   scripts/homebase.sh replay [text]  the corpus against ~/src now (or only entries whose path
#                                    contains the text), as the new baseline: after a fastdeploy day
#   scripts/homebase.sh sweep        run ~/day.sh now instead of waiting for cron
#   scripts/homebase.sh log          the latest day and Hall of Fame summaries
#   scripts/homebase.sh pull <id>    copy work/<id>/ to artifacts/work/ (git-ignored), show triage.md
#   scripts/homebase.sh gaps <id> [regex]  offline, on the VM: what the robot answers for that
#                                    saved route, kind by kind, and the kinds it cannot answer;
#                                    a regex prints those kinds' values (a wrong convention)
#   scripts/homebase.sh times [day]  minutes after the release at which each route was solved
#   scripts/homebase.sh report [day] the release at a glance: outcomes, then the questions and
#                                    field suggestions of each unresolved Warmups/Metadata route
#
# HB_HOST (required, e.g. HuntressCTF@<homebase-ip>) and HB_KEY (optional) set the host and key.
set -euo pipefail
host="${HB_HOST:?set HB_HOST=HuntressCTF@<homebase-ip> (your Homebase VM)}"
key="${HB_KEY:-$HOME/.ssh/huntress_homebase}"
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$HOME/.ssh"
options=(-o ConnectTimeout=10 -o ControlPath="$HOME/.ssh/cm-huntress-%r@%h:%p")

connect() {
  ssh "${options[@]}" -O check "$host" 2>/dev/null && return 0
  if [ -f "$key" ] && ssh "${options[@]}" -i "$key" -o BatchMode=yes -o ControlMaster=yes \
      -o ControlPersist=600 -fN "$host" 2>/dev/null; then
    return 0
  fi
  HB_HOST="$host" HB_CONTROL="$HOME/.ssh/cm-huntress-%r@%h:%p" expect <<'EOF' >/dev/null
set timeout 30
set password [exec security find-generic-password -a HuntressCTF -s huntress-homebase -w]
spawn ssh -o ConnectTimeout=10 -o PubkeyAuthentication=no -o ControlMaster=yes -o ControlPersist=600 -o ControlPath=$env(HB_CONTROL) -fN $env(HB_HOST)
expect {
  "assword:" { send -- "$password\r"; exp_continue }
  timeout { exit 2 }
  eof
}
catch wait result
exit [lindex $result 3]
EOF
  ssh "${options[@]}" -O check "$host" 2>/dev/null || { echo "Cannot reach $host: is the CTF VPN up?" >&2; exit 1; }
}
remote() { ssh "${options[@]}" "$host" "$@"; }
connect

case "${1:-}" in
  run)
    remote "cd ~ && export PYTHONPATH=~/src HUNTRESS_GM_URL=http://10.0.0.219/huntress-ctf-proxy; ${2:?usage: homebase.sh run '<command>'}"
    ;;
  deploy)
    stamp=$(date +%Y%m%d-%H%M%S)
    (cd "$root" && find src tests -name __pycache__ -prune -o -type f -print \
      | tar -cf - -T - scripts/homebase-day.sh scripts/homebase-hof.sh scripts/replay.py) \
      | remote "set -e
        d=~/deploy-$stamp; mkdir \$d; tar -xf - -C \$d; cd \$d
        if ! HUNTRESS_LOCK=/tmp/deploy-test.lock PYTHONPATH=src python3 -m unittest discover -s tests > test.log 2>&1; then
          tail -25 test.log; echo 'Tests failed on the VM; ~/src is unchanged.'; exit 1
        fi
        tail -3 test.log
        # Every assignment the robot scored, re-solved with the new code (scripts/replay.py):
        # an answer that matched the accepted one and no longer does stops the deploy, and so
        # does a solver over twice as slow as with the deployed code, or one that broke.
        if [ '${SKIP_REPLAY:-0}' != 1 ] && ! HUNTRESS_ALLOW_SLOWER='${ALLOW_SLOWER:-0}' HUNTRESS_STATE_DIR=~/.huntress PYTHONPATH=src python3 scripts/replay.py --dry > replay.log 2>&1; then
          grep -B1 -A3 -E 'REGRESSION|SLOWER|BROKE' replay.log | head -40; grep '^slowest solvers' replay.log || true
          echo 'Replay found regressions, slower or broken solvers; ~/src is unchanged (ALLOW_SLOWER=1 accepts slower solvers, SKIP_REPLAY=1 deploys anyway).'; exit 1
        fi
        rm -rf ~/src.previous ~/src.new; cp -a ~/src ~/src.previous; cp -a src ~/src.new
        rm -rf ~/src; mv ~/src.new ~/src
        install -m 755 scripts/homebase-day.sh ~/day.sh; install -m 755 scripts/homebase-hof.sh ~/hof.sh
        install -m 755 scripts/replay.py ~/replay.py
        HUNTRESS_STATE_DIR=~/.huntress PYTHONPATH=~/src python3 ~/replay.py > /dev/null 2>&1 || true  # New baseline.
        echo \"Deployed \$d (previous code in ~/src.previous).\""
    ;;
  fastdeploy)
    shift
    for lane in "$@"; do [[ $lane =~ ^[a-z-]+$ ]] || { echo "Not a lane name: $lane" >&2; exit 2; }; done
    stamp=$(date +%Y%m%d-%H%M%S)
    (cd "$root" && find src tests -name __pycache__ -prune -o -type f -print \
      | tar -cf - -T - scripts/homebase-day.sh scripts/homebase-hof.sh scripts/replay.py \
          scripts/fastdeploy.py scripts/homebase-fastdeploy.sh) \
      | remote "set -e; d=~/deploy-$stamp; mkdir \$d; tar -xf - -C \$d; cd \$d
        DRY='${DRY:-0}' ALLOW_SLOWER='${ALLOW_SLOWER:-0}' SKIP_REPLAY='${SKIP_REPLAY:-0}' bash scripts/homebase-fastdeploy.sh $*"
    ;;
  replay)
    only="${2:-}"
    [[ $only =~ ^[A-Za-z0-9_-]*$ ]] || { echo "Not an entry name: $only" >&2; exit 2; }
    remote "cd ~ && HUNTRESS_STATE_DIR=~/.huntress PYTHONPATH=~/src python3 ~/replay.py ${only:+--only $only} > ~/replay-last.log 2>&1; status=\$?
      grep -B1 -A3 -E 'REGRESSION|SLOWER|BROKE' ~/replay-last.log | head -40; tail -1 ~/replay-last.log
      echo \"\$(grep -c ' answered |' ~/replay-last.log) entries replayed (exit \$status; ~/replay-last.log)\""
    ;;
  sweep)
    remote 'out=$(~/day.sh 2>&1); echo "${out:-Nothing new since the last sweep (or a sweep is already running).}"'
    ;;
  log)
    remote 'tail -n 40 ~/day-auto.log; echo; tail -n 20 ~/hof-auto.log 2>/dev/null || true'
    ;;
  pull)
    id="${2:?usage: homebase.sh pull <challenge-id>}"
    folder="${id//[^A-Za-z0-9_-]/_}"
    mkdir -p "$root/artifacts/work"
    remote "cd ~/work && tar -cf - '$folder'" | tar -xf - -C "$root/artifacts/work"
    echo "Copied to artifacts/work/$folder (untrusted data: never execute it)."
    sed -n '1,80p' "$root/artifacts/work/$folder/triage.md"
    ;;
  gaps)
    id="${2:?usage: homebase.sh gaps <challenge-id> [regex]}"
    folder="${id//[^A-Za-z0-9_-]/_}"
    show=""
    [ -n "${3:-}" ] && show="--show '$3'"
    remote "python3 -I - ~/work/'$folder' --src ~/src $show" < "$root/scripts/solve_offline.py"
    ;;
  times)
    remote "python3 -I - ${2:-1}" < "$root/scripts/solvetimes.py"
    ;;
  report)
    remote "python3 -I - ${2:-}" < "$root/scripts/release_report.py"
    ;;
  *)
    sed -n '2,/^# HB_HOST/p' "$0"
    exit 2
    ;;
esac
