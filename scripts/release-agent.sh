#!/bin/bash
# Release-day agent: when the robot leaves a route unresolved, a headless Claude Code run
# writes the missing solver on its own branch. It never submits or deploys: a human reviews
# the branch and deploys it (scripts/homebase.sh deploy), and the robot sweeps again.
#
#   scripts/release-agent.sh <challenge-id> [--push]     one route
#   scripts/release-agent.sh --watch <day> [--max N]     after the release: every unsolved,
#                                                        started route of the day, one by one
#
# Needs Claude Code (`claude`, logged in: a Pro plan's usage is shared with your own
# sessions, so --max limits the runs per day) and the Game Master token in this shell for
# the read-only `prepare` (status + artifact). The agent itself runs in a fresh git worktree
# with the token removed from its environment, no .env, and only file edits, tests, replay,
# offline analysis and git commit allowed (scripts/release-agent.md holds its rules).
# Env: AGENT_TIMEOUT (seconds, default 2700), AGENT_WORKTREES (default ~/agent-worktrees),
#      AGENT_LANES (default all artifact lanes), AGENT_MODEL (optional --model).
set -u
repo=$(cd "$(dirname "$0")/.." && pwd)
state="${HUNTRESS_STATE_DIR:-$repo/.huntress}"
export PYTHONPATH="$repo/src"
lanes="${AGENT_LANES:-binary-reverse-engineering,metadata-forensics,mobile-android,script-analysis,warmups}"

run_agent() {  # <challenge-id> [--push]
  id="$1"; push="${2:-}"
  command -v claude > /dev/null || { echo "claude (Claude Code) is not installed here."; return 1; }
  safe=$(printf '%s' "$id" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-64)
  stamp=$(date +%Y%m%d-%H%M%S)
  branch="agent/$safe-$stamp"
  dir="${AGENT_WORKTREES:-$HOME/agent-worktrees}/$safe-$stamp"
  mkdir -p "$(dirname "$dir")"
  git -C "$repo" worktree add -q -b "$branch" "$dir" HEAD || return 1
  (cd "$repo" && python3 -m huntress_ctf prepare "$id" --work-dir "$dir/work") || { echo "Nothing to prepare for $id."; return 1; }
  work="work/$safe"
  echo "== $id: before"; (cd "$dir" && PYTHONPATH=src python3 scripts/solve_offline.py "$work" | sed -n '/answered/,$p' | head -30)
  prompt=$(sed -e "s|{ID}|$id|g" -e "s|{WORK}|$work|g" "$repo/scripts/release-agent.md")
  echo "== $id: agent on $branch ($dir), log agent.log"
  (cd "$dir" && env -u HUNTRESS_GM_TOKEN -u HUNTRESS_GM_URL PYTHONPATH=src HUNTRESS_STATE_DIR="$state" \
    timeout "${AGENT_TIMEOUT:-2700}" claude -p "$prompt" ${AGENT_MODEL:+--model "$AGENT_MODEL"} \
      --permission-mode acceptEdits --output-format text \
      --allowedTools "Read" "Edit" "Write" "Glob" "Grep" \
        "Bash(python3 -m unittest:*)" "Bash(python3 scripts/replay.py:*)" "Bash(python3 scripts/solve_offline.py:*)" \
        "Bash(python3 -m huntress_ctf triage:*)" "Bash(python3 -m huntress_ctf suggest:*)" "Bash(python3 -I:*)" \
        "Bash(git status:*)" "Bash(git diff:*)" "Bash(git add:*)" "Bash(git commit:*)" "Bash(git log:*)" \
        "Bash(ls:*)" "Bash(xxd:*)" "Bash(file:*)" "Bash(strings:*)" "Bash(unzip -l:*)" "Bash(grep:*)" "Bash(head:*)" \
      > agent.log 2>&1)
  echo "== $id: agent finished (exit $?). Its report:"; tail -40 "$dir/agent.log"
  # Checked here, not taken from the agent's word.
  echo "== $id: after"; (cd "$dir" && PYTHONPATH=src python3 scripts/solve_offline.py "$work" | sed -n '/answered/,$p' | head -30)
  (cd "$dir" && PYTHONPATH=src python3 -m unittest discover -s tests > tests.log 2>&1 && echo "tests: OK" || { echo "tests: FAILED"; tail -15 tests.log; })
  (cd "$dir" && PYTHONPATH=src HUNTRESS_STATE_DIR="$state" python3 scripts/replay.py --dry > replay.log 2>&1 && echo "replay: no regressions" || { echo "replay: REGRESSIONS"; grep -A3 REGRESSION replay.log | head -20; })
  git -C "$dir" log --oneline "HEAD@{1}..HEAD" 2>/dev/null || git -C "$dir" log --oneline -3
  if [ "$push" = "--push" ]; then git -C "$dir" push -q -u origin "$branch" && echo "pushed $branch"; fi
  echo "Review: git -C $repo diff HEAD...$branch   Deploy after review; remove with: git -C $repo worktree remove $dir"
}

if [ "${1:-}" = "--watch" ]; then
  day="${2:?usage: release-agent.sh --watch <day> [--max N]}"
  max=4; [ "${3:-}" = "--max" ] && max="${4:-4}"
  handled="$state/agent-day$day.handled"; touch "$handled"
  runs=0; until_s=$(( $(date +%s) + ${AGENT_WATCH_HOURS:-6} * 3600 ))
  echo "Watching day $day (lanes $lanes, at most $max agent runs)."
  while [ "$(date +%s)" -lt "$until_s" ] && [ "$runs" -lt "$max" ]; do
    # Unsolved routes in our lanes that someone started at least 3 minutes ago (the robot's
    # sweep had its chance) and that no agent took yet. All read-only.
    todo=$(cd "$repo" && python3 -m huntress_ctf list --day "$day" 2>/dev/null | LANES="$lanes" HANDLED="$handled" python3 -c '
import json, os, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit()
items = data.get("challenges", data) if isinstance(data, dict) else data
done = set(open(os.environ["HANDLED"]).read().split())
for c in items:
    if isinstance(c, dict) and c.get("lane") in os.environ["LANES"].split(",") and c.get("solved") is not True and c.get("id") not in done:
        print(c["id"])')
    picked=""
    for id in $todo; do
      started=$(cd "$repo" && python3 -m huntress_ctf status "$id" 2>/dev/null | python3 -c '
import json, sys, datetime
try:
    s = json.load(sys.stdin)
except ValueError:
    sys.exit()
at = s.get("started_at")
if at and s.get("questions"):
    age = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(at.replace("Z", "+00:00"))
    print(int(age.total_seconds()))')
      if [ -n "$started" ] && [ "$started" -ge 180 ]; then picked="$id"; break; fi
    done
    if [ -n "$picked" ]; then
      echo "$picked" >> "$handled"; runs=$((runs + 1))
      run_agent "$picked"
    else
      sleep 120
    fi
  done
  echo "Watch over ($runs agent runs)."
  exit 0
fi

run_agent "${1:?usage: release-agent.sh <challenge-id> [--push] | --watch <day> [--max N]}" "${2:-}"
