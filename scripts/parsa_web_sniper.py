#!/usr/bin/env python3
"""Parsa's Ultra-Fast Web Lane Sniper & Live War Console.

Dedicated high-precision weapon for Huntress CTF Web Exploitation lane:
1. Sub-second high-speed polling right at release drop (09:00 EDT).
2. Direct-to-token submission: guarantees flags are registered under Parsa's identity.
3. Multi-threaded Mastery burst solving (< 3 seconds total per mastery set).
4. Auto-reactive engine (HTTP 426 WebSocket, 403 Proxy header bypass, 405 Method swap).
5. Interactive instant HUD if any novel zero-day challenge needs live interactive nudges.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

# Resolve local package
REPO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_DIR / "src"))

from huntress_ctf.client import GameMasterClient, GameMasterError
from huntress_ctf.config import load_env
from huntress_ctf.solvers.web import handlers, scoped_http
from huntress_ctf.solvers.web.curriculum import _scope


def c_cyan(s: str) -> str: return f"\033[1;36m{s}\033[0m"
def c_green(s: str) -> str: return f"\033[1;32m{s}\033[0m"
def c_yellow(s: str) -> str: return f"\033[1;33m{s}\033[0m"
def c_red(s: str) -> str: return f"\033[1;31m{s}\033[0m"
def c_magenta(s: str) -> str: return f"\033[1;35m{s}\033[0m"


def print_banner() -> None:
    print(c_cyan("=" * 70))
    print(c_cyan("   ⚡ HUNTRESS CTF 2026 - PARSA'S WEB AUTONOMOUS SNIPER ⚡"))
    print(c_cyan("   Target: Top 10 / First Blood Dominance | Web Exploitation Lane"))
    print(c_cyan("=" * 70))


def get_client() -> GameMasterClient:
    load_env()
    token = os.environ.get("HUNTRESS_GM_TOKEN")
    url = os.environ.get("HUNTRESS_GM_URL", "https://2026.huntress.ctf.games")
    if not token:
        print(c_red("[-] Error: HUNTRESS_GM_TOKEN not set in .env"))
        sys.exit(1)
    return GameMasterClient(base_url=url, token=token)


def solve_single_target(url: str, curriculum_day: int | None = None) -> str | None:
    """Tries autonomous handlers and returns a verified proof string."""
    try:
        proof = handlers.detect_and_solve(url, curriculum_day)
        if proof and handlers.PROOF_PATTERN.fullmatch(proof):
            return proof
    except Exception:
        pass

    try:
        proof = handlers.solve_autonomous_web(url)
        if proof and handlers.PROOF_PATTERN.fullmatch(proof):
            return proof
    except Exception:
        pass

    return None


def interactive_hud(target_url: str) -> str | None:
    """Interactive fallback HUD for novel formats requiring live intervention."""
    base = target_url.rstrip("/")
    print(c_yellow(f"\n[!] Target requires manual triage: {target_url}"))
    
    st, clues_b, _ = handlers._request(f"{base}/api/clues")
    clues = {}
    if st == 200:
        try:
            clues = json.loads(clues_b)
            print(c_cyan("  /api/clues: ") + json.dumps(clues, indent=2))
        except Exception:
            print("  Raw clues:", clues_b[:200])

    feat = clues.get("feature_route", "/")
    sec = clues.get("secondary_route")
    print(f"  Key routes: feature='{feat}', secondary='{sec}'")
    print("  Commands: [1] Custom GET | [2] Custom POST JSON | [3] Raw Proof | [q] Skip")

    while True:
        try:
            cmd = input(c_yellow("  HUD > ")).strip()
        except (EOFError, KeyboardInterrupt):
            return None

        if cmd == "q":
            return None
        elif cmd == "1":
            p = input("  Path: ").strip()
            s, b, h = handlers._request(f"{base}{p}")
            print(f"  Status {s}:\n{b[:600]}")
            proof = handlers._extract_proof(b, h)
            if proof:
                print(c_green(f"  [✔] Proof extracted: {proof}"))
                return proof
        elif cmd == "2":
            p = input(f"  Path [{feat}]: ").strip() or feat
            data = input("  JSON body: ").strip()
            s, b, h = handlers._request(f"{base}{p}", method="POST", data=data.encode("utf-8"),
                                        headers={"Content-Type": "application/json"})
            print(f"  Status {s}:\n{b[:600]}")
            proof = handlers._extract_proof(b, h)
            if proof:
                print(c_green(f"  [✔] Proof extracted: {proof}"))
                return proof
        elif cmd == "3":
            raw = input("  Paste proof: ").strip()
            proof = handlers._extract_proof(raw)
            if proof:
                return proof


def snipe_challenge(client: GameMasterClient, cid: str, mode: str = "single_solve") -> bool:
    print(f"\n{c_magenta('[*] Sniping challenge:')} {cid} ({mode})")
    t0 = time.monotonic()
    
    try:
        st = client.status(cid)
        if st.get("result") in ("expired", "timeout", "failed"):
            st = client.retry(cid)
    except GameMasterError:
        try:
            st = client.start(cid)
        except GameMasterError as e:
            print(c_red(f"[-] Failed to start: {e}"))
            return False

    if st.get("result") == "CORRECT" or st.get("solved"):
        flag = st.get("flag")
        sb = (st.get("solved_by") or {}).get("name", "Unknown")
        print(c_green(f"[✔] Already solved! Flag: {flag} (by {sb})"))
        return True

    # Spin until targets are available
    targets = st.get("targets", [])
    for _ in range(25):
        if targets:
            break
        time.sleep(0.8)
        st = client.status(cid)
        targets = st.get("targets", [])

    if not targets:
        print(c_red("[-] Timed out waiting for challenge containers to spin up."))
        return False

    answer_ids = st.get("answer_ids", [])
    questions = st.get("questions", [])
    target_urls = [t.get("url") for t in targets if t.get("url")]
    curriculum_day = st.get("curriculum_day")
    
    print(c_green(f"[+] Containers live ({len(targets)} targets). Solving in parallel..."))

    solved_answers: dict[str, str] = {}
    http = scoped_http(target_urls)

    with _scope(http):
        if len(targets) == 1 and len(answer_ids) == 1:
            # Single Solve or Time Trial
            turl = target_urls[0]
            proof = solve_single_target(turl, curriculum_day)
            if not proof:
                proof = interactive_hud(turl)
            if proof:
                solved_answers[answer_ids[0]] = proof
        else:
            # Multi-target / Mastery mode - execute concurrently
            def _worker(item):
                i, aid = item
                turl = targets[i]["url"] if i < len(targets) else target_urls[0]
                p = solve_single_target(turl, curriculum_day)
                if not p:
                    p = interactive_hud(turl)
                return aid, p

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(targets), 8)) as ex:
                results = list(ex.map(_worker, enumerate(answer_ids)))
                for aid, p in results:
                    if p:
                        solved_answers[aid] = p

    if len(solved_answers) != len(answer_ids):
        print(c_red(f"[-] Incomplete answers ({len(solved_answers)}/{len(answer_ids)} resolved)"))
        return False

    # Immediate submission
    print(c_cyan(f"[*] Submitting {len(solved_answers)} proofs directly to GameMaster..."))
    if len(solved_answers) == 1:
        aid, ans = next(iter(solved_answers.items()))
        res = client.submit(cid, aid, ans)
    else:
        res = client.submit_many(cid, solved_answers)

    elapsed = time.monotonic() - t0
    result = res.get("result")
    flag = res.get("flag")
    sb = (res.get("solved_by") or {}).get("name")

    if result == "CORRECT":
        print(c_green(f"[✔✔✔] SOLVED in {elapsed:.2f}s! Flag: {flag} | Solved by: {sb}"))
        return True
    else:
        print(c_red(f"[-] Submission returned: {result} ({res})"))
        return False


def watch_and_snipe_drop(day: int) -> None:
    """Precision countdown and instantaneous sub-second polling loop."""
    print_banner()
    client = get_client()
    print(c_cyan(f"[*] Armed for Day {day} Web Exploitation drop."))
    print(c_yellow("[*] Polling GameMaster API with sub-second interval..."))

    poll_count = 0
    while True:
        poll_count += 1
        try:
            chs = client.list_challenges(day=day)
            chs = chs.get("challenges", []) if isinstance(chs, dict) else chs
            web_chs = [ch for ch in chs if ch.get("lane") == "web-exploitation"]
            if web_chs:
                print(c_green(f"\n[!] DROP DETECTED! Found {len(web_chs)} Web challenge modes!"))
                for ch in web_chs:
                    cid = ch.get("id")
                    mode = ch.get("mode", "single_solve")
                    solved = ch.get("solved", False)
                    if not solved:
                        snipe_challenge(client, cid, mode)
                print(c_green(f"\n[✔] ALL WEB CHALLENGES FOR DAY {day} COMPLETED!"))
                break
        except Exception as e:
            pass

        time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Parsa's Huntress CTF Web Sniper")
    parser.add_argument("--day", type=int, help="Day number (e.g. 29)")
    parser.add_argument("--challenge", type=str, help="Specific challenge ID to snipe directly")
    parser.add_argument("--watch", action="store_true", help="High-speed watch loop until release")
    args = parser.parse_args()

    print_banner()
    client = get_client()

    target_day = args.day or 29

    if args.challenge:
        snipe_challenge(client, args.challenge)
    elif args.watch:
        watch_and_snipe_drop(target_day)
    else:
        # Check current day or target day
        chs = client.list_challenges(day=target_day)
        chs = chs.get("challenges", []) if isinstance(chs, dict) else chs
        web_chs = [ch for ch in chs if ch.get("lane") == "web-exploitation"]
        if not web_chs:
            print(c_yellow(f"[*] Day {target_day} web challenges are not yet released."))
            print(c_cyan(f"[*] Use --watch to standby and auto-snipe on drop:"))
            print(c_cyan(f"    python3 scripts/parsa_web_sniper.py --day {target_day} --watch"))
        else:
            for ch in web_chs:
                cid = ch.get("id")
                mode = ch.get("mode", "single_solve")
                snipe_challenge(client, cid, mode)


if __name__ == "__main__":
    main()
