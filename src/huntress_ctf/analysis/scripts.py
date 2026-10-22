"""Static script triage for the Script Analysis lane: recover hidden material, extract IOCs,
map ATT&CK techniques. Never executes anything; works on text.

The lane's fixtures hide a configuration (JSON, or "v=1|steps=...|campaign_id=..." records)
behind a declared codec chain such as "hex_pairs|xor_5a" or "integer_tuple|rolling_xor|5e":
    <material format> | <transform> | <key>
The names describe the ENCODING; recover() applies the inverse. Chains without a key, or
undeclared ones, are searched, and only output that validates as a config record is accepted.
"""
import base64
import binascii
import json
import os
import re
import urllib.parse

# ---- language detection ------------------------------------------------------------------------

EXT_LANG = {".ps1": "powershell", ".psm1": "powershell", ".js": "jscript", ".mjs": "node", ".ts": "node",
            ".vbs": "vbscript", ".vbe": "vbscript", ".cmd": "batch", ".bat": "batch", ".sh": "bash",
            ".py": "python", ".php": "php", ".lua": "lua", ".mof": "mof", ".au3": "autoit",
            ".ahk": "autohotkey", ".applescript": "applescript", ".proj": "msbuild", ".csproj": "msbuild",
            ".pl": "perl", ".rb": "ruby", ".hta": "hta"}


def language(path, text=None):
    lang = EXT_LANG.get(os.path.splitext(path)[1].lower())
    if lang:
        return lang
    text = text or ""
    for rx, name in ((r"^#!.*\b(ba)?sh\b", "bash"), (r"^#!.*python", "python"), (r"<Project\b", "msbuild"),
                     (r"^\s*@echo off", "batch"), (r"\$\w+\s*=|Write-Host|Invoke-", "powershell"),
                     (r"\bDim\b|\bEnd Function\b", "vbscript"), (r"\bfunction\b.*\{|\bvar\b", "jscript")):
        if re.search(rx, text, re.M | re.I):
            return name
    return "unknown"


# ---- material formats: text -> bytes -----------------------------------------------------------

def _ints(s):
    # Dashes are separators here ("125-50-58"), never signs.
    vals = [int(v, 16) if v.lower().startswith("0x") else int(v) for v in re.findall(r"0x[0-9a-fA-F]+|\d+", s)]
    if not vals or any(v < 0 or v > 255 for v in vals):
        raise ValueError("not a byte list")
    return bytes(vals)


def _hex(s):
    s = re.sub(r"(0x|\\x|%|[\s:,\-|'\"\[\]\\])", "", s, flags=re.I)
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s):
        raise ValueError("not hex")
    return binascii.unhexlify(s)


def _b64(s, url=False):
    s = re.sub(r"[\s'\",]", "", s)  # keep '+': it is a base64 character
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", s) or len(s) < 4:
        raise ValueError("not base64")
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s) if url or re.search(r"[-_]", s) else base64.b64decode(s)


def _escaped(s):
    hits = re.findall(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\([0-7]{1,3})", s)
    if not hits:
        raise ValueError("no escapes")
    return bytes(int(h, 16) if h else int(u, 16) & 0xFF if u else int(o, 8) for h, u, o in hits)


def _percent(s):
    if "%" not in s:
        raise ValueError("no percent-encoding")
    return urllib.parse.unquote_to_bytes(s)


FORMATS = {
    "base64": _b64, "urlsafe_base64": lambda s: _b64(s, url=True),
    "hex": _hex, "percent_hex": _percent, "escaped_octets": _escaped,
    "integers": _ints, "text": lambda s: s.encode("utf-8"),
}
# Declared material-format names -> parser (+ whether the byte order is reversed first).
FORMAT_ALIASES = {
    "base64_literal": ("base64", False), "base64_chunks": ("base64", False), "urlsafe_base64": ("urlsafe_base64", False),
    "hex_pairs": ("hex", False), "hex_colon": ("hex", False), "hex_compact": ("hex", False), "hex_dash": ("hex", False),
    "hex_literal": ("hex", False), "hex_array": ("hex", False), "hex_buffer": ("hex", False),
    "hex_escape": ("escaped_octets", False), "escaped_octets": ("escaped_octets", False),
    "unicode_escapes": ("escaped_octets", False), "percent_hex": ("percent_hex", False),
    "reversed_hex": ("hex", True), "decimal_csv": ("integers", False), "decimal_bytes": ("integers", False),
    "decimal_pipe": ("integers", False), "decimal_comma": ("integers", False), "decimal_dash": ("integers", False),
    "decimal_array": ("integers", False), "integer_tuple": ("integers", False), "integer_list": ("integers", False),
    "json_numbers": ("integers", False), "reversed_decimal": ("integers", True),
    "reversed_integer_list": ("integers", True), "plain_fragments": ("text", False),
    "split_fragments": ("text", False), "reversed_text": ("text", True),
    "reversed_base64": ("base64", True), "decimal_space": ("integers", False),
}


# ---- transforms: inverse of the named encoding step --------------------------------------------

def _rol(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xFF


def _ror(b, n):
    return ((b >> n) | (b << (8 - n))) & 0xFF


def _unroll(d, first):
    out, prior = bytearray(), first
    for b in d:
        out.append(b ^ prior)
        prior = b
    return bytes(out)


# Every recovered record starts with one of these, so an unknown single-byte key can be derived
# from the first encoded byte instead of brute-forcing all 256.
STARTS = (ord("v"), ord("{"), ord("["))


def _derive(first, op):
    return sorted({op(first, s) & 0xFF for s in STARTS})


XOR_TABLES = [bytes(i ^ k for i in range(256)) for k in range(256)]
ADD_TABLES = [bytes((i + k) % 256 for i in range(256)) for k in range(256)]


def _xor1(d, k):
    return d.translate(XOR_TABLES[k & 0xFF])           # C-speed single-byte XOR


def _addk(d, k):
    return d.translate(ADD_TABLES[k % 256])            # (b + k) % 256 for every byte


TRANSFORMS = {
    # name -> function(data, keys) -> candidate plaintexts. `keys` is a list of key byte-lists
    # (declared or harvested from the script); single-byte keys are also derived when absent.
    "identity": lambda d, ks: [d],
    "reverse": lambda d, ks: [d[::-1]],
    "reverse_bytes": lambda d, ks: [d[::-1]],
    "single_byte_xor": lambda d, ks: [_xor1(d, k) for k in _one(ks, d, lambda f, s: f ^ s)],
    "repeating_key_xor": lambda d, ks: [bytes(b ^ k[i % len(k)] for i, b in enumerate(d)) for k in ks if len(k) > 1]
                                       + [bytes(b ^ k[i % len(k)] for i, b in enumerate(d[::-1])) for k in ks if len(k) > 1],
    "rolling_xor": lambda d, ks: [_unroll(d, k) for k in _one(ks, d, lambda f, s: f ^ s)],
    "add_modulo_256": lambda d, ks: [_addk(d, -k) for k in _one(ks, d, lambda f, s: f - s)],
    "subtract_modulo_256": lambda d, ks: [_addk(d, k) for k in _one(ks, d, lambda f, s: s - f)],
    "rotate_left": lambda d, ks: [bytes(_ror(b, n) for b in d) for n in range(1, 8)],
    "rotate_right": lambda d, ks: [bytes(_rol(b, n) for b in d) for n in range(1, 8)],
    "reverse_then_xor": lambda d, ks: [_xor1(d[::-1], k) for k in _one(ks, d[::-1], lambda f, s: f ^ s)],
    "xor_then_reverse": lambda d, ks: [_xor1(d, k)[::-1] for k in _one(ks, d[::-1], lambda f, s: f ^ s)],
    "reverse_xor": lambda d, ks: [_xor1(d[::-1], k) for k in _one(ks, d[::-1], lambda f, s: f ^ s)],
}


def _one(keys, d, op):
    """Single-byte key candidates: declared/harvested ones, then ones derived from d[0]."""
    out = [k[0] for k in keys if len(k) == 1]
    return out + [k for k in (_derive(d[0], op) if d else []) if k not in out]


def _transform_for(step):
    """'xor_5a' -> ('single_byte_xor', [0x5a]); 'add_7' -> ('add_modulo_256', [7])."""
    m = re.fullmatch(r"xor_([0-9a-f]{2})", step)
    if m:
        return "single_byte_xor", [int(m.group(1), 16)]
    m = re.fullmatch(r"(add|sub|subtract)_(\d+)", step)
    if m:
        return ("add_modulo_256" if m.group(1) == "add" else "subtract_modulo_256"), [int(m.group(2))]
    return step, None


KEY_ARRAY = re.compile(r"(?i)\b\w*key\w*\s*[:=]\s*(?:new\s+\w+\s*)?[\[\(\{]\s*((?:(?:0x[0-9a-f]+|\d{1,3})\s*,\s*){0,31}(?:0x[0-9a-f]+|\d{1,3}))\s*,?\s*[\]\)\}]")
INLINE_KEY = re.compile(r"(?i)(?:\^|\bxor\b|\bbxor\b|-bxor)\s*\(?\s*(0x[0-9a-f]{1,2}|\d{1,3})\b")


def harvest_keys(text):
    """Key byte-lists the script itself carries: keyBytes = [..] arrays and `^ 99` constants."""
    keys = []
    for m in KEY_ARRAY.finditer(text):
        try:
            k = list(_ints(m.group(1)))
        except ValueError:
            continue
        if k and k not in keys:
            keys.append(k)
    for m in INLINE_KEY.finditer(text):
        v = int(m.group(1), 0)
        if v < 256 and [v] not in keys:
            keys.append([v])
    return keys


def parse_key(text):
    if not text:
        return None
    parts = [p for p in re.split(r"[,\s]+", text.strip()) if p]
    try:
        return [int(p, 16) for p in parts]
    except ValueError:
        return None


# ---- validation ---------------------------------------------------------------------------------

RECORD_RE = re.compile(rb"^(v=\d+\|[\x20-\x7e]+|\{\s*\"[\x20-\x7e\s]+\}|\[[\x20-\x7e\s]+\])$", re.S)


def is_record(data):
    """True when bytes look like a recovered config: 'v=1|k=v|...' or a JSON object/array."""
    if not data or not RECORD_RE.match(data.strip()):
        return False
    s = data.strip()
    if s[:1] in (b"{", b"["):
        try:
            json.loads(s)
        except ValueError:
            return False
    return True


def parse_record(data):
    """'v=1|steps=a,b|x=y' -> dict (steps split on commas); JSON -> object."""
    s = data.decode("utf-8", errors="replace").strip()
    if s[:1] in "{[":
        return json.loads(s)
    out = {}
    for part in s.split("|"):
        k, _, v = part.partition("=")
        out[k] = v.split(",") if k == "steps" else v
    return out


# ---- material extraction ------------------------------------------------------------------------

CODEC_DECL = re.compile(r"""(?:HUNTRESS-CODEC:|\bCODEC\w*\s*[:=]\s*["']|\bCodec\w*\s*=\s*["'])([A-Za-z0-9_|,\- ]+)""")
MATERIAL_DECL = re.compile(r"""(?:HUNTRESS-MATERIAL:|\bMATERIAL\w*\s*[:=]\s*|\bMaterial\w*\s*=\s*)(.+)""")
STRING_LIT = re.compile(r'"((?:[^"\\\n]|\\.){8,})"|\'((?:[^\'\\\n]|\\.){8,})\'')
INT_ARRAY = re.compile(r"[\[\(\{]\s*((?:-?(?:0x[0-9a-fA-F]+|\d{1,3})\s*,\s*){7,}-?(?:0x[0-9a-fA-F]+|\d{1,3}))\s*,?\s*[\]\)\}]")
VB_ARRAY = re.compile(r"Array\(\s*((?:\d{1,3}\s*,\s*){7,}\d{1,3})\s*\)")


# String pieces joined inline: "a" + "b" (JS/Python), 'a''b' (bash adjacency), "a" . "b" (PHP/Perl),
# "a" .. "b" (Lua), "a" & "b" / & _ (VBScript), with optional newlines in between.
ANY_LIT = r'(?:"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\')'
CONCAT_RUN = re.compile(ANY_LIT + r'(?:\s*(?:\+|\.\.|\.|&|_)?\s*(?:_\s*)?' + ANY_LIT + r')+')


def concat_runs(text):
    """Each run of 2+ joined string literals, concatenated without the quotes."""
    out = []
    for m in CONCAT_RUN.finditer(text):
        pieces = re.findall(ANY_LIT, m.group())
        joined = "".join(pc[1:-1] for pc in pieces)
        if len(joined) >= 16:
            out.append(joined)
    return out


def declared_codecs(text):
    return [m.group(1).strip() for m in CODEC_DECL.finditer(text)]


def materials(text, cheap=False):
    """Candidate encoded materials, most specific first: declared MATERIAL, then joined integer
    arrays (firstPart.concat(secondPart)), single arrays, then long string literals."""
    out = []
    # Python implicit concatenation across lines: MATERIAL_x = ("abc"\n    "def")
    for m in re.finditer(r"(?s)\bMATERIAL\w*\s*=\s*\(\s*((?:[\"'][^\"'\n]*[\"']\s*){2,})\)", text):
        out.append("".join(re.findall(r"[\"']([^\"'\n]*)[\"']", m.group(1))))
    # Shell-style quoted material that wraps across lines: Material_x='abc\ndef'
    # ... and adjacent quoted pieces that the shell concatenates: Material_x='abc''def'"ghi"
    for m in re.finditer(r"(?s)\bMaterial\w*\s*=\s*((?:'[^']*'|\"[^\"]*\")+)", text):
        joined = "".join(re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(1)) and
                         [a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(1))])
        if len(joined) >= 16:
            out.append(re.sub(r"\s+", "", joined))
    for m in MATERIAL_DECL.finditer(text):
        v = m.group(1).strip().rstrip(";")
        lit = STRING_LIT.search(v)
        out.append(lit.group(1) or lit.group(2) if lit else v)
    arrays = [m.group(1) for m in INT_ARRAY.finditer(text)] + [m.group(1) for m in VB_ARRAY.finditer(text)]
    if len(arrays) > 1:
        out.append(",".join(arrays))
    out += arrays
    if not cheap:                        # concat_runs is the slowest regex pass; recover() tries without it first
        out += concat_runs(text)
    out += [m.group(1) or m.group(2) for m in STRING_LIT.finditer(text)]
    # Adjacent string fragments joined ("abc" + "def", set frag0/frag1 ...).
    frags = [m.group(1) or m.group(2) for m in STRING_LIT.finditer(text)]
    if len(frags) > 1:
        out.append("".join(frags))
    # Batch: values of `set name=value` lines in order, carets unescaped (often the plaintext).
    sets = re.findall(r'(?im)^\s*set\s+"?(\w+)=([^"\r\n]*?)"?(?:\s*&\s*rem[^\r\n]*)?\s*$', text)
    joined = "".join(v.replace("^", "") for k, v in sets
                     if not re.match(r"(?i)neutral|recovered|cfg$|huntress", k))
    if joined:
        out.insert(0, joined)
    seen, uniq = set(), []
    for o in out:
        if o and o not in seen:
            seen.add(o)
            uniq.append(o)
    return uniq


def _candidates(material, fmt_name=None):
    """(format label, bytes) for a material string, using a declared format if given."""
    if fmt_name in FORMAT_ALIASES:
        parser, rev = FORMAT_ALIASES[fmt_name]
        try:
            # text and base64 are reversed as strings before parsing; byte formats after parsing
            pre = rev and parser in ("text", "base64", "urlsafe_base64")
            b = FORMATS[parser](material[::-1] if pre else material)
            yield fmt_name, (b[::-1] if rev and not pre else b)
        except (ValueError, binascii.Error):
            pass
    for name, fn in FORMATS.items():
        try:
            b = fn(material)
        except (ValueError, binascii.Error, UnicodeEncodeError):
            continue
        yield name, b
        yield name + "+reversed", b[::-1]


def recover(text):
    """Find the hidden record. Returns {'chain', 'material', 'plaintext', 'record'} or None.

    Uses the declared codec when present; otherwise searches formats x transforms (keys brute-
    forced where needed) and keeps the first output that validates with is_record()."""
    decls = declared_codecs(text)
    plans = []
    for d in decls:
        parts = d.split("|")
        fmt = parts[0] if parts and parts[0] in FORMAT_ALIASES else None
        step = parts[1] if len(parts) > 1 and parts[1] else "identity"
        name, key = _transform_for(step)
        key = key or parse_key(parts[2] if len(parts) > 2 else "")
        plans.append((d, fmt, name, key))
    # Fast pass: declared codec only, cheap material candidates (no concat runs, no brute force).
    for decl, fmt, tname, key in plans:
        if tname not in TRANSFORMS:
            continue
        for mat in materials(text, cheap=True):
            for flabel, data in _candidates(mat, fmt):
                if flabel != fmt:
                    break                    # only the declared format in the fast pass
                if is_record(data):
                    return _result(decl, flabel, "identity", None, mat, data)
                for plain in TRANSFORMS[tname](data, [key] if key else []):
                    if is_record(plain):
                        return _result(decl, flabel, tname, _used_key(tname, data, plain, [key] if key else []), mat, plain)
    harvested = harvest_keys(text)
    plans.append((None, None, None, None))  # undeclared search as the fallback
    mats = materials(text)
    for decl, fmt, tname, key in plans:
        keys = ([key] if key else []) + harvested
        tnames = [tname] if tname in TRANSFORMS else list(TRANSFORMS)
        for mat in mats:
            for flabel, data in _candidates(mat, fmt):
                if is_record(data):
                    return _result(decl, flabel, "identity", None, mat, data)
                for t in tnames:
                    for plain in _probed(t, data, keys):
                        if is_record(plain):
                            return _result(decl, flabel, t, _used_key(t, data, plain, keys), mat, plain)
    return None


# Transforms whose output starts from the input's first bytes vs its last bytes. A record must
# start with v= / { / [, so an 8-byte probe rejects almost every wrong key before the full transform.
FORWARD = {"identity", "single_byte_xor", "rolling_xor", "add_modulo_256", "subtract_modulo_256",
           "rotate_left", "rotate_right"}
BACKWARD = {"reverse", "reverse_bytes", "reverse_then_xor", "reverse_xor", "xor_then_reverse"}
# First bytes of any record (see RECORD_RE): printable, and v=<digit> / {"... / [...
PROBE_RE = re.compile(rb'^\s*(?:v=\d|\{\s*"|\[)[\x20-\x7e\s]*$')


def _probed(t, data, keys):
    """Same candidates, in the same order, as TRANSFORMS[t](data, keys), minus those whose first
    bytes cannot start a record."""
    if t not in FORWARD and t not in BACKWARD or len(data) <= 16:
        return TRANSFORMS[t](data, keys)
    probe = data[:8] if t in FORWARD else data[-8:]
    hits = [i for i, c in enumerate(TRANSFORMS[t](probe, keys)) if PROBE_RE.match(c)]
    if not hits:
        return []
    full = TRANSFORMS[t](data, keys)
    return [full[i] for i in hits]


def _used_key(t, data, plain, keys):
    if t in ("identity", "reverse", "reverse_bytes", "rotate_left", "rotate_right"):
        return None
    if t == "repeating_key_xor":
        return next((k for k in keys if len(k) > 1 and (data[0] ^ k[0]) == plain[0]), None)
    src = data[::-1] if t in ("reverse_then_xor", "reverse_xor", "xor_then_reverse") else data
    if t in ("single_byte_xor", "reverse_then_xor", "reverse_xor", "xor_then_reverse", "rolling_xor"):
        return [src[0] ^ (plain[-1] if t == "xor_then_reverse" else plain[0])]
    if t == "add_modulo_256":
        return [(data[0] - plain[0]) % 256]
    if t == "subtract_modulo_256":
        return [(plain[0] - data[0]) % 256]
    return None


def _result(decl, fmt, transform, key, material, plain):
    return {"declared": decl, "chain": f"{fmt}|{transform}" + (f"|{','.join(f'{k:02x}' for k in key)}" if key else ""),
            "material": material[:80] + ("..." if len(material) > 80 else ""),
            "plaintext": plain.decode("utf-8", errors="replace"), "record": parse_record(plain)}


# ---- indicators ---------------------------------------------------------------------------------

IOC_PATTERNS = {
    "url": r"\b(?:https?|ftp)://[^\s\"'<>|`)\]]+",
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "domain": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:invalid|example|test|com|net|org|io|ru|cn|xyz|top|info|biz|local|lan|onion)\b",
    "email": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
    "windows_path": r"\b[A-Za-z]:\\(?:[^\\\s\"'|<>]+\\)*[^\\\s\"'|<>]*",
    "unix_path": r"(?<![\w:])/(?:tmp|var|etc|usr|home|opt|dev/shm|root)(?:/[\w.\-]+)+",
    "registry": r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)(?:\\\\?[^\s\"'|]+)+",
    "mutex": r"\b(?:Global|Local)\\\\?[\w.\-]+",
    "user_agent": r"Mozilla/\d\.\d[^\"'|\n]*",
    "md5": r"\b[a-f0-9]{32}\b", "sha1": r"\b[a-f0-9]{40}\b", "sha256": r"\b[a-f0-9]{64}\b",
    "wallet": r"\bwallet_[0-9a-f]{16,}\b",
    "filename": r"\b[\w\-]+\.(?:exe|dll|dat|bin|zip|ps1|vbs|js|bat|cmd|txt|lnk|hta|scr|tmp|log)\b",
}


def iocs(text):
    """{kind: [unique values in first-seen order]} over the text (and JSON-escaped variants)."""
    text = text.replace("\\\\", "\\")
    out = {}
    url_spans = [m.span() for m in re.finditer(IOC_PATTERNS["url"], text, re.I)]
    for kind, rx in IOC_PATTERNS.items():
        vals = []
        for m in re.finditer(rx, text, re.I if kind in ("domain", "url", "windows_path") else 0):
            if kind == "filename" and any(a <= m.start() < b for a, b in url_spans):
                continue  # a URL's last path segment is not a separate file indicator
            v = m.group().rstrip(".,;")
            if v not in vals:
                vals.append(v)
        if vals:
            out[kind] = vals
    return out


# ---- ATT&CK -------------------------------------------------------------------------------------

ATTACK = [
    # (technique id, name, regex over script text + recovered plaintext)
    ("T1496", "Resource Hijacking", r"wallet|miner|xmrig|stratum\+tcp|hashrate"),
    ("T1555.003", "Credentials from Web Browsers", r"Login Data|Cookies|logins\.json|key4\.db|Local State"),
    ("T1005", "Data from Local System", r"Get-ChildItem|\bfind\s+/|collect_local|locate_local"),
    ("T1560.001", "Archive via Utility", r"ZipFile|Compress-Archive|\bzip\b|\btar\s+-?c|7z\s+a"),
    ("T1486", "Data Encrypted for Impact", r"\.locked|RECOVER|ransom|Cryptography\.Aes|encrypt_files|transform_content"),
    ("T1490", "Inhibit System Recovery", r"vssadmin|wbadmin|bcdedit|shadowcopy"),
    ("T1105", "Ingress Tool Transfer", r"DownloadFile|DownloadString|Invoke-WebRequest|certutil|bitsadmin|curl\s|wget\s|acquire_remote|XMLHTTP"),
    ("T1041", "Exfiltration Over C2 Channel", r"UploadFile|UploadData|upload_remote|HttpWebRequest|POST"),
    ("T1071.001", "Web Protocols", r"https?://"),
    ("T1547.001", "Registry Run Keys", r"\\Run\b|CurrentVersion\\\\?Run"),
    ("T1053.005", "Scheduled Task", r"schtasks|Register-ScheduledTask|scheduled"),
    ("T1053.003", "Cron", r"crontab|/etc/cron"),
    ("T1546.003", "WMI Event Subscription", r"__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding|ActiveScriptEventConsumer"),
    ("T1127.001", "MSBuild", r"<Project\b|msbuild|UsingTask|CodeTaskFactory"),
    ("T1218.010", "Regsvr32", r"regsvr32"),
    ("T1218.011", "Rundll32", r"rundll32"),
    ("T1218.005", "Mshta", r"mshta"),
    ("T1620", "Reflective Code Loading", r"Assembly\]::Load|dispatch_memory|VirtualAlloc|memory_stage"),
    ("T1027", "Obfuscated Files or Information", r"FromBase64String|fromCharCode|Chr\(|\bxor\b|\^\s*\d+"),
    ("T1140", "Deobfuscate/Decode Files", r"decode_configuration|certutil\s+-decode|base64\s+-d"),
    ("T1112", "Modify Registry", r"Set-ItemProperty|reg\s+add|RegWrite|Microsoft\.Win32\.Registry"),
    ("T1082", "System Information Discovery", r"systeminfo|uname|Win32_OperatingSystem|hostname"),
    ("T1059.001", "PowerShell", r"powershell|\.ps1\b"),
    ("T1059.003", "Windows Command Shell", r"cmd(\.exe)?\s*/c|@echo off"),
    ("T1059.005", "Visual Basic", r"\bWScript\.|CreateObject\("),
    ("T1059.007", "JavaScript", r"ActiveXObject|WScript\.Shell|node\b|require\("),
    ("T1059.004", "Unix Shell", r"^#!.*sh|/bin/(ba)?sh"),
]


def attack(text):
    """[(technique, name, evidence)] for every rule that matches, in table order.

    These are CANDIDATES, not a verdict: fixtures carry decoy strings (e.g. "Login Data" in an
    impact sample), so the analyst still picks the primary technique from the behaviour."""
    out = []
    for tid, name, rx in ATTACK:
        m = re.search(rx, text, re.I | re.M)
        if m:
            out.append((tid, name, m.group()[:40]))
    return out


def triage(path):
    """One-file report: language, declared codecs, recovered record, IOCs, ATT&CK candidates."""
    text = open(path, encoding="utf-8", errors="replace").read()
    rec = recover(text)
    combined = text + "\n" + (rec["plaintext"] if rec else "")
    return {"path": path, "language": language(path, text), "declared_codecs": declared_codecs(text),
            "recovered": rec, "iocs": iocs(combined), "attack": attack(combined)}


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        r = triage(p)
        print(f"== {p}  [{r['language']}] declared={r['declared_codecs']}")
        if r["recovered"]:
            print(f"   chain {r['recovered']['chain']}: {r['recovered']['plaintext'][:200]}")
        else:
            print("   no record recovered")
        for k, v in r["iocs"].items():
            print(f"   {k}: {v[:4]}")
        print("   ATT&CK:", [t for t, _, _ in r["attack"]])
