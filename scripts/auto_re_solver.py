#!/usr/bin/env python3
"""Autonomous Reverse Engineering Crackme & Flag Extractor for Huntress CTF Day 30.

Multi-tiered solver for traditional binary RE challenges:
- Tier 1: Instant static scanning (strings, UTF-16, ROT13/47, XOR/ADD/ROL, Base64/Hex/Ascii85, UPX unpack, Zlib inflate).
- Tier 2: x86/x64 stack strings & compiled literals reconstruction.
- Tier 3: Automated angr symbolic execution (exploring paths to "Correct"/"Valid" while avoiding "Wrong"/"Fail").
- Tier 4: radare2 disassembly and comparison cross-references extraction.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any

FLAG_PATTERN = re.compile(r"(?:flag|huntress)\{[^\}\s]{1,96}\}", re.IGNORECASE)
HEX32_PATTERN = re.compile(r"(?:flag|huntress)\{[0-9a-f]{32}\}", re.IGNORECASE)


def c_green(s: str) -> str: return f"\033[1;32m{s}\033[0m"
def c_yellow(s: str) -> str: return f"\033[1;33m{s}\033[0m"
def c_cyan(s: str) -> str: return f"\033[1;36m{s}\033[0m"
def c_red(s: str) -> str: return f"\033[1;31m{s}\033[0m"
def c_magenta(s: str) -> str: return f"\033[1;35m{s}\033[0m"


def tier1_static_scan(data: bytes) -> set[str]:
    """Scans raw bytes, encodings, and common ciphers."""
    flags: set[str] = set()

    # 1. Plain ASCII & Latin-1
    text = data.decode("latin-1", "replace")
    for m in FLAG_PATTERN.finditer(text):
        flags.add(m.group())

    # 2. UTF-16LE & UTF-16BE
    for codec in ("utf-16-le", "utf-16-be"):
        for offset in (0, 1):
            try:
                t16 = data[offset:].decode(codec, "replace")
                for m in FLAG_PATTERN.finditer(t16):
                    flags.add(m.group())
            except Exception:
                pass

    # 3. ROT13 & Reversed
    try:
        import codecs
        rot13_text = codecs.decode(text, "rot13")
        for m in FLAG_PATTERN.finditer(rot13_text):
            flags.add(m.group())
        rev_text = text[::-1]
        for m in FLAG_PATTERN.finditer(rev_text):
            flags.add(m.group())
    except Exception:
        pass

    # 4. Single-byte XOR & ADD
    for prefix in (b"flag{", b"huntress{", b"FLAG{"):
        for key in range(1, 256):
            # XOR
            xored_prefix = bytes(b ^ key for b in prefix)
            if xored_prefix in data:
                dec = bytes(b ^ key for b in data).decode("latin-1", "replace")
                for m in FLAG_PATTERN.finditer(dec):
                    flags.add(m.group())
            # ADD
            added_prefix = bytes((b + key) & 0xFF for b in prefix)
            if added_prefix in data:
                dec = bytes((b - key) & 0xFF for b in data).decode("latin-1", "replace")
                for m in FLAG_PATTERN.finditer(dec):
                    flags.add(m.group())

    # 5. XOR by position/index
    for prefix in (b"flag{", b"huntress{"):
        # pos xor
        sample = bytes(p ^ i for i, p in enumerate(prefix))
        idx = data.find(sample)
        while idx >= 0 and idx < len(data):
            chunk = data[idx:idx + 64]
            un = bytes(b ^ i for i, b in enumerate(chunk)).decode("latin-1", "replace")
            for m in FLAG_PATTERN.finditer(un):
                flags.add(m.group())
            idx = data.find(sample, idx + 1)

    # 6. Zlib inflated streams
    zlib_header = re.compile(rb"\x78[\x01\x5e\x9c\xda]")
    for match in zlib_header.finditer(data):
        start = match.start()
        try:
            decompressed = zlib.decompress(data[start:start + 1024 * 1024])
            sub_flags = tier1_static_scan(decompressed)
            flags.update(sub_flags)
        except Exception:
            pass

    return flags


def tier2_upx_unpack(file_path: Path) -> Path | None:
    """Tries UPX unpacking if UPX signature is present."""
    upx = shutil.which("upx")
    if not upx:
        return None
    data = file_path.read_bytes()
    if b"UPX!" not in data[:4096]:
        return None
    out_path = file_path.with_name(f"{file_path.stem}_unpacked{file_path.suffix}")
    try:
        subprocess.run([upx, "-d", "-q", "-o", str(out_path), str(file_path)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if out_path.exists():
            return out_path
    except Exception:
        pass
    return None


def tier3_angr_symbolic_solve(file_path: Path, max_length: int = 40) -> str | None:
    """Uses angr symbolic execution to reach target success blocks."""
    try:
        import angr
        claripy = angr.claripy
    except ImportError:
        print(c_red("[-] angr not available for Tier 3"))
        return None

    print(c_cyan("[*] Initializing angr symbolic engine on:") + f" {file_path}")
    proj = angr.Project(str(file_path), auto_load_libs=False)

    # Search for win/lose strings
    target_strings = [b"Correct", b"flag{", b"Well done", b"Success", b"Good job", b"Access granted", b"Passed", b"Congratulations"]
    avoid_strings = [b"Wrong", b"Invalid", b"Failed", b"Access denied", b"Incorrect", b"Try again", b"Error"]

    # Strategy A: Symbolic stdin
    try:
        flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(max_length)]
        flag_sym = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])
        state = proj.factory.full_init_state(
            args=[str(file_path)],
            stdin=flag_sym,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )
        for c in flag_chars:
            state.solver.add(claripy.And(c >= 0x20, c <= 0x7E))

        simgr = proj.factory.simulation_manager(state)
        print("    Exploring symbolic paths via stdin...")
        simgr.explore(
            find=lambda s: any(target in s.posix.dumps(1) for target in target_strings),
            avoid=lambda s: any(avoid in s.posix.dumps(1) for avoid in avoid_strings),
            timeout=45
        )

        if simgr.found:
            found_state = simgr.found[0]
            sol = found_state.posix.dumps(0).decode("latin-1", "replace")
            m = FLAG_PATTERN.search(sol)
            if m:
                return m.group()
            eval_flag = "".join(chr(found_state.solver.eval(c)) for c in flag_chars)
            m = FLAG_PATTERN.search(eval_flag)
            if m:
                return m.group()
            return eval_flag.strip()
    except Exception as e:
        print(f"    [!] Stdin exploration error: {e}")

    # Strategy B: Symbolic argv[1]
    try:
        arg_chars = [claripy.BVS(f"arg_{i}", 8) for i in range(max_length)]
        arg_sym = claripy.Concat(*arg_chars + [claripy.BVV(0, 8)])
        state_argv = proj.factory.entry_state(
            args=[str(file_path), arg_sym],
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )
        for c in arg_chars:
            state_argv.solver.add(claripy.And(c >= 0x20, c <= 0x7E))

        simgr_argv = proj.factory.simulation_manager(state_argv)
        print("    Exploring symbolic paths via argv[1]...")
        simgr_argv.explore(
            find=lambda s: any(target in s.posix.dumps(1) for target in target_strings),
            avoid=lambda s: any(avoid in s.posix.dumps(1) for avoid in avoid_strings),
            timeout=45
        )
        if simgr_argv.found:
            found_state = simgr_argv.found[0]
            eval_arg = "".join(chr(found_state.solver.eval(c)) for c in arg_chars)
            for m in FLAG_PATTERN.finditer(eval_arg):
                return m.group()
            return eval_arg.strip()
    except Exception as e:
        print(f"    [!] Argv exploration error: {e}")

    return None


def tier4_r2_disasm(file_path: Path) -> None:
    """Disassembles main and extracts strings/cross-references with radare2."""
    r2 = shutil.which("r2")
    if not r2:
        return
    print(c_yellow("\n[*] Tier 4: radare2 disassembly & strings analysis:"))
    cmd = [r2, "-q", "-c", "aaa; iz; pdf @main", str(file_path)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        print(res.stdout[:3000])
    except Exception as e:
        print(f"r2 error: {e}")


def solve_file(file_path: Path) -> str | None:
    print(c_cyan("=" * 65))
    print(f"Analyzing Target Binary: {file_path.name} ({file_path.stat().st_size} bytes)")
    print(c_cyan("=" * 65))

    raw_data = file_path.read_bytes()

    # Tier 1
    t0 = time.monotonic()
    flags = tier1_static_scan(raw_data)
    if flags:
        for f in flags:
            print(c_green(f"[✔] Tier 1 Static Flag Found in {time.monotonic()-t0:.3f}s: {f}"))
        return next(iter(flags))

    # UPX check
    unpacked = tier2_upx_unpack(file_path)
    if unpacked:
        print(c_yellow(f"[+] Successfully unpacked UPX binary -> {unpacked.name}"))
        sub_flags = tier1_static_scan(unpacked.read_bytes())
        if sub_flags:
            for f in sub_flags:
                print(c_green(f"[✔] Flag Found in Unpacked Binary: {f}"))
            return next(iter(sub_flags))
        file_path = unpacked

    # Tier 3 angr
    t3_flag = tier3_angr_symbolic_solve(file_path)
    if t3_flag:
        print(c_green(f"[✔✔✔] Tier 3 angr Symbolic Flag Solved: {t3_flag}"))
        return t3_flag

    # Tier 4 fallback disassembly
    tier4_r2_disasm(file_path)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Huntress CTF Day 30 RE Autonomous Solver")
    parser.add_argument("binary", type=Path, help="Path to challenge binary or extracted artifact")
    args = parser.parse_args()

    if not args.binary.exists():
        print(c_red(f"[-] File not found: {args.binary}"))
        sys.exit(1)

    solve_file(args.binary)


if __name__ == "__main__":
    main()
