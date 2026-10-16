#!/usr/bin/env python3
"""Bounded evidence listener for the shell-free HeadlessChrome PoC."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import socket


REQUIRED_MARKERS = (
    b"===STATUS===",
    b"===CMDLINE===",
    b"===UNAME===",
    b"===EXE===",
)


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def section(data: bytes, marker: bytes, next_marker: bytes | None) -> bytes:
    start = data.find(marker)
    if start < 0:
        return b""
    start += len(marker)
    if data[start : start + 1] == b"\n":
        start += 1
    if next_marker is None:
        return data[start:]
    end = data.find(next_marker, start)
    return data[start:] if end < 0 else data[start:end]


def parse_status(raw: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    return fields


def parse_capture(data: bytes) -> dict[str, object]:
    status_raw = section(data, b"===STATUS===", b"===CMDLINE===")
    cmdline_raw = section(data, b"===CMDLINE===", b"===UNAME===")
    uname_raw = section(data, b"===UNAME===", b"===EXE===")
    has_env = b"===ENVIRON===" in data
    exe_raw = section(
        data, b"===EXE===", b"===ENVIRON===" if has_env else b"===EXTRA==="
    )
    env_raw = section(data, b"===ENVIRON===", b"===EXTRA===") if has_env else b""
    extra_raw = section(data, b"===EXTRA===", None)

    status = parse_status(status_raw)
    cmdline = [
        item.decode("utf-8", "replace")
        for item in cmdline_raw.strip(b"\n\x00").split(b"\x00")
        if item
    ]
    uts = [
        uname_raw[offset : offset + 65].rstrip(b"\x00").decode("utf-8", "replace")
        for offset in range(0, min(len(uname_raw), 390), 65)
    ]
    while len(uts) < 6:
        uts.append("")

    uid = status.get("Uid", "").split()
    gid = status.get("Gid", "").split()
    return {
        "process": status.get("Name"),
        "pid": status.get("Pid"),
        "ppid": status.get("PPid"),
        "uid": uid[0] if uid else None,
        "gid": gid[0] if gid else None,
        "groups": status.get("Groups"),
        "id_equivalent": (
            f"uid={uid[0] if uid else '?'} gid={gid[0] if gid else '?'} "
            f"groups={status.get('Groups', '')}"
        ).strip(),
        "cmdline": cmdline,
        "uname": {
            "sysname": uts[0],
            "nodename": uts[1],
            "release": uts[2],
            "version": uts[3],
            "machine": uts[4],
            "domainname": uts[5],
        },
        "exe": exe_raw.strip(b"\n\x00").decode("utf-8", "replace"),
        "environ_redacted": (
            env_raw.strip(b"\n").decode("utf-8", "replace") if has_env else None
        ),
        "extra_file": extra_raw.strip(b"\n\x00").decode("utf-8", "replace"),
        "security": {
            "NoNewPrivs": status.get("NoNewPrivs"),
            "Seccomp": status.get("Seccomp"),
            "CapEff": status.get("CapEff"),
            "Threads": status.get("Threads"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=19707)
    parser.add_argument("--out-dir", default="./captures")
    parser.add_argument("--max-bytes", type=int, default=32 * 1024)
    parser.add_argument("--keep-listening", action="store_true")
    args = parser.parse_args()

    os.makedirs(args.out_dir, mode=0o700, exist_ok=True)
    meta_path = os.path.join(args.out_dir, "connections.ndjson")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(8)
        print(f"listening on {args.host}:{args.port}; evidence={args.out_dir}", flush=True)

        while True:
            conn, peer = server.accept()
            started = utc_now()
            chunks: list[bytes] = []
            total = 0
            truncated = False
            with conn:
                conn.settimeout(10)
                while total < args.max_bytes:
                    try:
                        chunk = conn.recv(min(4096, args.max_bytes - total))
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                if total == args.max_bytes:
                    truncated = bool(conn.recv(1))

            data = b"".join(chunks)
            digest = hashlib.sha256(data).hexdigest()
            stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S.%fZ")
            raw_name = None
            if data:
                raw_name = (
                    f"headless-proc-{stamp}-{peer[0].replace(':', '_')}-{peer[1]}.raw"
                )
                raw_path = os.path.join(args.out_dir, raw_name)
                with open(raw_path, "xb") as fh:
                    fh.write(data)
                os.chmod(raw_path, 0o600)

            present = {
                marker.decode("ascii"): marker in data for marker in REQUIRED_MARKERS
            }
            record = {
                "started": started,
                "finished": utc_now(),
                "peer_ip": peer[0],
                "peer_port": peer[1],
                "length": len(data),
                "sha256": digest,
                "raw_file": raw_name,
                "truncated": truncated,
                "markers": present,
                "parsed": parse_capture(data) if data else None,
            }
            with open(meta_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
            print(json.dumps(record, indent=2, sort_keys=True), flush=True)

            complete = data and all(present.values()) and not truncated
            if complete and not args.keep_listening:
                break


if __name__ == "__main__":
    main()
