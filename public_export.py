#!/usr/bin/python3
"""Publish a privacy-reviewed derivative of locally signed kernel_task samples."""

import datetime as dt
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

import publisher


SOURCE = Path("/var/db/nsa_kernal_task/archive")
REPO = Path.home() / "Library/Application Support/nsa_kernal_task/public_repo"
PRIVATE_REPO = Path.home() / "Library/Application Support/nsa_kernal_task/repo"
INSTALLED = Path("/Library/Application Support/nsa_kernal_task")
STATE = Path.home() / "Library/Application Support/nsa_kernal_task/public-status.json"
REMOTE = "https://github.com/eagleandtheclaw/nsa_kernal_task.git"
GIT = "/usr/bin/git"
GH = "/opt/homebrew/bin/gh"
THREAD = re.compile(r"^\s+Thread\s+0x[0-9a-fA-F]+.*?\b(\d+) samples?\b")
FRAME = re.compile(r"^\s*\*(\d+)\s+(.+)$")
ADDRESS = re.compile(r"(?i)0x[0-9a-f]+")
UUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
PRIVATE = re.compile(
    r"(?i)(/Users/|/Volumes/|/private/var/|"
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|"
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|"
    r"(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])|"
    r"\b(?:password|secret|credential|api[_ -]?key)\b)"
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def run(command, cwd=None, timeout=120):
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1"})
    result = subprocess.run(command, cwd=str(cwd) if cwd else None, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError("%s failed (%d): %s" %
                           (command[0], result.returncode, result.stderr.decode(errors="replace")))
    return result.stdout.decode(errors="replace").strip()


def sanitize(record):
    body = record["body"]
    if body.get("schema") == 2:
        section, count, _, _ = publisher.capture.extract_kernel_task(body["raw_target_report"].encode())
    else:
        section = body["kernel_task_section"]
        count = body["kernel_task_num_samples"]
    if count != body["kernel_task_num_samples"]:
        raise RuntimeError("sample count mismatch before public export")
    lines = section.splitlines()
    first = next((i for i, line in enumerate(lines) if THREAD.match(line)), None)
    if first is None:
        raise RuntimeError("kernel_task sample has no thread stacks")
    out = ["Process: kernel_task [0]", "Num samples: %d" % count]
    threads = frames = 0
    for line in lines[first:]:
        if line.strip().startswith(("Binary Images:", "Kextstat:")):
            break
        if not line.strip():
            continue
        match = THREAD.match(line)
        if match:
            threads += 1
            out.append("Thread %d: %s samples" % (threads, match.group(1)))
            continue
        match = FRAME.match(line)
        if match:
            frames += 1
            symbol = UUID.sub("[uuid]", ADDRESS.sub("[address]", match.group(2)))
            if PRIVATE.search(symbol):
                raise RuntimeError("private field in frame; review required")
            out.append("  *%s %s" % (match.group(1), symbol))
            continue
        raise RuntimeError("unknown line in kernel_task stacks; review required")
    if not threads or not frames:
        raise RuntimeError("public export contains no thread stacks")
    result = "\n".join(out) + "\n"
    if PRIVATE.search(result) or UUID.search(result) or ADDRESS.search(result):
        raise RuntimeError("privacy scan failed for public stack report")
    return result, threads, frames


def build_public_record(path, previous):
    original, compressed = publisher.read_sample(path)
    body = original["body"]
    sanitized, threads, frames = sanitize(original)
    public_body = {
        "schema": 1,
        "sequence": body["sequence"],
        "capture_started_utc": body["capture_started_utc"],
        "kernel_task_pid": 0,
        "kernel_task_num_samples": body["kernel_task_num_samples"],
        "thread_count": threads,
        "frame_count": frames,
        "stack_report": sanitized,
        "stack_report_sha256": sha256(sanitized.encode()),
        "original_body_sha256": original["body_sha256"],
        "original_compressed_sha256": sha256(compressed),
        "previous_public_body_sha256": previous,
    }
    data = canonical(public_body)
    packed = lzma.compress(canonical({"body": public_body, "body_sha256": sha256(data)}) + b"\n", preset=6)
    return public_body, sha256(data), packed


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp." + secrets.token_hex(6))
    temporary.write_bytes(canonical(value) + b"\n")
    os.replace(str(temporary), str(path))


def publish_once():
    if os.geteuid() == 0:
        raise RuntimeError("public exporter must run as the signed-in user")
    if run([GH, "api", "user", "--jq", ".login"], timeout=30) != "eagleandtheclaw":
        raise RuntimeError("GitHub account mismatch")
    if run([GIT, "remote", "get-url", "origin"], REPO) != REMOTE:
        raise RuntimeError("public remote mismatch")
    expected_code = json.loads((PRIVATE_REPO / "CODE_HASHES.json").read_text())
    actual_code = sha256(Path(__file__).read_bytes())
    if actual_code != expected_code["public_export.py"]:
        raise RuntimeError("installed public exporter code hash mismatch")
    collector_code = (INSTALLED / "capture.py").read_bytes()
    if sha256(collector_code) != expected_code["capture.py"]:
        raise RuntimeError("installed collector code hash mismatch")
    if re.search(r"/Users/[A-Za-z0-9._-]+(?:/|\b)|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
                 collector_code.decode("utf-8"), re.IGNORECASE):
        raise RuntimeError("identifier in collector code; public source review required")
    run([GIT, "fetch", "origin", "main"], REPO)
    run([GIT, "merge", "--ff-only", "origin/main"], REPO)
    public_code = REPO / "src" / "capture.py"
    public_code.parent.mkdir(parents=True, exist_ok=True)
    public_code.write_bytes(collector_code)
    write_json(REPO / "SOURCE_HASHES.json", {"capture.py": sha256(collector_code)})
    head_path = REPO / "PUBLIC_CHAIN_HEAD.json"
    head = json.loads(head_path.read_text()) if head_path.exists() else {
        "sequence": 0, "body_sha256": "0" * 64}
    sequence = head["sequence"]
    previous = head["body_sha256"]
    previous_original = "0" * 64
    if sequence:
        published = list((REPO / "samples").glob("*/%08d_*.json.xz" % sequence))
        source_head = list(SOURCE.glob("%08d_*.json.xz" % sequence))
        if len(published) != 1 or len(source_head) != 1:
            raise RuntimeError("public or private chain head sample missing")
        public_record = json.loads(lzma.decompress(published[0].read_bytes()))
        original_record, _ = publisher.read_sample(source_head[0])
        if (public_record["body_sha256"] != previous or
                public_record["body"]["original_body_sha256"] != original_record["body_sha256"]):
            raise RuntimeError("public and signed original heads differ")
        previous_original = original_record["body_sha256"]
    count = 0
    for path in sorted(SOURCE.glob("*.json.xz")):
        number = int(path.name.split("_", 1)[0])
        if number <= sequence:
            continue
        if number != sequence + 1:
            raise RuntimeError("public sample sequence gap")
        original_record, _ = publisher.read_sample(path)
        if (original_record["body"]["sequence"] != number or
                original_record["body"]["previous_body_sha256"] != previous_original):
            raise RuntimeError("signed original sequence or chain mismatch")
        public_body, body_hash, packed = build_public_record(path, previous)
        output = REPO / "samples" / public_body["capture_started_utc"][:10] / path.name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(packed)
        previous = body_hash
        previous_original = original_record["body_sha256"]
        sequence = number
        count += 1
    write_json(head_path, {"sequence": sequence, "body_sha256": previous,
                           "updated_at_utc": utc_now()})
    write_json(REPO / "PUBLIC_HEARTBEAT.json", {
        "committed_at_utc": utc_now(), "last_sequence": sequence,
        "samples_in_commit": count, "nonce": secrets.token_hex(16)})
    run([GIT, "add", "PUBLIC_CHAIN_HEAD.json", "PUBLIC_HEARTBEAT.json", "SOURCE_HASHES.json", "src/capture.py", "samples"], REPO)
    run([GIT, "-c", "user.name=eagleandtheclaw",
         "-c", "user.email=318743460+eagleandtheclaw@users.noreply.github.com",
         "commit", "-m", "Publish sanitized kernel_task through sequence %d" % sequence], REPO)
    commit = run([GIT, "rev-parse", "HEAD"], REPO)
    run([GIT, "push", "origin", "HEAD:main"], REPO)
    remote = run([GIT, "ls-remote", "origin", "refs/heads/main"], REPO).split()[0]
    if remote != commit:
        raise RuntimeError("public remote commit mismatch")
    status = {"state": "published", "commit": commit, "last_sequence": sequence,
              "samples_in_commit": count, "updated_at_utc": utc_now()}
    write_json(STATE, status)
    print(json.dumps(status, sort_keys=True), flush=True)
    return status


def loop():
    while True:
        started = time.monotonic()
        try:
            publish_once()
            delay = 180 + secrets.randbelow(181)
        except Exception as exc:
            write_json(STATE, {"state": "error", "error": str(exc), "updated_at_utc": utc_now()})
            print("public export error: " + str(exc), file=sys.stderr, flush=True)
            delay = 30 + secrets.randbelow(31)
        remaining = delay - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("once", "loop"):
        raise SystemExit("usage: public_export.py once|loop")
    if sys.argv[1] == "once":
        publish_once()
    else:
        loop()
