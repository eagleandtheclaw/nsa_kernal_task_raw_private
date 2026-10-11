#!/usr/bin/python3
"""Boot-time, root-owned kernel_task stack collector."""

import argparse
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
import tempfile
import time


ROOT = Path(os.environ.get("NSA_KERNEL_ROOT", "/var/db/nsa_kernal_task"))
SIGNING_KEY = ROOT / "signing_key"
PUBLIC_KEY = ROOT / "signing_key.pub"
ARCHIVE = ROOT / "archive"
MANIFEST = ROOT / "manifest.jsonl"
STATUS = ROOT / "status.json"
CODE_HASHES = Path("/Library/Application Support/nsa_kernal_task/CODE_HASHES.json")
SPINDUMP = "/usr/sbin/spindump"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
NAMESPACE = "nsa_kernal_task"
MAX_START_GAP_SECONDS = 60


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def atomic_write(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp." + secrets.token_hex(8))
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temp), str(path))
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if temp.exists():
            temp.unlink()


def append_manifest(item):
    line = canonical(item) + b"\n"
    fd = os.open(str(MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def last_manifest():
    if not MANIFEST.exists():
        return None
    with MANIFEST.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        if size == 0:
            return None
        handle.seek(max(0, size - 4096))
        tail = handle.read()
    lines = tail.splitlines(keepends=True)
    if not lines or (size > 4096 and len(lines) < 2):
        raise RuntimeError("manifest final record exceeds tail window")
    if size > 4096:
        lines = lines[1:]
    if not lines:
        return None
    if not lines[-1].endswith(b"\n"):
        raise RuntimeError("manifest has an incomplete final record")
    return json.loads(lines[-1])


def extract_kernel_task(report):
    text = report.decode("utf-8", errors="replace")
    match = re.search(r"^Process:\s+kernel_task \[0\]\s*$", text, re.MULTILINE)
    if match is None:
        raise RuntimeError("spindump report has no kernel_task [0] section")
    later = re.search(r"^Process:", text[match.end():], re.MULTILINE)
    end = match.end() + later.start() if later else len(text)
    section = text[match.start():end].rstrip() + "\n"
    sample_match = re.search(r"^Num samples:\s+(\d+)", section, re.MULTILINE)
    if sample_match is None or int(sample_match.group(1)) < 1:
        raise RuntimeError("kernel_task section has no samples")
    date_match = re.search(r"^Date/Time:\s+(.+)$", text, re.MULTILINE)
    duration_match = re.search(r"^Duration:\s+(.+)$", text, re.MULTILINE)
    return section, int(sample_match.group(1)), date_match.group(1) if date_match else None, duration_match.group(1) if duration_match else None


def sign(data):
    result = subprocess.run(
        [SSH_KEYGEN, "-Y", "sign", "-f", str(SIGNING_KEY), "-n", NAMESPACE],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
    )
    if result.returncode:
        raise RuntimeError("ssh-keygen signing failed: " + result.stderr.decode(errors="replace"))
    return result.stdout.decode("ascii")


def set_status(**fields):
    if STATUS.exists():
        try:
            previous = json.loads(STATUS.read_text())
            previous.update(fields)
            fields = previous
        except (OSError, ValueError):
            pass
    fields["updated_at_utc"] = utc_now()
    atomic_write(STATUS, canonical(fields) + b"\n", mode=0o640)
    os.chown(str(STATUS), 0, 20)


def capture_once():
    prior = last_manifest()
    sequence = prior["sequence"] + 1 if prior else 1
    previous_hash = prior["body_sha256"] if prior else "0" * 64
    started_utc = utc_now()
    started_monotonic = time.monotonic()
    ARCHIVE.mkdir(mode=0o750, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="capture-", dir=str(ROOT)) as tmp:
        raw_path = Path(tmp) / "system.spindump.txt"
        command = [SPINDUMP, "-noTarget", "1", "100", "-noBinary", "-automation", "-o", str(raw_path)]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=55)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("spindump timed out after 55 seconds") from exc
        if result.returncode:
            raise RuntimeError("spindump failed (%d): %s" % (result.returncode, result.stderr.decode(errors="replace")))
        raw = raw_path.read_bytes()
        raw_hash = sha256(raw)
        section, sample_count, report_date, report_duration = extract_kernel_task(raw)
    section_bytes = section.encode("utf-8")
    body = {
        "schema": 1,
        "sequence": sequence,
        "previous_body_sha256": previous_hash,
        "capture_started_utc": started_utc,
        "capture_finished_utc": utc_now(),
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
        "report_date": report_date,
        "report_duration": report_duration,
        "kernel_task_pid": 0,
        "kernel_task_num_samples": sample_count,
        "raw_system_report_sha256": raw_hash,
        "kernel_task_section_sha256": sha256(section_bytes),
        "kernel_task_section": section,
        "collector_command": [SPINDUMP, "-noTarget", "1", "100", "-noBinary", "-automation"],
        "collector_uid": os.geteuid(),
        "collector_code_sha256": sha256(Path(__file__).read_bytes()),
    }
    body_bytes = canonical(body)
    body_hash = sha256(body_bytes)
    record = {"body": body, "body_sha256": body_hash, "signature": sign(body_bytes)}
    packed = lzma.compress(canonical(record) + b"\n", preset=6)
    filename = "%08d_%s.json.xz" % (sequence, secrets.token_hex(6))
    archive_path = ARCHIVE / filename
    atomic_write(archive_path, packed, mode=0o640)
    os.chown(str(archive_path), 0, 20)
    item = {
        "sequence": sequence,
        "filename": filename,
        "body_sha256": body_hash,
        "previous_body_sha256": previous_hash,
        "kernel_task_section_sha256": body["kernel_task_section_sha256"],
        "raw_system_report_sha256": raw_hash,
        "compressed_sha256": sha256(packed),
        "compressed_bytes": len(packed),
        "capture_started_utc": started_utc,
        "kernel_task_num_samples": sample_count,
    }
    append_manifest(item)
    set_status(state="running", last_sequence=sequence, last_capture_utc=started_utc,
               last_capture_elapsed_seconds=body["elapsed_seconds"], last_error=None)
    print(json.dumps(item, sort_keys=True), flush=True)
    return item


def ensure_root():
    if os.geteuid() != 0:
        raise SystemExit("capture requires root")
    ROOT.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chmod(str(ROOT), 0o750)
    if not SIGNING_KEY.exists() or not PUBLIC_KEY.exists():
        raise RuntimeError("signing key missing; run installer first")
    if not ARCHIVE.is_dir():
        raise RuntimeError("archive missing; run installer first")
    if CODE_HASHES.exists():
        expected = json.loads(CODE_HASHES.read_text())["capture.py"]
        if sha256(Path(__file__).read_bytes()) != expected:
            raise RuntimeError("installed collector code hash mismatch")


def loop():
    ensure_root()
    while True:
        start = time.monotonic()
        try:
            capture_once()
        except Exception as exc:
            set_status(state="error", last_error=str(exc))
            print("capture error: " + str(exc), file=sys.stderr, flush=True)
        target_gap = 25 + secrets.randbelow(26)
        remaining = target_gap - (time.monotonic() - start)
        if remaining > 0:
            time.sleep(remaining)
        elif time.monotonic() - start > MAX_START_GAP_SECONDS:
            print("capture start gap exceeded 60 seconds", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["once", "loop"])
    args = parser.parse_args()
    ensure_root()
    if args.action == "once":
        capture_once()
    else:
        loop()


if __name__ == "__main__":
    main()
