#!/usr/bin/python3
"""Login-session publisher for signed kernel_task captures."""

import argparse
import datetime as dt
import hashlib
import json
import lzma
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

import capture


ROOT = Path(os.environ.get("NSA_KERNEL_ROOT", "/var/db/nsa_kernal_task"))
ARCHIVE = ROOT / "archive"
PUBLIC_KEY = ROOT / "signing_key.pub"
COLLECTOR_STATUS = ROOT / "status.json"
REPO = Path(os.environ.get("NSA_KERNEL_REPO", "/Users/nick/Library/Application Support/nsa_kernal_task/repo"))
STATE = Path(os.environ.get("NSA_KERNEL_PUBLISHER_STATE", "/Users/nick/Library/Application Support/nsa_kernal_task/publisher-status.json"))
SSH_KEYGEN = "/usr/bin/ssh-keygen"
GIT = "/usr/bin/git"
GH = "/opt/homebrew/bin/gh"
NAMESPACE = "nsa_kernal_task"
EXPECTED_LOGIN = "eagleandtheclaw"
EXPECTED_REMOTE = "https://github.com/eagleandtheclaw/nsa_kernal_task_raw_private.git"
INSTALLED = Path("/Library/Application Support/nsa_kernal_task")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def run(command, cwd=None, timeout=60):
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1", "GIT_CONFIG_NOSYSTEM": "0"})
    result = subprocess.run(command, cwd=str(cwd) if cwd else None, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError("%s failed (%d): %s" % (command[0], result.returncode,
                           result.stderr.decode(errors="replace").strip()))
    return result.stdout.decode("utf-8", errors="replace").strip()


def verify_signature(body_bytes, signature):
    key = PUBLIC_KEY.read_text().strip()
    if not key.startswith("ssh-ed25519 "):
        raise RuntimeError("unexpected collector public key type")
    with tempfile.TemporaryDirectory(prefix="nsa-verify-") as directory:
        allowed = Path(directory) / "allowed_signers"
        sig_file = Path(directory) / "record.sig"
        allowed.write_text(NAMESPACE + " " + key + "\n")
        sig_file.write_text(signature)
        result = subprocess.run([SSH_KEYGEN, "-Y", "verify", "-f", str(allowed),
                                 "-I", NAMESPACE, "-n", NAMESPACE, "-s", str(sig_file)],
                                input=body_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15)
        if result.returncode:
            raise RuntimeError("sample signature verification failed: " + result.stderr.decode(errors="replace"))


def read_sample(path):
    compressed = path.read_bytes()
    if len(compressed) > 2_000_000:
        raise RuntimeError("sample exceeds 2 MB compressed limit: " + path.name)
    data = lzma.decompress(compressed)
    if len(data) > 10_000_000:
        raise RuntimeError("sample exceeds 10 MB decoded limit: " + path.name)
    record = json.loads(data)
    body = record["body"]
    body_bytes = canonical(body)
    if sha256(body_bytes) != record["body_sha256"]:
        raise RuntimeError("sample body hash mismatch: " + path.name)
    if body.get("schema") == 2:
        report = body["raw_target_report"].encode("utf-8")
        if sha256(report) != body["raw_target_report_sha256"]:
            raise RuntimeError("raw target report hash mismatch: " + path.name)
        section, count, _, _ = capture.extract_kernel_task(report)
        if count != body["kernel_task_num_samples"]:
            raise RuntimeError("kernel_task sample count mismatch: " + path.name)
        if report.count(b"\nProcess:") != 1:
            raise RuntimeError("target report includes another process: " + path.name)
    else:
        section = body["kernel_task_section"]
    if sha256(section.encode("utf-8")) != body["kernel_task_section_sha256"]:
        raise RuntimeError("kernel_task section hash mismatch: " + path.name)
    if body["kernel_task_pid"] != 0 or "Process:          kernel_task [0]" not in section:
        raise RuntimeError("sample does not contain kernel_task [0]: " + path.name)
    verify_signature(body_bytes, record["signature"])
    return record, compressed


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp." + secrets.token_hex(4))
    temp.write_bytes(canonical(obj) + b"\n")
    os.replace(str(temp), str(path))


def publish_once():
    if os.geteuid() == 0:
        raise RuntimeError("publisher must run as the authenticated user, not root")
    account = run([GH, "api", "user", "--jq", ".login"], timeout=30)
    if account != EXPECTED_LOGIN:
        raise RuntimeError("GitHub account mismatch: " + account)
    if run([GIT, "remote", "get-url", "origin"], cwd=REPO) != EXPECTED_REMOTE:
        raise RuntimeError("repository remote mismatch")
    run([GIT, "fetch", "origin", "main"], cwd=REPO, timeout=90)
    run([GIT, "merge", "--ff-only", "origin/main"], cwd=REPO, timeout=30)
    expected_code = json.loads((REPO / "CODE_HASHES.json").read_text())
    code_alerts = []
    for filename in ("capture.py", "publisher.py"):
        actual_hash = sha256((INSTALLED / filename).read_bytes())
        if actual_hash != expected_code[filename]:
            code_alerts.append("installed %s hash mismatch" % filename)
    chain_path = REPO / "CHAIN_HEAD.json"
    chain = json.loads(chain_path.read_text()) if chain_path.exists() else {"sequence": 0, "body_sha256": "0" * 64}
    sequence = chain["sequence"]
    previous = chain["body_sha256"]
    if sequence:
        head_paths = list((REPO / "samples").glob("*/%08d_*.json.xz" % sequence))
        if len(head_paths) != 1:
            raise RuntimeError("published chain head sample missing or duplicated")
        head_record, _ = read_sample(head_paths[0])
        if head_record["body"]["sequence"] != sequence or head_record["body_sha256"] != previous:
            raise RuntimeError("published chain head does not match signed sample")
    elif previous != "0" * 64:
        raise RuntimeError("zero-sequence chain head has nonzero hash")
    count = 0
    paths = sorted(ARCHIVE.glob("*.json.xz"))
    for path in paths:
        prefix = int(path.name.split("_", 1)[0])
        if prefix <= sequence:
            continue
        if prefix != sequence + 1:
            raise RuntimeError("sample sequence gap: expected %d, found %d" % (sequence + 1, prefix))
        record, compressed = read_sample(path)
        body = record["body"]
        allowed_collector_hashes = expected_code.get("capture_history", [expected_code["capture.py"]])
        if body.get("collector_code_sha256") not in allowed_collector_hashes:
            code_alerts.append("sample %d collector code hash mismatch" % prefix)
        if body["sequence"] != prefix or body["previous_body_sha256"] != previous:
            raise RuntimeError("sample chain mismatch: " + path.name)
        date = body["capture_started_utc"][:10]
        destination = REPO / "samples" / date / path.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(compressed)
        sequence = prefix
        previous = record["body_sha256"]
        count += 1
    write_json(chain_path, {"sequence": sequence, "body_sha256": previous, "updated_at_utc": utc_now()})
    collector = json.loads(COLLECTOR_STATUS.read_text()) if COLLECTOR_STATUS.exists() else {}
    last_capture = collector.get("last_capture_utc")
    age_seconds = None
    if last_capture:
        age_seconds = max(0, int((dt.datetime.now(dt.timezone.utc) -
                                  dt.datetime.fromisoformat(last_capture)).total_seconds()))
    alert = None
    if collector.get("state") == "error":
        alert = "collector error: " + str(collector.get("last_error"))
    elif age_seconds is None or age_seconds > 90:
        alert = "collector sample gap exceeds 90 seconds"
    if code_alerts:
        alert = (alert + "; " if alert else "") + "; ".join(code_alerts)
    heartbeat = REPO / "HEARTBEAT.json"
    write_json(heartbeat, {"committed_at_utc": utc_now(), "last_sequence": sequence,
                           "samples_in_commit": count, "last_capture_age_seconds": age_seconds,
                           "collector_alert": alert, "nonce": secrets.token_hex(16)})
    run([GIT, "add", "CHAIN_HEAD.json", "HEARTBEAT.json", "samples"], cwd=REPO)
    run([GIT, "-c", "user.name=eagleandtheclaw",
         "-c", "user.email=318743460+eagleandtheclaw@users.noreply.github.com",
         "commit", "-m", "Capture kernel_task through sequence %d" % sequence], cwd=REPO)
    commit = run([GIT, "rev-parse", "HEAD"], cwd=REPO)
    run([GIT, "push", "origin", "HEAD:main"], cwd=REPO, timeout=120)
    remote = run([GIT, "ls-remote", "origin", "refs/heads/main"], cwd=REPO, timeout=45).split()[0]
    if remote != commit:
        raise RuntimeError("remote main does not match local commit after push")
    status = {"state": "published", "updated_at_utc": utc_now(), "commit": commit,
              "last_sequence": sequence, "samples_in_commit": count, "collector_alert": alert}
    write_json(STATE, status)
    print(json.dumps(status, sort_keys=True), flush=True)
    return status


def loop():
    while True:
        start = time.monotonic()
        try:
            publish_once()
            delay = 180 + secrets.randbelow(181)
        except Exception as exc:
            message = {"state": "error", "updated_at_utc": utc_now(), "error": str(exc)}
            write_json(STATE, message)
            print("publisher error: " + str(exc), file=sys.stderr, flush=True)
            delay = 30 + secrets.randbelow(31)
        remaining = delay - (time.monotonic() - start)
        if remaining > 0:
            time.sleep(remaining)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["once", "loop"])
    args = parser.parse_args()
    if args.action == "once":
        publish_once()
    else:
        loop()


if __name__ == "__main__":
    main()
