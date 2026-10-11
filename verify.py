#!/usr/bin/python3
"""Verify signed local captures, launchd state, and the remote head."""

import argparse
import datetime as dt
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys

import publisher
import public_export


def command(argv):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout.decode(errors="replace").strip(), result.stderr.decode(errors="replace").strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="verify every local archive sample")
    args = parser.parse_args()
    failures = []
    paths = sorted(publisher.ARCHIVE.glob("*.json.xz"))
    if not paths:
        raise SystemExit("FAIL: no archived samples")
    selected = paths if args.all else paths[-1:]
    previous = None
    prior_sequence = None
    for path in selected:
        record, compressed = publisher.read_sample(path)
        body = record["body"]
        if previous is not None and body["previous_body_sha256"] != previous:
            raise SystemExit("FAIL: local chain break at " + path.name)
        if prior_sequence is not None and body["sequence"] != prior_sequence + 1:
            raise SystemExit("FAIL: local sequence gap at " + path.name)
        previous = record["body_sha256"]
        prior_sequence = body["sequence"]
        print("PASS sample", path.name, "sequence", body["sequence"],
              "sha256", publisher.sha256(compressed))
    latest_record, _ = publisher.read_sample(paths[-1])
    last_capture = dt.datetime.fromisoformat(latest_record["body"]["capture_started_utc"])
    capture_age = (dt.datetime.now(dt.timezone.utc) - last_capture).total_seconds()
    if capture_age > 90:
        failures.append("latest capture is %.0f seconds old" % capture_age)
    for domain, label in [
        ("system", "com.eagleandtheclaw.nsa-kernal-task.capture"),
        ("gui/%d" % os.getuid(), "com.eagleandtheclaw.nsa-kernal-task.publish"),
        ("gui/%d" % os.getuid(), "com.eagleandtheclaw.nsa-kernal-task.public"),
    ]:
        rc, output, error = command(["/bin/launchctl", "print", domain + "/" + label])
        if rc:
            failures.append("launchd %s: %s" % (label, error))
        else:
            if "state = running" not in output:
                failures.append("launchd %s loaded but not running" % label)
            else:
                print("PASS launchd", label, "running")
    rc, output, error = command(["/usr/bin/osascript", "-e",
        'tell application "System Events" to exists login item "NSA Kernel Task Monitor"'])
    if rc or output != "true":
        failures.append("classic Login Item missing: " + (error or output))
    else:
        print("PASS classic Login Item NSA Kernel Task Monitor")
    rc, _, error = command(["/usr/bin/codesign", "--verify", "/Applications/NSA Kernel Task Monitor.app"])
    if rc:
        failures.append("Login Item code signature: " + error)
    else:
        print("PASS Login Item code signature")
    rc, output, error = command([publisher.GIT, "ls-remote", publisher.EXPECTED_REMOTE, "refs/heads/main"])
    if rc:
        failures.append("remote: " + error)
    else:
        remote = output.split()[0] if output else "missing"
        print("remote main", remote)
        rc, local, error = command([publisher.GIT, "-C", str(publisher.REPO), "rev-parse", "HEAD"])
        if rc or local != remote:
            failures.append("runtime clone and remote main differ")
    state = publisher.STATE
    if state.exists():
        value = json.loads(state.read_text())
        print("publisher state", json.dumps(value, sort_keys=True))
        published_at = dt.datetime.fromisoformat(value["updated_at_utc"])
        age = (dt.datetime.now(dt.timezone.utc) - published_at).total_seconds()
        if value.get("state") != "published" or age > 780 or value.get("collector_alert"):
            failures.append("publisher state stale, failed, or alerting")
    else:
        failures.append("publisher state missing")
    public_head = public_export.REPO / "PUBLIC_CHAIN_HEAD.json"
    if not public_head.exists():
        failures.append("public chain head missing")
    else:
        try:
            head = json.loads(public_head.read_text())
            public_paths = sorted((public_export.REPO / "samples").glob("*/*.json.xz"))
            if len(public_paths) != head["sequence"]:
                raise RuntimeError("public sample count differs from chain head")
            selected_public = public_paths if args.all else public_paths[-1:]
            previous_public = "0" * 64
            for path in selected_public:
                stored = json.loads(lzma.decompress(path.read_bytes()))
                body = stored["body"]
                if not args.all:
                    previous_public = body["previous_public_body_sha256"]
                if body["sequence"] != int(path.name.split("_", 1)[0]):
                    raise RuntimeError("public sample sequence mismatch")
                source = publisher.ARCHIVE / path.name
                expected_body, expected_hash, expected_packed = public_export.build_public_record(source, previous_public)
                if body != expected_body or stored["body_sha256"] != expected_hash or path.read_bytes() != expected_packed:
                    raise RuntimeError("public derivative or hash mismatch at " + path.name)
                previous_public = expected_hash
            if selected_public and previous_public != head["body_sha256"]:
                raise RuntimeError("public chain head hash mismatch")
            print("PASS public sanitized chain through sequence", head["sequence"])
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            failures.append("public sample verification: " + str(exc))
    rc, output, error = command([publisher.GIT, "ls-remote", public_export.REMOTE, "refs/heads/main"])
    if rc:
        failures.append("public remote: " + error)
    else:
        public_remote = output.split()[0] if output else "missing"
        rc, local, error = command([publisher.GIT, "-C", str(public_export.REPO), "rev-parse", "HEAD"])
        if rc or local != public_remote:
            failures.append("public clone and remote main differ")
        else:
            print("PASS public remote main", public_remote)
    if public_export.STATE.exists():
        value = json.loads(public_export.STATE.read_text())
        age = (dt.datetime.now(dt.timezone.utc) -
               dt.datetime.fromisoformat(value["updated_at_utc"])).total_seconds()
        if value.get("state") != "published" or age > 780:
            failures.append("public exporter state stale or failed")
        else:
            print("PASS public exporter state", value["commit"])
    else:
        failures.append("public exporter state missing")
    if failures:
        for failure in failures:
            print("FAIL", failure, file=sys.stderr)
        raise SystemExit(1)
    print("PASS capture, services, publisher, and remote")


if __name__ == "__main__":
    main()
