#!/usr/bin/python3
"""Verify signed local captures, launchd state, and the remote head."""

import argparse
import datetime as dt
import json
import os
import subprocess
import sys

import publisher


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
    for path in selected:
        record, compressed = publisher.read_sample(path)
        body = record["body"]
        if previous is not None and body["previous_body_sha256"] != previous:
            raise SystemExit("FAIL: local chain break at " + path.name)
        previous = record["body_sha256"]
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
    if failures:
        for failure in failures:
            print("FAIL", failure, file=sys.stderr)
        raise SystemExit(1)
    print("PASS capture, services, publisher, and remote")


if __name__ == "__main__":
    main()
