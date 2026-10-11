#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")" && pwd)"
SYSTEM_DIR="/Library/Application Support/nsa_kernal_task"
DATA_DIR="/var/db/nsa_kernal_task"
DAEMON_LABEL="com.eagleandtheclaw.nsa-kernal-task.capture"
AGENT_LABEL="com.eagleandtheclaw.nsa-kernal-task.publish"
DAEMON_PLIST="/Library/LaunchDaemons/${DAEMON_LABEL}.plist"
AGENT_PLIST="/Users/nick/Library/LaunchAgents/${AGENT_LABEL}.plist"
RUNTIME_REPO="/Users/nick/Library/Application Support/nsa_kernal_task/repo"

[[ "$(id -un)" == "nick" ]] || { echo "Run installer as nick." >&2; exit 1; }
[[ "$(/opt/homebrew/bin/gh api user --jq .login)" == "eagleandtheclaw" ]] || { echo "GitHub account mismatch." >&2; exit 1; }
[[ "$(/opt/homebrew/bin/gh repo view eagleandtheclaw/nsa_kernal_task --json visibility --jq .visibility)" == "PRIVATE" ]] || { echo "GitHub repository must be private." >&2; exit 1; }
/usr/bin/plutil -lint "$PROJECT/launchd/${DAEMON_LABEL}.plist" "$PROJECT/launchd/${AGENT_LABEL}.plist"
/usr/bin/python3 -m py_compile "$PROJECT/capture.py" "$PROJECT/publisher.py" "$PROJECT/verify.py"
sudo -n true

sudo -n /usr/bin/install -d -o root -g staff -m 0750 "$DATA_DIR" "$DATA_DIR/archive"
if [[ ! -f "$DATA_DIR/signing_key" ]]; then
  sudo -n /usr/bin/ssh-keygen -q -t ed25519 -N '' -C nsa_kernal_task_collector -f "$DATA_DIR/signing_key"
fi
sudo -n /usr/sbin/chown root:wheel "$DATA_DIR/signing_key" "$DATA_DIR/signing_key.pub"
sudo -n /bin/chmod 0600 "$DATA_DIR/signing_key"
sudo -n /bin/chmod 0644 "$DATA_DIR/signing_key.pub"
sudo -n /usr/bin/install -d -o root -g wheel -m 0755 "$SYSTEM_DIR"
sudo -n /usr/bin/install -o root -g wheel -m 0755 "$PROJECT/capture.py" "$SYSTEM_DIR/capture.py"
sudo -n /usr/bin/install -o root -g wheel -m 0755 "$PROJECT/publisher.py" "$SYSTEM_DIR/publisher.py"
PROJECT_PATH="$PROJECT" /usr/bin/python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
project = Path(os.environ["PROJECT_PATH"])
hashes = {name: hashlib.sha256((project / name).read_bytes()).hexdigest()
          for name in ("capture.py", "publisher.py")}
(project / "CODE_HASHES.json").write_text(json.dumps(hashes, sort_keys=True) + "\n")
PY
sudo -n /usr/bin/install -o root -g wheel -m 0644 "$PROJECT/CODE_HASHES.json" "$SYSTEM_DIR/CODE_HASHES.json"
sudo -n /usr/bin/install -o root -g wheel -m 0644 "$PROJECT/launchd/${DAEMON_LABEL}.plist" "$DAEMON_PLIST"
/usr/bin/install -m 0644 "$PROJECT/launchd/${AGENT_LABEL}.plist" "$AGENT_PLIST"

sudo -n /bin/cat "$DATA_DIR/signing_key.pub" > "$PROJECT/collector.pub"
if ! /usr/bin/git -C "$PROJECT" diff --quiet -- collector.pub CODE_HASHES.json || [[ -n "$(/usr/bin/git -C "$PROJECT" ls-files --others --exclude-standard collector.pub CODE_HASHES.json)" ]]; then
  /usr/bin/git -C "$PROJECT" add collector.pub CODE_HASHES.json
  /usr/bin/git -C "$PROJECT" -c user.name=eagleandtheclaw -c user.email=318743460+eagleandtheclaw@users.noreply.github.com commit -m "Publish collector verification key"
  pushed=0
  for attempt in 1 2 3; do
    /usr/bin/git -C "$PROJECT" fetch origin main
    /usr/bin/git -C "$PROJECT" rebase origin/main
    if /usr/bin/git -C "$PROJECT" push origin main; then
      pushed=1
      break
    fi
  done
  [[ "$pushed" == 1 ]] || { echo "Failed to publish verification key after three attempts." >&2; exit 1; }
fi

/opt/homebrew/bin/gh auth setup-git
/bin/mkdir -p "/Users/nick/Library/Application Support/nsa_kernal_task" "/Users/nick/Library/Logs/nsa_kernal_task"
if [[ ! -d "$RUNTIME_REPO/.git" ]]; then
  /usr/bin/git clone --depth 1 "https://github.com/eagleandtheclaw/nsa_kernal_task.git" "$RUNTIME_REPO"
fi
sudo -n /usr/sbin/chown root:staff "$DATA_DIR" "$DATA_DIR/archive"
sudo -n /bin/chmod 0750 "$DATA_DIR" "$DATA_DIR/archive"

if sudo -n /bin/launchctl print "system/$DAEMON_LABEL" >/dev/null 2>&1; then
  sudo -n /bin/launchctl bootout "system/$DAEMON_LABEL"
fi
sudo -n /bin/launchctl bootstrap system "$DAEMON_PLIST"
sudo -n /bin/launchctl kickstart -k "system/$DAEMON_LABEL"
if /bin/launchctl print "gui/$(id -u)/$AGENT_LABEL" >/dev/null 2>&1; then
  /bin/launchctl bootout "gui/$(id -u)/$AGENT_LABEL"
fi
/bin/launchctl bootstrap "gui/$(id -u)" "$AGENT_PLIST"
/bin/launchctl kickstart -k "gui/$(id -u)/$AGENT_LABEL"
echo "Installed capture daemon and login publisher. Verify live status with:"
echo "/usr/bin/python3 '$PROJECT/verify.py'"
