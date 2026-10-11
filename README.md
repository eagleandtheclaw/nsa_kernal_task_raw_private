# nsa_kernal_task

Boot-time `kernel_task` stack capture and private GitHub replication for the Mac
running Darwin 27.2.0. The requested repository name retains `kernal`; the
macOS process is `kernel_task` (PID 0).

## Operation

- A root LaunchDaemon starts at boot. It uses `spindump 0 -onlyTarget` for
  one second at 100 ms intervals. A cryptographically random delay targets
  capture starts 25 to 50 seconds apart. Processing delays, sleep, a stalled
  operating system, or a crashed collector can create longer gaps. Gaps are
  recorded and must be reviewed; this is no hard real-time guarantee.
- The collector retains the complete PID 0 report, computes SHA-256 for it
  and its `kernel_task` process section, signs a canonical JSON record with a
  root-only Ed25519 key, compresses it with xz, and appends its hash to a
  chained manifest. Other processes are excluded at acquisition.
- Root owns `/var/db/nsa_kernal_task`. The capture archive is readable by
  the `staff` group and writable only by root. The signing key is root-only.
- A root-owned LaunchAgent starts in the user's login session. A separate
  classic Login Item appears as `NSA Kernel Task Monitor` and restarts the
  publisher at login. The publisher verifies every pending signature,
  hash, and sequence link, then commits compressed samples to the private
  `eagleandtheclaw/nsa_kernal_task` repository. Its next attempt uses a
  cryptographically random 3 to 6 minute delay. A new heartbeat commit is
  created even when there is no new sample. Failed attempts retry after a
  random 30 to 60 seconds.
- GitHub credentials remain in the existing user's keyring. The boot daemon
  has no GitHub credential. Remote commits require a logged-in user session,
  working network, and valid GitHub authentication.

## Evidence and limitations

The signed record contains the complete PID 0 report and hashes of both
that report and its extracted `kernel_task` section. Both hashes can be
rechecked later, together with the Ed25519 signature. A SHA-256
chain detects modification of retained records when compared with a previously
published head. Neither local root ownership nor a private GitHub repository
is tamper-proof against an adversary with root access and control of the same
GitHub account. Independent external monitoring and account separation would
be needed for stronger assurance. `kernel_task` stacks alone do not establish
attribution or capture every userspace action.

The targeted benchmark on this host produced a 190.9 KB report with ten
stack samples; xz preset 6 compressed it to 24.6 KB. Continuous capture has
ongoing CPU and disk cost. The
archive and Git history grow until a separate, evidence-aware retention
policy is adopted.

On 2026-10-11, GitHub rejected a private-branch protection request with HTTP
403: `Upgrade to GitHub Pro or make this repository public to enable this
feature.` The repository remains private. Force-push and branch-deletion
protection are not active. The initial bootstrap heartbeat reported a missing
sample before the first capture completed; an upgrade later flagged captures
from the previous approved collector version. Current code tracks that
version history, and subsequent heartbeats have no active collector alert.

## Verify

Check both launchd jobs, their status files, the signed archive, and the
remote commit. A saved plist alone does not establish that either job ran.
The installer and verification commands are in `install.sh` and `verify.py`.
