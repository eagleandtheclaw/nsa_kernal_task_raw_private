# nsa_kernal_task

Boot-time `kernel_task` stack capture and private GitHub replication for the Mac
running Darwin 27.2.0. The requested repository name retains `kernal`; the
macOS process is `kernel_task` (PID 0).

## Operation

- A root LaunchDaemon starts at boot. It uses the system `spindump` tool for
  one second at 100 ms intervals. A cryptographically random delay targets
  capture starts 25 to 50 seconds apart. Processing delays, sleep, a stalled
  operating system, or a crashed collector can create longer gaps. Gaps are
  recorded and must be reviewed; this is no hard real-time guarantee.
- The collector extracts the full `kernel_task` process section, computes
  SHA-256 for the temporary full report and the extracted section, signs a
  canonical JSON record with a root-only Ed25519 key, compresses it with xz,
  and appends its hash to a chained manifest. The full system report is then
  discarded to limit storage and unrelated process exposure.
- Root owns `/var/db/nsa_kernal_task`. The capture archive is readable by
  the `staff` group and writable only by root. The signing key is root-only.
- A user LaunchAgent starts on login. It verifies every pending signature,
  hash, and sequence link, then commits compressed samples to the private
  `eagleandtheclaw/nsa_kernal_task` repository. Its next attempt uses a
  cryptographically random 3 to 10 minute delay. A new heartbeat commit is
  created even when there is no new sample. Failed attempts retry after a
  random 30 to 60 seconds.
- GitHub credentials remain in the existing user's keyring. The boot daemon
  has no GitHub credential. Remote commits require a logged-in user session,
  working network, and valid GitHub authentication.

## Evidence and limitations

The signed record contains exact `kernel_task` stack text and hashes of both
the original temporary report and extracted section. The original full
report is not retained, so its hash cannot be rechecked later. The extracted
section can be rechecked against its hash and Ed25519 signature. A SHA-256
chain detects modification of retained records when compared with a previously
published head. Neither local root ownership nor a private GitHub repository
is tamper-proof against an adversary with root access and control of the same
GitHub account. Independent external monitoring and account separation would
be needed for stronger assurance. `kernel_task` stacks alone do not establish
attribution or capture every userspace action.

The benchmark on this host produced a 4.6 MB full-system report in 11.62
seconds. A prior full `kernel_task` section of 226.9 KB compressed to 29 KB
with xz preset 6. Continuous capture has ongoing CPU and disk cost. The
archive and Git history grow until a separate, evidence-aware retention
policy is adopted.

## Verify

Check both launchd jobs, their status files, the signed archive, and the
remote commit. A saved plist alone does not establish that either job ran.
The installer and verification commands are in `install.sh` and `verify.py`.
