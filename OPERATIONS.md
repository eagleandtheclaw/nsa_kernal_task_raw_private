# Operations log

## 2026-10-11: Public sanitized repository migration

- The original repository was renamed to the private
  `eagleandtheclaw/nsa_kernal_task_raw_private` (GitHub repository ID
  `1414404209`). Its signed original reports and Git history remain private.
- A separate repository was created at the requested public URL
  `https://github.com/eagleandtheclaw/nsa_kernal_task` (ID `1414431332`).
  Its first commit `d442896872b0c80c95da8e37a2ae7e6309739f9c` had one
  fresh root history and 40 sanitized sample files. The published compressed
  objects had zero SHA-256 overlap with the original compressed objects.
- The local source and running private publisher were repointed to the
  renamed private repository before the new public repository was created.
  The collector kept running during the change. A new root-owned login
  LaunchAgent now publishes sanitized derivatives and random heartbeats.
- Fresh clone audit passed `verify_public.py`, an identifier scan, and an
  anonymous HTTP 200 read of the repository and sample 44 with matching
  SHA-256. Both publishers and the collector passed `verify.py --all` through
  sequence 44. A later normal public commit reached sequence 45.
- Public `main` branch protection is active: normal commits are allowed;
  force pushes and branch deletion are disabled, including for administrators.
  An account administrator can change these settings, so this is an
  additional barrier rather than independent tamper proofing.
- Public derivatives preserve the private original's hashes but do not carry
  its root signature. Provenance verification still requires the private
  signed original. Full raw content is not in the public repository.
- The public repository also includes a privacy-reviewed byte-for-byte copy
  of the installed `capture.py` collector and its SHA-256 in
  `SOURCE_HASHES.json`. The exact login publisher and deployment files remain
  in the private repository because they include local account paths.

## 2026-10-11: Audio blocks automation-mode spindump

- Status: mitigated and verified live at 2026-10-11 14:21 UTC. Installed
  collector omits `-automation`; signed sequence 22 captured successfully,
  and publisher committed it to the private remote as
  `bf53c1a4cded7e58b0514851ddec5f1ff902b9d4` with no collector alert.
- Component: `/usr/sbin/spindump` invoked by
  `com.eagleandtheclaw.nsa-kernal-task.capture`.
- Exact command: `spindump 0 1 100 -onlyTarget -noBinary -automation`.
- Raw evidence: `/var/db/nsa_kernal_task/capture.stderr.log` and
  `/var/db/nsa_kernal_task/status.json` at approximately 2026-10-11
  14:19 UTC.
- Error: `spindump failed (69)` with `Unable to sample due to audio running`.
- Effect: the collector retries, but this attempt did not create a sample.
  The publisher committed the collector alert in Git commit
  `f78834af44a37d8bb3538be10d9f6e7aa4d14287`. The longest observed
  gap between successful capture starts across sequences 1 through 23 was
  218.638 seconds, including this incident and the collector restart.
- Next action: observe continued sampling and publishing across future audio
  playback, sleep, and reboot; any resulting gap remains evidence to examine.
- Test result: `sudo -n spindump 0 1 100 -onlyTarget -noBinary -o
  /Users/nick/CURSOR/SYSTEM_GEN/diagnostics/kernal_task/kernel_task_audio_test.spindump.txt`
  exited 0 and wrote a report immediately after the failure. This isolates
  the `-automation` option as the distinguishing setting in this session.
- Verification: `/usr/bin/python3 verify.py --all` passed the signed archive
  through sequence 22, both running launchd jobs, the Login Item signature,
  publisher state, and remote main. The report for sequence 22 records the
  installed command without `-automation` and has compressed SHA-256
  `1ab2dfc0e78339c890aae7b142d9474062d66c0c177fd8c6b78762acb726f072`.
