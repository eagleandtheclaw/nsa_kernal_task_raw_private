# Operations log

## 2026-10-11: Audio blocks automation-mode spindump

- Status: reproduction succeeded without `-automation`; installation and
  recurrence check pending.
- Component: `/usr/sbin/spindump` invoked by
  `com.eagleandtheclaw.nsa-kernal-task.capture`.
- Exact command: `spindump 0 1 100 -onlyTarget -noBinary -automation`.
- Raw evidence: `/var/db/nsa_kernal_task/capture.stderr.log` and
  `/var/db/nsa_kernal_task/status.json` at approximately 2026-10-11
  14:19 UTC.
- Error: `spindump failed (69)` with `Unable to sample due to audio running`.
- Effect: the collector retries, but this attempt did not create a sample.
  The publisher committed the collector alert in Git commit
  `f78834af44a37d8bb3538be10d9f6e7aa4d14287`.
- Next action: test targeted PID 0 sampling without `-automation` while audio
  is running, then update the installed collector if it succeeds.
- Test result: `sudo -n spindump 0 1 100 -onlyTarget -noBinary -o
  /Users/nick/CURSOR/SYSTEM_GEN/diagnostics/kernal_task/kernel_task_audio_test.spindump.txt`
  exited 0 and wrote a report immediately after the failure. This isolates
  the `-automation` option as the distinguishing setting in this session.
