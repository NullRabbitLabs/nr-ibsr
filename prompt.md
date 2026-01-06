Update the existing `ibsr` single-binary tool to address the following issues observed on Debian:

Observed problems:
- Reporter processed stale snapshots from previous runs (snapshots processed > collection cycles, duration mismatch).
- Output files overwrite and accumulate data in the same directory.
- `rules.json` output is invalid JSON (missing closing brace / incomplete write).
- `evidence.csv` is missing newline at EOF (output glued to shell prompt).
- SYN flood test (nmap synflood) did not trigger offenders; current `success_ratio` metric is wrong because ACK count includes established-session ACKs, producing impossible ratios (>1).
- CLI lacks `-v/--verbose` logging.
- Collection being duration-only is disliked; prefer continuous with optional duration.
- Need status reporting interval (“it’s running…” messages).
- Need to monitor multiple destination ports (“a couple of ports”).

Hard constraints:
- Tests-first: **ALL tests written before implementation**; no function without a test.
- 100% coverage enforced.
- macOS dev; tests run via docker-compose (unit tests default non-privileged; integration tests in separate privileged compose file if needed).
- Collector remains passive: never drop/redirect/copy packets; no payload inspection beyond deriving header lengths.
- Guard in `../nr-guard` must not be edited and is not used at runtime.

Implement the following changes:

1) Timestamped run directories (no overwrite, no stale snapshots)
- `ibsr run` must create a unique run directory inside `--out-dir`, e.g. `--out-dir ./output` creates `./output/ibsr-YYYYMMDD-HHMMSSZ/`.
- All artifacts must be written inside that run dir:
  - `snapshots/` (or equivalent)
  - `report.md`, `rules.json`, `evidence.csv`
- Reporter must only read snapshots from the run dir created in this invocation (no mixing).
- Add tests that prove:
  - new run dir is created and unique
  - files are written into that directory
  - reporter reads only those snapshots
  - no overwrite of previous runs

2) JSON/CSV correctness
- Fix `rules.json` writing: always write complete, valid JSON with closing braces and newline at EOF.
- Fix `evidence.csv`: always newline-terminate each row and newline at EOF.
- Add tests:
  - rules.json parses as JSON (strict parser)
  - evidence.csv ends with newline and has correct column count

3) Collection mode: continuous by default, optional duration
- `ibsr collect` and `ibsr run`:
  - default: run until SIGINT/Ctrl+C
  - optional: `--duration-sec` stops automatically after N seconds
- Add tests for:
  - duration specified stops
  - no duration => continues (test via mocked clock + cancellation token, not real sleep)

4) Verbose logging + status reporting interval
- Add `-v/--verbose` and `-vv`:
  - default: minimal output
  - -v: show config summary + per-report-interval status line
  - -vv: include internal counters, snapshot counts, matched packet/syn totals
- Add `--report-interval-sec` (default 60):
  - prints “still running” status (elapsed, snapshots written, matched packets/syn, unique keys, top talkers)
  - ensure this does not require root or kernel in unit tests; use mocks.
- Add tests for deterministic logging output given mocked clock and mocked counters.

5) Monitor multiple destination ports
- Replace single `--dst-port` with one of:
  - `--dst-ports 22,8899` (comma-separated) OR allow repeatable `--dst-port`.
- Limit to a small bounded set (e.g. max 8) to keep XDP bounded.
- XDP filter must match if dest port is in the configured set.
- Snapshot output must not mix ports incorrectly:
  - Either write separate snapshot streams per port (recommended), OR include dst_port per BucketEntry.
- Add tests:
  - parsing `--dst-ports`
  - enforcing max ports
  - snapshot schema reflects correct port association
  - reporter handles multi-port snapshots deterministically

6) Fix SYN-flood detection metric (handshake approximation)
- Current `success_ratio = total_ack / total_syn` is invalid because it counts established ACKs.
- Replace ack counting with “handshake ACK” approximation:
  - count ACK packets where:
    - ACK set
    - SYN not set
    - RST not set
    - payload length == 0 (derive from IP total length - IP header - TCP header)
- Define `handshake_success_ratio = handshake_ack / max(syn, 1)`.
- Use this in trigger condition instead of total_ack.
- Add tests using synthetic packet events/counters showing:
  - established ACK traffic does not inflate handshake_ack
  - synflood (many SYN, few handshake_ack) triggers offenders
  - legitimate traffic (SYN with handshake_ack) does not trigger

7) Interface detection visibility
- Ensure logs show:
  - selected interface name
  - attach mode (native/generic)
  - confirmation that XDP attached successfully
  - matched packet/syn totals increasing during collection
- Add tests around interface selection logic (mock routing table or mock detector) and logging output.

Testing rules (strict):
- Write all tests first for each change above.
- Any new function must be covered by at least one test.
- Use mocks for filesystem/clock/bpf-map access/CLI output.
- Unit tests must not require privileged BPF.
- Integration tests requiring attach/load BPF go into a separate `docker-compose.integration.yml`.

Deliverable:
- Updated code passing all tests and 100% coverage, with deterministic outputs and improved operator UX.
