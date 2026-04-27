# Lab 12 - Kata Containers

## Scope
- Date: `2026-04-27`
- Environment: `Ubuntu 24.04 on WSL2`
- Work folder: `labs/lab12`

I saved all logs in `labs/lab12` subfolders: `setup`, `runc`, `kata`, `isolation`, `bench`, `analysis`.

## Task 1 - Install and configure Kata

### 1.1 Install Kata
- Installed Kata assets with `labs/lab12/scripts/install-kata-assets.sh`.
- Verified shim:
  - `labs/lab12/setup/kata-shim-command-path.txt`
  - `labs/lab12/setup/kata-built-version.txt`
- Verified runtime config link:
  - `labs/lab12/setup/kata-config-link.txt`

### 1.2 Configure containerd + nerdctl
- Added Kata runtime (`io.containerd.kata.v2`) in containerd config.
- Evidence:
  - `labs/lab12/setup/containerd-kata-config-snippet.txt`
  - `labs/lab12/setup/containerd-active-after-kata.txt`

### 1.3 Test Kata run
- Ran test container with Kata runtime.
- Evidence:
  - `labs/lab12/setup/kata-test-uname.txt`

Task 1 completed.

## Task 2 - Compare runc and kata

### 2.1 Start runc container (Juice Shop)
- Started `juice-runc` on port `3012`.
- Evidence:
  - `labs/lab12/runc/juice-runc-container-id.txt`
  - `labs/lab12/runc/nerdctl-ps.txt`
  - `labs/lab12/runc/nerdctl-ps-a.txt`
  - `labs/lab12/runc/health.txt`
  - `labs/lab12/runc/health-raw.txt`

### 2.2 Run Kata test containers
- Ran short Alpine commands with `--runtime io.containerd.kata.v2`.
- Evidence:
  - `labs/lab12/kata/test1.txt`
  - `labs/lab12/kata/kernel.txt`
  - `labs/lab12/kata/cpu.txt`

### 2.3 Kernel comparison
- Evidence: `labs/lab12/analysis/kernel-comparison.txt`
- Host kernel (runc): `6.6.87.2-microsoft-standard-WSL2`
- Kata guest kernel: `6.18.15`

### 2.4 CPU comparison
- Evidence: `labs/lab12/analysis/cpu-comparison.txt`

In my run, CPU model text looks similar for host and Kata. Better proof is different kernel version and Kata boot logs.
So, `runc` shares host kernel, and `kata` runs container inside a small VM with its own kernel.

Task 2 completed.

## Task 3 - Isolation tests

### 3.1 dmesg test
- Evidence: `labs/lab12/isolation/dmesg.txt`
- Kata output shows guest boot logs.

### 3.2 /proc visibility
- Evidence: `labs/lab12/isolation/proc.txt`
- Host `/proc` entries: `90`
- Kata `/proc` entries: `54`

### 3.3 Network interfaces
- Evidence: `labs/lab12/isolation/network.txt`
- Kata guest has own interface list (`lo`, `eth0`).

### 3.4 Kernel modules
- Evidence: `labs/lab12/isolation/modules.txt`
- Host modules: `202`
- Kata guest modules: `76`

Security implication:
- Escape from `runc` can affect host kernel directly.
- Escape from `kata` first affects guest VM, then attacker still needs VM escape.

Task 3 completed.

## Task 4 - Performance snapshot

### 4.1 Startup time
- Evidence: `labs/lab12/bench/startup.txt`
- runc: `1.102s`
- kata: `7.824s`
- In this environment, startup numbers are higher than the example values in task text (`<1s` and `3-5s`).

### 4.2 HTTP latency (juice-runc)
- Evidence:
  - `labs/lab12/bench/curl-3012.txt`
  - `labs/lab12/bench/http-latency.txt`
- Result:
  - `avg=0.0031s min=0.0024s max=0.0061s n=50`

Performance notes:
- Startup overhead is clearly higher for Kata in my test.
- I also measured simple runtime overhead with the same short command loop:
  - evidence: `labs/lab12/bench/runtime-overhead.txt`
  - runc samples are around `829-1091 ms`
  - kata samples are around `2133-7807 ms`
- I added a CPU time snapshot with same command pattern:
  - evidence: `labs/lab12/bench/cpu-overhead.txt`
  - this is a lightweight check, not a full benchmark
- Trade-off is simple: runc is faster, kata gives stronger isolation.

When to use:
- I would use `runc` when startup speed is important and workload is trusted.
- I would use `kata` when stronger isolation is needed, especially for multi-tenant risk.

Task 4 completed.

## Notes about known issue
- In this lab setup, detached long-running Kata container (`juice-kata`) hits known `nerdctl + kata runtime-rs` issue from assignment notes.
- Because of that, I validated Kata runtime with short-lived containers using `--runtime io.containerd.kata.v2` (`setup/kata-test-uname.txt`, `kata/test1.txt`, `kata/kernel.txt`, `kata/cpu.txt`).

## Acceptance Criteria Mapping
- Kata shim installed and verified: `labs/lab12/setup/kata-built-version.txt`
- containerd configured for Kata runtime: `labs/lab12/setup/containerd-kata-config-snippet.txt`
- Kata runtime used with `io.containerd.kata.v2`: `labs/lab12/setup/kata-test-uname.txt`, `labs/lab12/kata/test1.txt`
- runc workload reachable: `labs/lab12/runc/health.txt`, `labs/lab12/runc/health-raw.txt`
- Isolation tests executed: `labs/lab12/isolation/dmesg.txt`, `proc.txt`, `network.txt`, `modules.txt`
- Performance snapshot recorded: `labs/lab12/bench/startup.txt`, `labs/lab12/bench/http-latency.txt`
- Artifacts saved under `labs/lab12`: yes

## Checklist
- [x] Task 1 - Kata install and config
- [x] Task 2 - runc vs kata comparison
- [x] Task 3 - isolation tests
- [x] Task 4 - performance snapshot
