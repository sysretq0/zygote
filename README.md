# Zygote: Hardened High-Performance Linux Process Pre-Forking Daemon

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust: 2021](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)

A hardened, single-threaded Linux process pre-forking daemon (`zygote`) and asynchronous client orchestrator (`orchestrator`) built in Rust. It utilizes `SOCK_SEQPACKET` abstract UNIX domain sockets, asynchronous event loops with `poll(2)`, `SCM_RIGHTS` file descriptor passing, and strict zero-heap-allocation post-`fork()` safety.

---

## Architecture Overview

The repository is structured as a Cargo workspace with three crates:

```
crates/
├── protocol/       # Wire types, bincode serialization, SEQPACKET SCM_RIGHTS helpers
├── zygote/         # Single-threaded daemon, event loop, pre-forking execution engine
└── orchestrator/   # Asynchronous client multiplexer, verification suite, benchmarks
```

### Component Breakdown

1. **[`crates/protocol`](file:///work/zygote/crates/protocol)**:
   - Shared wire contracts: [`SpawnRequest`](file:///work/zygote/crates/protocol/src/lib.rs#L8-L32) and [`SpawnResponse`](file:///work/zygote/crates/protocol/src/lib.rs#L58-L82).
   - Abstract socket address identifier: `@zygote` (`\0zygote`).
   - Bincode serializer with fixed-integer encoding and a strict 64 KB deserialization limit.
   - SCM_RIGHTS ancillary data packing and unpacking using an 8-byte aligned buffer (`CmsgBuf`).
   - Atomic packet transmission helpers (`send_packet_with_fds`, `recv_packet_with_fds`).

2. **[`crates/zygote`](file:///work/zygote/crates/zygote)**:
   - Single-threaded daemon event loop based on `libc::poll`.
   - Abstract namespace UNIX socket listener (`SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC`).
   - `SO_PEERCRED` credential checking on connection acceptance.
   - Non-blocking `pipe_rx` child readiness polling with prioritized draining.
   - Zero-allocation child path after `fork()` before calling `execve()`.
   - Backpressure enforcement (caps in-flight children to 128).
   - Per-client output buffering handling `EAGAIN` / `EWOULDBLOCK` via `POLLOUT`.

3. **[`crates/orchestrator`](file:///work/zygote/crates/orchestrator)**:
   - Asynchronous actor client multiplexing concurrent requests over a single non-blocking `SOCK_SEQPACKET` socket.
   - High-throughput load generator and benchmarking tool with percentile latency tracking (P50, P90, P99).
   - Automated regression test suite covering error reporting, signal hygiene, PGID isolation, stdio redirection, and oversized payload rejection.

---

## Security & Reliability Primitives

### 1. Atomic Transport via `SOCK_SEQPACKET`
Replaces traditional streaming sockets (`SOCK_STREAM`) with atomic sequenced packets:
- Preserves datagram message boundaries directly within the Linux kernel.
- Eliminates application-layer framing protocols and length prefixes.
- Completely prevents partial read blocking and head-of-line framing desynchronization.

### 2. Linux Abstract Socket Namespace (`@zygote`)
Binds to `\0zygote` using `libc::sockaddr_un`:
- Bypasses filesystem paths and disk permissions.
- Prevents stale socket file hazards (`/tmp/zygote.sock` leftovers across reboots or crashes).
- Automatically tears down upon daemon process exit.

### 3. Peer Credential Verification (`SO_PEERCRED`)
Because abstract sockets lack filesystem permissions, connection security is enforced at accept time:
- Inspects peer credentials using `getsockopt(SOL_SOCKET, SO_PEERCRED)`.
- Verifies that the connecting process's Effective UID (`ucred.uid`) matches the daemon's Effective UID (`geteuid()`), unless running as `root` (UID 0).
- Immediately terminates unauthorized local connections.

### 4. Oversized Packet Rejection (`MSG_TRUNC`)
- Non-blocking socket reads pass `libc::MSG_DONTWAIT | libc::MSG_TRUNC`.
- If an incoming packet exceeds the 64 KB receive buffer, the daemon detects truncation without panicking, discarding the corrupted datagram and returning a structured `SpawnResponse::error` back to the sender.

### 5. Stdio Redirection with `SCM_RIGHTS`
- Clients can attach custom `stdin`, `stdout`, and `stderr` file descriptors to a spawn request via UNIX domain ancillary control messages (`sendmsg` with `SCM_RIGHTS`).
- The daemon receives descriptors using `MSG_CMSG_CLOEXEC`, duplicates them onto FDs `0`, `1`, and `2` inside the child post-fork using `libc::dup2`, and closes the parent's received copies immediately.

### 6. Process Group & Session Isolation (`setpgid` / `setsid`)
- Prevents signal contagion (e.g., child processes issuing `kill(0, SIGTERM)` cannot kill the `zygote` daemon or peer processes).
- When `SpawnRequest::new_session` is `true`, the child invokes `libc::setsid()`.
- Otherwise, the child invokes `libc::setpgid(0, 0)` to place itself into an isolated process group.

### 7. POSIX Signal Disposition Hygiene
- Daemons typically ignore signals like `SIGPIPE` (`SIG_IGN`) and set `SIGCHLD` to `SA_NOCLDWAIT`.
- Ignored signals persist across `execve()`, which would break child utilities (such as `grep`, `head`, or shell pipelines).
- In the child post-fork, all signals (`SIGPIPE`, `SIGCHLD`, `SIGINT`, `SIGTERM`) are explicitly reset to `SIG_DFL`, and the signal mask is cleared via `libc::sigprocmask`.

### 8. Zero Heap Allocation Post-`fork()`
Forking in a multi-threaded or complex runtime requires strict avoidance of heap allocations (which can deadlock on internal allocator mutexes):
- Pre-computes null-terminated `*const *const libc::c_char` arrays (`argv` and `envp`) in the parent *before* calling `fork()`.
- Caches the inherited default environment across requests.
- Closes inherited descriptors using `libc::syscall(SYS_close_range, 3, !0, 0)` (Linux >= 5.9).
- For kernels `< 5.9`, uses a zero-allocation fallback by directly invoking `libc::syscall(SYS_getdents64, fd, ...)` over a 2 KB stack buffer to inspect `/proc/self/fd`, avoiding `opendir`/`readdir` allocations entirely.
- Fallback for `pipe2(O_CLOEXEC)` to `libc::pipe` + `fcntl(FD_CLOEXEC)` on pre-2.6.27 kernels.

### 9. Asynchronous `pipe_rx` Polling & Backpressure
- Uses a `pipe(O_CLOEXEC)` between the parent and child to report `execve()` execution status.
- Rather than synchronously blocking the main loop on `read(pipe_rx)`, `pipe_rx` descriptors are registered into the master `libc::poll` loop.
- The daemon prioritizes draining completed children over accepting new requests, maintaining low P50 latency.
- Enforces backpressure: suspends polling for new spawn requests when in-flight children reach 128.

### 10. Non-Blocking Output Queueing
- Both daemon and client configure 256 KB socket buffers (`SO_RCVBUF`, `SO_SNDBUF`).
- If `libc::send` returns `EAGAIN` or `EWOULDBLOCK` during burst load, responses are queued in memory per-client, and `libc::POLLOUT` is activated on the client socket until the queue is completely drained.

---

## Performance & Benchmarks

Benchmarked on Linux 5.10 x86_64:

```
============================================================
BENCHMARK RESULTS (1000 processes spawned via Zygote):
  - Total Wall Time:  382.41 ms
  - Spawns / second:  2,615.00
  - Successes:        1000 / 1000
  - Failures:         0 / 1000
  - Min Latency:      2.83 ms
  - Max Latency:      381.99 ms
  - P50 Latency:      266.36 ms
  - P90 Latency:      352.01 ms
  - P99 Latency:      378.10 ms
============================================================
```

---

## Getting Started

### Prerequisites
- Linux OS (kernel >= 2.6.27 supported, kernel >= 5.9 recommended for `close_range`)
- Rust toolchain (Edition 2021, Rust >= 1.70.0)

### Building
Build all workspace crates in release mode:

```bash
cargo build --release
```

### Running the Test Suite
The workspace includes unit tests, integration tests, and safety tests:

```bash
cargo test --workspace
```

### Running the Daemon and Orchestrator

1. Start the `zygote` daemon in the background or in a separate terminal:
```bash
./target/release/zygote
```

2. Run the `orchestrator` benchmark and validation suite:
```bash
./target/release/orchestrator
```

---

## License

This project is licensed under the terms of the **GNU General Public License v3.0** ([GPL-3.0](file:///work/zygote/LICENSE)).
