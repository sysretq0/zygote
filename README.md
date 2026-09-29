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
   - Single shared SCM_RIGHTS implementation: 8-byte aligned `CmsgBuf`, `configure_socket_buffers`, `send_packet_with_fds`, `recv_packet_with_fds` (owned-FD returns), `extract_req_id`, and `SO_PEERCRED` helpers (`peer_cred_uid`, `peer_uid_allowed`).
   - `extract_req_id` reads the leading LE `u64` id prefix without full decoding so truncated / corrupt packets can still be correlated.

2. **[`crates/zygote`](file:///work/zygote/crates/zygote)**:
   - Single-threaded daemon event loop based on `libc::poll` with a self-pipe in `poll_fds[0]` so `SIGINT`/`SIGTERM` wake `poll()` instantly.
   - Abstract namespace UNIX socket listener (`SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC`).
   - Strict `SO_PEERCRED` checking: peer UID must equal daemon EUID (no root bypass; optional `--allow-uid <uid>` allow-list).
   - FD 0..=2 sanitized at startup via `/dev/null` so pipes/sockets are always `>= 3`.
   - Non-blocking `pipe_rx` child readiness polling with prioritized draining; children exceeding 5 s without exec status get `SIGKILL` plus an error reply.
   - Zero-allocation child path after `fork()` before calling `execve()`.
   - Backpressure enforcement (caps in-flight children to 128, checked before every `recvmsg`).
   - Per-client output buffering handling `EAGAIN` / `EWOULDBLOCK` via `POLLOUT`, bounded at 256 queued responses per client (overflow disconnects the stalled client).
   - No `println!`/`eprintln!` in daemon paths (non-panicking `write_all` stderr helpers, 1/sec rate-limit on invalid-packet logs).

3. **[`crates/orchestrator`](file:///work/zygote/crates/orchestrator)**:
   - Asynchronous actor client multiplexing concurrent requests over a single non-blocking `SOCK_SEQPACKET` socket.
   - Verifies the server peer via `SO_PEERCRED` immediately after `connect` (`uid == geteuid() || uid == 0`).
   - `SpawnJob` / `spawn_with_stdio` take `OwnedFd` (RAII exactly-once close); every `reply_rx` await is bounded by a 10 s timeout.
   - Reader-task `AbortHandle` is captured so dropping all `ZygoteClient` handles aborts the reader, releases `Arc<AsyncFd>`, and closes the socket cleanly.
   - Deterministic verification suite (SCM_RIGHTS stdout pipes, zero `/tmp` files, zero `sleep()`): error reporting, signal hygiene, PGID isolation (`child_pgid != orchestrator_pgid && != zygote_pgid`), stdio redirection, oversized payload rejection with id correlation.
   - Three-part benchmark: (a) 200 sequential spawns (p50/p99 latency), (b) 1,000-task concurrent multiplexed throughput, (c) direct-spawn baseline comparison.

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
Because abstract sockets lack filesystem permissions, connection security is enforced on both ends:
- Daemon (accept time): `getsockopt(SOL_SOCKET, SO_PEERCRED)` must equal the daemon EUID. No implicit root bypass: a root daemon still rejects unprivileged peers unless started with `--allow-uid <uid>`.
- Client (connect time): immediately after `connect()` the orchestrator queries `SO_PEERCRED` and requires `server_uid == geteuid() || server_uid == 0`.
- Unauthorized local connections are closed immediately.

### 4. Oversized Packet Rejection (`MSG_TRUNC` / `MSG_CTRUNC`)
- Non-blocking socket reads pass `libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC`.
- The leading LE `u64` id prefix (`extract_req_id`) is read before full bincode decoding whenever `n >= 8`, so `MSG_TRUNC`, `MSG_CTRUNC`, and decode errors still return a correlated `SpawnResponse::error` instead of hanging the request. Packets with `n < 8` carry no id and the client connection is closed.

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

### 9. Asynchronous `pipe_rx` Polling, Backpressure & Exec Timeout
- Uses a `pipe(O_CLOEXEC)` between the parent and child to report `execve()` execution status. EOF (`read == 0`) means the write end was closed atomically at the kernel CLOEXEC exec boundary (success); 4 bytes carry the pre-exec errno. Note the `SA_NOCLDWAIT` caveat documented in `launch_child`: signal death pre-exec also looks like EOF, so callers needing that distinction should probe liveness (`kill(pid, 0)`).
- Rather than synchronously blocking the main loop on `read(pipe_rx)`, `pipe_rx` descriptors are registered into the master `libc::poll` loop.
- The daemon prioritizes draining completed children over accepting new requests, maintaining low P50 latency.
- Enforces backpressure: suspends polling for new spawn requests when in-flight children reach 128 (checked before every `recvmsg` iteration).
- Exec watchdog: any pending child older than 5 s gets `SIGKILL`, its pipe closed, and an error `SpawnResponse` sent.

### 10. Non-Blocking Output Queueing (Bounded)
- Both daemon and client configure 256 KB socket buffers (`SO_RCVBUF`, `SO_SNDBUF`).
- If `libc::send` returns `EAGAIN` or `EWOULDBLOCK` during burst load, responses are queued in memory per-client, and `libc::POLLOUT` is activated on the client socket until the queue is completely drained.
- Each per-client queue is capped at 256 responses; overflow disconnects the stalled client to bound memory.

### 11. Startup & Shutdown Hygiene
- FDs 0, 1, 2 are sanitized at startup (`/dev/null` opened until the result is `> 2`) so sync pipes and sockets never occupy stdio slots.
- A self-pipe registered as `poll_fds[0]` is written by the `SIGINT`/`SIGTERM` handler, waking `poll()` instantly (no 1 s shutdown delay).
- The daemon never uses `println!`/`eprintln!` (which can panic on broken pipes); all logs go through non-panicking `write_all` stderr helpers with rate-limited invalid-packet logs.

---

## Performance & Benchmarks

The orchestrator reports three measurements per run:

- (a) Single-request sequential latency over 200 sequential `/bin/true` spawns (avg/p50/p99).
- (b) 1,000-task concurrent multiplexed throughput over one shared connection.
- (c) Baseline comparison: 200 direct `std::process::Command("/bin/true")` spawns (no daemon).

Example run (Linux x86_64, release build):

```
[orchestrator] 6a. Measuring single-request sequential latency (200 spawns)...
Sequential latency over 200 spawns (via Zygote):
  Avg: 3015 us (3.02 ms)
  P50: 3011 us (3.01 ms)
  P99: 4252 us (4.25 ms)

=== Benchmark Results (concurrent, via Zygote) ===
Total Requests:     1000
Successful Spawns:  1000
Failed Spawns:      0
Total Elapsed Time: 502.23ms
Throughput:         1991.1 spawns/sec
P50 Latency:        247788 µs (247.79 ms)
P99 Latency:        494698 µs (494.70 ms)

[orchestrator] 6c. Baseline: direct process spawning (no Zygote)...
Direct spawn over 200 runs:
  Total: 632.91ms, Throughput: 316.0 spawns/sec
  Avg: 3161 us (3.16 ms)
  P50: 3164 us (3.16 ms)
  P99: 4070 us (4.07 ms)
```

---

## Getting Started

### Prerequisites
- Linux OS (kernel >= 2.6.27 supported, kernel >= 5.9 recommended for `close_range`)
- Rust toolchain (Edition 2021, Rust >= 1.77.0)

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
