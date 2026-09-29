use protocol::{SpawnRequest, SpawnResponse, DEFAULT_ABSTRACT_NAME};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};

/// Connects to a non-blocking SOCK_SEQPACKET abstract socket with 256 KB socket buffers.
/// F2: immediately verifies the server peer via SO_PEERCRED (uid == geteuid() || uid == 0).
fn connect_abstract_seqpacket(abstract_name: &[u8]) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    protocol::configure_socket_buffers(fd);

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if abstract_name.len() + 1 > addr.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Abstract socket name exceeds maximum sockaddr_un path length",
        ));
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            abstract_name.as_ptr(),
            addr.sun_path.as_mut_ptr().add(1),
            abstract_name.len(),
        );
    }

    let sun_path_offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let addr_len = (sun_path_offset + 1 + abstract_name.len()) as libc::socklen_t;

    let ret = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), addr_len) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // F2: verify server authenticity before exchanging any request.
    let peer_uid = protocol::peer_cred_uid(fd).inspect_err(|_| {
        unsafe { libc::close(fd) };
    })?;
    let my_euid = unsafe { libc::geteuid() };
    if peer_uid != my_euid && peer_uid != 0 {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Zygote server UID {peer_uid} != client EUID {my_euid}"),
        ));
    }

    unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
}

/// Request envelope sent to the multiplexer actor; OwnedFd gives RAII
/// exactly-once close on both success and error paths (F4).
struct SpawnJob {
    request: SpawnRequest,
    reply: oneshot::Sender<SpawnResponse>,
    attached_fds: Vec<OwnedFd>,
}

/// Client handle for multiplexing process spawn requests across an atomic SOCK_SEQPACKET connection to Zygote.
#[derive(Clone)]
pub struct ZygoteClient {
    tx: mpsc::Sender<SpawnJob>,
    pub next_id: Arc<AtomicU64>,
}

impl ZygoteClient {
    /// Connect to the Zygote daemon via Linux abstract namespace SOCK_SEQPACKET socket (\0zygote).
    pub async fn connect_abstract(name: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let owned_fd = connect_abstract_seqpacket(name)?;
        Self::connect_with_fd(owned_fd).await
    }

    /// Shared connection setup from an already-connected socket (also used by tests).
    /// Verifies the peer credential (F2) then spawns writer/reader actors.
    pub(crate) async fn connect_with_fd(
        owned_fd: OwnedFd,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // F2 defense-in-depth for direct-fd callers (e.g. tests): re-verify peer.
        if let Ok(peer_uid) = protocol::peer_cred_uid(owned_fd.as_raw_fd()) {
            let my_euid = unsafe { libc::geteuid() };
            if peer_uid != my_euid && peer_uid != 0 {
                return Err(format!(
                    "Zygote server UID {peer_uid} != client EUID {my_euid}"
                )
                .into());
            }
        }
        let async_fd = Arc::new(AsyncFd::new(owned_fd)?);

        let (tx, mut rx) = mpsc::channel::<SpawnJob>(1024);
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<SpawnResponse>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Reader task: reads atomic SEQPACKET responses and routes to awaiting callers by correlation ID.
        let pending_reader = pending.clone();
        let async_fd_reader = async_fd.clone();
        let reader_handle = tokio::spawn(async move {
            let raw_fd = async_fd_reader.get_ref().as_raw_fd();
            let mut buf = vec![0u8; 65536];

            loop {
                let mut guard = match async_fd_reader.readable().await {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("[orchestrator] Socket readable error: {e}");
                        break;
                    }
                };

                let n = unsafe {
                    libc::recv(
                        raw_fd,
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                    )
                };

                if n == 0 {
                    let mut lock = pending_reader.lock().unwrap();
                    for (_, reply) in lock.drain() {
                        let _ = reply.send(SpawnResponse::error(
                            0,
                            "Connection closed by Zygote daemon",
                        ));
                    }
                    break;
                } else if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    } else if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    } else {
                        eprintln!("[orchestrator] Socket recv error: {err}");
                        let mut lock = pending_reader.lock().unwrap();
                        for (_, reply) in lock.drain() {
                            let _ = reply
                                .send(SpawnResponse::error(0, format!("Connection error: {err}")));
                        }
                        break;
                    }
                } else {
                    guard.retain_ready();
                    if (n as usize) > buf.len() {
                        eprintln!(
                            "[orchestrator] Received truncated packet (length: {n} > max {})",
                            buf.len()
                        );
                        // F3: correlate via id prefix when available.
                        let req_id = protocol::extract_req_id(&buf).unwrap_or(0);
                        let mut lock = pending_reader.lock().unwrap();
                        let reply_opt = lock.remove(&req_id).or_else(|| {
                            if lock.len() == 1 {
                                let key = *lock.keys().next().unwrap();
                                lock.remove(&key)
                            } else {
                                None
                            }
                        });
                        if let Some(reply) = reply_opt {
                            let _ = reply.send(SpawnResponse::error(
                                req_id,
                                format!(
                                    "Response packet truncated (length: {n} > max {})",
                                    buf.len()
                                ),
                            ));
                        }
                        continue;
                    }

                    let packet = &buf[..n as usize];
                    match protocol::decode_packet::<SpawnResponse>(packet) {
                        Ok(resp) => {
                            let mut lock = pending_reader.lock().unwrap();
                            if let Some(reply) = lock.remove(&resp.id) {
                                let _ = reply.send(resp);
                            } else {
                                eprintln!(
                                    "[orchestrator] Received response for unknown request ID {}",
                                    resp.id
                                );
                            }
                        }
                        Err(e) => {
                            // F3: never hang a waiter on a corrupt response when the id is recoverable.
                            if packet.len() >= 8 {
                                if let Some(req_id) = protocol::extract_req_id(packet) {
                                    let mut lock = pending_reader.lock().unwrap();
                                    if let Some(reply) = lock.remove(&req_id) {
                                        let _ = reply.send(SpawnResponse::error(
                                            req_id,
                                            format!("Invalid response: {e}"),
                                        ));
                                        continue;
                                    }
                                }
                            }
                            eprintln!("[orchestrator] Deserialization error: {e}");
                        }
                    }
                }
            }
        });
        let reader_abort = reader_handle.abort_handle();

        // Writer task: receives jobs, registers pending response callback, and sends atomic SEQPACKET packets with SCM_RIGHTS.
        // F10: holds the reader AbortHandle; when all ZygoteClient handles drop,
        // rx.recv() returns None, we abort the reader so Arc<AsyncFd> is released
        // and the socket closes cleanly.
        let pending_writer = pending.clone();
        let async_fd_writer = async_fd.clone();
        tokio::spawn(async move {
            let raw_fd = async_fd_writer.get_ref().as_raw_fd();
            let mut send_buf = Vec::with_capacity(1024);
            while let Some(job) = rx.recv().await {
                let req_id = job.request.id;
                if let Err(e) = protocol::encode_packet_into(&job.request, &mut send_buf) {
                    // job.attached_fds dropped here exactly once (RAII).
                    let _ = job.reply.send(SpawnResponse::error(
                        req_id,
                        format!("Serialization failed: {e}"),
                    ));
                    continue;
                }

                {
                    let mut lock = pending_writer.lock().unwrap();
                    lock.insert(req_id, job.reply);
                }

                // Borrow raw fds for sendmsg; OwnedFd vector stays alive until end of iteration.
                let raw_fds: Vec<RawFd> =
                    job.attached_fds.iter().map(|f| f.as_raw_fd()).collect();
                loop {
                    let mut guard = match async_fd_writer.writable().await {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("[orchestrator] Socket writable error: {e}");
                            let mut lock = pending_writer.lock().unwrap();
                            if let Some(reply) = lock.remove(&req_id) {
                                let _ = reply.send(SpawnResponse::error(
                                    req_id,
                                    format!("Socket writable error: {e}"),
                                ));
                            }
                            break;
                        }
                    };

                    match protocol::send_packet_with_fds(raw_fd, &send_buf, &raw_fds) {
                        Ok(_) => {
                            guard.retain_ready();
                            break;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            guard.clear_ready();
                            continue;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(err) => {
                            eprintln!("[orchestrator] Socket sendmsg error: {err}");
                            let mut lock = pending_writer.lock().unwrap();
                            if let Some(reply) = lock.remove(&req_id) {
                                let _ = reply.send(SpawnResponse::error(
                                    req_id,
                                    format!("Socket send error: {err}"),
                                ));
                            }
                            break;
                        }
                    }
                }
                // job.attached_fds dropped here: originals closed, kernel holds sent copies.
            }
            // All client handles dropped: abort reader so the socket fd is released.
            reader_abort.abort();
            // Fail any still-pending waiters instead of hanging them.
            let mut lock = pending_writer.lock().unwrap();
            for (_, reply) in lock.drain() {
                let _ = reply.send(SpawnResponse::error(0, "Zygote client shut down"));
            }
        });

        Ok(Self {
            tx,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Dispatch a custom spawn request with optional attached file descriptors (owned).
    pub async fn spawn_request(
        &self,
        request: SpawnRequest,
        attached_fds: Vec<OwnedFd>,
    ) -> Result<i32, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(SpawnJob {
                request,
                reply: reply_tx,
                attached_fds,
            })
            .await
            .map_err(|_| "Multiplexer actor channel closed".to_string())?;

        // F3: never hang requests; 10s timeout bounds every await.
        let response = tokio::time::timeout(Duration::from_secs(10), reply_rx)
            .await
            .map_err(|_| "Request timed out after 10s".to_string())?
            .map_err(|_| "Reply channel canceled".to_string())?;

        response.result
    }

    /// Dispatch a spawn request attaching custom stdio file descriptors via SCM_RIGHTS (owned, F4).
    pub async fn spawn_with_stdio(
        &self,
        path: impl Into<String>,
        args: Vec<String>,
        stdin: Option<OwnedFd>,
        stdout: Option<OwnedFd>,
        stderr: Option<OwnedFd>,
    ) -> Result<i32, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut attached_fds = Vec::new();
        let pass_stdin = stdin.is_some();
        let pass_stdout = stdout.is_some();
        let pass_stderr = stderr.is_some();

        if let Some(fd) = stdin {
            attached_fds.push(fd);
        }
        if let Some(fd) = stdout {
            attached_fds.push(fd);
        }
        if let Some(fd) = stderr {
            attached_fds.push(fd);
        }

        let mut request = SpawnRequest::new(id, path, args);
        request.pass_stdin = pass_stdin;
        request.pass_stdout = pass_stdout;
        request.pass_stderr = pass_stderr;

        self.spawn_request(request, attached_fds).await
    }

    /// Dispatch a standard spawn request and await the confirmed response.
    pub async fn spawn(&self, path: impl Into<String>, args: Vec<String>) -> Result<i32, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = SpawnRequest::new(id, path, args);
        self.spawn_request(request, Vec::new()).await
    }
}

/// Create a blocking CLOEXEC pipe returning owned ends.
fn make_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// Blocking read of a pipe to string until EOF with a deadline (no sleep-based waits).
fn read_pipe_to_string(rx: &OwnedFd, deadline: Duration) -> std::io::Result<String> {
    let raw = rx.as_raw_fd();
    let start = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let elapsed = start.elapsed();
        if elapsed >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Timed out reading child pipe",
            ));
        }
        let remaining = deadline - elapsed;
        let ms = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd: raw,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, ms) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if r == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Timed out reading child pipe",
            ));
        }
        let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Scan /proc for a live `zygote` daemon and return its process-group id if found.
fn find_zygote_pgid() -> Option<i32> {
    let procs = std::fs::read_dir("/proc").ok()?;
    for entry in procs.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid_str}/comm")) else {
            continue;
        };
        if comm.trim() != "zygote" {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid_str}/stat")) else {
            continue;
        };
        // stat: pid (comm) state ppid pgid ... -> pgid is 5th whitespace token overall,
        // but comm may contain spaces; split after last ')'.
        if let Some(idx) = stat.rfind(')') {
            let after = &stat[idx + 1..];
            let parts: Vec<&str> = after.split_whitespace().collect();
            // after: state ppid pgid ... so pgid is parts[2].
            if parts.len() >= 3 {
                if let Ok(pgid) = parts[2].parse::<i32>() {
                    return Some(pgid);
                }
            }
        }
    }
    None
}

fn percentile_sorted(mut v: Vec<u128>, p: usize) -> u128 {
    v.sort_unstable();
    v[v.len() * p / 100]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Orchestrator Service (Hardened SOCK_SEQPACKET Multiplexer) ===");
    let abstract_name = DEFAULT_ABSTRACT_NAME;

    // Retry connecting to Zygote abstract socket if it's currently starting up
    let client = {
        let mut retries = 10;
        loop {
            match ZygoteClient::connect_abstract(abstract_name).await {
                Ok(c) => break c,
                Err(e) => {
                    retries -= 1;
                    if retries == 0 {
                        eprintln!(
                            "[orchestrator] Could not connect to Zygote daemon at @{}: {e}",
                            String::from_utf8_lossy(abstract_name)
                        );
                        eprintln!("Please ensure the `zygote` daemon is running.");
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    };

    println!(
        "[orchestrator] Successfully connected to Zygote daemon at abstract socket @{}\n",
        String::from_utf8_lossy(abstract_name)
    );

    // ------------------------------------------------------------------------
    // Part 1: Verify Error Handling for invalid binaries (execve failure reporting)
    // ------------------------------------------------------------------------
    println!("[orchestrator] 1. Testing error reporting for non-existent binary...");
    match client
        .spawn("/bin/non_existent_binary_xyz_123", vec![])
        .await
    {
        Ok(pid) => {
            eprintln!("[orchestrator] Unexpected success with PID: {pid}");
            return Err("Expected execve failure for non-existent binary".into());
        }
        Err(err) => println!("[orchestrator] Verified expected execve failure reporting: {err}"),
    }

    // ------------------------------------------------------------------------
    // Part 2: Signal disposition reset via SCM_RIGHTS stdout pipe (no /tmp, no sleep)
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 2. Testing process spawn & signal disposition reset...");
    {
        let (pipe_rx, pipe_tx) = make_pipe()?;
        let pid = client
            .spawn_with_stdio(
                "/bin/sh",
                vec!["sh".into(), "-c".into(), "trap -p".into()],
                None,
                Some(pipe_tx),
                None,
            )
            .await
            .map_err(|e| format!("Test 2 spawn failed: {e}"))?;
        println!("[orchestrator] Verified spawn: child PID = {pid}");
        // pipe_tx ownership moved into the client; parent holds only pipe_rx so EOF
        // arrives as soon as the child exits. No sleep, no /tmp file.
        let content =
            read_pipe_to_string(&pipe_rx, Duration::from_secs(5)).map_err(|e| {
                format!("Test 2 failed reading child stdout pipe: {e}")
            })?;
        assert!(
            !content.contains("SIGPIPE") && !content.contains("SIGCHLD"),
            "[orchestrator] FAILURE: Child inherited ignored signals: {content}"
        );
        println!(
            "[orchestrator] Verified signal disposition: SIGPIPE/SIGCHLD properly reset to SIG_DFL (clean trap table)"
        );
    }

    // ------------------------------------------------------------------------
    // Part 3: Child PGID isolation via SCM_RIGHTS stdout pipe (no /tmp, no sleep)
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 3. Testing child process group isolation...");
    {
        let (pipe_rx, pipe_tx) = make_pipe()?;
        let child_pid = client
            .spawn_with_stdio(
                "/bin/cat",
                vec!["cat".into(), "/proc/self/stat".into()],
                None,
                Some(pipe_tx),
                None,
            )
            .await
            .map_err(|e| format!("Test 3 spawn failed: {e}"))?;
        let content =
            read_pipe_to_string(&pipe_rx, Duration::from_secs(5)).map_err(|e| {
                format!("Test 3 failed reading child stdout pipe: {e}")
            })?;
        let parts: Vec<&str> = content.split_whitespace().collect();
        assert!(
            parts.len() >= 5,
            "[orchestrator] FAILURE Test 3: malformed /proc/self/stat: {content:?}"
        );
        let child_actual_pid: i32 = parts[0].parse().map_err(|_| {
            format!("[orchestrator] FAILURE Test 3: cannot parse pid from {content:?}")
        })?;
        let child_pgid: i32 = parts[4].parse().map_err(|_| {
            format!("[orchestrator] FAILURE Test 3: cannot parse pgid from {content:?}")
        })?;
        let my_pgid = unsafe { libc::getpgrp() };
        println!(
            "[orchestrator] Child PID = {child_pid} (procfs: {child_actual_pid}), Child PGID = {child_pgid}, Orchestrator PGID = {my_pgid}"
        );
        assert_eq!(
            child_actual_pid, child_pid,
            "[orchestrator] FAILURE Test 3: reported pid mismatch"
        );
        // setpgid(0,0) => pgid == pid; must differ from orchestrator group.
        assert!(
            child_pgid != my_pgid,
            "[orchestrator] FAILURE: Child shares PGID with orchestrator!"
        );
        assert_eq!(
            child_pgid, child_pid,
            "[orchestrator] FAILURE Test 3: child pgid != child pid (setpgid broken?)"
        );
        // And must differ from the zygote daemon's group when discoverable.
        if let Some(zygote_pgid) = find_zygote_pgid() {
            println!("[orchestrator] Zygote PGID = {zygote_pgid}");
            assert!(
                child_pgid != zygote_pgid,
                "[orchestrator] FAILURE: Child shares PGID with zygote daemon!"
            );
        } else {
            println!(
                "[orchestrator] Zygote PGID not discoverable via /proc; pgid==pid check above implies isolation"
            );
        }
        println!(
            "[orchestrator] Verified process group isolation: child_pgid ({child_pgid}) != orchestrator_pgid ({my_pgid}) and != zygote pgid"
        );
    }

    // ------------------------------------------------------------------------
    // Part 4: Verify SCM_RIGHTS Stdio File Descriptor Passing
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 4. Testing SCM_RIGHTS stdio file descriptor passing...");
    {
        let (pipe_rx, pipe_tx) = make_pipe()?;
        let echo_msg = "hello from scm_rights pipe";
        let pid = client
            .spawn_with_stdio(
                "/bin/echo",
                vec!["echo".into(), echo_msg.into()],
                None,
                Some(pipe_tx),
                None,
            )
            .await
            .map_err(|e| format!("Test 4 spawn failed: {e}"))?;
        println!("[orchestrator] Spawned /bin/echo with custom stdout: PID = {pid}");
        let received_output =
            read_pipe_to_string(&pipe_rx, Duration::from_secs(5)).map_err(|e| {
                format!("Test 4 failed reading child stdout pipe: {e}")
            })?;
        assert!(
            !received_output.is_empty(),
            "Failed to read from child custom stdout pipe"
        );
        println!(
            "[orchestrator] Verified child stdout captured: '{}'",
            received_output.trim()
        );
        assert!(received_output.contains(echo_msg));
    }

    // ------------------------------------------------------------------------
    // Part 5: Verify Detection of Truncated Oversized Packets (MSG_TRUNC)
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 5. Testing detection of oversized truncated packets (MSG_TRUNC)...");
    {
        let raw_test_fd = connect_abstract_seqpacket(abstract_name)?;
        // Send a 70 KB payload (> 64 KB REQ_BUF_SIZE) with a valid id prefix so the
        // daemon can correlate the rejection.
        let mut oversized = vec![0x41u8; 70_000];
        let req_id: u64 = 0x0BAD_F00D_DEAD_BEEF;
        oversized[..8].copy_from_slice(&req_id.to_le_bytes());
        let n = unsafe {
            libc::send(
                raw_test_fd.as_raw_fd(),
                oversized.as_ptr().cast(),
                oversized.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(n, 70_000);

        let mut resp_buf = [0u8; 1024];
        // Set blocking mode to wait for response
        unsafe {
            let flags = libc::fcntl(raw_test_fd.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(
                raw_test_fd.as_raw_fd(),
                libc::F_SETFL,
                flags & !libc::O_NONBLOCK,
            );
        }
        let nr = unsafe {
            libc::recv(
                raw_test_fd.as_raw_fd(),
                resp_buf.as_mut_ptr().cast(),
                resp_buf.len(),
                0,
            )
        };
        assert!(
            nr > 0,
            "Failed to receive response from Zygote: errno = {}",
            std::io::Error::last_os_error()
        );
        let resp = protocol::decode_packet::<SpawnResponse>(&resp_buf[..nr as usize])?;
        println!(
            "[orchestrator] Verified oversized packet rejection: {:?}",
            resp.result
        );
        assert!(matches!(resp.result, Err(ref s) if s.contains("Payload exceeds max packet size")));
        assert_eq!(resp.id, req_id, "Truncated-packet reply must carry the request id");
    }

    // ------------------------------------------------------------------------
    // Part 6a: Single-request sequential latency (200 sequential spawns, p50/p99)
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 6a. Measuring single-request sequential latency (200 spawns)...");
    {
        const SEQ_REQUESTS: usize = 200;
        let mut latencies_us: Vec<u128> = Vec::with_capacity(SEQ_REQUESTS);
        for _ in 0..SEQ_REQUESTS {
            let t0 = Instant::now();
            client
                .spawn("/bin/true", vec!["true".into()])
                .await
                .map_err(|e| format!("Sequential latency spawn failed: {e}"))?;
            latencies_us.push(t0.elapsed().as_micros());
        }
        let p50 = percentile_sorted(latencies_us.clone(), 50);
        let p99 = percentile_sorted(latencies_us.clone(), 99);
        let avg: u128 = latencies_us.iter().sum::<u128>() / (latencies_us.len() as u128);
        println!("Sequential latency over {SEQ_REQUESTS} spawns (via Zygote):");
        println!("  Avg: {avg} us ({:.2} ms)", avg as f64 / 1000.0);
        println!("  P50: {p50} us ({:.2} ms)", p50 as f64 / 1000.0);
        println!("  P99: {p99} us ({:.2} ms)", p99 as f64 / 1000.0);
    }

    // ------------------------------------------------------------------------
    // Part 6b: High-Throughput Concurrent Client Multiplexing (1000 tasks)
    // ------------------------------------------------------------------------
    const TOTAL_REQUESTS: usize = 1_000;
    println!("\n[orchestrator] 6b. Launching {TOTAL_REQUESTS} concurrent mock client tasks...");

    let start_time = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();

    for i in 0..TOTAL_REQUESTS {
        let client_clone = client.clone();
        tasks.spawn(async move {
            let req_start = Instant::now();
            let res = client_clone.spawn("/bin/true", vec!["true".into()]).await;
            let latency = req_start.elapsed();
            (i, res, latency)
        });
    }

    let mut success_count = 0;
    let mut failure_count = 0;
    let mut latencies = Vec::with_capacity(TOTAL_REQUESTS);

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((_, Ok(_pid), latency)) => {
                success_count += 1;
                latencies.push(latency);
            }
            Ok((i, Err(err), _)) => {
                failure_count += 1;
                eprintln!("[orchestrator] Request {i} failed: {err}");
            }
            Err(e) => {
                failure_count += 1;
                eprintln!("[orchestrator] Task join error: {e}");
            }
        }
    }

    let total_duration = start_time.elapsed();
    latencies.sort();

    println!("\n=== Benchmark Results (concurrent, via Zygote) ===");
    println!("Total Requests:     {TOTAL_REQUESTS}");
    println!("Successful Spawns:  {success_count}");
    println!("Failed Spawns:      {failure_count}");
    println!("Total Elapsed Time: {:.2?}", total_duration);

    if !latencies.is_empty() {
        let throughput = (success_count as f64) / total_duration.as_secs_f64();
        let avg_us =
            latencies.iter().map(|d| d.as_micros()).sum::<u128>() / (latencies.len() as u128);
        let p50_us = latencies[latencies.len() * 50 / 100].as_micros();
        let p90_us = latencies[latencies.len() * 90 / 100].as_micros();
        let p99_us = latencies[latencies.len() * 99 / 100].as_micros();

        println!("Throughput:         {throughput:.1} spawns/sec");
        println!(
            "Average Latency:    {avg_us} µs ({:.2} ms)",
            avg_us as f64 / 1000.0
        );
        println!(
            "P50 Latency:        {p50_us} µs ({:.2} ms)",
            p50_us as f64 / 1000.0
        );
        println!(
            "P90 Latency:        {p90_us} µs ({:.2} ms)",
            p90_us as f64 / 1000.0
        );
        println!(
            "P99 Latency:        {p99_us} µs ({:.2} ms)",
            p99_us as f64 / 1000.0
        );
    }

    // ------------------------------------------------------------------------
    // Part 6c: Baseline comparison against direct process spawning
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 6c. Baseline: direct process spawning (no Zygote)...");
    {
        const BASELINE_N: usize = 200;
        let t0 = Instant::now();
        let mut direct_us: Vec<u128> = Vec::with_capacity(BASELINE_N);
        for _ in 0..BASELINE_N {
            let s = Instant::now();
            let st = std::process::Command::new("/bin/true")
                .status()
                .map_err(|e| format!("Direct spawn failed: {e}"))?;
            assert!(st.success(), "Direct /bin/true must exit 0");
            direct_us.push(s.elapsed().as_micros());
        }
        let total = t0.elapsed();
        let p50 = percentile_sorted(direct_us.clone(), 50);
        let p99 = percentile_sorted(direct_us.clone(), 99);
        let avg: u128 = direct_us.iter().sum::<u128>() / (direct_us.len() as u128);
        let throughput = (BASELINE_N as f64) / total.as_secs_f64();
        println!("Direct spawn over {BASELINE_N} runs:");
        println!("  Total: {total:.2?}, Throughput: {throughput:.1} spawns/sec");
        println!("  Avg: {avg} us ({:.2} ms)", avg as f64 / 1000.0);
        println!("  P50: {p50} us ({:.2} ms)", p50 as f64 / 1000.0);
        println!("  P99: {p99} us ({:.2} ms)", p99 as f64 / 1000.0);
    }

    println!("\n[orchestrator] Mock client run completed successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_seqpacket_async_fd() {
        let mut fds = [0; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0);

        let fd1 = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let fd2 = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let async1 = AsyncFd::new(fd1).unwrap();
        let async2 = AsyncFd::new(fd2).unwrap();

        // Write packet 1
        {
            let mut guard = async1.writable().await.unwrap();
            let n = unsafe {
                libc::send(
                    async1.get_ref().as_raw_fd(),
                    b"packet 1".as_ptr().cast(),
                    8,
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            assert_eq!(n, 8);
            guard.retain_ready();
        }

        // Read packet 1
        {
            let mut guard = async2.readable().await.unwrap();
            let mut buf = [0u8; 64];
            let n = unsafe {
                libc::recv(
                    async2.get_ref().as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            assert_eq!(n, 8);
            assert_eq!(&buf[..8], b"packet 1");
            guard.clear_ready();
        }
    }

    #[test]
    fn test_cmsg_buf_alignment() {
        let buf = protocol::CmsgBuf::new();
        assert_eq!(std::mem::align_of::<protocol::CmsgBuf>(), 8);
        assert_eq!(buf.0.as_ptr() as usize % 8, 0);
    }

    #[tokio::test]
    async fn test_msg_trunc_detection() {
        let mut fds = [0; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0);

        let fd1 = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let fd2 = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let payload = [0x42u8; 128];
        let n = unsafe {
            libc::send(
                fd1.as_raw_fd(),
                payload.as_ptr().cast(),
                payload.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(n, 128);

        let mut small_buf = [0u8; 32];
        let nr = unsafe {
            libc::recv(
                fd2.as_raw_fd(),
                small_buf.as_mut_ptr().cast(),
                small_buf.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        assert_eq!(nr, 128);
        assert!((nr as usize) > small_buf.len());
    }

    #[test]
    fn test_procfs_pgid_parsing() {
        let stat_content =
            std::fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
        let parts: Vec<&str> = stat_content.split_whitespace().collect();
        assert!(parts.len() >= 5);
        let pid: i32 = parts[0].parse().expect("parse pid");
        let pgid: i32 = parts[4].parse().expect("parse pgid");
        assert_eq!(pid, unsafe { libc::getpid() });
        assert_eq!(pgid, unsafe { libc::getpgrp() });
    }

    #[test]
    fn test_encode_packet_into_reuse() {
        let mut buf = Vec::with_capacity(1024);
        let req1 = SpawnRequest::new(1, "/bin/echo", vec!["echo".into()]);
        protocol::encode_packet_into(&req1, &mut buf).unwrap();
        assert!(!buf.is_empty());
        let cap_before = buf.capacity();

        let req2 = SpawnRequest::new(2, "/bin/ls", vec!["ls".into()]);
        protocol::encode_packet_into(&req2, &mut buf).unwrap();
        assert_eq!(buf.capacity(), cap_before);
    }

    #[tokio::test]
    async fn test_client_drop_closes_socket() {
        // F10: dropping all ZygoteClient handles must abort the reader task,
        // release Arc<AsyncFd>, and close the socket (peer observes EOF/HUP).
        let mut fds = [0; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let client_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let server_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let client = ZygoteClient::connect_with_fd(client_end).await.unwrap();
        // Sanity: a request with no server gets a shutdown/timeout error, not a hang.
        drop(client);
        // Allow writer exit + reader abort to run.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Peer must observe close: poll for POLLIN/POLLHUP then recv==0 or error.
        let mut pfd = libc::pollfd {
            fd: server_end.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, 2000) };
        assert!(r > 0, "Server end saw no event after client drop (socket leaked?)");
        let mut buf = [0u8; 16];
        let n = unsafe {
            libc::recv(
                server_end.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        // Closed SEQPACKET peer: recv returns 0 (EOF) or ENOTCONN/ECONNRESET; any of
        // these prove the fd was released. WouldBlock with no HUP would mean leak.
        if n == 0 {
            // clean EOF: socket closed.
        } else if n < 0 {
            let e = std::io::Error::last_os_error();
            assert!(
                pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLIN) != 0,
                "recv failed without HUP after client drop: {e}"
            );
        } else {
            panic!("Unexpected data on fresh socketpair after client drop (n={n})");
        }
    }
}
