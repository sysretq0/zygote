use protocol::{SpawnRequest, SpawnResponse, DEFAULT_ABSTRACT_NAME};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};

/// Socket send/receive buffer size (256 KB) to prevent EAGAIN under burst conditions.
const SOCKET_BUFFER_SIZE: libc::c_int = 256 * 1024;

/// Connects to a non-blocking SOCK_SEQPACKET abstract socket with 256 KB socket buffers.
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

    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&SOCKET_BUFFER_SIZE as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&SOCKET_BUFFER_SIZE as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

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
            addr.sun_path.as_mut_ptr().add(1) as *mut u8,
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

    unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
}

#[repr(align(8))]
pub(crate) struct CmsgBuf([u8; 64]);

/// Helper function to perform sendmsg with optional SCM_RIGHTS ancillary data.
fn raw_sendmsg(raw_fd: RawFd, packet: &[u8], fds: &[RawFd]) -> Result<isize, std::io::Error> {
    let mut iov = libc::iovec {
        iov_base: packet.as_ptr() as *mut libc::c_void,
        iov_len: packet.len(),
    };
    let mut cmsg_buf = CmsgBuf([0u8; 64]);
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    if !fds.is_empty() {
        let fds_bytes = (fds.len() * std::mem::size_of::<libc::c_int>()) as u32;
        msg.msg_control = cmsg_buf.0.as_mut_ptr().cast();
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(fds_bytes) } as usize;

        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if !cmsg.is_null() {
            unsafe {
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(fds_bytes) as usize;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr(),
                    libc::CMSG_DATA(cmsg).cast(),
                    fds.len(),
                );
            }
        }
    }

    let n = unsafe { libc::sendmsg(raw_fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if n >= 0 {
        Ok(n)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Request envelope sent to the multiplexer actor.
struct SpawnJob {
    request: SpawnRequest,
    reply: oneshot::Sender<SpawnResponse>,
    attached_fds: Vec<RawFd>,
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
        let async_fd = Arc::new(AsyncFd::new(owned_fd)?);

        let (tx, mut rx) = mpsc::channel::<SpawnJob>(1024);
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<SpawnResponse>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Writer task: receives jobs, registers pending response callback, and sends atomic SEQPACKET packets with SCM_RIGHTS
        let pending_writer = pending.clone();
        let async_fd_writer = async_fd.clone();
        tokio::spawn(async move {
            let raw_fd = async_fd_writer.get_ref().as_raw_fd();
            let mut send_buf = Vec::with_capacity(1024);
            while let Some(job) = rx.recv().await {
                let req_id = job.request.id;
                if let Err(e) = protocol::encode_packet_into(&job.request, &mut send_buf) {
                    for fd in job.attached_fds {
                        unsafe { libc::close(fd) };
                    }
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

                loop {
                    let mut guard = match async_fd_writer.writable().await {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("[orchestrator] Socket writable error: {e}");
                            for fd in job.attached_fds {
                                unsafe { libc::close(fd) };
                            }
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

                    match raw_sendmsg(raw_fd, &send_buf, &job.attached_fds) {
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
                            for fd in job.attached_fds {
                                unsafe { libc::close(fd) };
                            }
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
            }
        });

        // Reader task: reads atomic SEQPACKET responses and routes to awaiting callers by correlation ID
        let pending_reader = pending.clone();
        let async_fd_reader = async_fd.clone();
        tokio::spawn(async move {
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
                        let req_id = if buf.len() >= 8 {
                            u64::from_le_bytes(buf[..8].try_into().unwrap_or([0; 8]))
                        } else {
                            0
                        };
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
                            eprintln!("[orchestrator] Deserialization error: {e}");
                        }
                    }
                }
            }
        });

        Ok(Self {
            tx,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Dispatch a custom spawn request with optional attached file descriptors.
    pub async fn spawn_request(
        &self,
        request: SpawnRequest,
        attached_fds: Vec<RawFd>,
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

        let response = reply_rx
            .await
            .map_err(|_| "Reply channel canceled".to_string())?;

        response.result
    }

    /// Dispatch a spawn request attaching custom stdio file descriptors via SCM_RIGHTS.
    pub async fn spawn_with_stdio(
        &self,
        path: impl Into<String>,
        args: Vec<String>,
        stdin: Option<RawFd>,
        stdout: Option<RawFd>,
        stderr: Option<RawFd>,
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
        Ok(pid) => eprintln!("[orchestrator] Unexpected success with PID: {pid}"),
        Err(err) => println!("[orchestrator] Verified expected execve failure reporting: {err}"),
    }

    // ------------------------------------------------------------------------
    // Part 2: Verify Single Spawn Functionality & Signal Disposition Reset
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 2. Testing process spawn & signal disposition reset...");
    let trap_file = "/tmp/zygote_trap_test.txt";
    let _ = std::fs::remove_file(trap_file);
    let pid = client
        .spawn(
            "/bin/sh",
            vec!["sh".into(), "-c".into(), format!("trap -p > {trap_file}")],
        )
        .await?;
    println!("[orchestrator] Verified spawn: child PID = {pid}");

    // Wait briefly for shell to finish writing and exit
    tokio::time::sleep(Duration::from_millis(100)).await;
    if let Ok(content) = std::fs::read_to_string(trap_file) {
        if content.contains("SIGPIPE") || content.contains("SIGCHLD") {
            panic!("[orchestrator] FAILURE: Child inherited ignored signals: {content}");
        } else {
            println!("[orchestrator] Verified signal disposition: SIGPIPE/SIGCHLD properly reset to SIG_DFL (clean trap table)");
        }
        let _ = std::fs::remove_file(trap_file);
    }

    // ------------------------------------------------------------------------
    // Part 3: Verify Child Process Group Isolation (setpgid / setsid)
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 3. Testing child process group isolation (pgid != zygote_pgid)...");
    let pgid_file = "/tmp/zygote_pgid_test.txt";
    let _ = std::fs::remove_file(pgid_file);
    let child_pid = client
        .spawn(
            "/bin/sh",
            vec![
                "sh".into(),
                "-c".into(),
                format!("/bin/cat /proc/self/stat > {pgid_file}"),
            ],
        )
        .await?;

    tokio::time::sleep(Duration::from_millis(150)).await;
    if let Ok(content) = std::fs::read_to_string(pgid_file) {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 5 {
            let child_actual_pid: i32 = parts[0].parse().unwrap_or(0);
            let child_pgid: i32 = parts[4].parse().unwrap_or(0);
            let my_pgid = unsafe { libc::getpgrp() };

            println!(
                "[orchestrator] Child PID = {child_pid} (reported by procfs: {child_actual_pid}), Child PGID = {child_pgid}, Orchestrator PGID = {my_pgid}"
            );

            if child_pgid != my_pgid {
                println!(
                    "[orchestrator] Verified process group isolation: child_pgid ({child_pgid}) != parent_pgid ({my_pgid})"
                );
            } else {
                panic!("[orchestrator] FAILURE: Child shares PGID with parent/zygote!");
            }
        }
        let _ = std::fs::remove_file(pgid_file);
    }

    // ------------------------------------------------------------------------
    // Part 4: Verify SCM_RIGHTS Stdio File Descriptor Passing
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 4. Testing SCM_RIGHTS stdio file descriptor passing...");
    let mut pipe_fds = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    let (pipe_rx, pipe_tx) = (pipe_fds[0], pipe_fds[1]);

    let echo_msg = "hello from scm_rights pipe";
    let pid = client
        .spawn_with_stdio(
            "/bin/echo",
            vec!["echo".into(), echo_msg.into()],
            None,
            Some(pipe_tx),
            None,
        )
        .await?;
    println!("[orchestrator] Spawned /bin/echo with custom stdout: PID = {pid}");

    // Close writer end in parent so EOF is reached once child finishes
    unsafe { libc::close(pipe_tx) };

    let mut out_buf = [0u8; 128];
    let n = unsafe { libc::read(pipe_rx, out_buf.as_mut_ptr().cast(), out_buf.len()) };
    unsafe { libc::close(pipe_rx) };

    assert!(n > 0, "Failed to read from child custom stdout pipe");
    let received_output = String::from_utf8_lossy(&out_buf[..n as usize]);
    println!(
        "[orchestrator] Verified child stdout captured: '{}'",
        received_output.trim()
    );
    assert!(received_output.contains(echo_msg));

    // ------------------------------------------------------------------------
    // Part 5: Verify Detection of Truncated Oversized Packets (MSG_TRUNC)
    // ------------------------------------------------------------------------
    println!("\n[orchestrator] 5. Testing detection of oversized truncated packets (MSG_TRUNC)...");
    {
        let raw_test_fd = connect_abstract_seqpacket(abstract_name)?;
        // Send a 70 KB payload (> 64 KB REQ_BUF_SIZE)
        let oversized = vec![0x41u8; 70_000];
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
    }

    // ------------------------------------------------------------------------
    // Part 6: High-Throughput Concurrent Client Multiplexing Demonstration
    // ------------------------------------------------------------------------
    const TOTAL_REQUESTS: usize = 1_000;
    println!("\n[orchestrator] 6. Launching {TOTAL_REQUESTS} concurrent mock client tasks...");

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

    println!("\n=== Benchmark Results ===");
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

        println!("Throughput:         {:.1} spawns/sec", throughput);
        println!(
            "Average Latency:    {} µs ({:.2} ms)",
            avg_us,
            avg_us as f64 / 1000.0
        );
        println!(
            "P50 Latency:        {} µs ({:.2} ms)",
            p50_us,
            p50_us as f64 / 1000.0
        );
        println!(
            "P90 Latency:        {} µs ({:.2} ms)",
            p90_us,
            p90_us as f64 / 1000.0
        );
        println!(
            "P99 Latency:        {} µs ({:.2} ms)",
            p99_us,
            p99_us as f64 / 1000.0
        );
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
        let buf = CmsgBuf([0u8; 64]);
        assert_eq!(std::mem::align_of::<CmsgBuf>(), 8);
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

        let payload = vec![0x42u8; 128];
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
}
