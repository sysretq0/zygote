use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Maximum number of in-flight spawned children awaiting execve confirmation before applying backpressure.
const MAX_IN_FLIGHT_SPAWNS: usize = 128;

/// Maximum duration to drain pending children when shutdown signal is received.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum buffer size for a single SEQPACKET payload (64 KB).
const REQ_BUF_SIZE: usize = 65536;

/// Maximum queued responses per client before the stalled client is disconnected.
const MAX_OUT_QUEUE_LEN: usize = 256;

/// Maximum time a child may take to report execve status before SIGKILL.
const CHILD_EXEC_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of packets processed from a single client per poll turn to prevent starvation.
const MAX_PACKETS_PER_TURN: usize = 32;

/// Global shutdown signal flag set by SIGINT or SIGTERM handler.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Write end of the self-pipe used to wake `poll()` instantly on SIGINT/SIGTERM.
static SHUTDOWN_PIPE_WR: AtomicI32 = AtomicI32::new(-1);

/// Last millis timestamp of a rate-limited invalid-packet log (1 msg/sec max).
static INVALID_LOG_LAST_MS: AtomicU64 = AtomicU64::new(0);

/// C-ABI signal handler for graceful shutdown: sets flag and wakes poll() via self-pipe.
extern "C" fn sig_term_handler(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
    let wr = SHUTDOWN_PIPE_WR.load(Ordering::SeqCst);
    if wr >= 0 {
        let b = [1u8];
        unsafe {
            libc::write(wr, b.as_ptr().cast(), 1);
        }
    }
}

/// Non-panicking stderr log (never uses println!/eprintln! which may panic on broken pipes).
fn log_to_stderr(msg: &str) {
    let _ = std::io::stderr().write_all(msg.as_bytes());
}

fn log_info(msg: &str) {
    let mut s = String::with_capacity(msg.len() + 10);
    s.push_str("[zygote] ");
    s.push_str(msg);
    s.push('\n');
    log_to_stderr(&s);
}

fn log_warn(msg: &str) {
    let mut s = String::with_capacity(msg.len() + 10);
    s.push_str("[zygote] ");
    s.push_str(msg);
    s.push('\n');
    log_to_stderr(&s);
}

/// Rate-limited invalid-packet log: at most one message per second to avoid log flooding.
fn log_invalid_ratelimited(msg: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last = INVALID_LOG_LAST_MS.load(Ordering::Relaxed);
    if now.wrapping_sub(last) >= 1000 {
        INVALID_LOG_LAST_MS.store(now, Ordering::Relaxed);
        log_warn(msg);
    }
}

/// Ensure FDs 0, 1, 2 are valid so pipe_tx / sockets are always >= 3.
/// Opens /dev/null until the returned fd exceeds 2 (kept opens fill 0..=2).
fn sanitize_std_fds() {
    loop {
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            break;
        }
        if fd > 2 {
            unsafe { libc::close(fd) };
            break;
        }
        // fd is 0, 1 or 2: intentionally leaked to occupy the std slot.
    }
}

/// Parse optional `--allow-uid <uid>` / `--allow-uid=<uid>` CLI argument.
fn parse_allow_uid() -> Option<u32> {
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        if a == "--allow-uid" {
            if let Some(v) = args.next() {
                if let Ok(uid) = v.parse::<u32>() {
                    return Some(uid);
                }
            }
        } else if let Some(rest) = a.strip_prefix("--allow-uid=") {
            if let Ok(uid) = rest.parse::<u32>() {
                return Some(uid);
            }
        }
    }
    None
}

/// Pre-cached environment pointer table constructed once at startup.
struct CachedEnv {
    _strings: Vec<CString>,
    ptrs: Vec<*const libc::c_char>,
}

impl CachedEnv {
    fn capture() -> Self {
        let mut strings = Vec::new();
        for (k, v) in std::env::vars() {
            if let Ok(c) = CString::new(format!("{k}={v}")) {
                strings.push(c);
            }
        }
        let mut ptrs: Vec<*const libc::c_char> = strings.iter().map(|s| s.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        Self {
            _strings: strings,
            ptrs,
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const *const libc::c_char {
        self.ptrs.as_ptr()
    }
}

/// State of an active client connection over SOCK_SEQPACKET with outgoing message queue.
struct ClientInfo {
    id: u64,
    fd: OwnedFd,
    out_queue: VecDeque<Vec<u8>>,
}

/// Tracking metadata for an in-flight child process awaiting execve confirmation.
struct PendingChild {
    _pipe_rx: OwnedFd,
    client_id: u64,
    req_id: u64,
    child_pid: i32,
    spawned_at: Instant,
}

/// Configure signal handlers:
/// 1. SIGCHLD with SA_NOCLDWAIT to automatically reap zombie child processes without parent intervention.
/// 2. SIGPIPE set to SIG_IGN so broken client sockets return EPIPE rather than killing the daemon.
/// 3. SIGINT and SIGTERM set without SA_RESTART so blocking syscalls (poll/accept) exit with EINTR.
fn setup_signals() -> Result<(), Box<dyn std::error::Error>> {
    let sa_chld = SigAction::new(
        SigHandler::SigDfl,
        SaFlags::SA_NOCLDWAIT | SaFlags::SA_NOCLDSTOP,
        SigSet::empty(),
    );
    unsafe {
        sigaction(Signal::SIGCHLD, &sa_chld)?;
    }

    let sa_pipe = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    unsafe {
        sigaction(Signal::SIGPIPE, &sa_pipe)?;
    }

    let sa_term = SigAction::new(
        SigHandler::Handler(sig_term_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe {
        sigaction(Signal::SIGINT, &sa_term)?;
        sigaction(Signal::SIGTERM, &sa_term)?;
    }

    Ok(())
}

/// Creates a non-blocking listening SOCK_SEQPACKET socket bound to Linux abstract namespace.
fn create_listener_seqpacket(abstract_name: &[u8]) -> Result<OwnedFd, std::io::Error> {
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

    // Abstract socket name begins with \0, followed by name bytes
    unsafe {
        std::ptr::copy_nonoverlapping(
            abstract_name.as_ptr(),
            addr.sun_path.as_mut_ptr().add(1),
            abstract_name.len(),
        );
    }

    let sun_path_offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let addr_len = (sun_path_offset + 1 + abstract_name.len()) as libc::socklen_t;

    let bind_ret = unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), addr_len) };
    if bind_ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let listen_ret = unsafe { libc::listen(fd, 1024) };
    if listen_ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
}

/// Creates a pipe with O_CLOEXEC, providing a pre-2.6.27 fallback to pipe + fcntl(FD_CLOEXEC) if ENOSYS is returned.
fn create_pipe_cloexec() -> Result<(OwnedFd, OwnedFd), String> {
    match nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC) {
        Ok(pair) => Ok(pair),
        Err(nix::errno::Errno::ENOSYS) => {
            let mut fds = [0 as libc::c_int; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
                return Err(format!(
                    "pipe fallback failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let (rx_raw, tx_raw) = (fds[0], fds[1]);
            for &fd in &[rx_raw, tx_raw] {
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if flags < 0
                    || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
                {
                    unsafe {
                        libc::close(rx_raw);
                        libc::close(tx_raw);
                    }
                    return Err(format!(
                        "fcntl FD_CLOEXEC failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            unsafe { Ok((OwnedFd::from_raw_fd(rx_raw), OwnedFd::from_raw_fd(tx_raw))) }
        }
        Err(e) => Err(format!("pipe2 failed: {e}")),
    }
}

/// Closes all file descriptors above standard I/O (>= 3) except `preserved_fd`.
/// 1. Uses Linux 5.9+ close_range syscall.
/// 2. Falls back to zero-allocation SYS_getdents64 on /proc/self/fd with a fixed [u8; 1024] stack buffer.
/// 3. Falls back to RLIMIT_NOFILE iteration.
unsafe fn close_inherited_except(preserved_fd: libc::c_int) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const SYS_CLOSE_RANGE: libc::c_long = 436; // Linux 5.9+ close_range syscall number
        let preserved = preserved_fd as u32;
        let r1 = if preserved > 3 {
            libc::syscall(SYS_CLOSE_RANGE, 3_u32, preserved - 1, 0_u32)
        } else {
            0
        };
        let r2 = libc::syscall(SYS_CLOSE_RANGE, preserved + 1, u32::MAX, 0_u32);
        if r1 == 0 && r2 == 0 {
            return;
        }
    }

    // Fallback 1: Zero-allocation SYS_getdents64 on /proc/self/fd
    let dir_fd = libc::open(
        c"/proc/self/fd".as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    );
    if dir_fd >= 0 {
        let mut buf = [0u8; 1024];
        loop {
            let n = libc::syscall(libc::SYS_getdents64, dir_fd, buf.as_mut_ptr(), buf.len());
            if n <= 0 {
                break;
            }
            let mut bpos = 0usize;
            let nread = n as usize;
            while bpos < nread {
                if bpos + 19 > nread {
                    break;
                }
                let d_reclen = u16::from_ne_bytes([buf[bpos + 16], buf[bpos + 17]]) as usize;
                if d_reclen == 0 || bpos + d_reclen > nread {
                    break;
                }
                let name_start = bpos + 19;
                let mut p = name_start;
                let mut fd: libc::c_int = 0;
                let mut valid = false;
                while p < bpos + d_reclen && buf[p] != 0 {
                    let b = buf[p];
                    if b.is_ascii_digit() {
                        fd = fd * 10 + (b - b'0') as libc::c_int;
                        valid = true;
                        p += 1;
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && fd > 2 && fd != preserved_fd && fd != dir_fd {
                    libc::close(fd);
                }
                bpos += d_reclen;
            }
        }
        libc::close(dir_fd);
        return;
    }

    // Fallback 2: Query RLIMIT_NOFILE
    let mut lim: libc::rlimit = std::mem::zeroed();
    let hard = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
        (lim.rlim_cur as usize).min(4096)
    } else {
        256
    };
    for fd in 3..hard {
        let fd = fd as libc::c_int;
        if fd != preserved_fd {
            libc::close(fd);
        }
    }
}

/// Portable errno read after a failed syscall (`__errno_location` is glibc-only;
/// bionic/Android exposes `__errno` instead).
#[cfg(target_os = "android")]
#[inline]
unsafe fn last_errno() -> i32 {
    *libc::__errno()
}
#[cfg(not(target_os = "android"))]
#[inline]
unsafe fn last_errno() -> i32 {
    *libc::__errno_location()
}

/// Child process logic executed immediately after fork().
/// Does not return: always invokes execve() or exits with _exit(127).
/// Performs ZERO heap allocations.
#[allow(clippy::too_many_arguments)]
unsafe fn child_exec(
    redirect_null: bool,
    new_session: bool,
    stdin_fd: Option<i32>,
    stdout_fd: Option<i32>,
    stderr_fd: Option<i32>,
    devnull_fd: i32,
    path_ptr: *const libc::c_char,
    argv_ptr: *const *const libc::c_char,
    envp_ptr: *const *const libc::c_char,
    cwd_ptr: Option<*const libc::c_char>,
    pipe_tx_raw: libc::c_int,
) -> ! {
    // 1. Isolate process group or session to prevent signal contagion
    if new_session {
        libc::setsid();
    } else {
        libc::setpgid(0, 0);
    }

    // 2. Redirect stdio: custom SCM_RIGHTS file descriptors take precedence over redirect_null
    if let Some(fd) = stdin_fd {
        if libc::dup2(fd, libc::STDIN_FILENO) < 0 {
            let err = last_errno();
            libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
            libc::_exit(127);
        }
    } else if redirect_null && devnull_fd >= 0 {
        libc::dup2(devnull_fd, libc::STDIN_FILENO);
    }

    if let Some(fd) = stdout_fd {
        if libc::dup2(fd, libc::STDOUT_FILENO) < 0 {
            let err = last_errno();
            libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
            libc::_exit(127);
        }
    } else if redirect_null && devnull_fd >= 0 {
        libc::dup2(devnull_fd, libc::STDOUT_FILENO);
    }

    if let Some(fd) = stderr_fd {
        if libc::dup2(fd, libc::STDERR_FILENO) < 0 {
            let err = last_errno();
            libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
            libc::_exit(127);
        }
    } else if redirect_null && devnull_fd >= 0 {
        libc::dup2(devnull_fd, libc::STDERR_FILENO);
    }

    // 3. Change working directory if specified
    if let Some(dir) = cwd_ptr {
        if libc::chdir(dir) < 0 {
            let err = last_errno();
            libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
            libc::_exit(127);
        }
    }

    // 4. Sweep inherited descriptors, ensuring pipe_tx is preserved
    close_inherited_except(pipe_tx_raw);

    // 5. Reset signal dispositions to SIG_DFL and restore empty signal mask
    let mut sa_dfl: libc::sigaction = std::mem::zeroed();
    sa_dfl.sa_sigaction = libc::SIG_DFL;
    libc::sigaction(libc::SIGPIPE, &sa_dfl, std::ptr::null_mut());
    libc::sigaction(libc::SIGCHLD, &sa_dfl, std::ptr::null_mut());
    libc::sigaction(libc::SIGINT, &sa_dfl, std::ptr::null_mut());
    libc::sigaction(libc::SIGTERM, &sa_dfl, std::ptr::null_mut());

    let mut empty_mask: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut empty_mask);
    libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut());

    // 6. Invoke libc::execve directly without any heap allocations
    libc::execve(path_ptr, argv_ptr, envp_ptr);

    // If execve returns, it failed: report errno to parent and exit
    let err = last_errno();
    libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
    libc::_exit(127);
}

/// RAII guard holding received stdio descriptors as OwnedFd so Rust's drop
/// checker closes each descriptor exactly once on both success and error paths.
struct StdioGuard {
    stdin_fd: Option<OwnedFd>,
    stdout_fd: Option<OwnedFd>,
    stderr_fd: Option<OwnedFd>,
    disarmed: bool,
}

impl StdioGuard {
    fn new(
        stdin_fd: Option<OwnedFd>,
        stdout_fd: Option<OwnedFd>,
        stderr_fd: Option<OwnedFd>,
    ) -> Self {
        Self {
            stdin_fd,
            stdout_fd,
            stderr_fd,
            disarmed: false,
        }
    }

    /// Release ownership without closing: the child keeps the raw fds across
    /// fork (they are dup2'd then reaped by `close_inherited_except`).
    /// Must leak via `into_raw_fd` here because struct fields are still
    /// dropped (closed) after `Drop::drop` finishes, so merely setting
    /// `disarmed = true` would not prevent the close.
    fn disarm(&mut self) {
        self.disarmed = true;
        if let Some(fd) = self.stdin_fd.take() {
            let _ = fd.into_raw_fd();
        }
        if let Some(fd) = self.stdout_fd.take() {
            let _ = fd.into_raw_fd();
        }
        if let Some(fd) = self.stderr_fd.take() {
            let _ = fd.into_raw_fd();
        }
    }

    fn raw(&self) -> (Option<RawFd>, Option<RawFd>, Option<RawFd>) {
        (
            self.stdin_fd.as_ref().map(|f| f.as_raw_fd()),
            self.stdout_fd.as_ref().map(|f| f.as_raw_fd()),
            self.stderr_fd.as_ref().map(|f| f.as_raw_fd()),
        )
    }

    fn close(&mut self) {
        if !self.disarmed {
            self.stdin_fd.take();
            self.stdout_fd.take();
            self.stderr_fd.take();
        }
    }
}

impl Drop for StdioGuard {
    fn drop(&mut self) {
        self.close();
    }
}

/// Prepares strings and pointer arrays before fork(), creates a CLOEXEC synchronization pipe,
/// calls unsafe fork(), and returns the child's read pipe and PID without blocking on execve.
///
/// Pre-exec verification / O_CLOEXEC EOF semantics (F7):
/// The sync pipe is created O_CLOEXEC. The child holds the write end across
/// fork and execve: a successful execve atomically closes the write end at the
/// kernel CLOEXEC boundary, so the parent's `read(pipe_rx)` observes EOF (0
/// bytes) which unambiguously reports success. If execve (or dup2/chdir)
/// fails first, the child writes the 4-byte errno then `_exit(127)`, so the
/// parent reads exactly 4 bytes. Note the SA_NOCLDWAIT limitation: the daemon
/// cannot waitpid() to distinguish "child killed by a signal before exec"
/// (which also closes the write end and looks like EOF) from a true exec;
/// callers needing that distinction should verify child liveness (kill(pid,0)).
fn launch_child(
    request: &protocol::SpawnRequest,
    stdin_fd: Option<OwnedFd>,
    stdout_fd: Option<OwnedFd>,
    stderr_fd: Option<OwnedFd>,
    devnull_fd: RawFd,
    cached_env: &CachedEnv,
) -> Result<(OwnedFd, i32), String> {
    let mut stdio_guard = StdioGuard::new(stdin_fd, stdout_fd, stderr_fd);

    let path_c = CString::new(request.path.as_bytes()).map_err(|_| "Path contains null byte")?;

    let cwd_c = if let Some(ref cwd) = request.cwd {
        Some(CString::new(cwd.as_bytes()).map_err(|_| "Working directory contains null byte")?)
    } else {
        None
    };

    let mut args_c = Vec::with_capacity(request.args.len().max(1));
    if request.args.is_empty() {
        args_c.push(path_c.clone());
    } else {
        for arg in &request.args {
            args_c.push(CString::new(arg.as_bytes()).map_err(|_| "Argument contains null byte")?);
        }
    }

    // Prepare argv pointer array: stack array if <= 15 args, else heap
    let mut argv_heap: Vec<*const libc::c_char>;
    let mut argv_stack: [*const libc::c_char; 16] = [std::ptr::null(); 16];
    let argv_ptr: *const *const libc::c_char = if args_c.len() < 16 {
        for (i, c) in args_c.iter().enumerate() {
            argv_stack[i] = c.as_ptr();
        }
        argv_stack[args_c.len()] = std::ptr::null();
        argv_stack.as_ptr()
    } else {
        argv_heap = Vec::with_capacity(args_c.len() + 1);
        for c in &args_c {
            argv_heap.push(c.as_ptr());
        }
        argv_heap.push(std::ptr::null());
        argv_heap.as_ptr()
    };

    // Prepare envp pointer array: use cached_env if request.env is empty
    let (_custom_env_strings, _custom_env_ptrs, envp_ptr) = if request.env.is_empty() {
        (None, None, cached_env.as_ptr())
    } else {
        let mut env_strings = Vec::with_capacity(request.env.len());
        let mut env_ptrs = Vec::with_capacity(request.env.len() + 1);
        for (k, v) in &request.env {
            let c = CString::new(format!("{k}={v}"))
                .map_err(|_| "Environment variable contains null byte")?;
            env_ptrs.push(c.as_ptr());
            env_strings.push(c);
        }
        env_ptrs.push(std::ptr::null());
        let ptr = env_ptrs.as_ptr();
        (Some(env_strings), Some(env_ptrs), ptr)
    };

    // Create an O_CLOEXEC synchronization pipe (with pre-2.6.27 fallback).
    // EOF on pipe_rx after fork means execve succeeded (CLOEXEC closed pipe_tx
    // at the kernel exec boundary); 4 bytes means pre-exec failure errno.
    let (pipe_rx, pipe_tx) = create_pipe_cloexec()?;

    let pipe_tx_raw = pipe_tx.as_raw_fd();
    let cwd_ptr = cwd_c.as_ref().map(|c| c.as_ptr());
    let path_ptr = path_c.as_ptr();
    let redirect_null = request.redirect_null;
    let new_session = request.new_session;
    let (stdin_raw, stdout_raw, stderr_raw) = stdio_guard.raw();

    let fork_res = unsafe { nix::unistd::fork() };

    match fork_res {
        Ok(nix::unistd::ForkResult::Child) => {
            drop(pipe_rx);
            stdio_guard.disarm();
            unsafe {
                child_exec(
                    redirect_null,
                    new_session,
                    stdin_raw,
                    stdout_raw,
                    stderr_raw,
                    devnull_fd,
                    path_ptr,
                    argv_ptr,
                    envp_ptr,
                    cwd_ptr,
                    pipe_tx_raw,
                );
            }
        }
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            drop(pipe_tx);
            stdio_guard.close();
            Ok((pipe_rx, child.as_raw()))
        }
        Err(e) => {
            stdio_guard.close();
            Err(format!("fork failed: {e}"))
        }
    }
}

/// Send a response packet to a client or queue it if the socket buffer is full (EAGAIN).
/// Returns false when the per-client queue exceeds MAX_OUT_QUEUE_LEN: caller must
/// disconnect the stalled client to bound memory.
fn send_or_queue_response(client: &mut ClientInfo, packet: &[u8]) -> bool {
    if client.out_queue.len() >= MAX_OUT_QUEUE_LEN {
        return false;
    }
    if client.out_queue.is_empty() {
        let n = unsafe {
            libc::send(
                client.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if n >= 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            client.out_queue.push_back(packet.to_vec());
            return client.out_queue.len() <= MAX_OUT_QUEUE_LEN;
        }
        // Hard send errors are handled by the caller via disconnect on POLLOUT flush;
        // here we queue so the flush path observes and disconnects on next POLLOUT.
        // To keep behavior simple, report true and let flush disconnect on EPIPE.
        client.out_queue.push_back(packet.to_vec());
        return client.out_queue.len() <= MAX_OUT_QUEUE_LEN;
    }
    client.out_queue.push_back(packet.to_vec());
    client.out_queue.len() <= MAX_OUT_QUEUE_LEN
}

/// Queue an error response for a pending child whose client may be gone; drops if client vanished.
fn respond_to_client(
    clients: &mut HashMap<RawFd, ClientInfo>,
    client_id: u64,
    resp: &protocol::SpawnResponse,
    resp_buf: &mut Vec<u8>,
    overflowed: &mut Vec<RawFd>,
) {
    let _ = protocol::encode_packet_into(resp, resp_buf);
    if let Some((&fd, _)) = clients.iter().find(|(_, c)| c.id == client_id) {
        let ok = clients
            .get_mut(&fd)
            .is_some_and(|c| send_or_queue_response(c, resp_buf));
        if !ok {
            overflowed.push(fd);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // F6: sanitize FDs 0..=2 first so pipe_tx / sockets are always >= 3.
    sanitize_std_fds();

    let allow_uid = parse_allow_uid();

    // O5: self-pipe so SIGINT/SIGTERM wakes poll() instantly (no 1s delay).
    let mut selfpipe_raw = [0 as libc::c_int; 2];
    if unsafe {
        libc::pipe2(
            selfpipe_raw.as_mut_ptr(),
            libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(Box::new(std::io::Error::last_os_error()));
    }
    let shutdown_pipe_rd = unsafe { OwnedFd::from_raw_fd(selfpipe_raw[0]) };
    let shutdown_pipe_wr = unsafe { OwnedFd::from_raw_fd(selfpipe_raw[1]) };
    SHUTDOWN_PIPE_WR.store(shutdown_pipe_wr.as_raw_fd(), Ordering::SeqCst);
    // Keep write end alive for the daemon lifetime (raw stored in static for handler).
    std::mem::forget(shutdown_pipe_wr);

    setup_signals()?;

    // Cache default environment at startup
    let cached_env = CachedEnv::capture();

    // Cache /dev/null descriptor with O_CLOEXEC for child standard I/O redirection
    let devnull_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if devnull_fd < 0 {
        log_warn(&format!(
            "Warning: Failed to open /dev/null (errno: {}), redirection disabled",
            std::io::Error::last_os_error()
        ));
    }

    // Bind Linux abstract namespace SOCK_SEQPACKET socket (\0zygote)
    let listener = create_listener_seqpacket(protocol::DEFAULT_ABSTRACT_NAME)?;
    let listener_fd = listener.as_raw_fd();

    log_info(&format!(
        "Single-threaded process spawner listening on abstract SOCK_SEQPACKET socket @{}",
        String::from_utf8_lossy(protocol::DEFAULT_ABSTRACT_NAME)
    ));

    // Pre-allocated reusable buffers for zero allocations in hot loop
    let mut req_buf = vec![0u8; REQ_BUF_SIZE];
    let mut resp_buf = Vec::with_capacity(512);

    let mut poll_fds: Vec<libc::pollfd> = Vec::with_capacity(2048);
    let mut clients: HashMap<RawFd, ClientInfo> = HashMap::with_capacity(16);
    let mut pending_children: HashMap<RawFd, PendingChild> = HashMap::with_capacity(2048);
    let mut next_client_id: u64 = 1;
    let mut shutdown_start: Option<Instant> = None;
    let mut accept_backoff_until: Option<Instant> = None;

    loop {
        let is_shutting_down = SHUTDOWN.load(Ordering::SeqCst);
        if is_shutting_down {
            let start = *shutdown_start.get_or_insert_with(Instant::now);
            let queues_empty = clients.values().all(|c| c.out_queue.is_empty());
            if (pending_children.is_empty() && queues_empty)
                || start.elapsed() >= SHUTDOWN_DRAIN_TIMEOUT
            {
                break;
            }
        }

        // Expire accept backoff deadline if reached
        if let Some(deadline) = accept_backoff_until {
            if Instant::now() >= deadline {
                accept_backoff_until = None;
            }
        }

        poll_fds.clear();

        // O5: self-pipe first so signals wake poll() immediately.
        poll_fds.push(libc::pollfd {
            fd: shutdown_pipe_rd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });

        // Only listen for new incoming client connections if NOT shutting down and not backed off
        if !is_shutting_down && accept_backoff_until.is_none() {
            poll_fds.push(libc::pollfd {
                fd: listener_fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        // Client polling:
        // - POLLIN if can accept requests and not shutting down
        // - POLLOUT if client has pending outgoing responses in out_queue
        let can_read_clients = !is_shutting_down && (pending_children.len() < MAX_IN_FLIGHT_SPAWNS);
        for (&fd, client) in &clients {
            let mut events = libc::POLLHUP | libc::POLLERR;
            if can_read_clients {
                events |= libc::POLLIN;
            }
            if !client.out_queue.is_empty() {
                events |= libc::POLLOUT;
            }
            poll_fds.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            });
        }

        // Always register in-flight child execve pipes into poll loop
        for &fd in pending_children.keys() {
            poll_fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            });
        }

        // Compute poll timeout: during shutdown drain, bounded by remaining drain window
        let timeout = if is_shutting_down {
            let elapsed = shutdown_start.unwrap().elapsed();
            let remaining =
                SHUTDOWN_DRAIN_TIMEOUT.saturating_sub(elapsed).as_millis() as libc::c_int;
            remaining.clamp(1, 50)
        } else if let Some(deadline) = accept_backoff_until {
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as libc::c_int;
            remaining.clamp(1, 50)
        } else if pending_children.is_empty() && clients.values().all(|c| c.out_queue.is_empty()) {
            1000
        } else {
            50
        };

        let ret = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                timeout,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log_warn(&format!("poll error: {err}"));
            break;
        }

        // O5: drain self-pipe when signaled.
        if let Some(sp) = poll_fds.first() {
            if sp.revents & libc::POLLIN != 0 {
                let mut tmp = [0u8; 64];
                loop {
                    let n = unsafe {
                        libc::read(
                            shutdown_pipe_rd.as_raw_fd(),
                            tmp.as_mut_ptr().cast(),
                            tmp.len(),
                        )
                    };
                    if n <= 0 {
                        break;
                    }
                    if (n as usize) < tmp.len() {
                        break;
                    }
                }
            }
        }

        // --------------------------------------------------------------------
        // PHASE 1: Prioritize processing and draining ready child pipes FIRST
        // --------------------------------------------------------------------
        // F7: O_CLOEXEC EOF semantics: read()==0 means the write end was closed
        // by a successful execve at the kernel CLOEXEC boundary -> success.
        // read()==4 carries the pre-exec errno (dup2/chdir/execve failure).
        // Anything else is a malformed status. See launch_child docs for the
        // SA_NOCLDWAIT caveat (signal death pre-exec also looks like EOF).
        let mut completed_children = Vec::new();
        for pfd in &poll_fds {
            if pfd.revents == 0 {
                continue;
            }
            if pending_children.contains_key(&pfd.fd)
                && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
            {
                completed_children.push(pfd.fd);
            }
        }

        let mut overflowed: Vec<RawFd> = Vec::new();
        for pipe_fd in completed_children {
            if let Some(pending) = pending_children.remove(&pipe_fd) {
                let mut err_buf = [0u8; 4];
                let n = unsafe { libc::read(pipe_fd, err_buf.as_mut_ptr().cast(), 4) };
                let response = match n {
                    0 => protocol::SpawnResponse::success(pending.req_id, pending.child_pid),
                    4 => {
                        let err_code = i32::from_ne_bytes(err_buf);
                        let err_desc = nix::errno::Errno::from_raw(err_code);
                        protocol::SpawnResponse::error(
                            pending.req_id,
                            format!("execve failed: {err_desc} (errno {err_code})"),
                        )
                    }
                    _ => protocol::SpawnResponse::error(
                        pending.req_id,
                        "execve failed: malformed pipe status",
                    ),
                };

                respond_to_client(
                    &mut clients,
                    pending.client_id,
                    &response,
                    &mut resp_buf,
                    &mut overflowed,
                );
            }
        }

        // F5: kill children that never report execve status within 5s.
        {
            let now = Instant::now();
            let expired: Vec<RawFd> = pending_children
                .iter()
                .filter(|(_, p)| now.duration_since(p.spawned_at) >= CHILD_EXEC_TIMEOUT)
                .map(|(&fd, _)| fd)
                .collect();
            for pipe_fd in expired {
                if let Some(pending) = pending_children.remove(&pipe_fd) {
                    unsafe { libc::kill(pending.child_pid, libc::SIGKILL) };
                    // pipe_rx closed here by OwnedFd drop.
                    log_invalid_ratelimited(&format!(
                        "Child {} exec timeout after 5s, SIGKILL sent",
                        pending.child_pid
                    ));
                    let resp = protocol::SpawnResponse::error(
                        pending.req_id,
                        "Child exec timeout (SIGKILL sent after 5s)",
                    );
                    respond_to_client(
                        &mut clients,
                        pending.client_id,
                        &resp,
                        &mut resp_buf,
                        &mut overflowed,
                    );
                }
            }
        }

        // --------------------------------------------------------------------
        // PHASE 2: Flush outgoing queues on POLLOUT and process incoming requests
        // --------------------------------------------------------------------
        let mut disconnected_clients = Vec::new();
        disconnected_clients.extend(overflowed);
        for pfd in &poll_fds {
            if pfd.revents == 0 {
                continue;
            }

            if clients.contains_key(&pfd.fd) {
                let client_fd = pfd.fd;

                if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    disconnected_clients.push(client_fd);
                    continue;
                }

                // 2A: Flush pending outgoing responses if POLLOUT is ready
                if pfd.revents & libc::POLLOUT != 0 {
                    if let Some(client) = clients.get_mut(&client_fd) {
                        while let Some(packet) = client.out_queue.front() {
                            let n = unsafe {
                                libc::send(
                                    client_fd,
                                    packet.as_ptr().cast(),
                                    packet.len(),
                                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                                )
                            };
                            if n >= 0 {
                                client.out_queue.pop_front();
                            } else {
                                let err = std::io::Error::last_os_error();
                                if err.kind() == std::io::ErrorKind::WouldBlock {
                                    break;
                                } else if err.kind() == std::io::ErrorKind::Interrupted {
                                    continue;
                                } else {
                                    disconnected_clients.push(client_fd);
                                    break;
                                }
                            }
                        }
                    }
                }

                // 2B: Read incoming requests if POLLIN is ready
                if pfd.revents & libc::POLLIN != 0 {
                    if disconnected_clients.contains(&client_fd) {
                        continue;
                    }
                    let client_id = clients[&client_fd].id;
                    let mut packets_processed = 0;

                    while packets_processed < MAX_PACKETS_PER_TURN {
                        // F5: strict in-flight cap before every recvmsg iteration.
                        if pending_children.len() >= MAX_IN_FLIGHT_SPAWNS {
                            break;
                        }
                        let mut cmsg_buf = protocol::CmsgBuf::new();
                        let outcome = match protocol::recv_packet_with_fds(
                            client_fd,
                            &mut req_buf,
                            &mut cmsg_buf,
                        ) {
                            Ok(o) => o,
                            Err(err) => {
                                if err.kind() == std::io::ErrorKind::WouldBlock {
                                    break;
                                } else if err.kind() == std::io::ErrorKind::Interrupted {
                                    continue;
                                } else {
                                    disconnected_clients.push(client_fd);
                                    break;
                                }
                            }
                        };

                        packets_processed += 1;
                        // Owned fds; dropped exactly once on every path below.
                        let rec_fds: Vec<OwnedFd> = outcome.fds;

                        // F3: no id prefix -> cannot correlate a reply; close connection.
                        if outcome.reported_len < 8 {
                            disconnected_clients.push(client_fd);
                            break;
                        }
                        let prefix_len = outcome.reported_len.min(req_buf.len());
                        let req_id_opt =
                            protocol::extract_req_id(&req_buf[..prefix_len]);

                        // CTRUNC: ancillary data incomplete; fds already dropped.
                        if outcome.ctrunc {
                            log_invalid_ratelimited("Ancillary data truncated (MSG_CTRUNC)");
                            match req_id_opt {
                                Some(req_id) => {
                                    let resp = protocol::SpawnResponse::error(
                                        req_id,
                                        "Ancillary data truncated (MSG_CTRUNC)",
                                    );
                                    let _ = protocol::encode_packet_into(&resp, &mut resp_buf);
                                    if let Some(client) = clients.get_mut(&client_fd) {
                                        if !send_or_queue_response(client, &resp_buf) {
                                            disconnected_clients.push(client_fd);
                                            break;
                                        }
                                    }
                                }
                                None => {
                                    disconnected_clients.push(client_fd);
                                    break;
                                }
                            }
                            break;
                        }

                        if outcome.truncated {
                            log_invalid_ratelimited(&format!(
                                "Truncated packet received (length: {} > max {})",
                                outcome.reported_len,
                                req_buf.len()
                            ));
                            match req_id_opt {
                                Some(req_id) => {
                                    let resp = protocol::SpawnResponse::error(
                                        req_id,
                                        "Payload exceeds max packet size",
                                    );
                                    let _ = protocol::encode_packet_into(&resp, &mut resp_buf);
                                    if let Some(client) = clients.get_mut(&client_fd) {
                                        if !send_or_queue_response(client, &resp_buf) {
                                            disconnected_clients.push(client_fd);
                                            break;
                                        }
                                    }
                                }
                                None => {
                                    disconnected_clients.push(client_fd);
                                    break;
                                }
                            }
                            break;
                        }

                        let packet = &req_buf[..outcome.reported_len];
                        match protocol::decode_packet::<protocol::SpawnRequest>(packet) {
                            Ok(request) => {
                                let expected_fds = request.expected_fd_count();
                                if rec_fds.len() != expected_fds {
                                    let err_msg = format!(
                                        "Mismatched SCM_RIGHTS FD count: expected {}, got {}",
                                        expected_fds,
                                        rec_fds.len()
                                    );
                                    let resp =
                                        protocol::SpawnResponse::error(request.id, err_msg);
                                    let _ = protocol::encode_packet_into(&resp, &mut resp_buf);
                                    if let Some(client) = clients.get_mut(&client_fd) {
                                        if !send_or_queue_response(client, &resp_buf) {
                                            disconnected_clients.push(client_fd);
                                            break;
                                        }
                                    }
                                    continue;
                                }

                                // Split owned fds in wire order: stdin, stdout, stderr.
                                let mut owned_iter = rec_fds.into_iter();
                                let stdin_fd =
                                    if request.pass_stdin { owned_iter.next() } else { None };
                                let stdout_fd =
                                    if request.pass_stdout { owned_iter.next() } else { None };
                                let stderr_fd =
                                    if request.pass_stderr { owned_iter.next() } else { None };

                                match launch_child(
                                    &request,
                                    stdin_fd,
                                    stdout_fd,
                                    stderr_fd,
                                    devnull_fd,
                                    &cached_env,
                                ) {
                                    Ok((pipe_rx, child_pid)) => {
                                        let pipe_fd = pipe_rx.as_raw_fd();
                                        pending_children.insert(
                                            pipe_fd,
                                            PendingChild {
                                                _pipe_rx: pipe_rx,
                                                client_id,
                                                req_id: request.id,
                                                child_pid,
                                                spawned_at: Instant::now(),
                                            },
                                        );
                                    }
                                    Err(err_msg) => {
                                        let resp =
                                            protocol::SpawnResponse::error(request.id, err_msg);
                                        let _ = protocol::encode_packet_into(&resp, &mut resp_buf);
                                        if let Some(client) = clients.get_mut(&client_fd) {
                                            if !send_or_queue_response(client, &resp_buf) {
                                                disconnected_clients.push(client_fd);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // F3: never hang: reply with extracted req_id when available.
                                log_invalid_ratelimited(&format!(
                                    "Packet deserialization error: {e}"
                                ));
                                match req_id_opt {
                                    Some(req_id) => {
                                        let resp = protocol::SpawnResponse::error(
                                            req_id,
                                            format!("Invalid packet: {e}"),
                                        );
                                        let _ =
                                            protocol::encode_packet_into(&resp, &mut resp_buf);
                                        if let Some(client) = clients.get_mut(&client_fd) {
                                            if !send_or_queue_response(client, &resp_buf) {
                                                disconnected_clients.push(client_fd);
                                                break;
                                            }
                                        }
                                    }
                                    None => {
                                        disconnected_clients.push(client_fd);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Remove disconnected clients (F8: includes out_queue overflow victims).
        for fd in disconnected_clients {
            clients.remove(&fd);
        }

        // --------------------------------------------------------------------
        // PHASE 3: Process listener socket with strict UID access control (F1)
        // --------------------------------------------------------------------
        let listener_ready = poll_fds
            .iter()
            .find(|p| p.fd == listener_fd)
            .is_some_and(|p| p.revents & libc::POLLIN != 0);

        if !is_shutting_down && listener_ready {
            let client_raw = unsafe {
                libc::accept4(
                    listener_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            };

            if client_raw >= 0 {
                protocol::configure_socket_buffers(client_raw);

                // F1: strictly enforce peer uid == daemon euid (optional --allow-uid).
                // No root bypass: a root daemon rejects unprivileged peers by default.
                let my_euid = unsafe { libc::geteuid() };
                let peer_ok = match protocol::peer_cred_uid(client_raw) {
                    Ok(peer_uid) => {
                        protocol::peer_uid_allowed(peer_uid, my_euid, allow_uid)
                    }
                    Err(_) => false,
                };
                if !peer_ok {
                    let peer_desc = match protocol::peer_cred_uid(client_raw) {
                        Ok(u) => u.to_string(),
                        Err(_) => "unknown".to_string(),
                    };
                    log_warn(&format!(
                        "Rejecting connection: peer UID {peer_desc} != server EUID {my_euid}"
                    ));
                    unsafe { libc::close(client_raw) };
                } else {
                    let client_fd = unsafe { OwnedFd::from_raw_fd(client_raw) };
                    clients.insert(
                        client_raw,
                        ClientInfo {
                            id: next_client_id,
                            fd: client_fd,
                            out_queue: VecDeque::with_capacity(16),
                        },
                    );
                    next_client_id += 1;
                }
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EMFILE)
                    || err.raw_os_error() == Some(libc::ENFILE)
                {
                    log_warn(&format!("FD limit reached in accept4 ({err}), backing off 50ms"));
                    accept_backoff_until = Some(Instant::now() + Duration::from_millis(50));
                } else if err.kind() != std::io::ErrorKind::WouldBlock
                    && err.kind() != std::io::ErrorKind::Interrupted
                {
                    log_warn(&format!("accept error: {err}"));
                }
            }
        }
    }

    if devnull_fd >= 0 {
        unsafe { libc::close(devnull_fd) };
    }

    log_info("Daemon stopped gracefully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn test_getdents64() {
        let dir_fd = unsafe {
            libc::open(
                c"/proc/self/fd".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
        };
        assert!(
            dir_fd >= 0,
            "open /proc/self/fd failed: {}",
            std::io::Error::last_os_error()
        );
        let mut buf = [0u8; 1024];
        let mut parsed_fds = Vec::new();
        loop {
            let n =
                unsafe { libc::syscall(libc::SYS_getdents64, dir_fd, buf.as_mut_ptr(), buf.len()) };
            if n <= 0 {
                break;
            }
            let mut bpos = 0usize;
            let nread = n as usize;
            while bpos < nread {
                if bpos + 19 > nread {
                    break;
                }
                let d_reclen = u16::from_ne_bytes([buf[bpos + 16], buf[bpos + 17]]) as usize;
                if d_reclen == 0 || bpos + d_reclen > nread {
                    break;
                }
                let name_start = bpos + 19;
                let mut p = name_start;
                let mut fd: libc::c_int = 0;
                let mut valid = false;
                while p < bpos + d_reclen && buf[p] != 0 {
                    let b = buf[p];
                    if b.is_ascii_digit() {
                        fd = fd * 10 + (b - b'0') as libc::c_int;
                        valid = true;
                        p += 1;
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid {
                    parsed_fds.push(fd);
                }
                bpos += d_reclen;
            }
        }
        unsafe { libc::close(dir_fd) };
        assert!(
            !parsed_fds.is_empty(),
            "Should find open FDs in /proc/self/fd"
        );
        assert!(parsed_fds.contains(&0) || parsed_fds.contains(&1) || parsed_fds.contains(&2));
    }

    #[test]
    fn test_send_recv_fds_shared_helpers() {
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

        let sock_tx = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let sock_rx = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let mut pipe_fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let p_rx = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let p_tx = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        let sent = protocol::send_packet_with_fds(
            sock_tx.as_raw_fd(),
            b"hello",
            &[p_tx.as_raw_fd()],
        )
        .expect("send");
        assert_eq!(sent, 5);
        drop(p_tx);

        let mut recv_buf = [0u8; 64];
        let mut cmsg = protocol::CmsgBuf::new();
        let out =
            protocol::recv_packet_with_fds(sock_rx.as_raw_fd(), &mut recv_buf, &mut cmsg)
                .expect("recv");
        assert_eq!(out.reported_len, 5);
        assert_eq!(&recv_buf[..5], b"hello");
        assert_eq!(out.fds.len(), 1);

        let flags = unsafe { libc::fcntl(out.fds[0].as_raw_fd(), libc::F_GETFD) };
        assert!(flags & libc::FD_CLOEXEC != 0);

        assert_eq!(
            unsafe { libc::write(out.fds[0].as_raw_fd(), b"ping".as_ptr().cast(), 4) },
            4
        );
        let mut p_buf = [0u8; 4];
        assert_eq!(
            unsafe { libc::read(p_rx.as_raw_fd(), p_buf.as_mut_ptr().cast(), 4) },
            4
        );
        assert_eq!(&p_buf, b"ping");
    }

    fn make_owned_pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn test_stdio_guard_close_on_drop() {
        let (rx, tx) = make_owned_pipe();
        let rx_raw = rx.as_raw_fd();
        {
            let _guard = StdioGuard::new(Some(tx), None, None);
        }
        let mut buf = [0u8; 1];
        let n = unsafe { libc::read(rx_raw, buf.as_mut_ptr().cast(), 1) };
        assert_eq!(n, 0, "Reading from pipe after guard drop should return EOF");
    }

    #[test]
    fn test_stdio_guard_disarm() {
        let (rx, tx) = make_owned_pipe();
        let tx_raw;
        {
            let mut guard = StdioGuard::new(Some(tx), None, None);
            tx_raw = guard.stdin_fd.as_ref().unwrap().as_raw_fd();
            guard.disarm();
            // Disarmed guard drops without closing: tx_raw stays open.
        }
        assert_eq!(unsafe { libc::write(tx_raw, b"a".as_ptr().cast(), 1) }, 1);
        let mut buf = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(rx.as_raw_fd(), buf.as_mut_ptr().cast(), 1) },
            1
        );
        assert_eq!(buf[0], b'a');
        unsafe {
            libc::close(tx_raw);
        }
    }

    #[test]
    fn test_cmsg_buf_alignment() {
        assert!(std::mem::align_of::<protocol::CmsgBuf>() >= 8);
        assert!(
            std::mem::align_of::<protocol::CmsgBuf>() >= std::mem::align_of::<libc::cmsghdr>()
        );
    }

    #[test]
    fn test_expected_fd_count() {
        let mut req = protocol::SpawnRequest::new(1, "/bin/echo", vec![]);
        req.pass_stdin = true;
        req.pass_stdout = true;
        req.pass_stderr = false;
        assert_eq!(req.expected_fd_count(), 2);

        let req_none = protocol::SpawnRequest::new(2, "/bin/echo", vec![]);
        assert_eq!(req_none.expected_fd_count(), 0);
    }

    #[test]
    fn test_out_queue_cap() {
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
        let fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let mut client = ClientInfo {
            id: 1,
            fd,
            out_queue: VecDeque::with_capacity(16),
        };
        // Fill socket buffer so send() hits EAGAIN: use large packets until queued.
        let big = vec![0u8; 32768];
        for _ in 0..300 {
            if !send_or_queue_response(&mut client, &big) {
                break;
            }
            if !client.out_queue.is_empty() {
                // Once queueing starts, keep filling to the cap.
                continue;
            }
        }
        // Force-fill to cap to verify bound independent of kernel buffer state.
        while client.out_queue.len() < MAX_OUT_QUEUE_LEN {
            client.out_queue.push_back(vec![1u8; 8]);
        }
        assert_eq!(client.out_queue.len(), MAX_OUT_QUEUE_LEN);
        assert!(!send_or_queue_response(&mut client, &[1u8; 8]));
    }
}
