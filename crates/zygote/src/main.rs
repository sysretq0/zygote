use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Maximum number of in-flight spawned children awaiting execve confirmation before applying backpressure.
const MAX_IN_FLIGHT_SPAWNS: usize = 128;

/// Maximum duration to drain pending children when shutdown signal is received.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum buffer size for a single SEQPACKET payload (64 KB).
const REQ_BUF_SIZE: usize = 65536;

/// Socket send/receive buffer size (256 KB) to prevent EAGAIN under burst conditions.
const SOCKET_BUFFER_SIZE: libc::c_int = 256 * 1024;

/// Maximum number of packets processed from a single client per poll turn to prevent starvation.
const MAX_PACKETS_PER_TURN: usize = 32;

/// Ancillary control message buffer aligned to 8 bytes (size_t / cmsghdr alignment).
#[repr(align(8))]
struct CmsgBuf([u8; 64]);

impl CmsgBuf {
    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Global shutdown signal flag set by SIGINT or SIGTERM handler.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// C-ABI signal handler for graceful shutdown.
extern "C" fn sig_term_handler(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
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

/// Tracking metadata for an in-flight child process awaiting execve completion.
struct PendingChild {
    _pipe_rx: OwnedFd,
    client_id: u64,
    req_id: u64,
    child_pid: i32,
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

/// Sets SO_SNDBUF and SO_RCVBUF to 256 KB on a socket.
fn configure_socket_buffers(fd: RawFd) {
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

    configure_socket_buffers(fd);

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
            addr.sun_path.as_mut_ptr().add(1) as *mut u8,
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

/// Child process logic executed immediately after fork().
/// Does not return: always invokes execve() or exits with _exit(127).
/// Performs ZERO heap allocations.
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
            let err = *libc::__errno_location();
            libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
            libc::_exit(127);
        }
    } else if redirect_null && devnull_fd >= 0 {
        libc::dup2(devnull_fd, libc::STDIN_FILENO);
    }

    if let Some(fd) = stdout_fd {
        if libc::dup2(fd, libc::STDOUT_FILENO) < 0 {
            let err = *libc::__errno_location();
            libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
            libc::_exit(127);
        }
    } else if redirect_null && devnull_fd >= 0 {
        libc::dup2(devnull_fd, libc::STDOUT_FILENO);
    }

    if let Some(fd) = stderr_fd {
        if libc::dup2(fd, libc::STDERR_FILENO) < 0 {
            let err = *libc::__errno_location();
            libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
            libc::_exit(127);
        }
    } else if redirect_null && devnull_fd >= 0 {
        libc::dup2(devnull_fd, libc::STDERR_FILENO);
    }

    // 3. Change working directory if specified
    if let Some(dir) = cwd_ptr {
        if libc::chdir(dir) < 0 {
            let err = *libc::__errno_location();
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
    let err = *libc::__errno_location();
    libc::write(pipe_tx_raw, (&err as *const i32).cast(), 4);
    libc::_exit(127);
}

/// RAII guard to ensure passed stdio descriptors are closed on early return, error, or parent post-fork,
/// unless explicitly disarmed in the child process.
struct StdioGuard {
    stdin_fd: Option<i32>,
    stdout_fd: Option<i32>,
    stderr_fd: Option<i32>,
    disarmed: bool,
}

impl StdioGuard {
    fn new(stdin_fd: Option<i32>, stdout_fd: Option<i32>, stderr_fd: Option<i32>) -> Self {
        Self {
            stdin_fd,
            stdout_fd,
            stderr_fd,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }

    fn close(&mut self) {
        if !self.disarmed {
            if let Some(fd) = self.stdin_fd.take() {
                unsafe { libc::close(fd) };
            }
            if let Some(fd) = self.stdout_fd.take() {
                unsafe { libc::close(fd) };
            }
            if let Some(fd) = self.stderr_fd.take() {
                unsafe { libc::close(fd) };
            }
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
fn launch_child(
    request: &protocol::SpawnRequest,
    stdin_fd: Option<i32>,
    stdout_fd: Option<i32>,
    stderr_fd: Option<i32>,
    devnull_fd: i32,
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

    // Create an O_CLOEXEC synchronization pipe (with pre-2.6.27 fallback)
    let (pipe_rx, pipe_tx) = create_pipe_cloexec()?;

    let pipe_tx_raw = pipe_tx.as_raw_fd();
    let cwd_ptr = cwd_c.as_ref().map(|c| c.as_ptr());
    let path_ptr = path_c.as_ptr();
    let redirect_null = request.redirect_null;
    let new_session = request.new_session;

    let fork_res = unsafe { nix::unistd::fork() };

    match fork_res {
        Ok(nix::unistd::ForkResult::Child) => {
            drop(pipe_rx);
            stdio_guard.disarm();
            unsafe {
                child_exec(
                    redirect_null,
                    new_session,
                    stdin_fd,
                    stdout_fd,
                    stderr_fd,
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
fn send_or_queue_response(client: &mut ClientInfo, packet: &[u8]) {
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
            return;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            client.out_queue.push_back(packet.to_vec());
            return;
        }
    } else {
        client.out_queue.push_back(packet.to_vec());
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_signals()?;

    // Cache default environment at startup
    let cached_env = CachedEnv::capture();

    // Cache /dev/null descriptor with O_CLOEXEC for child standard I/O redirection
    let devnull_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if devnull_fd < 0 {
        eprintln!(
            "[zygote] Warning: Failed to open /dev/null (errno: {}), redirection disabled",
            std::io::Error::last_os_error()
        );
    }

    // Bind Linux abstract namespace SOCK_SEQPACKET socket (\0zygote)
    let listener = create_listener_seqpacket(protocol::DEFAULT_ABSTRACT_NAME)?;
    let listener_fd = listener.as_raw_fd();

    println!(
        "[zygote] Single-threaded process spawner listening on abstract SOCK_SEQPACKET socket @{}",
        String::from_utf8_lossy(protocol::DEFAULT_ABSTRACT_NAME)
    );

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
            remaining.min(50).max(1)
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
            eprintln!("[zygote] poll error: {err}");
            break;
        }

        // --------------------------------------------------------------------
        // PHASE 1: Prioritize processing and draining ready child pipes FIRST
        // --------------------------------------------------------------------
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

                // Find destination client and send or queue response packet
                if let Some(client) = clients.values_mut().find(|c| c.id == pending.client_id) {
                    let _ = protocol::encode_packet_into(&response, &mut resp_buf);
                    send_or_queue_response(client, &resp_buf);
                }
            }
        }

        // --------------------------------------------------------------------
        // PHASE 2: Flush outgoing queues on POLLOUT and process incoming requests
        // --------------------------------------------------------------------
        let mut disconnected_clients = Vec::new();
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
                    let client_id = clients[&client_fd].id;
                    let mut packets_processed = 0;

                    while packets_processed < MAX_PACKETS_PER_TURN {
                        let mut req_iov = libc::iovec {
                            iov_base: req_buf.as_mut_ptr().cast(),
                            iov_len: req_buf.len(),
                        };
                        let mut cmsg_buf = CmsgBuf([0u8; 64]);
                        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                        msg.msg_iov = &mut req_iov;
                        msg.msg_iovlen = 1;
                        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
                        msg.msg_controllen = cmsg_buf.len();

                        let n = unsafe {
                            libc::recvmsg(
                                client_fd,
                                &mut msg,
                                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
                            )
                        };

                        if n == 0 {
                            disconnected_clients.push(client_fd);
                            break;
                        } else if n < 0 {
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

                        packets_processed += 1;

                        // Extract any passed SCM_RIGHTS file descriptors
                        let mut rec_fds = Vec::new();
                        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                        while !cmsg.is_null() {
                            unsafe {
                                if (*cmsg).cmsg_level == libc::SOL_SOCKET
                                    && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                                {
                                    let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                                    let base_len = libc::CMSG_LEN(0) as usize;
                                    if (*cmsg).cmsg_len >= base_len {
                                        let num_fds = ((*cmsg).cmsg_len - base_len)
                                            / std::mem::size_of::<libc::c_int>();
                                        for i in 0..num_fds {
                                            rec_fds.push(*data_ptr.add(i));
                                        }
                                    }
                                }
                                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                            }
                        }

                        // Check if control data was truncated (F4)
                        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
                            for fd in rec_fds {
                                unsafe { libc::close(fd) };
                            }
                            eprintln!("[zygote] Ancillary data truncated (MSG_CTRUNC)");
                            let resp = protocol::SpawnResponse::error(
                                0,
                                "Ancillary data truncated (MSG_CTRUNC)",
                            );
                            let _ = protocol::encode_packet_into(&resp, &mut resp_buf);
                            if let Some(client) = clients.get_mut(&client_fd) {
                                send_or_queue_response(client, &resp_buf);
                            }
                            break;
                        }

                        // Detect truncated packets via MSG_TRUNC (Refinement 2)
                        let is_truncated =
                            (n as usize) > req_buf.len() || (msg.msg_flags & libc::MSG_TRUNC != 0);

                        if is_truncated {
                            for fd in rec_fds {
                                unsafe { libc::close(fd) };
                            }
                            eprintln!(
                                "[zygote] Truncated packet received (length: {n} > max {})",
                                req_buf.len()
                            );
                            let resp = protocol::SpawnResponse::error(
                                0,
                                "Payload exceeds max packet size",
                            );
                            let _ = protocol::encode_packet_into(&resp, &mut resp_buf);
                            if let Some(client) = clients.get_mut(&client_fd) {
                                send_or_queue_response(client, &resp_buf);
                            }
                            break;
                        }

                        let packet = &req_buf[..n as usize];
                        match protocol::decode_packet::<protocol::SpawnRequest>(packet) {
                            Ok(request) => {
                                let expected_fds = request.expected_fd_count();
                                if rec_fds.len() != expected_fds {
                                    let err_msg = format!(
                                        "Mismatched SCM_RIGHTS FD count: expected {}, got {}",
                                        expected_fds,
                                        rec_fds.len()
                                    );
                                    for fd in rec_fds {
                                        unsafe { libc::close(fd) };
                                    }
                                    let resp = protocol::SpawnResponse::error(request.id, err_msg);
                                    let _ = protocol::encode_packet_into(&resp, &mut resp_buf);
                                    if let Some(client) = clients.get_mut(&client_fd) {
                                        send_or_queue_response(client, &resp_buf);
                                    }
                                    continue;
                                }

                                let mut fd_idx = 0;
                                let stdin_fd = if request.pass_stdin {
                                    let fd = rec_fds[fd_idx];
                                    fd_idx += 1;
                                    Some(fd)
                                } else {
                                    None
                                };
                                let stdout_fd = if request.pass_stdout {
                                    let fd = rec_fds[fd_idx];
                                    fd_idx += 1;
                                    Some(fd)
                                } else {
                                    None
                                };
                                let stderr_fd = if request.pass_stderr {
                                    let fd = rec_fds[fd_idx];
                                    Some(fd)
                                } else {
                                    None
                                };

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
                                            },
                                        );
                                    }
                                    Err(err_msg) => {
                                        let resp =
                                            protocol::SpawnResponse::error(request.id, err_msg);
                                        let _ = protocol::encode_packet_into(&resp, &mut resp_buf);
                                        if let Some(client) = clients.get_mut(&client_fd) {
                                            send_or_queue_response(client, &resp_buf);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                for fd in rec_fds {
                                    unsafe { libc::close(fd) };
                                }
                                eprintln!("[zygote] Packet deserialization error: {e}");
                            }
                        }

                        if pending_children.len() >= MAX_IN_FLIGHT_SPAWNS {
                            break;
                        }
                    }
                }
            }
        }

        // Remove disconnected clients
        for fd in disconnected_clients {
            clients.remove(&fd);
        }

        // --------------------------------------------------------------------
        // PHASE 3: Process listener socket with UID access control
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
                configure_socket_buffers(client_raw);

                // Verify peer credentials via SO_PEERCRED
                let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
                let mut len: libc::socklen_t =
                    std::mem::size_of::<libc::ucred>() as libc::socklen_t;
                let ret = unsafe {
                    libc::getsockopt(
                        client_raw,
                        libc::SOL_SOCKET,
                        libc::SO_PEERCRED,
                        (&mut ucred as *mut libc::ucred).cast(),
                        &mut len,
                    )
                };

                let my_euid = unsafe { libc::geteuid() };
                if ret < 0 || (my_euid != 0 && ucred.uid != my_euid) {
                    eprintln!(
                        "[zygote] Rejecting connection: peer UID {} != server EUID {}",
                        ucred.uid, my_euid
                    );
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
                    eprintln!("[zygote] FD limit reached in accept4 ({err}), backing off 50ms");
                    accept_backoff_until = Some(Instant::now() + Duration::from_millis(50));
                } else if err.kind() != std::io::ErrorKind::WouldBlock
                    && err.kind() != std::io::ErrorKind::Interrupted
                {
                    eprintln!("[zygote] accept error: {err}");
                }
            }
        }
    }

    if devnull_fd >= 0 {
        unsafe { libc::close(devnull_fd) };
    }

    println!("[zygote] Daemon stopped gracefully.");
    Ok(())
}

#[cfg(test)]
mod tests {
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
    fn test_send_recv_fds() {
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

        let (sock_tx, sock_rx) = (fds[0], fds[1]);

        let mut pipe_fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let (p_rx, p_tx) = (pipe_fds[0], pipe_fds[1]);

        let payload = b"hello";
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };

        let mut cmsg_buf = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;

        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
            std::ptr::copy_nonoverlapping(
                &p_tx as *const libc::c_int,
                libc::CMSG_DATA(cmsg).cast(),
                1,
            );
        }

        let sent = unsafe { libc::sendmsg(sock_tx, &msg, 0) };
        assert_eq!(sent, 5);

        let mut recv_buf = [0u8; 64];
        let mut recv_iov = libc::iovec {
            iov_base: recv_buf.as_mut_ptr().cast(),
            iov_len: recv_buf.len(),
        };
        let mut recv_cmsg_buf = [0u8; 64];
        let mut recv_msg: libc::msghdr = unsafe { std::mem::zeroed() };
        recv_msg.msg_iov = &mut recv_iov;
        recv_msg.msg_iovlen = 1;
        recv_msg.msg_control = recv_cmsg_buf.as_mut_ptr().cast();
        recv_msg.msg_controllen = recv_cmsg_buf.len();

        let n = unsafe { libc::recvmsg(sock_rx, &mut recv_msg, libc::MSG_CMSG_CLOEXEC) };
        assert_eq!(n, 5);
        assert_eq!(&recv_buf[..5], b"hello");

        let rec_cmsg = unsafe { libc::CMSG_FIRSTHDR(&recv_msg) };
        assert!(!rec_cmsg.is_null());
        assert_eq!(unsafe { (*rec_cmsg).cmsg_level }, libc::SOL_SOCKET);
        assert_eq!(unsafe { (*rec_cmsg).cmsg_type }, libc::SCM_RIGHTS);
        let rec_fd: libc::c_int = unsafe { *(libc::CMSG_DATA(rec_cmsg) as *const libc::c_int) };
        assert!(rec_fd >= 0);

        let flags = unsafe { libc::fcntl(rec_fd, libc::F_GETFD) };
        assert!(flags & libc::FD_CLOEXEC != 0);

        assert_eq!(
            unsafe { libc::write(rec_fd, b"ping".as_ptr().cast(), 4) },
            4
        );
        let mut p_buf = [0u8; 4];
        assert_eq!(unsafe { libc::read(p_rx, p_buf.as_mut_ptr().cast(), 4) }, 4);
        assert_eq!(&p_buf, b"ping");

        unsafe {
            libc::close(sock_tx);
            libc::close(sock_rx);
            libc::close(p_rx);
            libc::close(p_tx);
            libc::close(rec_fd);
        }
    }

    #[test]
    fn test_stdio_guard_close_on_drop() {
        let mut pipe_fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let (rx, tx) = (pipe_fds[0], pipe_fds[1]);

        {
            let _guard = super::StdioGuard::new(Some(tx), None, None);
            // _guard dropped here, closing tx
        }

        let mut buf = [0u8; 1];
        let n = unsafe { libc::read(rx, buf.as_mut_ptr().cast(), 1) };
        assert_eq!(n, 0, "Reading from pipe after guard drop should return EOF");
        unsafe { libc::close(rx) };
    }

    #[test]
    fn test_stdio_guard_disarm() {
        let mut pipe_fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let (rx, tx) = (pipe_fds[0], pipe_fds[1]);

        {
            let mut guard = super::StdioGuard::new(Some(tx), None, None);
            guard.disarm();
            // _guard dropped here without closing tx
        }

        assert_eq!(unsafe { libc::write(tx, b"a".as_ptr().cast(), 1) }, 1);
        let mut buf = [0u8; 1];
        assert_eq!(unsafe { libc::read(rx, buf.as_mut_ptr().cast(), 1) }, 1);
        assert_eq!(buf[0], b'a');

        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    }

    #[test]
    fn test_cmsg_buf_alignment() {
        assert!(std::mem::align_of::<super::CmsgBuf>() >= 8);
        assert!(std::mem::align_of::<super::CmsgBuf>() >= std::mem::align_of::<libc::cmsghdr>());
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
}
