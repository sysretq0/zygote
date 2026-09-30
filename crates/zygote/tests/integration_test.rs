//! Daemon-level integration tests: boot the real `zygote` binary on
//! `@zygote` and exercise spawn, `SCM_RIGHTS` stdio, env/cwd, concurrency,
//! multiplexed correlation, and malformed-packet survival.
//!
//! Tests hold a global lock and each spawns its own daemon, so state never
//! leaks between tests in this process.

use protocol::{SpawnRequest, SpawnResponse};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

static SUITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn suite_lock() -> std::sync::MutexGuard<'static, ()> {
    SUITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Daemon {
    child: std::process::Child,
}

impl Daemon {
    fn start() -> Self {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_zygote"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn zygote");
        let start = Instant::now();
        loop {
            if connect().is_ok() {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "zygote never listened"
            );
            if let Ok(Some(status)) = child.try_wait() {
                panic!("zygote exited early with {status}");
            }
            thread::sleep(Duration::from_millis(50));
        }
        // Functional probe: a stale/broken holder may listen without
        // serving (accept-and-close). Any failure panics loudly here
        // instead of surfacing as a confusing timeout mid-test.
        if let Ok(conn) = connect() {
            let r = spawn_req(
                conn.as_fd(),
                u64::MAX - 1,
                "/bin/true",
                vec!["true".into()],
                Vec::new(),
                None,
                &[None, None, None],
            );
            assert!(r.result.is_ok(), "stale/broken daemon holding @zygote");
        }
        Self { child }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn connect() -> Result<OwnedFd, std::io::Error> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let name = protocol::DEFAULT_ABSTRACT_NAME;
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            addr.sun_path.as_mut_ptr().cast::<u8>().add(1),
            name.len(),
        );
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
    if unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn spawn_req(
    fd: BorrowedFd<'_>,
    id: u64,
    path: &str,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    stdio: &[Option<RawFd>; 3],
) -> SpawnResponse {
    let mut req = SpawnRequest::new(id, path, args);
    req.env = env;
    req.cwd = cwd;
    req.pass_stdin = stdio[0].is_some();
    req.pass_stdout = stdio[1].is_some();
    req.pass_stderr = stdio[2].is_some();
    let packet = protocol::encode_packet(&req).expect("encode");
    let fds: Vec<RawFd> = stdio.iter().filter_map(|f| *f).collect();
    protocol::send_packet_with_fds(fd.as_raw_fd(), &packet, &fds).expect("send");
    let mut rx = vec![0u8; protocol::MAX_PACKET_SIZE];
    let mut cmsg = protocol::CmsgBuf::new();
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no spawn response"
        );
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut pfd, 1, 2000) } > 0);
        let out = protocol::recv_packet_with_fds(fd.as_raw_fd(), &mut rx, &mut cmsg).expect("recv");
        assert!(!out.truncated, "truncated spawn response");
        let resp: SpawnResponse =
            protocol::decode_packet(&rx[..out.reported_len.min(rx.len())]).expect("decode");
        if resp.id == id {
            return resp;
        }
        // Not ours (shouldn't happen on a private connection, but skip robustly).
    }
}

fn read_to_end(fd: RawFd, timeout: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    let start = Instant::now();
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
        assert!(start.elapsed() < timeout);
    }
    out
}

#[test]
fn spawn_true_and_bad_binary() {
    let _lock = suite_lock();
    let _daemon = Daemon::start();
    let conn = connect().expect("connect");
    let r = spawn_req(
        conn.as_fd(),
        1,
        "/bin/true",
        vec!["true".into()],
        Vec::new(),
        None,
        &[None, None, None],
    );
    assert_eq!(r.id, 1);
    assert!(r.result.is_ok(), "true failed: {r:?}");

    let r = spawn_req(
        conn.as_fd(),
        2,
        "/bin/definitely_not_a_real_binary_xyz",
        Vec::new(),
        Vec::new(),
        None,
        &[None, None, None],
    );
    assert_eq!(r.id, 2);
    assert!(r.result.is_err(), "bad binary unexpectedly ok: {r:?}");
}

#[test]
fn spawn_echo_stdio_env_cwd() {
    let _lock = suite_lock();
    let _daemon = Daemon::start();
    let conn = connect().expect("connect");

    // stdout capture via SCM_RIGHTS.
    let mut pf = [0; 2];
    assert_eq!(unsafe { libc::pipe(pf.as_mut_ptr()) }, 0);
    let r = spawn_req(
        conn.as_fd(),
        10,
        "/bin/echo",
        vec!["echo".into(), "hello-zygote".into()],
        Vec::new(),
        None,
        &[None, Some(pf[1]), None],
    );
    assert!(r.result.is_ok(), "{r:?}");
    unsafe { libc::close(pf[1]) };
    let out = read_to_end(pf[0], Duration::from_secs(10));
    unsafe { libc::close(pf[0]) };
    assert_eq!(out, b"hello-zygote\n");

    // env passthrough via /bin/sh.
    let mut pf = [0; 2];
    assert_eq!(unsafe { libc::pipe(pf.as_mut_ptr()) }, 0);
    let r = spawn_req(
        conn.as_fd(),
        11,
        "/bin/sh",
        vec!["sh".into(), "-c".into(), "echo $E2E_FOO".into()],
        vec![("E2E_FOO".into(), "bar".into())],
        None,
        &[None, Some(pf[1]), None],
    );
    assert!(r.result.is_ok(), "{r:?}");
    unsafe { libc::close(pf[1]) };
    let out = read_to_end(pf[0], Duration::from_secs(10));
    unsafe { libc::close(pf[0]) };
    assert_eq!(out, b"bar\n");

    // cwd via /bin/pwd.
    let mut pf = [0; 2];
    assert_eq!(unsafe { libc::pipe(pf.as_mut_ptr()) }, 0);
    let r = spawn_req(
        conn.as_fd(),
        12,
        "/bin/pwd",
        vec!["pwd".into()],
        Vec::new(),
        Some("/tmp".into()),
        &[None, Some(pf[1]), None],
    );
    assert!(r.result.is_ok(), "{r:?}");
    unsafe { libc::close(pf[1]) };
    let out = read_to_end(pf[0], Duration::from_secs(10));
    unsafe { libc::close(pf[0]) };
    assert_eq!(out, b"/tmp\n");
}

#[test]
fn concurrent_spawns_multiplexed() {
    let _lock = suite_lock();
    let _daemon = Daemon::start();
    let mut handles = Vec::new();
    for i in 0..8u64 {
        handles.push(thread::spawn(move || {
            let conn = connect().expect("connect");
            // Two pipelined requests per connection: correlation must hold.
            for k in 0..2u64 {
                let id = i * 10 + k + 1;
                let r = spawn_req(
                    conn.as_fd(),
                    id,
                    "/bin/true",
                    vec!["true".into()],
                    Vec::new(),
                    None,
                    &[None, None, None],
                );
                assert_eq!(r.id, id);
                assert!(r.result.is_ok(), "{r:?}");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn malformed_packet_survives() {
    let _lock = suite_lock();
    let _daemon = Daemon::start();
    let conn = connect().expect("connect");
    // Garbage that is not a valid SpawnRequest: daemon must stay up.
    let junk = b"\xff\xff\xff\xff-not-a-packet";
    let n = unsafe {
        libc::send(
            conn.as_raw_fd(),
            junk.as_ptr().cast(),
            junk.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    assert_eq!(n, junk.len() as isize);
    thread::sleep(Duration::from_millis(300));
    // Daemon still serves afterwards.
    let r = spawn_req(
        conn.as_fd(),
        99,
        "/bin/true",
        vec!["true".into()],
        Vec::new(),
        None,
        &[None, None, None],
    );
    assert_eq!(r.id, 99);
    assert!(r.result.is_ok(), "{r:?}");
}
