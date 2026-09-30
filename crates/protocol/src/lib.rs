use bincode::Options;
use serde::{Deserialize, Serialize};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

/// Default Linux abstract socket namespace name for the Zygote daemon.
pub const DEFAULT_ABSTRACT_NAME: &[u8] = b"zygote";

/// Maximum buffer size for a single SEQPACKET payload (64 KB).
pub const MAX_PACKET_SIZE: usize = 65536;

/// Socket send/receive buffer size (256 KB) to prevent EAGAIN under burst conditions.
pub const SOCKET_BUFFER_SIZE: libc::c_int = 256 * 1024;

/// Request payload sent from the orchestrator to the Zygote daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnRequest {
    /// Correlation identifier for request-response matching across multiplexed channels.
    pub id: u64,
    /// Absolute or relative path to the executable to run.
    pub path: String,
    /// Command-line arguments. By convention, args[0] is typically the program name.
    pub args: Vec<String>,
    /// Environment variables as key-value pairs. If empty, the child inherits the cached default environment.
    pub env: Vec<(String, String)>,
    /// Optional working directory for the spawned process.
    pub cwd: Option<String>,
    /// When true, child process standard I/O streams are redirected to /dev/null
    /// (unless overridden by specific passed stdio file descriptors).
    pub redirect_null: bool,
    /// When true, the child calls setsid() to create a new session;
    /// otherwise, it calls setpgid(0, 0) to isolate its process group.
    pub new_session: bool,
    /// True if a custom stdin file descriptor is attached via SCM_RIGHTS.
    pub pass_stdin: bool,
    /// True if a custom stdout file descriptor is attached via SCM_RIGHTS.
    pub pass_stdout: bool,
    /// True if a custom stderr file descriptor is attached via SCM_RIGHTS.
    pub pass_stderr: bool,
}

impl SpawnRequest {
    /// Create a new spawn request with default settings (redirect_null = true, new_session = false, no passed FDs).
    pub fn new(id: u64, path: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            id,
            path: path.into(),
            args,
            env: Vec::new(),
            cwd: None,
            redirect_null: true,
            new_session: false,
            pass_stdin: false,
            pass_stdout: false,
            pass_stderr: false,
        }
    }

    /// Returns the number of file descriptors expected to be passed via SCM_RIGHTS.
    pub fn expected_fd_count(&self) -> usize {
        (self.pass_stdin as usize) + (self.pass_stdout as usize) + (self.pass_stderr as usize)
    }
}

/// Response payload returned by the Zygote daemon to the orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnResponse {
    /// Correlation identifier matching the corresponding `SpawnRequest`.
    pub id: u64,
    /// Outcome of the spawn attempt:
    /// - `Ok(pid)`: Child process was successfully forked and verified to have exec'd.
    /// - `Err(msg)`: Error description (e.g. fork failure, invalid path, or execve errno).
    pub result: Result<i32, String>,
}

impl SpawnResponse {
    /// Construct a successful spawn response carrying the child PID.
    pub fn success(id: u64, pid: i32) -> Self {
        Self {
            id,
            result: Ok(pid),
        }
    }

    /// Construct a failed spawn response carrying an error message.
    pub fn error(id: u64, message: impl Into<String>) -> Self {
        Self {
            id,
            result: Err(message.into()),
        }
    }
}

/// Encodes any serializable value directly into a bincode packet (no framing header).
#[inline]
pub fn encode_packet<T: Serialize>(val: &T) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(val)
}

/// Encodes any serializable value into a reusable buffer (no framing header).
#[inline]
pub fn encode_packet_into<T: Serialize>(val: &T, buf: &mut Vec<u8>) -> Result<(), bincode::Error> {
    buf.clear();
    bincode::serialize_into(buf, val)
}

/// Deserializes a packet directly from a byte slice.
#[inline]
pub fn decode_packet<'a, T: Deserialize<'a>>(slice: &'a [u8]) -> Result<T, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(65536)
        .deserialize(slice)
}

/// Extract the correlation id prefix without full bincode decoding.
///
/// `SpawnRequest` / `SpawnResponse` both encode `id: u64` first via
/// fixint little-endian, so the first 8 bytes are always the id.
/// Returns `None` when fewer than 8 bytes were received (caller must
/// close the connection: no id exists to correlate an error reply to).
#[inline]
pub fn extract_req_id(buf: &[u8]) -> Option<u64> {
    if buf.len() >= 8 {
        Some(u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8])))
    } else {
        None
    }
}

/// Ancillary control message buffer aligned to 8 bytes (size_t / cmsghdr alignment).
/// Sized for up to 3 SCM_RIGHTS fds: CMSG_SPACE(3 * 4) <= 64 on both x86_64 and aarch64.
#[repr(align(8))]
pub struct CmsgBuf(pub [u8; 64]);

impl CmsgBuf {
    /// Create a zeroed control buffer.
    #[inline]
    pub fn new() -> Self {
        Self([0u8; 64])
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for CmsgBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Sets SO_SNDBUF and SO_RCVBUF to 256 KB on a socket.
pub fn configure_socket_buffers(fd: RawFd) {
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

/// Atomic SEQPACKET transmission with optional SCM_RIGHTS fds.
/// Single shared implementation for daemon and client.
pub fn send_packet_with_fds(
    raw_fd: RawFd,
    packet: &[u8],
    fds: &[RawFd],
) -> Result<isize, std::io::Error> {
    let mut iov = libc::iovec {
        iov_base: packet.as_ptr() as *mut libc::c_void,
        iov_len: packet.len(),
    };
    let mut cmsg_buf = CmsgBuf::new();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    if !fds.is_empty() {
        let fds_bytes = std::mem::size_of_val(fds) as u32;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        // SAFETY: fds.len() <= 3 in this codebase, CMSG_SPACE fits in 64 bytes.
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

/// Outcome of one atomic `recvmsg` on a SEQPACKET socket.
pub struct RecvOutcome {
    /// Kernel-reported datagram length (may exceed `buf.len()` when truncated).
    pub reported_len: usize,
    /// Received SCM_RIGHTS descriptors (owned; closed on drop exactly once).
    pub fds: Vec<OwnedFd>,
    /// True when the data payload was truncated (MSG_TRUNC or longer than buffer).
    pub truncated: bool,
    /// True when ancillary control data was truncated (MSG_CTRUNC).
    pub ctrunc: bool,
}

/// Atomic SEQPACKET receive with SCM_RIGHTS. Single shared implementation.
/// `buf` holds the first `min(reported_len, buf.len())` payload bytes on success.
pub fn recv_packet_with_fds(
    fd: RawFd,
    buf: &mut [u8],
    cmsg_buf: &mut CmsgBuf,
) -> Result<RecvOutcome, std::io::Error> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len();

    let n = unsafe {
        libc::recvmsg(
            fd,
            &mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let reported = n as usize;

    let mut fds = Vec::new();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                let base_len = libc::CMSG_LEN(0) as usize;
                if (*cmsg).cmsg_len >= base_len {
                    let num = ((*cmsg).cmsg_len - base_len) / std::mem::size_of::<RawFd>();
                    for i in 0..num {
                        let raw = *data_ptr.add(i);
                        if raw >= 0 {
                            // MSG_CMSG_CLOEXEC already set CLOEXEC on receipt.
                            fds.push(OwnedFd::from_raw_fd(raw));
                        }
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    let ctrunc = msg.msg_flags & libc::MSG_CTRUNC != 0;
    let truncated = reported > buf.len() || (msg.msg_flags & libc::MSG_TRUNC != 0);
    Ok(RecvOutcome {
        reported_len: reported,
        fds,
        truncated,
        ctrunc,
    })
}

/// Query SO_PEERCRED uid of a connected UNIX socket peer.
pub fn peer_cred_uid(fd: RawFd) -> Result<libc::uid_t, std::io::Error> {
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut ucred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ucred.uid)
    }
}

/// Strict peer check: peer uid must equal our euid unless explicitly allow-listed.
/// No implicit root bypass: a root daemon still rejects unprivileged peers
/// unless `--allow-uid <uid>` was given.
#[inline]
pub fn peer_uid_allowed(
    peer_uid: libc::uid_t,
    my_euid: libc::uid_t,
    allow_uid: Option<u32>,
) -> bool {
    peer_uid == my_euid || Some(peer_uid) == allow_uid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spawn_request_roundtrip() {
        let req = SpawnRequest {
            env: vec![("FOO".into(), "BAR".into())],
            cwd: Some("/tmp".into()),
            new_session: true,
            pass_stdin: true,
            pass_stdout: true,
            pass_stderr: false,
            ..SpawnRequest::new(42, "/bin/echo", vec!["echo".into(), "hello".into()])
        };

        let packet = encode_packet(&req).expect("encode_packet failed");
        let decoded: SpawnRequest = decode_packet(&packet).expect("decode_packet failed");
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_expected_fd_count() {
        let mut req = SpawnRequest::new(1, "/bin/ls", vec![]);
        assert_eq!(req.expected_fd_count(), 0);
        req.pass_stdin = true;
        assert_eq!(req.expected_fd_count(), 1);
        req.pass_stdout = true;
        assert_eq!(req.expected_fd_count(), 2);
        req.pass_stderr = true;
        assert_eq!(req.expected_fd_count(), 3);
    }

    #[test]
    fn test_decode_packet_limit() {
        let malformed_len: [u8; 8] = [0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let res: Result<Vec<u8>, _> = decode_packet(&malformed_len);
        assert!(res.is_err());
    }

    #[test]
    fn test_spawn_response_roundtrip() {
        let resp_ok = SpawnResponse::success(101, 12345);
        let packet_ok = encode_packet(&resp_ok).expect("encode_packet ok failed");
        let decoded_ok: SpawnResponse = decode_packet(&packet_ok).expect("decode_packet ok failed");
        assert_eq!(resp_ok, decoded_ok);

        let resp_err = SpawnResponse::error(102, "execve failed: ENOENT");
        let packet_err = encode_packet(&resp_err).expect("encode_packet err failed");
        let decoded_err: SpawnResponse =
            decode_packet(&packet_err).expect("decode_packet err failed");
        assert_eq!(resp_err, decoded_err);
    }

    #[test]
    fn test_buffer_reuse_roundtrip() {
        let req = SpawnRequest::new(99, "/bin/true", vec!["true".into()]);
        let mut buf = Vec::with_capacity(512);

        encode_packet_into(&req, &mut buf).expect("encode_packet_into failed");
        let decoded: SpawnRequest = decode_packet(&buf).expect("decode_packet failed");
        assert_eq!(req, decoded);

        let resp = SpawnResponse::success(99, 4321);
        encode_packet_into(&resp, &mut buf).expect("encode_packet_into failed");
        let decoded_resp: SpawnResponse = decode_packet(&buf).expect("decode_packet failed");
        assert_eq!(resp, decoded_resp);
    }

    #[test]
    fn test_extract_req_id() {
        let req = SpawnRequest::new(0x0102030405060708, "/bin/true", vec!["true".into()]);
        let packet = encode_packet(&req).expect("encode");
        assert_eq!(extract_req_id(&packet), Some(0x0102030405060708));
        assert_eq!(extract_req_id(&packet[..8]), Some(0x0102030405060708));
        assert_eq!(extract_req_id(&packet[..7]), None);
        assert_eq!(extract_req_id(&[]), None);
    }

    #[test]
    fn test_peer_uid_allowed_strict() {
        assert!(peer_uid_allowed(1000, 1000, None));
        assert!(!peer_uid_allowed(1000, 0, None));
        assert!(peer_uid_allowed(1000, 0, Some(1000)));
        assert!(!peer_uid_allowed(1001, 0, Some(1000)));
    }

    #[test]
    fn test_cmsg_buf_alignment() {
        assert!(std::mem::align_of::<CmsgBuf>() >= 8);
        assert!(std::mem::align_of::<CmsgBuf>() >= std::mem::align_of::<libc::cmsghdr>());
    }

    #[test]
    fn test_send_recv_shared_helpers() {
        use std::os::fd::AsRawFd;
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
        let owned = unsafe { [OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])] };
        let mut pipe_fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let p_tx = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
        let p_rx = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };

        let sent = send_packet_with_fds(owned[0].as_raw_fd(), b"hello", &[p_tx.as_raw_fd()])
            .expect("send");
        assert_eq!(sent, 5);
        drop(p_tx);

        let mut buf = [0u8; 64];
        let mut cmsg = CmsgBuf::new();
        let out = recv_packet_with_fds(owned[1].as_raw_fd(), &mut buf, &mut cmsg).expect("recv");
        assert_eq!(out.reported_len, 5);
        assert!(!out.truncated && !out.ctrunc);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(out.fds.len(), 1);
        // Verify the received fd is functional: write through it, read via pipe rx.
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
}
