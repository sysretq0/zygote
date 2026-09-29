use bincode::Options;
use serde::{Deserialize, Serialize};

/// Default Linux abstract socket namespace name for the Zygote daemon.
pub const DEFAULT_ABSTRACT_NAME: &[u8] = b"zygote";

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
}
