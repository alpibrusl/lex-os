//! HTTP/1.1 client over `UnixStream` for the Firecracker management API.

// Several helpers below are wired into provision()/destroy() in a later
// task (#14); allow dead_code until then.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub(super) enum ApiError {
    #[error("api io: {0}")]
    Io(#[from] std::io::Error),
    #[error("api timeout waiting for {0}")]
    Timeout(String),
    #[error("firecracker returned {status} {reason}: {body}")]
    HttpError {
        status: u16,
        reason: String,
        body: String,
    },
}

/// PUT a JSON body to `path` on the Firecracker socket. `UnixStream`
/// implements `Write` on shared references, so callers pass `&stream`.
pub(super) fn put_json(stream: impl Write, path: &str, body: &str) -> Result<(), ApiError> {
    request_json(stream, "PUT", path, body)
}

/// POST a JSON body to `path` on the Firecracker socket.
pub(super) fn post_json(stream: impl Write, path: &str, body: &str) -> Result<(), ApiError> {
    request_json(stream, "POST", path, body)
}

fn request_json(
    mut stream: impl Write,
    method: &str,
    path: &str,
    body: &str,
) -> Result<(), ApiError> {
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}

/// Open a connection to the Firecracker socket and apply `f`. The Firecracker
/// API closes the connection after each request, so callers open a fresh one
/// per call.
pub(super) fn with_socket<P, F, T>(sock: P, f: F) -> Result<T, ApiError>
where
    P: AsRef<Path>,
    F: FnOnce(&UnixStream) -> Result<T, ApiError>,
{
    let stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let out = f(&stream)?;
    read_and_check_response(&stream)?;
    Ok(out)
}

fn read_and_check_response(stream: &UnixStream) -> Result<(), ApiError> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let (status, reason) = parse_status_line(&status_line)?;
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    if !(200..300).contains(&status) {
        return Err(ApiError::HttpError {
            status,
            reason,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    Ok(())
}

fn parse_status_line(line: &str) -> Result<(u16, String), ApiError> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.splitn(3, ' ');
    let _ver = parts.next();
    let status = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let reason = parts.next().unwrap_or("").to_string();
    Ok((status, reason))
}

/// Poll until the socket exists and accepts connections (Firecracker creates
/// it asynchronously on startup).
pub(super) fn wait_for_socket(sock: &Path, timeout: Duration) -> Result<(), ApiError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if sock.exists() && UnixStream::connect(sock).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(ApiError::Timeout(format!("{}", sock.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    #[test]
    fn put_serializes_a_well_formed_http_request_with_body() {
        let (mut server, client) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            put_json(&client, "/boot-source", "{\"kernel_image_path\":\"/k\"}").unwrap();
        });
        let mut received = Vec::new();
        server
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let _ = server.read_to_end(&mut received);
        let text = String::from_utf8_lossy(&received);
        // Body `{"kernel_image_path":"/k"}` is 26 bytes.
        assert!(
            text.starts_with("PUT /boot-source HTTP/1.1\r\n"),
            "got: {text}"
        );
        assert!(text.contains("Content-Length: 26\r\n"), "got: {text}");
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("Host: localhost\r\n"));
        assert!(
            text.ends_with("{\"kernel_image_path\":\"/k\"}"),
            "got: {text}"
        );
    }

    #[test]
    fn parse_status_line_extracts_code_and_reason() {
        assert_eq!(
            parse_status_line("HTTP/1.1 204 No Content\r\n").unwrap(),
            (204, "No Content".into())
        );
        assert_eq!(
            parse_status_line("HTTP/1.1 400 Bad Request\r\n").unwrap(),
            (400, "Bad Request".into())
        );
    }
}
