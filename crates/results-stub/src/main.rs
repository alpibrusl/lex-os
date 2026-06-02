//! results-stub: the single allowed-egress target for the lex-os demo
//! (issue #10).
//!
//! The demo's manifest (demo/manifest.json) declares an egress
//! allowlist of `results.demo.internal:443` — exactly one host.
//! To keep the demo self-contained and free of network
//! dependencies on a real service, this tiny binary impersonates
//! that endpoint: it accepts HTTP requests on a configurable port,
//! logs each one to stdout, and replies with a fixed 200.
//!
//! Deliberately hand-rolled HTTP/1.1 over std::net::TcpListener:
//! one async runtime, framework, and TLS stack avoided. The demo
//! only has one client making sequential requests; correctness
//! beats sophistication.
//!
//! TLS: not handled here. For the recorded demo, either:
//!   - terminate TLS in front (caddy/nginx) and forward to this stub,
//!   - or `curl http://results.demo.internal/...` and update
//!     scenario.md accordingly.
//!
//! The kernel-egress wall (issue #14) drops packets based on
//! destination IP+port, so the TLS layer is irrelevant to whether
//! the wall fires.

use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_LISTEN: &str = "0.0.0.0:8443";

fn main() {
    let args: Vec<String> = env::args().collect();
    let listen = parse_listen(&args).unwrap_or_else(|e| {
        eprintln!("{e}");
        eprintln!("usage: results-stub [--listen HOST:PORT]");
        process::exit(2);
    });

    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("results-stub: bind {listen}: {e}");
            process::exit(1);
        }
    };

    eprintln!("results-stub: listening on {listen} (the lex-os demo's allowed-egress target)");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(s) {
                    eprintln!("results-stub: handler error: {e}");
                }
            }
            Err(e) => eprintln!("results-stub: accept: {e}"),
        }
    }
}

fn parse_listen(args: &[String]) -> Result<String, String> {
    let mut iter = args.iter().skip(1);
    let Some(a) = iter.next() else {
        return Ok(DEFAULT_LISTEN.into());
    };
    match a.as_str() {
        "--listen" => iter
            .next()
            .cloned()
            .ok_or_else(|| "results-stub: --listen needs a value".into()),
        "-h" | "--help" => {
            println!("results-stub: HTTP stub for the lex-os demo's results.demo.internal target.");
            println!("usage: results-stub [--listen HOST:PORT]   (default: {DEFAULT_LISTEN})");
            process::exit(0);
        }
        other => Err(format!("results-stub: unknown arg `{other}`")),
    }
}

fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());

    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let request_line = request_line.trim_end_matches(['\r', '\n']).to_string();

    let mut headers = Vec::<(String, String)>::new();
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let body_preview = String::from_utf8_lossy(&body).chars().take(200).collect::<String>();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!(
        "[{ts}] peer={peer} req=\"{request_line}\" headers={} body_len={} body_preview={:?}",
        headers.len(),
        content_length,
        body_preview
    );

    let body = b"{\"ok\":true,\"stub\":true}";
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}
