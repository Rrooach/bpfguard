// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_harness_auth::{
    canonical_json_sha256, generate_keypair, public_key_fingerprint, read_final_ack_frame,
    read_frame, read_json_value_bounded, read_policy, read_secret_key, write_keypair,
    write_response_frame, HarnessServerSession, MAX_CANONICAL_JSON_BYTES,
};
use clap::{Parser, Subcommand};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Parser)]
#[clap(
    name = "bpf-harnessd",
    about = "Authenticated exclusive-vm-v1 harness signer"
)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a create-new Ed25519 private keypair and public key.
    Keygen {
        #[clap(long, parse(from_os_str))]
        secret_key: PathBuf,
        #[clap(long, parse(from_os_str))]
        public_key: PathBuf,
    },
    /// Validate a policy and print its canonical JSON SHA-256.
    PolicyDigest {
        #[clap(long, parse(from_os_str))]
        policy: PathBuf,
    },
    /// Parse bounded JSON and print its recursive-key-canonical SHA-256.
    CanonicalJsonDigest {
        #[clap(long, parse(from_os_str))]
        input: PathBuf,
    },
    /// Serve bounded sequential four-phase sessions over one Unix socket connection.
    Serve {
        #[clap(long, parse(from_os_str))]
        socket: PathBuf,
        #[clap(long, parse(from_os_str))]
        secret_key: PathBuf,
        #[clap(long, parse(from_os_str))]
        policy: PathBuf,
        /// Read/write timeout after the transport connects. QEMU may connect
        /// before the Guest finishes booting, so the default is five minutes.
        #[clap(long, default_value_t = 300_000)]
        timeout_ms: u64,
        /// Number of sequential four-phase sessions on the single connection.
        #[clap(long, default_value_t = 1)]
        max_sessions: u32,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            secret_key,
            public_key,
        } => {
            let keypair = generate_keypair()?;
            write_keypair(&keypair, &secret_key, &public_key)?;
            println!("{}", public_key_fingerprint(&keypair.public));
            Ok(())
        }
        Command::PolicyDigest { policy } => {
            println!("{}", read_policy(&policy)?.canonical_sha256()?);
            Ok(())
        }
        Command::CanonicalJsonDigest { input } => {
            let value = read_json_value_bounded(&input, MAX_CANONICAL_JSON_BYTES)?;
            println!("{}", canonical_json_sha256(&value)?);
            Ok(())
        }
        Command::Serve {
            socket,
            secret_key,
            policy,
            timeout_ms,
            max_sessions,
        } => serve(&socket, &secret_key, &policy, timeout_ms, max_sessions),
    }
}

fn serve(
    socket: &Path,
    secret_key: &Path,
    policy_path: &Path,
    timeout_ms: u64,
    max_sessions: u32,
) -> Result<()> {
    if timeout_ms == 0 {
        bail!("timeout-ms must be nonzero");
    }
    let parent = socket
        .parent()
        .context("Unix socket path has no parent directory")?;
    if parent.as_os_str().is_empty() || !parent.is_dir() {
        bail!("Unix socket parent must be an existing directory");
    }
    let keypair = read_secret_key(secret_key)?;
    let policy = read_policy(policy_path)?;
    let mut session = HarnessServerSession::with_max_sessions(policy, max_sessions)?;

    // UnixListener::bind refuses an existing path. Never unlink a caller's
    // pre-existing entry to make the daemon start.
    let listener = UnixListener::bind(socket)
        .with_context(|| format!("bind create-new Unix socket {}", socket.display()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict Unix socket {}", socket.display()))?;
    let guard = SocketPathGuard::new(socket)?;
    let (mut stream, _) = listener.accept().context("accept harness transport")?;
    drop(listener);
    configure_timeout(&stream, timeout_ms)?;

    for session_index in 0..max_sessions {
        for phase_index in 0..4_u32 {
            let request = read_frame(&mut stream)?.with_context(|| {
                format!(
                    "harness transport closed before session {} phase {}",
                    session_index + 1,
                    phase_index + 1
                )
            })?;
            let response = session.handle(request, &keypair)?;
            write_response_frame(&mut stream, &response)?;
        }
        // Do not close or recycle the ordered session after merely enqueueing
        // FINAL. A virtio-serial bridge may observe Host EOF before delivering
        // the tail of that frame. The Guest emits this bounded ACK only after
        // it has received and authenticated the complete FINAL transcript.
        let ack = read_final_ack_frame(&mut stream)?.with_context(|| {
            format!(
                "harness transport closed before FINAL_ACK for session {}",
                session_index + 1
            )
        })?;
        let ack_run_id = ack.run_id.clone();
        let ack_run_epoch = ack.run_epoch;
        let ack_response_sha256 = ack.final_response_sha256.clone();
        session.acknowledge_final(ack)?;
        println!(
            "session={} final_ack=VERIFIED run_id={:?} run_epoch={} final_response_sha256={}",
            session_index + 1,
            ack_run_id,
            ack_run_epoch,
            ack_response_sha256
        );
    }
    if !session.is_complete() {
        bail!("harness server ended before every requested session reached FINAL");
    }
    println!("result=COMPLETE sessions={max_sessions}");
    // Every FINAL response is now known to have reached and been validated by
    // the Guest. Dropping the stream after its last ACK cannot truncate an
    // outstanding Host-to-Guest response.
    drop(stream);
    drop(guard);
    Ok(())
}

fn configure_timeout(stream: &UnixStream, timeout_ms: u64) -> Result<()> {
    let timeout = Some(Duration::from_millis(timeout_ms));
    stream
        .set_read_timeout(timeout)
        .context("set harness read timeout")?;
    stream
        .set_write_timeout(timeout)
        .context("set harness write timeout")
}

struct SocketPathGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketPathGuard {
    fn new(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect bound Unix socket {}", path.display()))?;
        if !metadata.file_type().is_socket() {
            bail!("bound harness path is not a Unix socket");
        }
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}
