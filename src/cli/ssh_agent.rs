//! Narrow SSH agent: public enumeration and RFC 4252 userauth signatures only.
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use signature::Signer;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use zeroize::{Zeroize, Zeroizing};

const MAX_PACKET: usize = 256 * 1024;
const MAX_CREDENTIAL: u64 = 1024 * 1024;
const FAILURE: &[u8] = &[5];

#[derive(serde::Deserialize)]
struct Credential {
    private_key: String,
    passphrase: String,
}
impl Drop for Credential {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.passphrase.zeroize();
    }
}

fn decode_credential(value: &str) -> Result<PrivateKey, String> {
    if value.len() as u64 > MAX_CREDENTIAL {
        return Err("SSH credential exceeds 1 MiB".into());
    }
    let credential: Credential =
        serde_json::from_str(value).map_err(|_| "Invalid SSH credential")?;
    let key = PrivateKey::from_openssh(&credential.private_key)
        .map_err(|_| "Invalid OpenSSH private key")?;
    if matches!(key.kdf(), ssh_key::Kdf::Bcrypt { rounds, .. } if *rounds > 1024) {
        return Err("SSH key decryption exceeds the supported KDF cost (1024 rounds)".into());
    }
    let key = if key.is_encrypted() {
        key.decrypt(&credential.passphrase)
            .map_err(|_| "Could not decrypt the SSH private key")?
    } else {
        key
    };
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => Ok(key),
        _ => Err("Use an Ed25519 or ECDSA OpenSSH private key".into()),
    }
}

pub(super) fn public_key(stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let result = (|| {
        let mut input = Zeroizing::new(String::new());
        std::io::stdin()
            .take(MAX_CREDENTIAL + 1)
            .read_to_string(&mut input)
            .map_err(|e| e.to_string())?;
        if input.len() as u64 > MAX_CREDENTIAL {
            return Err("SSH credential exceeds 1 MiB".into());
        }
        let key = decode_credential(&input)?;
        let public = key.public_key().to_openssh().map_err(|e| e.to_string())?;
        stdout
            .write_all(public.as_bytes())
            .map_err(|e| e.to_string())
    })();
    report(result, stderr)
}

pub(super) fn run(args: Vec<OsString>, stderr: &mut dyn Write) -> i32 {
    report(
        (|| {
            if args.len() != 1 {
                return Err("usage: av ssh-agent SOCKET_PATH".into());
            }
            serve(Path::new(&args[0]))
        })(),
        stderr,
    )
}

fn report(result: Result<(), String>, stderr: &mut dyn Write) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "av ssh-agent: {error}");
            1
        }
    }
}

fn serve(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| p.is_absolute())
        .ok_or("Socket path must be absolute")?;
    // Never follow a substituted private directory or lock file.
    match std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.to_string()),
    }
    let meta = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("SSH agent directory must be owned by you with mode 0700".into());
    }
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent.join("lock"))
        .map_err(|e| e.to_string())?;
    let meta = lock.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("Unsafe SSH agent lock file".into());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("SSH agent is already running".into());
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
            return Err("Refusing to replace an unrelated socket path".into());
        }
        std::fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let parent_pid = unsafe { libc::getppid() };
    let clients = Arc::new(AtomicUsize::new(0));
    while unsafe { libc::getppid() } == parent_pid {
        match listener.accept() {
            Ok((stream, _)) => {
                // ponytail: 16 simultaneous clients; use an async listener if demand grows.
                if clients.load(Ordering::Relaxed) >= 16 {
                    continue;
                }
                clients.fetch_add(1, Ordering::Relaxed);
                let clients = clients.clone();
                std::thread::spawn(move || {
                    let _ = connection(stream);
                    clients.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}
use std::os::unix::fs::DirBuilderExt;

fn connection(mut stream: UnixStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    loop {
        let mut length = [0; 4];
        if stream.read_exact(&mut length).is_err() {
            return Ok(());
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_PACKET {
            return Err("Invalid SSH agent packet length".into());
        }
        let mut packet = vec![0; length];
        stream.read_exact(&mut packet).map_err(|e| e.to_string())?;
        let response = respond(&packet, |args, signing| {
            super::inject::approve_ssh_agent(args, stream.as_raw_fd(), signing)
        })
        .unwrap_or_else(|_| FAILURE.to_vec());
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .map_err(|e| e.to_string())?;
        stream.write_all(&response).map_err(|e| e.to_string())?;
    }
}

fn string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn take<'a>(input: &mut &'a [u8], size: usize) -> Result<&'a [u8], String> {
    if size > input.len() {
        return Err("Truncated SSH message".into());
    }
    let (value, rest) = input.split_at(size);
    *input = rest;
    Ok(value)
}
fn uint(input: &mut &[u8]) -> Result<u32, String> {
    Ok(u32::from_be_bytes(take(input, 4)?.try_into().unwrap()))
}
fn field<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let size = uint(input)? as usize;
    take(input, size)
}
fn digest(value: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, value)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// Limit this gate to SSH public-key authentication, never generic SSHSIG signing.
fn authentication(payload: &[u8], key: &[u8], algorithm: &str) -> Result<(), String> {
    let mut input = payload;
    if !(16..=64).contains(&field(&mut input)?.len())
        || take(&mut input, 1)? != [50]
        || field(&mut input)?.is_empty()
        || field(&mut input)? != b"ssh-connection"
        || field(&mut input)? != b"publickey"
        || take(&mut input, 1)? != [1]
        || field(&mut input)? != algorithm.as_bytes()
        || field(&mut input)? != key
        || !input.is_empty()
    {
        return Err("Only SSH public-key authentication is supported".into());
    }
    Ok(())
}

fn respond(
    packet: &[u8],
    mut authorize: impl FnMut(
        Vec<String>,
        bool,
    ) -> Result<std::collections::BTreeMap<String, String>, String>,
) -> Result<Vec<u8>, String> {
    if packet.len() > MAX_PACKET {
        return Err("SSH message too large".into());
    }
    if packet == [11] {
        let values = authorize(vec![], false)?;
        let public = values
            .get("public_key")
            .ok_or("SSH agent is not configured")?;
        let key = PublicKey::from_openssh(public).map_err(|_| "Invalid public key")?;
        let mut response = vec![12];
        response.extend_from_slice(&1u32.to_be_bytes());
        string(&mut response, &key.to_bytes().map_err(|e| e.to_string())?);
        string(&mut response, b"Automic Vault");
        return Ok(response);
    }
    if packet.first() != Some(&13) {
        return Ok(FAILURE.to_vec());
    }
    let mut input = &packet[1..];
    let key_blob = field(&mut input)?;
    let payload = field(&mut input)?;
    let flags = uint(&mut input)?;
    if !input.is_empty() {
        return Err("Trailing SSH message data".into());
    }
    let public = PublicKey::from_bytes(key_blob).map_err(|_| "Invalid SSH public key")?;
    let algorithm = match (public.algorithm(), flags) {
        (Algorithm::Ed25519, 0) => "ssh-ed25519".to_string(),
        (Algorithm::Ecdsa { .. }, 0) => public.algorithm().to_string(),
        _ => return Err("Unsupported SSH signature algorithm or flags".into()),
    };
    authentication(payload, key_blob, &algorithm)?;
    let mut values = authorize(
        vec![
            format!("payload-sha256={}", digest(payload)),
            format!("public-key-sha256={}", digest(key_blob)),
            format!("signature-flags={flags}"),
        ],
        true,
    )?;
    let credential = Zeroizing::new(values.remove("AV_SSH_CREDENTIAL").unwrap_or_default());
    values.values_mut().for_each(Zeroize::zeroize);
    let key = decode_credential(&credential)?;
    if key.public_key().key_data() != public.key_data() {
        return Err("SSH credential changed".into());
    }
    let signature: ssh_key::Signature = key.try_sign(payload).map_err(|_| "SSH signing failed")?;
    if signature.algorithm().to_string() != algorithm {
        return Err("Unexpected SSH signature algorithm".into());
    }
    let mut blob = Vec::new();
    string(&mut blob, algorithm.as_bytes());
    string(&mut blob, signature.as_bytes());
    let mut response = vec![14];
    string(&mut response, &blob);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Verifier;
    fn request(key: &PrivateKey) -> (Vec<u8>, Vec<u8>) {
        let blob = key.public_key().to_bytes().unwrap();
        let mut payload = Vec::new();
        string(&mut payload, &[7; 32]);
        payload.push(50);
        string(&mut payload, b"git");
        string(&mut payload, b"ssh-connection");
        string(&mut payload, b"publickey");
        payload.push(1);
        string(&mut payload, key.algorithm().as_str().as_bytes());
        string(&mut payload, &blob);
        let mut packet = vec![13];
        string(&mut packet, &blob);
        string(&mut packet, &payload);
        packet.extend_from_slice(&0u32.to_be_bytes());
        (packet, payload)
    }
    #[test]
    fn authentication_signature_binds_payload_and_key_and_verifies() {
        let key = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap();
        let (packet, payload) = request(&key);
        let value = serde_json::json!({"private_key": key.to_openssh(Default::default()).unwrap().as_str(), "passphrase": ""}).to_string();
        let response = respond(&packet, |args, signing| {
            assert!(signing);
            assert_eq!(args[0], format!("payload-sha256={}", digest(&payload)));
            assert_eq!(
                args[1],
                format!(
                    "public-key-sha256={}",
                    digest(&key.public_key().to_bytes().unwrap())
                )
            );
            Ok([("AV_SSH_CREDENTIAL".into(), value.clone())].into())
        })
        .unwrap();
        assert_eq!(response[0], 14);
        let mut input = &response[1..];
        let mut blob = field(&mut input).unwrap();
        assert_eq!(field(&mut blob).unwrap(), b"ssh-ed25519");
        let signature =
            ssh_key::Signature::new(Algorithm::Ed25519, field(&mut blob).unwrap().to_vec())
                .unwrap();
        Verifier::verify(key.public_key(), &payload, &signature).unwrap();
        assert!(respond(&packet, |_, _| Err("denied".into())).is_err());
    }
    #[test]
    fn all_supported_keys_sign_and_mismatched_credentials_fail() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP521,
            },
        ] {
            let key = PrivateKey::random(&mut rand::rngs::OsRng, algorithm.clone()).unwrap();
            let (packet, payload) = request(&key);
            let value = serde_json::json!({"private_key": key.to_openssh(Default::default()).unwrap().as_str(), "passphrase": ""}).to_string();
            let response = respond(&packet, |_, _| {
                Ok([("AV_SSH_CREDENTIAL".into(), value.clone())].into())
            })
            .unwrap();
            let mut input = &response[1..];
            let mut blob = field(&mut input).unwrap();
            assert_eq!(field(&mut blob).unwrap(), algorithm.as_str().as_bytes());
            let signature =
                ssh_key::Signature::new(algorithm, field(&mut blob).unwrap().to_vec()).unwrap();
            Verifier::verify(key.public_key(), &payload, &signature).unwrap();
            let different = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap();
            let wrong = serde_json::json!({"private_key": different.to_openssh(Default::default()).unwrap().as_str(), "passphrase": ""}).to_string();
            assert!(
                respond(&packet, |_, _| Ok([(
                    "AV_SSH_CREDENTIAL".into(),
                    wrong.clone()
                )]
                .into()))
                .is_err()
            );
        }
    }

    #[test]
    fn listing_never_requests_private_material() {
        let key = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap();
        let response = respond(&[11], |args, signing| {
            assert!(args.is_empty());
            assert!(!signing);
            Ok([("public_key".into(), key.public_key().to_openssh().unwrap())].into())
        })
        .unwrap();
        assert_eq!(response[0], 12);
        let mut input = &response[1..];
        assert_eq!(uint(&mut input).unwrap(), 1);
        assert_eq!(
            field(&mut input).unwrap(),
            key.public_key().to_bytes().unwrap()
        );
        assert_eq!(field(&mut input).unwrap(), b"Automic Vault");
        assert!(input.is_empty());
    }

    #[test]
    fn malformed_and_unsupported_requests_never_authorize() {
        let key = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap();
        let (packet, _) = request(&key);
        for end in 0..packet.len() {
            let _ = respond(&packet[..end], |_, _| {
                panic!("truncated message authorized")
            });
        }
        let mut trailing = packet.clone();
        trailing.push(0);
        assert!(respond(&trailing, |_, _| panic!()).is_err());
        let mut flags = packet;
        *flags.last_mut().unwrap() = 1;
        assert!(respond(&flags, |_, _| panic!()).is_err());
        for opcode in [17, 18, 19, 20, 22, 23, 25, 26, 27] {
            assert_eq!(respond(&[opcode], |_, _| panic!()).unwrap(), FAILURE);
        }
        assert!(authentication(b"SSHSIG arbitrary signing", b"", "ssh-ed25519").is_err());
    }
}
