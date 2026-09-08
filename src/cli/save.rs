use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

use zeroize::Zeroizing;

use super::inject;

const MAX_SECRET_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    Line,
    Multiline,
    Stdin,
}

pub(crate) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        let _ = writeln!(
            stdout,
            "{}\n\nDefault: hidden single-line terminal input.\n--multiline: hidden terminal input until Ctrl-D; preserve received whitespace.\n--stdin: read redirected stdin to EOF without trimming or newline conversion.\nInput must be nonempty UTF-8 without NUL, at most 1 MiB. Saving requires Approval.",
            usage()
        );
        return 0;
    }
    match run_inner(args) {
        Ok(()) => 0,
        Err(err) => {
            let _ = writeln!(stderr, "av save: {err}");
            1
        }
    }
}

fn run_inner(args: Vec<OsString>) -> Result<(), String> {
    let (key, project_directory, input) = parse_args(args)?;
    let key = key
        .to_str()
        .ok_or_else(|| "save key must be valid UTF-8".to_string())?;
    inject::validate_key_name(key)?;
    let value = if input == Input::Stdin {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return Err(
                "--stdin requires redirected input; use --multiline for hidden terminal input"
                    .into(),
            );
        }
        read_secret_to_end(stdin.lock())?
    } else {
        read_secret_from_tty(key, input)?
    };
    save_value(key, &value, project_directory.as_deref())
}

fn parse_args(args: Vec<OsString>) -> Result<(OsString, Option<String>, Input), String> {
    let mut key = None;
    let mut project_directory = None;
    let mut input = Input::Line;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--multiline" || arg == "--stdin" {
            if input != Input::Line {
                return Err("specify only one of --multiline or --stdin".into());
            }
            input = if arg == "--multiline" {
                Input::Multiline
            } else {
                Input::Stdin
            };
        } else if arg == "--project-directory" {
            let path = args.next().ok_or_else(usage)?;
            if project_directory.is_some() {
                return Err("--project-directory may be specified only once".into());
            }
            project_directory = Some(canonical_project_directory(Path::new(&path))?);
        } else if let Some(path) = arg
            .to_str()
            .and_then(|arg| arg.strip_prefix("--project-directory="))
        {
            if path.is_empty() || project_directory.is_some() {
                return Err(usage());
            }
            project_directory = Some(canonical_project_directory(Path::new(path))?);
        } else if key.replace(arg).is_some() {
            return Err(usage());
        }
    }
    Ok((key.ok_or_else(usage)?, project_directory, input))
}

fn usage() -> String {
    "usage: av save [--multiline | --stdin] [--project-directory=DIR] KEY".into()
}

fn canonical_project_directory(path: &Path) -> Result<String, String> {
    let path = std::fs::canonicalize(path).map_err(|err| {
        format!(
            "failed to resolve project directory {}: {err}",
            path.display()
        )
    })?;
    let metadata = path.metadata().map_err(|err| {
        format!(
            "failed to inspect project directory {}: {err}",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "project directory is not a directory: {}",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or("project directory cannot be a filesystem root")?;
    let parent_metadata = parent.metadata().map_err(|err| {
        format!(
            "failed to inspect project directory parent {}: {err}",
            parent.display()
        )
    })?;
    if parent == path || parent_metadata.dev() != metadata.dev() {
        return Err("project directory cannot be a filesystem root".into());
    }
    path.into_os_string()
        .into_string()
        .map_err(|_| "project directory must be valid UTF-8".into())
}

fn save_value(key: &str, value: &str, project_directory: Option<&str>) -> Result<(), String> {
    if value.is_empty() {
        return Err("empty key value".into());
    }
    if value.contains('\0') {
        return Err("Secret Value must not contain NUL".into());
    }
    if value.len() > MAX_SECRET_BYTES {
        return Err("Secret Value exceeds 1 MiB".into());
    }
    match project_directory {
        Some(path) => crate::secrets::store_project_secret(key, value, path),
        None => crate::secrets::store_secret(key, value),
    }
}

fn read_secret_to_end(reader: impl Read) -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "failed to read Secret Value".to_string())?;
    decode_secret(&bytes)
}

fn decode_secret(bytes: &[u8]) -> Result<Zeroizing<String>, String> {
    if bytes.len() > MAX_SECRET_BYTES {
        return Err("Secret Value exceeds 1 MiB".into());
    }
    let value =
        std::str::from_utf8(bytes).map_err(|_| "Secret Value must be valid UTF-8".to_string())?;
    Ok(Zeroizing::new(value.to_owned()))
}

fn read_secret_from_tty(key: &str, input: Input) -> Result<Zeroizing<String>, String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/tty")
        .map_err(|err| format!("failed to open /dev/tty: {err}"))?;
    let fd = tty.as_raw_fd();
    if fd as usize >= libc::FD_SETSIZE {
        return Err("terminal descriptor exceeds select limit".into());
    }
    let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let signals = InputSignals::install()?;
    let mut restore = EchoRestore {
        fd,
        original,
        restored: false,
    };
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    hidden.c_lflag |= libc::ICANON | libc::ISIG;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // Prompt only after echo is disabled so pasted input cannot race setup.
    if input == Input::Multiline {
        writeln!(tty, "Enter value for {key}. Ctrl-D ends input (twice without a final newline); Ctrl-C cancels.")
            .map_err(|err| format!("failed to prompt: {err}"))?;
    } else {
        write!(tty, "Value for {key}: ").map_err(|err| format!("failed to prompt: {err}"))?;
    }
    tty.flush()
        .map_err(|err| format!("failed to flush prompt: {err}"))?;

    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 4096]);
    let result: Result<(), String> = loop {
        if INPUT_SIGNAL.load(Ordering::Relaxed) != 0 {
            break Err("Secret input canceled".into());
        }
        // Use select: macOS poll can report POLLHUP for a live /dev/tty.
        // Nonblocking read and a bounded wait also close the signal-before-read race.
        let mut readable = unsafe { std::mem::zeroed::<libc::fd_set>() };
        let mut timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        unsafe {
            libc::FD_ZERO(&mut readable);
            libc::FD_SET(fd, &mut readable);
        }
        let ready = unsafe {
            libc::select(
                fd + 1,
                &mut readable,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut timeout,
            )
        };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break Err("failed to wait for Secret input".into());
        }
        if ready == 0 {
            continue;
        }
        match tty.read(&mut *chunk) {
            Ok(0) => break Ok(()),
            Ok(count) => {
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.len() > MAX_SECRET_BYTES {
                    break Err("Secret Value exceeds 1 MiB".into());
                }
                if input == Input::Line && bytes.ends_with(b"\n") {
                    break Ok(());
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => break Err("failed to read Secret Value".into()),
        }
    };
    // Restore the terminal before restoring signal dispositions or requesting Approval.
    restore.restore()?;
    writeln!(tty).ok();
    drop(signals);
    if INPUT_SIGNAL.load(Ordering::Relaxed) != 0 {
        return Err("Secret input canceled".into());
    }
    result?;
    if input == Input::Line {
        while bytes
            .last()
            .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
        {
            bytes.pop();
        }
    }
    decode_secret(&bytes)
}

struct EchoRestore {
    fd: i32,
    original: libc::termios,
    restored: bool,
}

impl EchoRestore {
    fn restore(&mut self) -> Result<(), String> {
        if !self.restored {
            // Discard unread input so canceled/pasted Secret text cannot reach the shell.
            if unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) } != 0 {
                return Err("failed to restore terminal settings".into());
            }
            self.restored = true;
        }
        Ok(())
    }
}

impl Drop for EchoRestore {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

static INPUT_SIGNAL: AtomicI32 = AtomicI32::new(0);
const INPUT_SIGNALS: [i32; 7] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
];

extern "C" fn cancel_input(signal: i32) {
    INPUT_SIGNAL.store(signal, Ordering::Relaxed);
}

struct InputSignals(Vec<(i32, libc::sigaction)>);

impl InputSignals {
    fn install() -> Result<Self, String> {
        INPUT_SIGNAL.store(0, Ordering::Relaxed);
        let mut guard = Self(Vec::new());
        for signal in INPUT_SIGNALS {
            let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
            let mut original = unsafe { std::mem::zeroed::<libc::sigaction>() };
            action.sa_sigaction = cancel_input as *const () as usize;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            if unsafe { libc::sigaction(signal, &action, &mut original) } != 0 {
                return Err("failed to protect terminal input from interruption".into());
            }
            guard.0.push((signal, original));
        }
        Ok(guard)
    }
}

impl Drop for InputSignals {
    fn drop(&mut self) {
        for (signal, original) in self.0.iter().rev() {
            unsafe { libc::sigaction(*signal, original, std::ptr::null_mut()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eof_input_preserves_exact_text_and_rejects_unsupported_values() {
        for value in [
            "  token  ",
            "line\nline",
            "line\nline\n",
            "line\r\nline\r\n",
            "é🔑\n",
        ] {
            let read = read_secret_to_end(value.as_bytes()).unwrap();
            assert_eq!(read.as_bytes(), value.as_bytes());
        }
        assert_eq!(
            read_secret_to_end(&b"sensitive\xff"[..]).unwrap_err(),
            "Secret Value must be valid UTF-8"
        );
        assert_eq!(
            read_secret_to_end(&vec![b'x'; MAX_SECRET_BYTES + 1][..]).unwrap_err(),
            "Secret Value exceeds 1 MiB"
        );
        assert_eq!(
            save_value("SAVED_KEY", "sensitive\0value", None).unwrap_err(),
            "Secret Value must not contain NUL"
        );
    }

    #[test]
    fn input_modes_are_explicit_and_mutually_exclusive() {
        for (flag, expected) in [("--multiline", Input::Multiline), ("--stdin", Input::Stdin)] {
            let (_, _, mode) = parse_args(vec![flag.into(), "SAVED_KEY".into()]).unwrap();
            assert_eq!(mode, expected);
            assert!(parse_args(vec![flag.into(), flag.into(), "SAVED_KEY".into()]).is_err());
        }
        assert!(
            parse_args(vec![
                "--stdin".into(),
                "SAVED_KEY".into(),
                "--multiline".into()
            ])
            .is_err()
        );
    }

    #[test]
    fn saves_value_to_test_keychain() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = std::env::temp_dir().join(format!("av-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &dir);
        }

        save_value("SAVED_KEY", "secret", None).unwrap();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("SAVED_KEY")).unwrap(),
            "secret"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_empty_value() {
        assert_eq!(
            save_value("SAVED_KEY", "", None).unwrap_err(),
            "empty key value"
        );
    }

    #[test]
    fn parses_and_canonicalizes_project_directory() {
        let directory = std::env::temp_dir();
        let (key, project, input) = parse_args(vec![
            OsString::from(format!("--project-directory={}", directory.display())),
            OsString::from("SAVED_KEY"),
        ])
        .unwrap();
        assert_eq!(key, "SAVED_KEY");
        assert_eq!(input, Input::Line);
        assert_eq!(
            project,
            Some(
                std::fs::canonicalize(directory)
                    .unwrap()
                    .display()
                    .to_string()
            )
        );
    }

    #[test]
    fn saves_project_value_separately_from_global_value() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-project-save-{}", std::process::id()));
        let keychain = root.join("keychain");
        let project = root.join("project");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&project).unwrap();
        let project = std::fs::canonicalize(project).unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain) };

        save_value("SAVED_KEY", "global", None).unwrap();
        save_value("SAVED_KEY", "project", project.to_str()).unwrap();

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR") };
        assert_eq!(
            std::fs::read_to_string(keychain.join("SAVED_KEY")).unwrap(),
            "global"
        );
        assert_eq!(
            std::fs::read_to_string(crate::secrets::test_project_secret_path(
                &keychain,
                project.to_str().unwrap(),
                "SAVED_KEY"
            ))
            .unwrap(),
            "project"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
