use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "av-save-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("keychain")).unwrap();
        Self(root)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_av"));
        command
            .arg("save")
            .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", self.0.join("keychain"));
        command
    }

    fn saved(&self) -> std::path::PathBuf {
        self.0.join("keychain/SAVED_KEY")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn stdin_preserves_pem_bytes_and_project_values() {
    let fixture = Fixture::new();
    let pem = "-----BEGIN PRIVATE KEY-----\nsynthetic-test-only\n-----END PRIVATE KEY-----";
    for value in [
        pem.to_owned(),
        format!("{pem}\n"),
        format!("{pem}\n").replace('\n', "\r\n"),
        "  é🔑  \n\n".into(),
    ] {
        let mut child = fixture
            .command()
            .args(["--stdin", "SAVED_KEY"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(value.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert_eq!(fs::read(fixture.saved()).unwrap(), value.as_bytes());
    }
    let project = fixture.0.join("project");
    fs::create_dir(&project).unwrap();
    let mut child = fixture
        .command()
        .args(["--stdin", "--project-directory"])
        .arg(&project)
        .arg("SAVED_KEY")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"project\r\nvalue\r\n")
        .unwrap();
    assert!(child.wait().unwrap().success());
    let encoded_path: String = fs::canonicalize(project)
        .unwrap()
        .to_str()
        .unwrap()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        fs::read(
            fixture
                .0
                .join("keychain/.project-values")
                .join(encoded_path)
                .join("SAVED_KEY")
        )
        .unwrap(),
        b"project\r\nvalue\r\n"
    );
    assert_eq!(fs::read(fixture.saved()).unwrap(), "  é🔑  \n\n".as_bytes());
}

#[test]
fn invalid_stdin_never_saves_or_echoes_input() {
    let fixture = Fixture::new();
    fs::write(fixture.saved(), "original").unwrap();
    for (value, error) in [
        (Vec::new(), "empty key value"),
        (
            b"sensitive-before\0sensitive-after".to_vec(),
            "must not contain NUL",
        ),
        (
            b"sensitive-before\xffsensitive-after".to_vec(),
            "must be valid UTF-8",
        ),
        (vec![b'x'; 1024 * 1024 + 1], "exceeds 1 MiB"),
    ] {
        let mut child = fixture
            .command()
            .args(["--stdin", "SAVED_KEY"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&value).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(error), "{stderr}");
        assert!(!stderr.contains("sensitive"));
        assert_eq!(fs::read(fixture.saved()).unwrap(), b"original");
    }
}

struct Terminal {
    child: Child,
    master: Option<File>,
    slave: File,
    output: Vec<u8>,
    original: libc::termios,
}

impl Terminal {
    fn spawn(fixture: &Fixture, args: &[&str]) -> Self {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        for file in [&master, &slave] {
            assert_eq!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        }
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut original = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut original) },
            0
        );
        let mut command = fixture.command();
        command
            .args(args)
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave.try_clone().unwrap());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Self {
            child: command.spawn().unwrap(),
            master: Some(master),
            slave,
            output: Vec::new(),
            original,
        }
    }

    fn drain(&mut self) {
        let mut chunk = [0; 4096];
        loop {
            match self.master.as_mut().unwrap().read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => self.output.extend_from_slice(&chunk[..count]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::EIO) =>
                {
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("{error}"),
            }
        }
    }

    fn ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.drain();
            let output = String::from_utf8_lossy(&self.output);
            if output.contains("Ctrl-C cancels.") || output.contains("Value for SAVED_KEY: ") {
                break;
            }
            assert!(Instant::now() < deadline, "prompt timed out: {output}");
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut attributes = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(
            unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut attributes) },
            0
        );
        assert_eq!(attributes.c_lflag & (libc::ECHO | libc::ECHONL), 0);
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.as_mut().unwrap().write_all(bytes).unwrap();
    }

    fn finish(&mut self, success: bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.drain();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.drain();
                assert_eq!(
                    status.success(),
                    success,
                    "{}",
                    String::from_utf8_lossy(&self.output)
                );
                break;
            }
            assert!(Instant::now() < deadline, "save did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        // macOS revokes the slave when the controlling session exits. The master
        // still exposes its termios; tcgetattr(slave) fails after child exit.
        let mut restored = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(
            unsafe { libc::tcgetattr(self.master.as_ref().unwrap().as_raw_fd(), &mut restored) },
            0
        );
        assert_eq!(restored.c_lflag, self.original.c_lflag);
        assert_eq!(restored.c_iflag, self.original.c_iflag);
        assert_eq!(restored.c_cc, self.original.c_cc);
        assert!(!String::from_utf8_lossy(&self.output).contains("synthetic-test-only"));
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        drop(self.master.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn terminal_modes_preserve_input_restore_echo_and_cancel_without_saving() {
    let fixture = Fixture::new();
    for final_newline in [true, false] {
        let mut tty = Terminal::spawn(&fixture, &["--multiline", "SAVED_KEY"]);
        tty.ready();
        let mut value =
            b"-----BEGIN PRIVATE KEY-----\nsynthetic-test-only\n-----END PRIVATE KEY-----".to_vec();
        if final_newline {
            value.push(b'\n');
        }
        tty.send(&value);
        tty.send(b"\x04");
        if !final_newline {
            // Separate the flush from the subsequent zero-byte EOF read.
            std::thread::sleep(Duration::from_millis(50));
            tty.send(b"\x04");
        }
        tty.finish(true);
        assert_eq!(fs::read(fixture.saved()).unwrap(), value);
    }
    let mut tty = Terminal::spawn(&fixture, &["SAVED_KEY"]);
    tty.ready();
    tty.send(b"  synthetic-test-only  \n");
    tty.finish(true);
    assert_eq!(
        fs::read(fixture.saved()).unwrap(),
        b"  synthetic-test-only  "
    );

    let mut tty = Terminal::spawn(&fixture, &["SAVED_KEY"]);
    tty.ready();
    tty.send(b"  synthetic-test-only");
    tty.send(b"\x04");
    std::thread::sleep(Duration::from_millis(50));
    assert!(tty.child.try_wait().unwrap().is_none());
    tty.send(b"  \n");
    tty.finish(true);
    assert_eq!(
        fs::read(fixture.saved()).unwrap(),
        b"  synthetic-test-only  "
    );

    for signal in [
        None,
        Some(libc::SIGTERM),
        Some(libc::SIGHUP),
        Some(libc::SIGTSTP),
    ] {
        let mut tty = Terminal::spawn(&fixture, &["--multiline", "SAVED_KEY"]);
        tty.ready();
        tty.send(b"synthetic-test-only\nunfinished-secret");
        if let Some(signal) = signal {
            assert_eq!(unsafe { libc::kill(tty.child.id() as i32, signal) }, 0);
        } else {
            tty.send(b"\x03");
        }
        tty.finish(false);
        assert_eq!(
            fs::read(fixture.saved()).unwrap(),
            b"  synthetic-test-only  "
        );
    }
    for value in [
        &b""[..],
        &b"synthetic-test-only\0value\n"[..],
        &b"synthetic-test-only\xff\n"[..],
    ] {
        let mut tty = Terminal::spawn(&fixture, &["--multiline", "SAVED_KEY"]);
        tty.ready();
        tty.send(value);
        tty.send(b"\x04");
        tty.finish(false);
        assert_eq!(
            fs::read(fixture.saved()).unwrap(),
            b"  synthetic-test-only  "
        );
    }
    let mut tty = Terminal::spawn(&fixture, &["--stdin", "SAVED_KEY"]);
    tty.finish(false);
    assert!(String::from_utf8_lossy(&tty.output).contains("requires redirected input"));
}
