use super::*;
use std::io;
use zeroize::Zeroizing;

// The dictionary is owned by the live XPC reply. Data transport preserves NULs
// and empty Values; environment-mode replies retain their existing string wire format.
pub(super) unsafe fn read_xpc_value(
    values: *mut std::ffi::c_void,
    key: &std::ffi::CStr,
) -> Result<String, String> {
    use std::ffi::{c_char, c_void};
    unsafe extern "C" {
        static _xpc_type_data: u8;
        fn xpc_dictionary_get_value(dict: *mut c_void, key: *const c_char) -> *mut c_void;
        fn xpc_get_type(object: *mut c_void) -> *const c_void;
        fn xpc_data_get_length(object: *mut c_void) -> usize;
        fn xpc_data_get_bytes_ptr(object: *mut c_void) -> *const c_void;
    }
    unsafe {
        let data = xpc_dictionary_get_value(values, key.as_ptr());
        if data.is_null() || xpc_get_type(data) != std::ptr::addr_of!(_xpc_type_data).cast() {
            return Err("missing or invalid FD Secret payload".into());
        }
        let length = xpc_data_get_length(data);
        if length == 0 {
            return Ok(String::new());
        }
        let bytes = xpc_data_get_bytes_ptr(data);
        if bytes.is_null() {
            return Err("invalid FD Secret payload".into());
        }
        String::from_utf8(std::slice::from_raw_parts(bytes.cast(), length).to_vec())
            .map_err(|_| "FD Secret payload is not valid UTF-8".into())
    }
}

// Reserve destination descriptors before XPC opens its own files. Keep them
// close-on-exec until all Secrets have been buffered and authorization succeeds.
struct SecretPipe {
    reader: File,
    writer: File,
}

fn duplicate(file: &impl AsRawFd, mappings: &BTreeMap<String, i32>) -> io::Result<File> {
    let mut minimum = 3;
    loop {
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let duplicate = unsafe { File::from_raw_fd(fd) };
        if !mappings.values().any(|destination| *destination == fd) {
            return Ok(duplicate);
        }
        minimum = fd + 1;
    }
}

fn reserve(mappings: &BTreeMap<String, i32>) -> Result<BTreeMap<String, SecretPipe>, String> {
    for fd in mappings.values() {
        if unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0
            || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
        {
            return Err(format!(
                "file descriptor {fd} is already open or unavailable"
            ));
        }
    }
    let mut pipes = BTreeMap::new();
    for (name, destination) in mappings {
        let make = || -> io::Result<SecretPipe> {
            let (reader, writer) = io::pipe()?;
            let temporary_reader = duplicate(&reader, mappings)?;
            let temporary_writer = duplicate(&writer, mappings)?;
            drop((reader, writer));
            if unsafe { libc::dup2(temporary_reader.as_raw_fd(), *destination) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let reader = unsafe { File::from_raw_fd(*destination) };
            if unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SecretPipe {
                reader,
                writer: temporary_writer,
            })
        };
        pipes.insert(
            name.clone(),
            make().map_err(|err| format!("cannot create Secret pipe: {err}"))?,
        );
    }
    Ok(pipes)
}

fn fill(
    pipes: BTreeMap<String, SecretPipe>,
    mut secrets: SecretValues,
) -> Result<Vec<File>, String> {
    let mut readers = Vec::new();
    for (name, mut pipe) in pipes {
        let value = Zeroizing::new(match secrets.remove(&name) {
            Some(value) => value,
            None => load_test_secret_if_present(&name)?
                .ok_or_else(|| format!("missing Secret: {name}"))?,
        });
        if unsafe { libc::fcntl(pipe.writer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(format!(
                "cannot prepare Secret pipe: {}",
                io::Error::last_os_error()
            ));
        }
        // ponytail: prebuffering caps Values at the kernel's available pipe
        // capacity; add a reviewed streaming writer if larger Values are needed.
        pipe.writer.write_all(value.as_bytes()).map_err(|err| {
            if err.kind() == io::ErrorKind::WouldBlock {
                format!("Secret {name} exceeds the anonymous pipe buffer capacity; Target was not started")
            } else {
                format!("cannot fill Secret pipe for {name}: {err}")
            }
        })?;
        drop(pipe.writer);
        readers.push(pipe.reader);
    }
    Ok(readers)
}

pub(super) fn exec(options: &Options) -> String {
    let prepare = || -> Result<_, String> {
        if options.shebang_script.is_some() {
            return Err("FD mode is not supported in av inject shebangs".into());
        }
        let pipes = reserve(&options.secret_fds)?;
        let mut readers = Vec::new();
        let (target, env) = prepare_injection(
            options,
            &mut io::sink(),
            None,
            None,
            approve_injection,
            |options, _, secrets| {
                readers = fill(pipes, secrets)?;
                Ok(secretless_environment(options, false, false))
            },
        )?;
        Ok((target, readers, env))
    };
    let (target, readers, env) = match prepare() {
        Ok(prepared) => prepared,
        Err(err) => return err,
    };
    let mut command = Command::new(&target);
    command.args(&options.args).env_clear().envs(env);
    // exec preserves the authorized PID. Closed writers guarantee EOF after
    // the exact stored bytes; no background process retains a Secret copy.
    unsafe {
        command.pre_exec(move || {
            for reader in &readers {
                if libc::fcntl(reader.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    format!("failed to execute {}: {}", target.display(), command.exec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xpc_data_preserves_exact_values_and_rejects_wrong_types() {
        use std::ffi::{c_char, c_void};
        unsafe extern "C" {
            fn xpc_dictionary_create_empty() -> *mut c_void;
            fn xpc_dictionary_set_data(
                dict: *mut c_void,
                key: *const c_char,
                bytes: *const c_void,
                length: usize,
            );
            fn xpc_dictionary_set_string(
                dict: *mut c_void,
                key: *const c_char,
                value: *const c_char,
            );
            fn xpc_release(object: *mut c_void);
        }
        unsafe {
            let dict = xpc_dictionary_create_empty();
            assert!(read_xpc_value(dict, c"FOO").is_err());
            for value in [b"".as_slice(), b"PEM\r\nline\0value\n\n"] {
                xpc_dictionary_set_data(dict, c"FOO".as_ptr(), value.as_ptr().cast(), value.len());
                assert_eq!(read_xpc_value(dict, c"FOO").unwrap().as_bytes(), value);
            }
            xpc_dictionary_set_string(dict, c"FOO".as_ptr(), c"must-not-leak".as_ptr());
            assert_eq!(
                read_xpc_value(dict, c"FOO").unwrap_err(),
                "missing or invalid FD Secret payload"
            );
            xpc_dictionary_set_data(dict, c"FOO".as_ptr(), b"\xff".as_ptr().cast(), 1);
            assert_eq!(
                read_xpc_value(dict, c"FOO").unwrap_err(),
                "FD Secret payload is not valid UTF-8"
            );
            xpc_release(dict);
        }
    }

    #[test]
    fn partial_preparation_closes_all_descriptors() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let mappings = BTreeMap::from([("A".into(), 200), ("B".into(), 201)]);
        let pipes = reserve(&mappings).unwrap();
        let secrets = BTreeMap::from([
            ("A".into(), "small".into()),
            ("B".into(), "x".repeat(1024 * 1024)),
        ]);
        assert!(fill(pipes, secrets).is_err());
        for fd in mappings.values() {
            assert_eq!(unsafe { libc::fcntl(*fd, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
    }
}
