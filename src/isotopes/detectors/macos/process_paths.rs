use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use zeroize::{Zeroize, Zeroizing};

// Passive diagnostic evidence only: never use these environments for execution
// or authorization. macOS may expose only the environment supplied at exec.
pub(super) struct ObservedProcess {
    pub pid: i32,
    pub executable: OsString,
}

pub(super) fn observed_paths() -> BTreeMap<OsString, Vec<ObservedProcess>> {
    let mut paths = BTreeMap::<OsString, Vec<ObservedProcess>>::new();
    let mut retained_bytes = 0;
    let mut pids = vec![0_i32; 16_384];
    // SAFETY: the output buffer holds the supplied number of bytes.
    let count = unsafe {
        libc::proc_listallpids(
            pids.as_mut_ptr().cast(),
            size_of_val(pids.as_slice()) as i32,
        )
    };
    if count <= 0 {
        return paths;
    }
    // Bound memory even when process arguments or the process list are hostile.
    let mut buffer = Zeroizing::new(vec![0_u8; 1024 * 1024]);
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    for pid in pids.into_iter().take(count as usize).filter(|pid| *pid > 0) {
        // SAFETY: proc_bsdinfo is a C data structure with valid all-zero fields.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // SAFETY: info is live and its exact byte size is supplied.
        let size = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size_of_val(&info) as i32,
            )
        };
        if size != size_of_val(&info) as i32 || info.pbi_uid != uid || info.pbi_ruid != uid {
            continue;
        }
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut len = buffer.len();
        // SAFETY: mib and buffer are live, correctly sized outputs; no new value is set.
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buffer.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0
            && len <= buffer.len()
            && let Some(path) = path_from_procargs(&buffer[..len])
        {
            // KERN_PROCARGS2's first string is the executable path, not argv[0].
            // Read it from the same snapshot as PATH; never retain command arguments.
            let mut remaining = &buffer[4..len];
            if let Some(executable) = take_string(&mut remaining) {
                let path_bytes = if paths.contains_key(&path) {
                    0
                } else {
                    path.len()
                };
                let bytes = path_bytes + executable.len();
                if retained_bytes + bytes <= 1024 * 1024 {
                    retained_bytes += bytes;
                    paths.entry(path).or_default().push(ObservedProcess {
                        pid,
                        executable: OsString::from_vec(executable.to_vec()),
                    });
                }
            }
        }
        // The kernel buffer also contains unrelated environment values.
        let written = if result == 0 {
            len.min(buffer.len())
        } else {
            buffer.len()
        };
        buffer[..written].zeroize();
    }
    paths
}

fn path_from_procargs(data: &[u8]) -> Option<OsString> {
    let argc = i32::from_ne_bytes(data.get(..4)?.try_into().ok()?);
    if argc <= 0 || argc as usize > data.len() {
        return None;
    }
    let mut remaining = &data[4..];
    take_string(&mut remaining)?; // Executable path, followed by alignment padding.
    while remaining.first() == Some(&0) {
        remaining = &remaining[1..];
    }
    for _ in 0..argc {
        take_string(&mut remaining)?;
    }
    while remaining.first() == Some(&0) {
        remaining = &remaining[1..];
    }
    let mut path = None;
    while !remaining.is_empty() && remaining[0] != 0 {
        let entry = take_string(&mut remaining)?;
        if let Some(value) = entry.strip_prefix(b"PATH=") {
            if path.is_some() {
                return None;
            }
            path = Some(OsString::from_vec(value.to_vec()));
        }
    }
    path
}

fn take_string<'a>(remaining: &mut &'a [u8]) -> Option<&'a [u8]> {
    let end = remaining.iter().position(|byte| *byte == 0)?;
    let value = &remaining[..end];
    *remaining = &remaining[end + 1..];
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn procargs(env: &[u8]) -> Vec<u8> {
        let mut data = 3_i32.to_ne_bytes().to_vec();
        data.extend_from_slice(b"/bin/example\0\0example\0\0PATH=argument\0\0\0");
        data.extend_from_slice(env);
        data
    }

    #[test]
    fn extracts_only_environment_path_after_all_arguments() {
        assert_eq!(
            path_from_procargs(&procargs(b"TOKEN=private\0PATH=/user/bin:/usr/bin\0\0")),
            Some(OsString::from("/user/bin:/usr/bin"))
        );
        assert_eq!(
            path_from_procargs(&procargs(b"PATH=\0\0")),
            Some(OsString::new())
        );
        assert_eq!(
            path_from_procargs(&procargs(b"PATH=/\xff\0\0")),
            Some(OsString::from_vec(b"/\xff".to_vec()))
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_truncated_values() {
        for env in [
            b"OTHER=value\0\0".as_slice(),
            b"PATH=/one\0PATH=/two\0\0",
            b"PATH=/truncated",
        ] {
            assert_eq!(path_from_procargs(&procargs(env)), None);
        }
        for data in [
            vec![],
            vec![0; 4],
            (-1_i32).to_ne_bytes().to_vec(),
            procargs(b"")[..8].to_vec(),
        ] {
            assert_eq!(path_from_procargs(&data), None);
        }
    }
}
