use std::ffi::{CStr, CString};

// Field names are static protocol metadata; rejected values must never enter diagnostics.
pub(crate) fn xpc_string(field: &'static [u8], value: &str) -> Result<CString, String> {
    let field =
        CStr::from_bytes_with_nul(field).map_err(|_| "invalid XPC field name".to_string())?;
    CString::new(value).map_err(|_| format!("XPC field {} contains NUL", field.to_string_lossy()))
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static _xpc_error_connection_invalid: u8;
    fn xpc_equal(object1: *mut std::ffi::c_void, object2: *mut std::ffi::c_void) -> bool;
}

#[cfg(target_os = "macos")]
pub(crate) unsafe fn connection_invalid(reply: *mut std::ffi::c_void) -> bool {
    unsafe {
        xpc_equal(
            reply,
            std::ptr::addr_of!(_xpc_error_connection_invalid)
                .cast_mut()
                .cast(),
        )
    }
}

pub(crate) fn unavailable_message(service: &CStr) -> &'static str {
    unavailable_message_for_sandbox(sandbox_denies_mach_lookup(service))
}

#[cfg(target_os = "macos")]
fn sandbox_denies_mach_lookup(service: &CStr) -> bool {
    use std::os::raw::{c_char, c_int};

    #[link(name = "sandbox")]
    unsafe extern "C" {
        fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter: c_int, ...) -> c_int;
    }

    const SANDBOX_FILTER_GLOBAL_NAME: c_int = 2;
    unsafe {
        sandbox_check(
            libc::getpid(),
            c"mach-lookup".as_ptr(),
            SANDBOX_FILTER_GLOBAL_NAME,
            service.as_ptr(),
        ) != 0
    }
}

fn unavailable_message_for_sandbox(sandbox_denied: bool) -> &'static str {
    if sandbox_denied {
        "Automic Vault approval service is blocked by this process's sandbox; retry with elevated permissions"
    } else {
        "Automic Vault approval service is not running; open the menu bar app"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xpc_string_errors_name_fields_without_disclosing_values() {
        for field in [&b"value\0"[..], &b"args\0"[..], &b"target\0"[..]] {
            let name = CStr::from_bytes_with_nul(field).unwrap().to_str().unwrap();
            assert_eq!(
                xpc_string(field, "sensitive-before\0sensitive-after").unwrap_err(),
                format!("XPC field {name} contains NUL")
            );
        }
        assert_eq!(
            xpc_string(b"value\0", " line\r\nline\n ")
                .unwrap()
                .to_bytes(),
            b" line\r\nline\n "
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn recognizes_connection_invalid_xpc_object() {
        let error = std::ptr::addr_of!(_xpc_error_connection_invalid)
            .cast_mut()
            .cast();
        assert!(unsafe { connection_invalid(error) });
    }

    #[test]
    fn unavailable_message_distinguishes_sandbox_denial() {
        assert_eq!(
            unavailable_message_for_sandbox(true),
            "Automic Vault approval service is blocked by this process's sandbox; retry with elevated permissions"
        );
        assert_eq!(
            unavailable_message_for_sandbox(false),
            "Automic Vault approval service is not running; open the menu bar app"
        );
    }
}
