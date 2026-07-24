use std::path::PathBuf;

const APPROVAL_SERVICE: &str = "com.automicvault.av2.approval";

pub(crate) fn store_secret(account: &str, value: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        std::fs::create_dir_all(&dir)
            .map_err(|err| format!("failed to create test keychain dir: {err}"))?;
        let path = PathBuf::from(dir).join(account);
        return std::fs::write(&path, value)
            .map_err(|err| format!("failed to write {}: {err}", path.display()));
    }
    xpc_request("save", b"key\0", account, Some((b"value\0", value))).map(|_| ())
}

pub(crate) fn load_secret(account: &str) -> Result<String, String> {
    if let Some(dir) = crate::test_keychain_dir() {
        let path = PathBuf::from(dir).join(account);
        return std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()));
    }
    xpc_request("load", b"key\0", account, None)?
        .ok_or_else(|| format!("failed to load isotope key {account}"))
}

pub(crate) fn bless_script(path: &str) -> Result<(), String> {
    xpc_request("bless", b"path\0", path, None).map(|_| ())
}

#[cfg(target_os = "macos")]
fn xpc_request(
    operation: &str,
    field: &'static [u8],
    field_value: &str,
    extra: Option<(&'static [u8], &str)>,
) -> Result<Option<String>, String> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};

    type XpcObject = *mut c_void;

    unsafe extern "C" {
        static _xpc_type_error: u8;
        static _xpc_error_key_description: *const c_char;

        fn xpc_connection_create_mach_service(
            name: *const c_char,
            targetq: *mut c_void,
            flags: u64,
        ) -> XpcObject;
        fn xpc_connection_activate(connection: XpcObject);
        fn xpc_connection_cancel(connection: XpcObject);
        fn xpc_connection_send_message_with_reply_sync(
            connection: XpcObject,
            message: XpcObject,
        ) -> XpcObject;
        fn xpc_dictionary_create_empty() -> XpcObject;
        fn xpc_dictionary_set_bool(xdict: XpcObject, key: *const c_char, value: bool);
        fn xpc_dictionary_get_bool(xdict: XpcObject, key: *const c_char) -> bool;
        fn xpc_dictionary_set_string(xdict: XpcObject, key: *const c_char, value: *const c_char);
        fn xpc_dictionary_get_string(xdict: XpcObject, key: *const c_char) -> *const c_char;
        fn xpc_get_type(object: XpcObject) -> *const c_void;
        fn xpc_release(object: XpcObject);
        fn xpc_connection_set_peer_code_signing_requirement(
            connection: XpcObject,
            requirement: *const c_char,
        ) -> c_int;
        fn av_xpc_connection_set_empty_event_handler(connection: XpcObject);
    }

    unsafe fn set_string(dict: XpcObject, key: &[u8], value: &str) -> Result<(), String> {
        let value =
            CString::new(value).map_err(|_| format!("XPC field contains NUL: {value:?}"))?;
        unsafe { xpc_dictionary_set_string(dict, key.as_ptr().cast(), value.as_ptr()) };
        Ok(())
    }

    let service = CString::new(APPROVAL_SERVICE).unwrap();
    let connection =
        unsafe { xpc_connection_create_mach_service(service.as_ptr(), std::ptr::null_mut(), 0) };
    if connection.is_null() {
        return Err("failed to create approval XPC connection".into());
    }

    let menu_requirement = CString::new(crate::MENU_HELPER_CODE_SIGNING_REQUIREMENT).unwrap();
    let requirement_status = unsafe {
        xpc_connection_set_peer_code_signing_requirement(connection, menu_requirement.as_ptr())
    };
    if requirement_status != 0 {
        unsafe { xpc_release(connection) };
        return Err("failed to configure approval XPC signing requirement".into());
    }

    unsafe {
        av_xpc_connection_set_empty_event_handler(connection);
        xpc_connection_activate(connection);
    }

    let message = unsafe { xpc_dictionary_create_empty() };
    if message.is_null() {
        unsafe { xpc_connection_cancel(connection) };
        unsafe { xpc_release(connection) };
        return Err("failed to create approval XPC message".into());
    }

    unsafe {
        set_string(message, b"op\0", operation)?;
        set_string(message, field, field_value)?;
        if let Some((extra_field, value)) = extra {
            set_string(message, extra_field, value)?;
        }
        xpc_dictionary_set_bool(message, b"interactive\0".as_ptr().cast(), true);
    }

    let reply = unsafe { xpc_connection_send_message_with_reply_sync(connection, message) };
    unsafe {
        xpc_release(message);
        xpc_connection_cancel(connection);
        xpc_release(connection);
    }
    if reply.is_null() {
        return Err("Automic Vault approval did not reply".into());
    }

    let result = unsafe {
        if xpc_get_type(reply) == std::ptr::addr_of!(_xpc_type_error).cast() {
            let error = xpc_dictionary_get_string(reply, _xpc_error_key_description);
            let error = if error.is_null() {
                "approval XPC connection failed".into()
            } else {
                std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned()
            };
            if error == "Connection invalid" {
                Err("Automic Vault approval service is not running; open the menu bar app".into())
            } else {
                Err(error)
            }
        } else if xpc_dictionary_get_bool(reply, b"ok\0".as_ptr().cast()) {
            let value = xpc_dictionary_get_string(reply, b"value\0".as_ptr().cast());
            Ok((!value.is_null()).then(|| {
                std::ffi::CStr::from_ptr(value)
                    .to_string_lossy()
                    .into_owned()
            }))
        } else {
            let error = xpc_dictionary_get_string(reply, b"error\0".as_ptr().cast());
            Err(if error.is_null() {
                format!("secret {operation} failed")
            } else {
                std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned()
            })
        }
    };
    unsafe { xpc_release(reply) };
    result
}

#[cfg(not(target_os = "macos"))]
fn xpc_request(
    _operation: &str,
    _field: &'static [u8],
    _field_value: &str,
    _extra: Option<(&'static [u8], &str)>,
) -> Result<Option<String>, String> {
    Err("the Automic Vault menu bar approval service is only available on macOS".to_string())
}
