use std::ffi::{CStr, CString};

#[cfg(target_os = "macos")]
pub(super) type XpcObject = *mut std::ffi::c_void;

#[cfg(target_os = "macos")]
pub(super) fn xpc_request(
    operation: &str,
    configure: impl FnOnce(XpcObject) -> Result<(), String>,
) -> Result<String, String> {
    use std::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        static _xpc_type_error: u8;
        static _xpc_error_key_description: *const c_char;
        fn xpc_connection_create_mach_service(
            name: *const c_char,
            queue: *mut c_void,
            flags: u64,
        ) -> XpcObject;
        fn xpc_connection_activate(connection: XpcObject);
        fn xpc_connection_cancel(connection: XpcObject);
        fn xpc_connection_send_message_with_reply_sync(
            connection: XpcObject,
            message: XpcObject,
        ) -> XpcObject;
        fn xpc_dictionary_create_empty() -> XpcObject;
        fn xpc_dictionary_get_bool(object: XpcObject, key: *const c_char) -> bool;
        fn xpc_dictionary_get_string(object: XpcObject, key: *const c_char) -> *const c_char;
        fn xpc_get_type(object: XpcObject) -> *const c_void;
        fn xpc_release(object: XpcObject);
        fn xpc_connection_set_peer_code_signing_requirement(
            connection: XpcObject,
            requirement: *const c_char,
        ) -> c_int;
        fn av_xpc_connection_set_empty_event_handler(connection: XpcObject);
    }
    let service = c"com.automicvault.av2.approval";
    let connection =
        unsafe { xpc_connection_create_mach_service(service.as_ptr(), std::ptr::null_mut(), 0) };
    if connection.is_null() {
        return Err("failed to create approval XPC connection".into());
    }
    let requirement = CString::new(crate::MENU_HELPER_CODE_SIGNING_REQUIREMENT).unwrap();
    if unsafe { xpc_connection_set_peer_code_signing_requirement(connection, requirement.as_ptr()) }
        != 0
    {
        unsafe { xpc_release(connection) };
        return Err("failed to configure approval XPC signing requirement".into());
    }
    unsafe {
        av_xpc_connection_set_empty_event_handler(connection);
        xpc_connection_activate(connection);
    }
    let message = unsafe { xpc_dictionary_create_empty() };
    unsafe {
        xpc_set_string(message, "op", operation)?;
    }
    if let Err(error) = configure(message) {
        unsafe {
            xpc_release(message);
            xpc_connection_cancel(connection);
            xpc_release(connection);
        }
        return Err(error);
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
            if crate::approval_service_connection_invalid(reply) {
                Err(crate::approval_service_unavailable_message(service).into())
            } else {
                let value = xpc_dictionary_get_string(reply, _xpc_error_key_description);
                let error = if value.is_null() {
                    "approval XPC connection failed".into()
                } else {
                    CStr::from_ptr(value).to_string_lossy().into_owned()
                };
                Err(error)
            }
        } else if !xpc_dictionary_get_bool(reply, c"ok".as_ptr()) {
            let value = xpc_dictionary_get_string(reply, c"error".as_ptr());
            Err(if value.is_null() {
                "request denied".into()
            } else {
                CStr::from_ptr(value).to_string_lossy().into_owned()
            })
        } else {
            let value = xpc_dictionary_get_string(reply, c"value".as_ptr());
            if value.is_null() {
                Err("Automic Vault returned no value".into())
            } else {
                Ok(CStr::from_ptr(value).to_string_lossy().into_owned())
            }
        }
    };
    unsafe { xpc_release(reply) };
    result
}

#[cfg(not(target_os = "macos"))]
pub(super) fn xpc_request(
    _operation: &str,
    _configure: impl FnOnce(*mut std::ffi::c_void) -> Result<(), String>,
) -> Result<String, String> {
    Err("Credential helpers are only available on macOS".into())
}

#[cfg(target_os = "macos")]
pub(super) unsafe fn xpc_set_string(
    object: XpcObject,
    key: &str,
    value: &str,
) -> Result<(), String> {
    unsafe extern "C" {
        fn xpc_dictionary_set_string(object: XpcObject, key: *const i8, value: *const i8);
    }
    let key = CString::new(key).unwrap();
    let value = CString::new(value).map_err(|_| "XPC field contains NUL".to_string())?;
    unsafe { xpc_dictionary_set_string(object, key.as_ptr(), value.as_ptr()) };
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) unsafe fn xpc_set_bool(object: XpcObject, key: &str, value: bool) {
    unsafe extern "C" {
        fn xpc_dictionary_set_bool(object: XpcObject, key: *const i8, value: bool);
    }
    unsafe { xpc_dictionary_set_bool(object, CString::new(key).unwrap().as_ptr(), value) };
}

#[cfg(target_os = "macos")]
pub(super) unsafe fn xpc_set_u64(object: XpcObject, key: &str, value: u64) {
    unsafe extern "C" {
        fn xpc_dictionary_set_uint64(object: XpcObject, key: *const i8, value: u64);
    }
    unsafe { xpc_dictionary_set_uint64(object, CString::new(key).unwrap().as_ptr(), value) };
}

#[cfg(target_os = "macos")]
pub(super) unsafe fn xpc_set_data(object: XpcObject, key: &str, value: &[u8]) {
    unsafe extern "C" {
        fn xpc_dictionary_set_data(
            object: XpcObject,
            key: *const i8,
            value: *const std::ffi::c_void,
            length: usize,
        );
    }
    unsafe {
        xpc_dictionary_set_data(
            object,
            CString::new(key).unwrap().as_ptr(),
            value.as_ptr().cast(),
            value.len(),
        )
    };
}

#[cfg(target_os = "macos")]
pub(super) unsafe fn xpc_set_array(
    object: XpcObject,
    key: &str,
    values: &[String],
) -> Result<(), String> {
    unsafe extern "C" {
        fn xpc_array_create_empty() -> XpcObject;
        fn xpc_array_set_string(array: XpcObject, index: usize, value: *const i8);
        fn xpc_dictionary_set_value(object: XpcObject, key: *const i8, value: XpcObject);
        fn xpc_release(object: XpcObject);
    }
    let array = unsafe { xpc_array_create_empty() };
    for value in values {
        let value =
            CString::new(value.as_str()).map_err(|_| "XPC array contains NUL".to_string())?;
        unsafe { xpc_array_set_string(array, usize::MAX, value.as_ptr()) };
    }
    unsafe {
        xpc_dictionary_set_value(object, CString::new(key).unwrap().as_ptr(), array);
        xpc_release(array);
    }
    Ok(())
}
