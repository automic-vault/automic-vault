#![allow(dead_code)]

pub(crate) mod hosts_token;
pub(crate) mod keychain_access;

use std::path::PathBuf;

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let mut reasons = Vec::new();
    let hosts_paths = candidate_hosts_paths()?;
    for path in &hosts_paths {
        if path.exists() && hosts_contains_oauth_token(&read_to_string(&path)?) {
            reasons.push(format!(
                "GitHub CLI hosts file contains plaintext OAuth tokens: {}",
                path.display()
            ));
        }
    }
    if keychain_services_allow_security_tool(&gh_keychain_services(&hosts_paths))? {
        reasons.push(
            "GitHub CLI keychain item allows non-interactive extraction by the security tool"
                .to_string(),
        );
    }
    Ok(reasons)
}

fn reasons_matching(prefix: &str) -> Result<Vec<String>, String> {
    Ok(install_insecurity_reasons()?
        .into_iter()
        .filter(|reason| reason.starts_with(prefix))
        .collect())
}

fn candidate_hosts_paths() -> Result<Vec<PathBuf>, String> {
    if let Some(dir) = std::env::var_os("GH_CONFIG_DIR").filter(|value| !value.is_empty()) {
        return Ok(vec![PathBuf::from(dir).join("hosts.yml")]);
    }

    let home = home_dir()?;
    let mut paths = vec![home.join(".config/gh/hosts.yml")];
    if let Some(xdg_config_home) =
        std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty())
    {
        paths.push(PathBuf::from(xdg_config_home).join("gh/hosts.yml"));
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

fn read_to_string(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn hosts_contains_oauth_token(contents: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix("oauth_token:")
            .map(str::trim)
            .is_some_and(non_empty_yaml_scalar)
    })
}

fn non_empty_yaml_scalar(value: &str) -> bool {
    let value = value
        .split_once('#')
        .map_or(value, |(value, _)| value)
        .trim();
    let value = value.trim_matches('"').trim_matches('\'');
    !value.is_empty() && value != "null" && value != "~"
}

fn gh_keychain_services(hosts_paths: &[PathBuf]) -> Vec<String> {
    let mut services = vec!["gh:github.com".to_string()];
    for path in hosts_paths {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines() {
            if line.starts_with(char::is_whitespace) {
                continue;
            }
            let Some(host) = line.trim().strip_suffix(':') else {
                continue;
            };
            if host.is_empty() || host == "hosts" {
                continue;
            }
            services.push(format!("gh:{host}"));
        }
    }
    services.sort();
    services.dedup();
    services
}

#[cfg(target_os = "macos")]
pub(crate) fn keychain_services_allow_security_tool(services: &[String]) -> Result<bool, String> {
    macos_keychain::keychain_allows_security_tool(services)
}

#[cfg(target_os = "macos")]
pub(crate) fn keychain_item_allows_security_tool(
    service: &str,
    account: &str,
) -> Result<bool, String> {
    macos_keychain::keychain_item_allows_security_tool(service, account)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn keychain_services_allow_security_tool(_services: &[String]) -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn keychain_item_allows_security_tool(
    _service: &str,
    _account: &str,
) -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "macos")]
pub(crate) use macos_keychain::{LegacyKeychainItem, legacy_keychain_items};

#[cfg(not(target_os = "macos"))]
pub(crate) struct LegacyKeychainItem {
    pub service: String,
    pub account: String,
}

#[cfg(not(target_os = "macos"))]
impl LegacyKeychainItem {
    pub(crate) fn delete(self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn legacy_keychain_items(
    _services: &[String],
) -> Result<Vec<LegacyKeychainItem>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_host_and_user_oauth_tokens() {
        assert!(hosts_contains_oauth_token(
            "github.com:\n  oauth_token: gho_secret\n"
        ));
        assert!(hosts_contains_oauth_token(
            "github.com:\n  users:\n    monalisa:\n      oauth_token: gho_secret\n"
        ));
    }

    #[test]
    fn ignores_empty_oauth_tokens() {
        assert!(!hosts_contains_oauth_token(
            "github.com:\n  oauth_token: ''\n"
        ));
        assert!(!hosts_contains_oauth_token(
            "github.com:\n  oauth_token: \"\"\n"
        ));
        assert!(!hosts_contains_oauth_token(
            "github.com:\n  oauth_token: null\n"
        ));
        assert!(!hosts_contains_oauth_token(
            "github.com:\n  oauth_token: # no token here\n"
        ));
    }

    #[test]
    fn gh_config_dir_overrides_default_locations() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "{}-detect-gh-config-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let config = root.join("gh");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("hosts.yml"),
            "github.com:\n  oauth_token: gho_secret\n",
        )
        .unwrap();

        let previous_home = std::env::var_os("HOME");
        let previous_gh_config = std::env::var_os("GH_CONFIG_DIR");
        unsafe {
            std::env::set_var("HOME", root.join("home"));
            std::env::set_var("GH_CONFIG_DIR", &config);
        }

        let reasons = install_insecurity_reasons().unwrap();

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_gh_config {
                Some(value) => std::env::set_var("GH_CONFIG_DIR", value),
                None => std::env::remove_var("GH_CONFIG_DIR"),
            }
        }

        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains(&config.join("hosts.yml").display().to_string()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn keychain_services_include_default_and_top_level_hosts() {
        let root = std::env::temp_dir().join(format!(
            "{}-detect-gh-services-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let hosts = root.join("hosts.yml");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &hosts,
            "github.example.com:\n  oauth_token: gho_secret\nusers:\n  monalisa:\n",
        )
        .unwrap();

        assert_eq!(
            gh_keychain_services(&[hosts]),
            vec![
                "gh:github.com".to_string(),
                "gh:github.example.com".to_string(),
                "gh:users".to_string(),
            ]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn keychain_services_ignore_duplicate_and_invalid_hosts() {
        let root = std::env::temp_dir().join(format!(
            "{}-detect-gh-services-dupes-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let hosts = root.join("hosts.yml");
        let missing = root.join("missing.yml");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &hosts,
            "github.com:\n  oauth_token: gho_secret\nhosts:\ncustom.example.com:\ncustom.example.com:\nnot-a-host\n",
        )
        .unwrap();

        assert_eq!(
            gh_keychain_services(&[missing, hosts]),
            vec![
                "gh:custom.example.com".to_string(),
                "gh:github.com".to_string(),
            ]
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(target_os = "macos")]
mod macos_keychain {
    use std::ffi::c_void;
    use std::ptr;

    const ERR_SEC_SUCCESS: i32 = 0;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const CSSM_ACL_AUTHORIZATION_ANY: i32 = 1;
    const CSSM_ACL_AUTHORIZATION_DECRYPT: i32 = 24;
    const SEC_GENERIC_PASSWORD_ITEM_CLASS: u32 = u32::from_be_bytes(*b"genp");
    const SEC_ACCOUNT_ITEM_ATTR: u32 = u32::from_be_bytes(*b"acct");
    const SEC_SERVICE_ITEM_ATTR: u32 = u32::from_be_bytes(*b"svce");
    const SECURITY_TOOL_PATH: &[u8] = b"/usr/bin/security";

    type CFTypeRef = *const c_void;
    type CFArrayRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFStringRef = *const c_void;
    type SecAccessRef = *const c_void;
    type SecACLRef = *const c_void;
    type SecKeychainItemRef = *const c_void;
    type SecKeychainSearchRef = *const c_void;
    type SecTrustedApplicationRef = *const c_void;

    #[repr(C)]
    struct SecKeychainAttribute {
        tag: u32,
        length: u32,
        data: *mut c_void,
    }

    #[repr(C)]
    struct SecKeychainAttributeList {
        count: u32,
        attr: *mut SecKeychainAttribute,
    }

    #[repr(C)]
    struct SecKeychainAttributeInfo {
        count: u32,
        tag: *mut u32,
        format: *mut u32,
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFArrayGetCount(array: CFArrayRef) -> isize;
        fn CFArrayGetValueAtIndex(array: CFArrayRef, index: isize) -> *const c_void;
        fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
        fn CFDataGetLength(data: CFDataRef) -> isize;
        fn CFRelease(value: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecACLCopyContents(
            acl: SecACLRef,
            application_list: *mut CFArrayRef,
            description: *mut CFStringRef,
            prompt_selector: *mut u16,
        ) -> i32;
        fn SecACLGetAuthorizations(acl: SecACLRef, tags: *mut i32, tag_count: *mut u32) -> i32;
        fn SecAccessCopyACLList(access: SecAccessRef, acl_list: *mut CFArrayRef) -> i32;
        fn SecKeychainItemCopyAccess(item: SecKeychainItemRef, access: *mut SecAccessRef) -> i32;
        fn SecKeychainItemCopyAttributesAndData(
            item: SecKeychainItemRef,
            info: *mut SecKeychainAttributeInfo,
            item_class: *mut u32,
            attr_list: *mut *mut SecKeychainAttributeList,
            length: *mut u32,
            data: *mut *mut c_void,
        ) -> i32;
        fn SecKeychainItemDelete(item: SecKeychainItemRef) -> i32;
        fn SecKeychainItemFreeAttributesAndData(
            attr_list: *mut SecKeychainAttributeList,
            data: *mut c_void,
        ) -> i32;
        fn SecKeychainSearchCopyNext(
            search: SecKeychainSearchRef,
            item: *mut SecKeychainItemRef,
        ) -> i32;
        fn SecKeychainSearchCreateFromAttributes(
            keychain_or_array: CFTypeRef,
            item_class: u32,
            attr_list: *const SecKeychainAttributeList,
            search: *mut SecKeychainSearchRef,
        ) -> i32;
        fn SecTrustedApplicationCopyData(
            app: SecTrustedApplicationRef,
            data: *mut CFDataRef,
        ) -> i32;
    }

    pub(super) fn keychain_allows_security_tool(services: &[String]) -> Result<bool, String> {
        for service in services {
            if service_allows_security_tool(service)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn keychain_item_allows_security_tool(
        service: &str,
        account: &str,
    ) -> Result<bool, String> {
        for item in service_items(service)? {
            if item_account(item.0)? == account && item_allows_security_tool(item.0)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) struct LegacyKeychainItem {
        pub service: String,
        pub account: String,
        item: ScopedCf<c_void>,
    }

    impl LegacyKeychainItem {
        pub(crate) fn delete(self) -> Result<(), String> {
            check_status(
                unsafe { SecKeychainItemDelete(self.item.0) },
                &format!(
                    "delete legacy keychain item (service {:?}, account {:?})",
                    self.service, self.account
                ),
            )
        }
    }

    pub(crate) fn legacy_keychain_items(
        services: &[String],
    ) -> Result<Vec<LegacyKeychainItem>, String> {
        let mut found = Vec::new();
        for service in services {
            for item in service_items(service)? {
                found.push(LegacyKeychainItem {
                    service: service.clone(),
                    account: item_account(item.0)?,
                    item,
                });
            }
        }
        Ok(found)
    }

    fn service_allows_security_tool(service: &str) -> Result<bool, String> {
        for item in service_items(service)? {
            if item_allows_security_tool(item.0)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn service_items(service: &str) -> Result<Vec<ScopedCf<c_void>>, String> {
        let mut service_bytes = service.as_bytes().to_vec();
        let mut attr = SecKeychainAttribute {
            tag: SEC_SERVICE_ITEM_ATTR,
            length: service_bytes.len() as u32,
            data: service_bytes.as_mut_ptr().cast(),
        };
        let attr_list = SecKeychainAttributeList {
            count: 1,
            attr: &mut attr,
        };
        let mut search = ptr::null();
        let status = unsafe {
            SecKeychainSearchCreateFromAttributes(
                ptr::null(),
                SEC_GENERIC_PASSWORD_ITEM_CLASS,
                &attr_list,
                &mut search,
            )
        };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(Vec::new());
        }
        check_status(status, "create keychain search")?;
        let _search_ref = ScopedCf(search);
        let mut items = Vec::new();

        loop {
            let mut item = ptr::null();
            let status = unsafe { SecKeychainSearchCopyNext(search, &mut item) };
            if status == ERR_SEC_ITEM_NOT_FOUND {
                return Ok(items);
            }
            check_status(status, "copy next keychain item")?;
            items.push(ScopedCf(item));
        }
    }

    fn item_account(item: SecKeychainItemRef) -> Result<String, String> {
        let mut tag = SEC_ACCOUNT_ITEM_ATTR;
        let mut info = SecKeychainAttributeInfo {
            count: 1,
            tag: &mut tag,
            format: ptr::null_mut(),
        };
        let mut attributes = ptr::null_mut();
        check_status(
            unsafe {
                SecKeychainItemCopyAttributesAndData(
                    item,
                    &mut info,
                    ptr::null_mut(),
                    &mut attributes,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            },
            "copy keychain item account",
        )?;
        let account = if attributes.is_null() || unsafe { (*attributes).count } != 1 {
            Err("legacy keychain item has no account".to_string())
        } else if let Some(attribute) = unsafe { (*attributes).attr.as_ref() } {
            if attribute.data.is_null() && attribute.length != 0 {
                Err("legacy keychain item has an invalid account".to_string())
            } else {
                let bytes = if attribute.length == 0 {
                    &[]
                } else {
                    unsafe {
                        std::slice::from_raw_parts(attribute.data.cast(), attribute.length as usize)
                    }
                };
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| "legacy keychain item account is not UTF-8".to_string())
            }
        } else {
            Err("legacy keychain item has no account".to_string())
        };
        check_status(
            unsafe { SecKeychainItemFreeAttributesAndData(attributes, ptr::null_mut()) },
            "free keychain item account",
        )?;
        account
    }

    fn item_allows_security_tool(item: SecKeychainItemRef) -> Result<bool, String> {
        let mut access = ptr::null();
        let status = unsafe { SecKeychainItemCopyAccess(item, &mut access) };
        check_status(status, "copy keychain item access")?;
        let _access_ref = ScopedCf(access);

        let mut acl_list = ptr::null();
        let status = unsafe { SecAccessCopyACLList(access, &mut acl_list) };
        check_status(status, "copy keychain ACL list")?;
        let _acl_list_ref = ScopedCf(acl_list);

        let acl_count = unsafe { CFArrayGetCount(acl_list) };
        for index in 0..acl_count {
            let acl = unsafe { CFArrayGetValueAtIndex(acl_list, index).cast::<c_void>() };
            if acl.is_null() {
                continue;
            }
            if acl_allows_security_tool(acl)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn acl_allows_security_tool(acl: SecACLRef) -> Result<bool, String> {
        if !acl_authorizes_secret_read(acl) {
            return Ok(false);
        }

        let mut app_list = ptr::null();
        let mut description = ptr::null();
        let mut prompt_selector = 0u16;
        let status = unsafe {
            SecACLCopyContents(acl, &mut app_list, &mut description, &mut prompt_selector)
        };
        check_status(status, "copy keychain ACL contents")?;
        let _description_ref = ScopedCf(description);
        if app_list.is_null() {
            return Ok(false);
        }
        let _app_list_ref = ScopedCf(app_list);

        let app_count = unsafe { CFArrayGetCount(app_list) };
        for index in 0..app_count {
            let app = unsafe { CFArrayGetValueAtIndex(app_list, index).cast::<c_void>() };
            if app.is_null() {
                continue;
            }
            if trusted_application_is_security_tool(app)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn acl_authorizes_secret_read(acl: SecACLRef) -> bool {
        let mut tags = [0i32; 64];
        let mut tag_count = tags.len() as u32;
        let status = unsafe { SecACLGetAuthorizations(acl, tags.as_mut_ptr(), &mut tag_count) };
        if status != ERR_SEC_SUCCESS {
            return false;
        }
        tags.iter()
            .take(tag_count as usize)
            .copied()
            .any(auth_tag_grants_secret_read)
    }

    fn auth_tag_grants_secret_read(tag: i32) -> bool {
        tag == CSSM_ACL_AUTHORIZATION_DECRYPT || tag == CSSM_ACL_AUTHORIZATION_ANY
    }

    fn trusted_application_is_security_tool(app: SecTrustedApplicationRef) -> Result<bool, String> {
        let mut data = ptr::null();
        let status = unsafe { SecTrustedApplicationCopyData(app, &mut data) };
        check_status(status, "copy trusted application data")?;
        let _data_ref = ScopedCf(data);

        let bytes = cf_data_bytes(data);
        Ok(bytes
            .windows(SECURITY_TOOL_PATH.len())
            .any(|window| window == SECURITY_TOOL_PATH))
    }

    fn cf_data_bytes(data: CFDataRef) -> Vec<u8> {
        let length = unsafe { CFDataGetLength(data) };
        if length <= 0 {
            return Vec::new();
        }
        let ptr = unsafe { CFDataGetBytePtr(data) };
        if ptr.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(ptr, length as usize).to_vec() }
    }

    fn check_status(status: i32, context: &str) -> Result<(), String> {
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(format!("{context} failed with OSStatus {status}"))
        }
    }

    struct ScopedCf<T>(*const T);

    impl<T> Drop for ScopedCf<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0.cast()) };
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn read_authorization_tags_cover_decrypt_and_any_only() {
            assert!(auth_tag_grants_secret_read(CSSM_ACL_AUTHORIZATION_DECRYPT));
            assert!(auth_tag_grants_secret_read(CSSM_ACL_AUTHORIZATION_ANY));
            assert!(!auth_tag_grants_secret_read(0));
        }
    }
}

pub(crate) fn findings(home: &std::path::Path) -> Vec<crate::Finding> {
    super::radioisotope::findings("gh-cli", install_insecurity_reasons, home)
}
