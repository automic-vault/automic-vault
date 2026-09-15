// The legacy ACL APIs are needed to inspect file-based Keychain access controls.
// SecAccessControl for the Data Protection Keychain is a different model.
use super::Inspection;
use std::{ffi::c_void, ptr};

type Ref = *const c_void;
// CSSM_ACL_AUTHORIZATION_SIGN = CSSM_WORDID_SIGN (Security/cssmtype.h).
const SIGN: i32 = 115;
const ANY: i32 = 1;
const ITEM_NOT_FOUND: i32 = -25300;
const CODESIGN: &[u8] = b"/usr/bin/codesign\0";
const CODE_SIGNING_EKU: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 3];

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: Ref;
    static kCFBooleanFalse: Ref;
    static kCFTypeArrayCallBacks: c_void;
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    fn CFRelease(value: Ref);
    fn CFGetTypeID(value: Ref) -> usize;
    fn CFArrayGetTypeID() -> usize;
    fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFDataGetTypeID() -> usize;
    fn CFArrayGetCount(array: Ref) -> isize;
    fn CFArrayGetValueAtIndex(array: Ref, index: isize) -> Ref;
    fn CFDictionaryCreate(
        allocator: Ref,
        keys: *const Ref,
        values: *const Ref,
        count: isize,
        key_callbacks: Ref,
        value_callbacks: Ref,
    ) -> Ref;
    fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
    fn CFDataGetLength(data: Ref) -> isize;
    fn CFDataGetBytePtr(data: Ref) -> *const u8;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: Ref;
    static kSecClassIdentity: Ref;
    static kSecReturnRef: Ref;
    static kSecMatchLimit: Ref;
    static kSecMatchLimitAll: Ref;
    static kSecMatchSearchList: Ref;
    static kSecUseDataProtectionKeychain: Ref;
    static kSecUseAuthenticationUI: Ref;
    static kSecUseAuthenticationUIFail: Ref;
    static kSecOIDExtendedKeyUsage: Ref;
    static kSecPropertyKeyValue: Ref;
    fn SecItemCopyMatching(query: Ref, result: *mut Ref) -> i32;
    fn SecIdentityCopyCertificate(identity: Ref, certificate: *mut Ref) -> i32;
    fn SecIdentityCopyPrivateKey(identity: Ref, key: *mut Ref) -> i32;
    fn SecCertificateCopyValues(certificate: Ref, keys: Ref, error: *mut Ref) -> Ref;
    fn SecKeychainItemCopyAccess(item: Ref, access: *mut Ref) -> i32;
    fn SecKeychainItemCopyKeychain(item: Ref, keychain: *mut Ref) -> i32;
    fn SecKeychainGetStatus(keychain: Ref, status: *mut u32) -> i32;
    fn SecAccessCopyACLList(access: Ref, acls: *mut Ref) -> i32;
    fn SecACLGetAuthorizations(acl: Ref, tags: *mut i32, count: *mut u32) -> i32;
    fn SecACLCopyContents(acl: Ref, apps: *mut Ref, description: *mut Ref, prompt: *mut u16)
    -> i32;
    fn SecTrustedApplicationCopyData(app: Ref, data: *mut Ref) -> i32;
    fn SecKeychainGetUserInteractionAllowed(allowed: *mut u8) -> i32;
    fn SecKeychainSetUserInteractionAllowed(allowed: u8) -> i32;
}

struct Owned(Ref);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}
fn copied(call: impl FnOnce(*mut Ref) -> i32) -> Result<Owned, ()> {
    let mut value = ptr::null();
    let status = call(&mut value);
    let value = Owned(value);
    if status == 0 && !value.0.is_null() {
        Ok(value)
    } else {
        Err(())
    }
}

// Scans run serially in the CLI/scanner process, separate from the custody app.
// Restore the existing process setting, including on every early return.
struct NoInteraction(u8);
impl NoInteraction {
    fn new() -> Result<Self, ()> {
        let mut previous = 0;
        if unsafe { SecKeychainGetUserInteractionAllowed(&mut previous) } != 0
            || unsafe { SecKeychainSetUserInteractionAllowed(0) } != 0
        {
            return Err(());
        }
        Ok(Self(previous))
    }
}
impl Drop for NoInteraction {
    fn drop(&mut self) {
        unsafe { SecKeychainSetUserInteractionAllowed(self.0) };
    }
}

pub(super) fn inspect() -> Result<Inspection, ()> {
    inspect_keychain(ptr::null())
}

// An explicit Keychain scopes the native integration fixture; null uses the
// normal file-based search list. Neither changes the process search list.
fn inspect_keychain(keychain: Ref) -> Result<Inspection, ()> {
    let _no_interaction = NoInteraction::new()?;
    // Return identity references only. No kSecReturnData, private-key operation,
    // certificate trust evaluation, external program, or network request.
    let scope = Owned(unsafe {
        CFArrayCreate(
            ptr::null(),
            &keychain,
            if keychain.is_null() { 0 } else { 1 },
            &kCFTypeArrayCallBacks,
        )
    });
    if scope.0.is_null() {
        return Err(());
    }
    let query = unsafe {
        let mut keys = vec![
            kSecClass,
            kSecReturnRef,
            kSecMatchLimit,
            kSecUseDataProtectionKeychain,
            kSecUseAuthenticationUI,
        ];
        let mut values = vec![
            kSecClassIdentity,
            kCFBooleanTrue,
            kSecMatchLimitAll,
            kCFBooleanFalse,
            kSecUseAuthenticationUIFail,
        ];
        if !keychain.is_null() {
            keys.push(kSecMatchSearchList);
            values.push(scope.0);
        }
        Owned(CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as isize,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        ))
    };
    if query.0.is_null() {
        return Err(());
    }
    let mut identities = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.0, &mut identities) };
    let identities = Owned(identities);
    if status == ITEM_NOT_FOUND {
        return Ok(Inspection::default());
    }
    if status != 0 {
        return Err(());
    }
    let mut result = Inspection::default();
    for identity in array(identities.0)? {
        match inspect_identity(identity) {
            Ok(Some(Grant::AllApps)) => result.all_apps += 1,
            Ok(Some(Grant::Codesign)) => result.codesign += 1,
            Ok(None) => {}
            Err(()) => result.unknown += 1,
        }
    }
    Ok(result)
}

fn inspect_identity(identity: Ref) -> Result<Option<Grant>, ()> {
    let certificate = copied(|out| unsafe { SecIdentityCopyCertificate(identity, out) })?;
    if !certificate_allows_signing(certificate.0)? {
        return Ok(None);
    }
    // A key reference is not key material. Only its ACL is subsequently read.
    let key = copied(|out| unsafe { SecIdentityCopyPrivateKey(identity, out) })?;
    let keychain = copied(|out| unsafe { SecKeychainItemCopyKeychain(key.0, out) })?;
    let mut status = 0;
    if unsafe { SecKeychainGetStatus(keychain.0, &mut status) } != 0 || status & 1 == 0 {
        return Err(());
    }
    // BLOCKER: the legacy owner-ACL RPC ignores the no-interaction setting when
    // it has to unlock a key. This preflight avoids known locked Keychains but
    // cannot prevent a lock racing the following call. Do not ship this reader
    // as a no-prompt Detector until that race has a supported solution.
    let access = copied(|out| unsafe { SecKeychainItemCopyAccess(key.0, out) })?;
    inspect_access(access.0)
}

fn certificate_allows_signing(certificate: Ref) -> Result<bool, ()> {
    let mut error = ptr::null();
    let oid = unsafe { kSecOIDExtendedKeyUsage };
    let keys = Owned(unsafe { CFArrayCreate(ptr::null(), &oid, 1, &kCFTypeArrayCallBacks) });
    if keys.0.is_null() {
        return Err(());
    }
    let values = Owned(unsafe { SecCertificateCopyValues(certificate, keys.0, &mut error) });
    let error = Owned(error);
    if !error.0.is_null() || values.0.is_null() {
        return Err(());
    }
    let eku = dictionary_value(values.0, unsafe { kSecOIDExtendedKeyUsage })?;
    // TN3161: codesign identity discovery requires explicit Code Signing EKU.
    // Other certificate uses and keys without a certificate are outside scope.
    if eku.is_null() {
        return Ok(false);
    }
    let values = dictionary_value(eku, unsafe { kSecPropertyKeyValue })?;
    let mut allows = false;
    for value in array(values)? {
        let oid = data(value)?;
        allows |= oid == CODE_SIGNING_EKU;
    }
    Ok(allows)
}

#[derive(Debug, PartialEq, Eq)]
enum Grant {
    AllApps,
    Codesign,
}

fn inspect_access(access: Ref) -> Result<Option<Grant>, ()> {
    let acls = copied(|out| unsafe { SecAccessCopyACLList(access, out) })?;
    let mut grant = None;
    for acl in array(acls.0)? {
        let mut tags = [0; 64];
        let mut count = tags.len() as u32;
        if unsafe { SecACLGetAuthorizations(acl, tags.as_mut_ptr(), &mut count) } != 0
            || count as usize > tags.len()
        {
            return Err(());
        }
        if !tags[..count as usize]
            .iter()
            .any(|tag| *tag == SIGN || *tag == ANY)
        {
            continue;
        }
        let mut apps = ptr::null();
        let mut description = ptr::null();
        let mut prompt = 0;
        let status = unsafe { SecACLCopyContents(acl, &mut apps, &mut description, &mut prompt) };
        let apps = Owned(apps);
        let _description = Owned(description);
        if status != 0 {
            return Err(());
        }
        // This is an ACL posture finding, not an effective-access decision.
        // Prompt flags and the independent partition check remain unverified.
        if apps.0.is_null() {
            grant = Some(Grant::AllApps);
            continue;
        }
        for app in array(apps.0)? {
            let app_data = copied(|out| unsafe { SecTrustedApplicationCopyData(app, out) })?;
            if data(app_data.0)? == CODESIGN && grant != Some(Grant::AllApps) {
                grant = Some(Grant::Codesign);
            }
        }
    }
    Ok(grant)
}

fn array(value: Ref) -> Result<Vec<Ref>, ()> {
    if value.is_null() || unsafe { CFGetTypeID(value) != CFArrayGetTypeID() } {
        return Err(());
    }
    let count = unsafe { CFArrayGetCount(value) };
    if !(0..=4096).contains(&count) {
        return Err(());
    }
    (0..count)
        .map(|index| {
            let item = unsafe { CFArrayGetValueAtIndex(value, index) };
            if item.is_null() { Err(()) } else { Ok(item) }
        })
        .collect()
}
fn dictionary_value(dictionary: Ref, key: Ref) -> Result<Ref, ()> {
    if dictionary.is_null() || unsafe { CFGetTypeID(dictionary) != CFDictionaryGetTypeID() } {
        return Err(());
    }
    Ok(unsafe { CFDictionaryGetValue(dictionary, key) })
}
fn data(value: Ref) -> Result<Vec<u8>, ()> {
    if value.is_null() || unsafe { CFGetTypeID(value) != CFDataGetTypeID() } {
        return Err(());
    }
    let length = unsafe { CFDataGetLength(value) };
    if !(0..=65536).contains(&length) {
        return Err(());
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let bytes = unsafe { CFDataGetBytePtr(value) };
    if bytes.is_null() {
        return Err(());
    }
    Ok(unsafe { std::slice::from_raw_parts(bytes, length as usize) }.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecAccessCreate(description: Ref, apps: Ref, access: *mut Ref) -> i32;
        fn SecACLCreateWithSimpleContents(
            access: Ref,
            apps: Ref,
            description: Ref,
            prompt: u16,
            acl: *mut Ref,
        ) -> i32;
        fn SecACLSetAuthorizations(acl: Ref, tags: *const i32, count: u32) -> i32;
        fn SecTrustedApplicationCreateFromPath(path: *const i8, app: *mut Ref) -> i32;
        fn SecCertificateCreateWithData(allocator: Ref, data: Ref) -> Ref;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(allocator: Ref, text: *const i8, encoding: u32) -> Ref;
        fn CFDataCreate(allocator: Ref, bytes: *const u8, count: isize) -> Ref;
    }

    // These ACL objects stay in memory. No user's Keychain or private key is read
    // or modified, and creating a trusted-app reference never executes that app.
    fn fixture_grant(app_path: Option<&str>, auth: i32, prompt: u16) -> Result<Option<Grant>, ()> {
        let name = CString::new("AV disposable ACL test").unwrap();
        let description =
            Owned(unsafe { CFStringCreateWithCString(ptr::null(), name.as_ptr(), 0x08000100) });
        let empty =
            Owned(unsafe { CFArrayCreate(ptr::null(), ptr::null(), 0, &kCFTypeArrayCallBacks) });
        let access = copied(|out| unsafe { SecAccessCreate(description.0, empty.0, out) }).unwrap();
        let app = app_path.filter(|path| !path.is_empty()).map(|path| {
            let path = CString::new(path).unwrap();
            copied(|out| unsafe { SecTrustedApplicationCreateFromPath(path.as_ptr(), out) })
                .unwrap()
        });
        let apps = app.as_ref().map(|app| {
            Owned(unsafe { CFArrayCreate(ptr::null(), &app.0, 1, &kCFTypeArrayCallBacks) })
        });
        let app_list = match app_path {
            None => ptr::null(),
            Some("") => empty.0,
            Some(_) => apps.as_ref().unwrap().0,
        };
        let acl = copied(|out| unsafe {
            SecACLCreateWithSimpleContents(access.0, app_list, description.0, prompt, out)
        })
        .unwrap();
        assert_eq!(unsafe { SecACLSetAuthorizations(acl.0, &auth, 1) }, 0);
        inspect_access(access.0)
    }

    #[test]
    fn native_acl_fixture_distinguishes_sign_decrypt_nil_empty_and_trusted_apps() {
        // Literal SDK authorization values independently exercise the reader:
        // SIGN=115, DECRYPT=24, ANY=1. A decrypt-only grant must not flag signing.
        assert_eq!(fixture_grant(None, 115, 0), Ok(Some(Grant::AllApps)));
        assert_eq!(fixture_grant(Some(""), 115, 0), Ok(None));
        assert_eq!(
            fixture_grant(Some("/usr/bin/codesign"), 115, 0),
            Ok(Some(Grant::Codesign))
        );
        assert_eq!(fixture_grant(Some("/usr/bin/codesign"), 24, 0), Ok(None));
        assert_eq!(fixture_grant(Some("/usr/bin/security"), 115, 0), Ok(None));
        assert_eq!(
            fixture_grant(Some("/usr/bin/codesign"), 1, 0),
            Ok(Some(Grant::Codesign))
        );
        // A prompt selector does not erase the observed trust grant. The finding
        // explicitly leaves authentication and effective access unverified.
        assert_eq!(
            fixture_grant(Some("/usr/bin/codesign"), 115, 1),
            Ok(Some(Grant::Codesign))
        );
    }

    #[test]
    fn native_certificate_fixture_requires_code_signing_eku_without_trust_evaluation() {
        for (der, expected) in [
            (include_bytes!("fixtures/code-signing.cer").as_slice(), true),
            (include_bytes!("fixtures/client-auth.cer").as_slice(), false),
            (include_bytes!("fixtures/no-eku.cer").as_slice(), false),
        ] {
            let data =
                Owned(unsafe { CFDataCreate(ptr::null(), der.as_ptr(), der.len() as isize) });
            let certificate = Owned(unsafe { SecCertificateCreateWithData(ptr::null(), data.0) });
            assert!(!certificate.0.is_null());
            assert_eq!(certificate_allows_signing(certificate.0), Ok(expected));
        }
        assert_eq!(array(ptr::null()), Err(()));
        assert_eq!(data(ptr::null()), Err(()));
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainCreate(
            path: *const i8,
            length: u32,
            password: *const c_void,
            prompt: u8,
            access: Ref,
            keychain: *mut Ref,
        ) -> i32;
        fn SecKeychainDelete(keychain: Ref) -> i32;
        fn SecKeychainLock(keychain: Ref) -> i32;
        fn SecKeychainUnlock(
            keychain: Ref,
            length: u32,
            password: *const c_void,
            use_password: u8,
        ) -> i32;
    }

    #[test]
    fn native_identity_fixture_scans_only_disposable_keychain_and_restores_interaction() {
        let _no_interaction = NoInteraction::new().unwrap();
        use std::{
            fs,
            os::unix::fs::DirBuilderExt,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };
        struct Fixture {
            directory: std::path::PathBuf,
            keychain: Owned,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                if !self.keychain.0.is_null() {
                    let password = b"disposable-fixture-password";
                    assert_eq!(
                        unsafe {
                            SecKeychainUnlock(
                                self.keychain.0,
                                password.len() as u32,
                                password.as_ptr().cast(),
                                1,
                            )
                        },
                        0
                    );
                    assert_eq!(unsafe { SecKeychainDelete(self.keychain.0) }, 0);
                }
                fs::remove_dir_all(&self.directory).unwrap();
            }
        }
        let directory = std::env::temp_dir().join(format!(
            "av-codesign-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let mut fixture = Fixture {
            directory,
            keychain: Owned(ptr::null()),
        };
        let path = fixture.directory.join("fixture.keychain-db");
        let path_c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        const PASSWORD: &str = "disposable-fixture-password";
        assert_eq!(
            unsafe {
                SecKeychainCreate(
                    path_c.as_ptr(),
                    PASSWORD.len() as u32,
                    PASSWORD.as_ptr().cast(),
                    0,
                    ptr::null(),
                    &mut fixture.keychain.0,
                )
            },
            0
        );
        assert_eq!(inspect_keychain(fixture.keychain.0).unwrap().unknown, 0);
        fs::write(fixture.directory.join("openssl.cnf"), "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=AV disposable identity fixture\n[ext]\nextendedKeyUsage=codeSigning\nkeyUsage=digitalSignature\n").unwrap();
        let run = |program: &str, args: &[&str]| {
            let output = Command::new(program)
                .args(args)
                .current_dir(&fixture.directory)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fixture setup failed: {program} ({})",
                output.status
            );
        };
        run(
            "/usr/bin/openssl",
            &[
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-config",
                "openssl.cnf",
                "-out",
                "certificate.pem",
                "-keyout",
                "private.pem",
            ],
        );
        run(
            "/usr/bin/openssl",
            &[
                "pkcs12",
                "-export",
                "-inkey",
                "private.pem",
                "-in",
                "certificate.pem",
                "-out",
                "identity.p12",
                "-passout",
                "pass:disposable-fixture-password",
            ],
        );
        run(
            "/usr/bin/security",
            &[
                "import",
                "identity.p12",
                "-k",
                path.to_str().unwrap(),
                "-P",
                PASSWORD,
                "-T",
                "/usr/bin/codesign",
            ],
        );
        let mut previous = 0;
        assert_eq!(
            unsafe { SecKeychainGetUserInteractionAllowed(&mut previous) },
            0
        );
        let result = inspect_keychain(fixture.keychain.0).unwrap();
        assert_eq!(
            (result.all_apps, result.codesign, result.unknown),
            (0, 1, 0)
        );
        assert_eq!(super::super::from_inspection(result)[0].severity, "medium");
        assert_eq!(unsafe { SecKeychainLock(fixture.keychain.0) }, 0);
        let locked = inspect_keychain(fixture.keychain.0).unwrap();
        assert_eq!(
            (locked.all_apps, locked.codesign, locked.unknown),
            (0, 0, 1)
        );
        let mut restored = 0;
        assert_eq!(
            unsafe { SecKeychainGetUserInteractionAllowed(&mut restored) },
            0
        );
        assert_eq!(restored, previous);
    }
}
