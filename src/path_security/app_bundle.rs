//! Diagnostic-only recognition of signed application command directories.
//! Mirrors AppBundleValidation.swift's targeted resource SPI; grants no authority.

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;

type Ref = *const c_void;
type ValidateResource = unsafe extern "C" fn(Ref, Ref, u32, *mut Ref) -> i32;
const STRICT: u32 = 1 << 4;
const ALL_ARCHITECTURES: u32 = 1;
const WITHOUT_RESOURCES: u32 = 1 << 2;
const MAX_ENTRIES: usize = 256;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: Ref,
        bytes: *const u8,
        len: isize,
        directory: u8,
    ) -> Ref;
    fn CFStringCreateWithCString(allocator: Ref, text: *const i8, encoding: u32) -> Ref;
    fn CFRelease(value: Ref);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecStaticCodeCreateWithPath(url: Ref, flags: u32, code: *mut Ref) -> i32;
    fn SecStaticCodeCheckValidity(code: Ref, flags: u32, requirement: Ref) -> i32;
    fn SecRequirementCreateWithString(text: Ref, flags: u32, requirement: *mut Ref) -> i32;
}

struct Owned(Ref);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: Owned holds one non-null Create-rule reference.
        unsafe { CFRelease(self.0) }
    }
}

fn url(path: &Path) -> Option<Owned> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: bytes remain live for the call; CoreFoundation copies them.
    let value = unsafe {
        CFURLCreateFromFileSystemRepresentation(
            ptr::null(),
            bytes.as_ptr(),
            bytes.len() as isize,
            0,
        )
    };
    (!value.is_null()).then_some(Owned(value))
}

fn validator() -> Option<ValidateResource> {
    static VALIDATOR: OnceLock<Option<ValidateResource>> = OnceLock::new();
    *VALIDATOR.get_or_init(|| {
        // SAFETY: Security is linked above; the SPI has the same ABI used by the Swift verifier.
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"SecStaticCodeValidateResourceWithErrors".as_ptr(),
            )
        };
        if symbol.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, ValidateResource>(symbol) })
        }
    })
}

#[derive(Default)]
pub(super) struct BundleInspection {
    bundles: HashMap<PathBuf, Option<Owned>>,
}

impl BundleInspection {
    pub(super) fn contains_sealed_commands(&mut self, directory: &Path) -> bool {
        // Restrict the diagnostic exception to installed apps, not arbitrary signed build products.
        if !directory.starts_with("/Applications") {
            return false;
        }
        self.inspect(directory, true)
    }

    fn inspect(&mut self, directory: &Path, require_vendor: bool) -> bool {
        let Some(validate) = validator() else {
            return false;
        };
        if !directory.is_absolute() || directory.canonicalize().ok().as_deref() != Some(directory) {
            return false;
        }
        let Some(bundle) = directory
            .ancestors()
            .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        else {
            return false;
        };
        if !directory.starts_with(bundle.join("Contents")) {
            return false;
        }
        let code = self
            .bundles
            .entry(bundle.to_owned())
            .or_insert_with(|| validated_bundle(bundle, require_vendor));
        let Some(code) = code else { return false };
        let Ok(entries) = std::fs::read_dir(directory) else {
            return false;
        };
        let mut count = 0;
        for entry in entries {
            count += 1;
            if count > MAX_ENTRIES {
                return false;
            }
            let Ok(entry) = entry else { return false };
            // Reject symlinks, subdirectories, and special files rather than follow unsealed targets.
            if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                return false;
            }
            let Some(resource) = url(&entry.path()) else {
                return false;
            };
            // SAFETY: both references are live and the SPI is resolved with its declared ABI.
            if unsafe { validate(code.0, resource.0, STRICT, ptr::null_mut()) } != 0 {
                return false;
            }
        }
        count > 0
    }
}

fn validated_bundle(bundle: &Path, require_vendor: bool) -> Option<Owned> {
    let bundle_url = url(bundle)?;
    let mut code = ptr::null();
    // SAFETY: the URL and output pointer are valid for the call.
    if unsafe { SecStaticCodeCreateWithPath(bundle_url.0, 0, &mut code) } != 0 || code.is_null() {
        return None;
    }
    let code = Owned(code);
    let requirement = if require_vendor {
        // Apple-distributed or Developer ID applications; never an ad-hoc or development signature.
        let text = c"anchor apple or (anchor apple generic and (certificate leaf[field.1.2.840.113635.100.6.1.9] exists or certificate leaf[field.1.2.840.113635.100.6.1.13] exists))";
        // SAFETY: the string is NUL terminated and the encoding is UTF-8.
        let string = unsafe { CFStringCreateWithCString(ptr::null(), text.as_ptr(), 0x08000100) };
        if string.is_null() {
            return None;
        }
        let string = Owned(string);
        let mut requirement = ptr::null();
        // SAFETY: the string and output pointer are valid for the call.
        if unsafe { SecRequirementCreateWithString(string.0, 0, &mut requirement) } != 0
            || requirement.is_null()
        {
            return None;
        }
        Some(Owned(requirement))
    } else {
        None
    };
    // SAFETY: code and the optional requirement remain live throughout validation.
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.0,
            STRICT | ALL_ARCHITECTURES | WITHOUT_RESOURCES,
            requirement.as_ref().map_or(ptr::null(), |value| value.0),
        )
    };
    (status == 0).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture {
        root: PathBuf,
        app: PathBuf,
        bin: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "av-sealed-path-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let app = root.join("Fixture.app");
            let bin = app.join("Contents/Resources/bin");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
            std::fs::copy("/usr/bin/true", app.join("Contents/MacOS/Fixture")).unwrap();
            std::fs::write(
                app.join("Contents/Info.plist"),
                br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>Fixture</string>
<key>CFBundleIdentifier</key><string>com.automicvault.test.path</string>
<key>CFBundlePackageType</key><string>APPL</string></dict></plist>"#,
            )
            .unwrap();
            std::fs::write(bin.join("command"), "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(bin.join("command"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            std::fs::write(app.join("Contents/Resources/unrelated"), "original").unwrap();
            Self { root, app, bin }
        }

        fn sign(&self) {
            let output = Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(&self.app)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn inspect(&self) -> bool {
            // Fixtures have no private signing identity; exercise identical resource validation
            // separately from the mandatory production vendor requirement and installation path.
            BundleInspection::default().inspect(&self.bin, false)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn sealed_path_rejects_unsigned_modified_and_added_files() {
        assert!(
            validator().is_some(),
            "targeted resource SPI required to exercise this test"
        );
        let fixture = Fixture::new();
        assert!(!fixture.inspect());
        fixture.sign();
        assert!(fixture.inspect());
        assert!(
            validated_bundle(&fixture.app, true).is_none(),
            "ad-hoc signatures cannot qualify"
        );
        assert!(
            !BundleInspection::default().contains_sealed_commands(&fixture.bin),
            "temporary build products cannot qualify"
        );

        std::fs::write(fixture.app.join("Contents/Resources/unrelated"), "changed").unwrap();
        assert!(
            fixture.inspect(),
            "unrelated resources are deliberately not scanned"
        );
        std::fs::write(fixture.bin.join("added"), "#!/bin/sh\nexit 0\n").unwrap();
        assert!(
            !fixture.inspect(),
            "an unsealed entry must retain the warning, even without execute permission"
        );
        std::fs::remove_file(fixture.bin.join("added")).unwrap();
        std::fs::write(fixture.bin.join(".DS_Store"), "unsealed").unwrap();
        assert!(!fixture.inspect(), "omitted resources must not qualify");
        std::fs::remove_file(fixture.bin.join(".DS_Store")).unwrap();
        std::fs::write(fixture.bin.join("command"), "#!/bin/sh\nexit 1\n").unwrap();
        assert!(!fixture.inspect());
        std::fs::write(fixture.bin.join("command"), "#!/bin/sh\nexit 0\n").unwrap();
        assert!(fixture.inspect());
        std::fs::write(
            fixture.app.join("Contents/MacOS/Fixture"),
            "modified executable",
        )
        .unwrap();
        assert!(!fixture.inspect());
    }

    #[test]
    fn sealed_path_rejects_a_modified_resource_manifest() {
        let fixture = Fixture::new();
        fixture.sign();
        assert!(fixture.inspect());
        let manifest = fixture.app.join("Contents/_CodeSignature/CodeResources");
        let mut bytes = std::fs::read(&manifest).unwrap();
        bytes.extend_from_slice(b"\n");
        std::fs::write(manifest, bytes).unwrap();
        assert!(
            !fixture.inspect(),
            "the resource seal itself must be authenticated"
        );
    }

    #[test]
    fn sealed_path_rejects_symlinks_empty_directories_and_oversized_directories() {
        let fixture = Fixture::new();
        symlink("/usr/bin/true", fixture.bin.join("external")).unwrap();
        fixture.sign();
        assert!(
            !fixture.inspect(),
            "even a sealed external symlink must not qualify"
        );
        std::fs::remove_file(fixture.bin.join("external")).unwrap();
        symlink("command", fixture.bin.join("internal")).unwrap();
        fixture.sign();
        assert!(
            !fixture.inspect(),
            "symlinks conservatively retain the warning"
        );
        std::fs::remove_file(fixture.bin.join("internal")).unwrap();
        fixture.sign();
        let alias = fixture.app.join("Contents/alias");
        symlink(&fixture.bin, &alias).unwrap();
        assert!(!BundleInspection::default().inspect(&alias, false));
        assert!(!BundleInspection::default().inspect(Path::new("relative"), false));
        assert!(!BundleInspection::default().inspect(&fixture.bin.join("missing"), false));
        std::fs::remove_file(fixture.bin.join("command")).unwrap();
        assert!(!fixture.inspect());
        for i in 0..=MAX_ENTRIES {
            std::fs::write(fixture.bin.join(i.to_string()), "sealed").unwrap();
        }
        fixture.sign();
        assert!(!fixture.inspect(), "work is bounded per directory");
    }

    #[test]
    #[ignore = "local integration benchmark; requires installed ChatGPT.app"]
    fn installed_chatgpt_path_benchmark() {
        let directory =
            Path::new("/Applications/ChatGPT.app/Contents/Resources/codex-cli/codex-path");
        let path = std::env::join_paths([directory, Path::new("/usr/bin")]).unwrap();
        let mut inspection = super::super::PathInspection::default();
        let start = std::time::Instant::now();
        assert!(
            inspection
                .user_writable_entries_before_system_paths(&path)
                .is_empty()
        );
        eprintln!("first directory check: {:?}", start.elapsed());
        let start = std::time::Instant::now();
        for _ in 0..78 {
            assert!(
                inspection
                    .user_writable_entries_before_system_paths(&path)
                    .is_empty()
            );
        }
        eprintln!("78 cached checks: {:?}", start.elapsed());
        assert_eq!(inspection.directories.len(), 1);
        assert_eq!(inspection.bundles.bundles.len(), 1);
        for _ in 0..3 {
            let start = std::time::Instant::now();
            assert!(super::super::user_writable_entries_before_system_paths(&path).is_empty());
            eprintln!("fresh scan: {:?}", start.elapsed());
        }
    }
}
