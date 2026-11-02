use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

mod app_bundle;

#[derive(Default)]
pub(crate) struct PathInspection {
    directories: HashMap<PathBuf, bool>,
    bundles: app_bundle::BundleInspection,
}

pub(crate) fn current_working_directory_utf8() -> Result<String, String> {
    let path = std::env::current_dir()
        .map_err(|error| format!("failed to read current directory: {error}"))?;
    path_to_utf8(path)
}

fn path_to_utf8(path: PathBuf) -> Result<String, String> {
    path.into_os_string()
        .into_string()
        .map_err(|_| "working directory is not valid UTF-8".to_string())
}

/// The wording consumers match on to recognise a user-writable PATH reason.
/// Producers build reasons with [`user_writable_path_reason`] rather than
/// composing this by hand.
pub(crate) const USER_WRITABLE_PATH_REASON: &str =
    "PATH has a user-writable directory before protected system directories";

/// The reason reporting one entry from
/// [`user_writable_entries_before_system_paths`], prefixed by the source that
/// found it (`Bash`, `Zsh`, `macOS GUI`).
pub(crate) fn user_writable_path_reason(source: &str, entry: &Path) -> String {
    format!("{source} {USER_WRITABLE_PATH_REASON}: {}", entry.display())
}

pub(crate) fn user_writable_entries_before_system_paths(path: &OsStr) -> Vec<PathBuf> {
    PathInspection::default().user_writable_entries_before_system_paths(path)
}

impl PathInspection {
    pub(crate) fn user_writable_entries_before_system_paths(
        &mut self,
        path: &OsStr,
    ) -> Vec<PathBuf> {
        let entries = std::env::split_paths(path)
            .map(|entry| {
                let writable = !entry.is_absolute() || is_user_writable_or_creatable(&entry);
                let displayed = if entry.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    entry
                };
                (displayed, writable)
            })
            .collect::<Vec<_>>();

        let last_system_path = entries.iter().rposition(|(_, writable)| !writable);
        let all_entries_are_writable = last_system_path.is_none();
        let mut seen = HashSet::<OsString>::new();

        entries
            .into_iter()
            .enumerate()
            .filter(|(index, (_, writable))| {
                *writable
                    && (all_entries_are_writable
                        || last_system_path.is_some_and(|last| *index < last))
            })
            .filter(|(_, (entry, _))| {
                !*self
                    .directories
                    .entry(entry.clone())
                    .or_insert_with(|| self.bundles.contains_sealed_commands(entry))
            })
            .filter_map(|(_, (entry, _))| {
                seen.insert(entry.as_os_str().to_owned()).then_some(entry)
            })
            .collect()
    }
}

fn is_user_writable_or_creatable(path: &Path) -> bool {
    let mut candidate = path;
    loop {
        if candidate.exists() {
            if !candidate.is_dir() {
                return candidate.parent().is_some_and(is_user_writable);
            }
            return is_user_writable(candidate);
        }
        let Some(parent) = candidate.parent() else {
            return false;
        };
        candidate = parent;
    }
}

pub(crate) fn is_user_writable(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is a live, NUL-terminated C string and access does not retain it.
    unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("av-path-security-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn reports_writable_entries_that_precede_protected_entries() {
        let root = temp_dir("order");
        let writable = root.join("writable");
        let protected = root.join("protected");
        let trailing = root.join("trailing");
        std::fs::create_dir_all(&writable).unwrap();
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::create_dir_all(&trailing).unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o555)).unwrap();

        let path = std::env::join_paths([&writable, &protected, &trailing]).unwrap();
        let insecure = user_writable_entries_before_system_paths(&path);

        assert_eq!(insecure, vec![writable]);
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_an_entirely_user_writable_path() {
        let root = temp_dir("all-writable");
        let one = root.join("one");
        let two = root.join("two");
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();
        let path = std::env::join_paths([&one, &two]).unwrap();

        assert_eq!(
            user_writable_entries_before_system_paths(&path),
            vec![one, two]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn treats_creatable_relative_and_empty_entries_as_user_writable() {
        let root = temp_dir("creatable");
        let missing = root.join("missing");
        let protected = root.join("protected");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o555)).unwrap();
        let path = OsString::from(format!(
            ":relative:{}:{}",
            missing.display(),
            protected.display()
        ));

        assert_eq!(
            user_writable_entries_before_system_paths(&path),
            vec![PathBuf::from("."), PathBuf::from("relative"), missing]
        );
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_utf8_working_directory_paths() {
        let path = PathBuf::from(OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff]));

        assert_eq!(
            path_to_utf8(path),
            Err("working directory is not valid UTF-8".to_string())
        );
    }
}
