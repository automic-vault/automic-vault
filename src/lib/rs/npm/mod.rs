use std::path::PathBuf;

pub(crate) fn qualified_name(package: &str) -> String {
    format!("npm:{package}")
}

pub(crate) fn install_relative_path(package: &str) -> PathBuf {
    if let Some(scoped) = package.strip_prefix('@')
        && let Some((scope, name)) = scoped.split_once('/')
    {
        return PathBuf::from(format!("@{scope}")).join(name);
    }

    PathBuf::from(package)
}

pub(crate) fn install_leaf_name(package: &str) -> String {
    install_relative_path(package)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(package)
        .to_string()
}

pub(crate) fn executable_name(package: &str) -> String {
    install_leaf_name(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_names_cover_scoped_and_unscoped_packages() {
        assert_eq!(qualified_name("openclaw"), "npm:openclaw");
        assert_eq!(install_relative_path("openclaw"), PathBuf::from("openclaw"));
        assert_eq!(
            install_relative_path("@scope/tool"),
            PathBuf::from("@scope").join("tool")
        );
        assert_eq!(install_leaf_name("@scope/tool"), "tool");
        assert_eq!(install_leaf_name("@scope"), "@scope");
        assert_eq!(executable_name("@scope/tool"), "tool");
    }
}
