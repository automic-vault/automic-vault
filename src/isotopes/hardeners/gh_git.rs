//! Diagnose legacy routing without installing or changing Git configuration.
use std::process::{Command, Stdio};

pub(super) fn diagnose() -> Result<(), (&'static str, String)> {
    let output = Command::new("/usr/bin/git")
        .args([
            "config",
            "--null",
            "--includes",
            "--get-regexp",
            r"^url\.av::.*\.(insteadof|pushinsteadof)$",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            (
                "gh_git_configuration",
                format!("could not inspect Git configuration: {error}"),
            )
        })?;
    match output.status.code() {
        Some(1) => Ok(()),
        Some(0) => Err((
            "gh_git_transport_deprecated",
            "Git URL rewrites select Automic Vault's deprecated Git HTTPS transport".into(),
        )),
        _ => Err((
            "gh_git_configuration",
            "could not inspect Git configuration".into(),
        )),
    }
}
