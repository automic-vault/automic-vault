//! Git routing selects the protected transport; it never grants Secret Use.
use super::isotope;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

const URL: &str = "https://github.com/";
const KEY: &str = "url.av::https://github.com/.insteadOf";
const SKIP: &str =
    "Use `av harden gh --without-git-configuration` to manage Git configuration yourself.";

fn config() -> Command {
    let mut command = Command::new("/usr/bin/git");
    command.arg("config").stdin(Stdio::null());
    command
}

fn configuration(mut command: Command) -> Result<bool, String> {
    let output = command
        .args([
            "--null",
            "--show-scope",
            "--includes",
            "--get-regexp",
            r"^(url\..*\.(insteadof|pushinsteadof)|includeif\..*\.path)$",
        ])
        .output()
        .map_err(|error| format!("could not inspect Git configuration: {error}"))?;
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    if !output.status.success() {
        return Err("could not inspect Git configuration".into());
    }
    inspect(&output.stdout)
}

fn inspect(bytes: &[u8]) -> Result<bool, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Git configuration is not UTF-8")?;
    let mut fields = text.split_terminator('\0');
    let mut configured = false;
    while let Some(scope) = fields.next() {
        let (key, value) = fields
            .next()
            .and_then(|entry| entry.split_once('\n'))
            .ok_or("could not parse Git configuration")?;
        if key.starts_with("includeif.") {
            return Err(
                "Git uses conditional configuration; automatic GitHub routing needs manual review"
                    .into(),
            );
        }
        if key == "url.av::https://github.com/.insteadof" && value == URL {
            configured |= scope == "global";
        } else if value.starts_with(URL) || URL.starts_with(value) {
            return Err(
                "Git has an overlapping GitHub URL rewrite; automatic routing needs manual review"
                    .into(),
            );
        }
    }
    Ok(configured)
}

fn inspect_environment() -> Result<(), String> {
    if std::env::vars_os().any(|(key, _)| {
        let key = key.to_string_lossy();
        key.starts_with("GIT_CONFIG")
            || matches!(
                key.as_ref(),
                "GIT_EXEC_PATH"
                    | "GIT_DIR"
                    | "GIT_WORK_TREE"
                    | "GIT_COMMON_DIR"
                    | "GIT_CEILING_DIRECTORIES"
                    | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
            )
    }) {
        return Err("Git environment overrides are set; run hardening without them".into());
    }
    Ok(())
}

pub(super) fn preflight() -> Result<(), String> {
    (|| {
        inspect_environment()?;
        configuration(config())?;
        crate::cli::git::verify_installed_cli()?;
        crate::cli::git::verify_adapter_resolution()
    })()
    .map_err(|error| format!("{error}. Git configuration was not changed. {SKIP}"))
}

fn write_route(mut command: Command) -> Result<(), String> {
    // Replace only this exact value; unrelated values on the same key survive.
    let output = command
        .args(["--fixed-value", "--replace-all", KEY, URL, URL])
        .output()
        .map_err(|error| format!("could not configure Git: {error}"))?;
    if !output.status.success() {
        return Err("could not write the global GitHub transport rule".into());
    }
    Ok(())
}

fn manual(hosts: &Path) -> bool {
    fs::read_to_string(hosts.with_file_name("av-git-configuration"))
        .is_ok_and(|value| value == "manual\n")
}

pub(super) fn apply(without_configuration: bool, hosts: &Path) -> Result<(), String> {
    let preference = hosts.with_file_name("av-git-configuration");
    if without_configuration {
        let parent = preference
            .parent()
            .ok_or("missing gh configuration directory")?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let stage = isotope::TemporaryDirectory::new_in(parent, "gh-git")?;
        let file = stage.path.join("preference");
        fs::write(&file, "manual\n").map_err(|error| error.to_string())?;
        return fs::rename(file, preference).map_err(|error| error.to_string());
    }
    let result = (|| {
        crate::cli::git::ensure_transport(&isotope::target(isotope::GH))?;
        // Reinspect after installation: never overwrite a conflict introduced while waiting.
        inspect_environment()?;
        let configured = configuration(config())?;
        crate::cli::git::verify_transport(&isotope::target(isotope::GH))?;
        if !configured {
            let mut command = config();
            command.arg("--global");
            write_route(command)?;
        }
        Ok::<_, String>(())
    })();
    result.map_err(|error| format!("{error}. {SKIP}"))?;
    match fs::remove_file(preference) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "Git routing is configured, but could not clear manual configuration preference: {error}"
        )),
    }
}

pub(super) fn diagnose(hosts: &Path) -> Result<(), String> {
    if manual(hosts) {
        return Ok(());
    }
    inspect_environment()?;
    if !configuration(config())? {
        return Err("GitHub HTTPS operations are not globally routed through Automic Vault".into());
    }
    crate::cli::git::verify_transport(&isotope::target(isotope::GH))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn rejects_conflicts_and_conditionals_but_preserves_unrelated_configuration() {
        assert!(
            !inspect(b"global\0url.ssh://git@example.com/.insteadof\nhttps://example.com/\0")
                .unwrap()
        );
        assert!(
            !inspect(b"local\0url.av::https://github.com/.insteadof\nhttps://github.com/\0")
                .unwrap()
        );
        assert!(
            inspect(b"global\0url.av::https://github.com/.insteadof\nhttps://github.com/\0")
                .unwrap()
        );
        for bytes in [
            &b"global\0url.ssh://git@github.com/.insteadof\nhttps://github.com/\0"[..],
            b"local\0url.ssh://git@github.com/.pushinsteadof\nhttps://github.com/org/\0",
            b"global\0url.ssh://git@github.com/.insteadof\nhttps://\0",
            b"global\0includeif.gitdir:~/work/.path\nwork.gitconfig\0",
            b"global\0invalid\0",
        ] {
            assert!(inspect(bytes).is_err());
        }
    }

    #[test]
    fn routing_is_idempotent_and_preserves_other_values() {
        let directory =
            std::env::temp_dir().join(format!("av-gh-git-{:016x}", rand::random::<u64>()));
        fs::create_dir(&directory).unwrap();
        let file = directory.join("config");
        fs::write(&file, "[user]\n name = Test\n[url \"av::https://github.com/\"]\n insteadOf = custom:github/\n").unwrap();
        for _ in 0..2 {
            let mut command = config();
            command.arg("--file").arg(&file);
            write_route(command).unwrap();
        }
        let text = fs::read_to_string(&file).unwrap();
        assert!(text.contains("name = Test"));
        assert!(text.contains("insteadOf = custom:github/"));
        assert_eq!(text.matches("insteadOf = https://github.com/").count(), 1);
        let mut command = config();
        command.arg("--file").arg(&file);
        // --file is command scope, so this cannot satisfy global installation.
        assert!(!configuration(command).unwrap());
        let hosts = directory.join("hosts.yml");
        apply(true, &hosts).unwrap();
        assert!(manual(&hosts));
        assert_eq!(fs::read_to_string(&file).unwrap(), text);
        assert!(diagnose(&hosts).is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn global_routing_reaches_fresh_clones_without_disclosing_to_a_helper() {
        let directory =
            std::env::temp_dir().join(format!("av-gh-route-{:016x}", rand::random::<u64>()));
        fs::create_dir(&directory).unwrap();
        let file = directory.join(".gitconfig");
        fs::write(
            &file,
            "[credential]\n helper = !touch \"$AV_TEST_CREDENTIAL_HELPER\"\n",
        )
        .unwrap();
        let mut command = config();
        command.arg("--file").arg(&file);
        write_route(command).unwrap();
        let helper = directory.join("git-remote-av");
        fs::write(&helper, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$AV_TEST_ROUTE\"\nprintf 'unsupported fixture operation\\n' >&2\nexit 1\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let marker = directory.join("credential-helper-ran");
        let route = directory.join("route");
        let output = Command::new("/usr/bin/git")
            .env_clear()
            .env("HOME", &directory)
            .env("XDG_CONFIG_HOME", &directory)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("PATH", format!("{}:/usr/bin:/bin", directory.display()))
            .env("AV_TEST_ROUTE", &route)
            .env("AV_TEST_CREDENTIAL_HELPER", &marker)
            .current_dir(&directory)
            .args([
                "clone",
                "https://github.com/fixture/repository.git",
                "clone",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported fixture operation"));
        assert_eq!(
            fs::read_to_string(route).unwrap(),
            "origin\nhttps://github.com/fixture/repository.git\n"
        );
        assert!(
            !marker.exists(),
            "failed transport must not fall back to credential disclosure"
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
