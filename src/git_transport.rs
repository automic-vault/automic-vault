//! Fixed Git HTTPS transport. Repository configuration never enters this phase.
//!
//! The installed runtime is root-owned; all mutable local operations run outside
//! its credential registration. Do not relax this to a preflight config scan.
use std::collections::BTreeMap;

pub(crate) const ROOT: &str = "/opt/av/git";
pub(crate) const GIT: &str = "/opt/av/git/bin/git";
pub(crate) const HTTPS: &str = "/opt/av/git/bin/git-remote-https";
pub(crate) const GH: &str = "/opt/av/git/bin/gh";
pub(crate) const REPOSITORY: &str = "/opt/av/git/repository";
pub(crate) const CONFIG: &str = "[core]\n\trepositoryformatversion = 0\n\tbare = true\n";

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Operation {
    pub command: String,
    pub url: String,
    pub destination: Option<String>,
}

impl Operation {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let error = "supported forms: clone https://github.com/OWNER/REPO.git DIRECTORY; fetch|pull|push https://github.com/OWNER/REPO.git (main only)";
        let [command, url, rest @ ..] = args else {
            return Err(error.into());
        };
        if !matches!(command.as_str(), "clone" | "fetch" | "pull" | "push")
            || rest.len() != usize::from(command == "clone")
            || rest
                .first()
                .is_some_and(|s| s.is_empty() || s.contains('\0'))
            || !valid_url(url)
        {
            return Err(error.into());
        }
        Ok(Self {
            command: command.clone(),
            url: url.clone(),
            destination: rest.first().cloned(),
        })
    }

    pub fn arguments(&self, phase: &str, oid: &str) -> Result<Vec<String>, String> {
        let tail: Vec<&str> = match phase {
            "advertise" if self.command != "push" && oid.is_empty() => vec![
                "ls-remote",
                "--exit-code",
                "--refs",
                "--",
                &self.url,
                "refs/heads/main",
            ],
            "fetch" if self.command != "push" && valid_oid(oid) => vec![
                "fetch",
                "--no-auto-maintenance",
                "--no-write-fetch-head",
                "--no-write-commit-graph",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                &self.url,
                oid,
            ],
            "push" if self.command == "push" && valid_oid(oid) => {
                vec!["push", "--no-verify", "--", &self.url]
            }
            _ => return Err("invalid Git transport phase".into()),
        };
        let mut args = vec!["--no-replace-objects".into()];
        for (key, value) in [
            ("credential.helper", ""),
            (
                "credential.helper",
                "!exec /opt/av/git/bin/gh auth git-credential",
            ),
            ("credential.useHttpPath", "true"),
            ("core.hooksPath", "/dev/null"),
            ("core.fsmonitor", "false"),
            ("http.sslBackend", "openssl"),
            ("http.sslVerify", "true"),
            ("http.sslCAInfo", "/private/etc/ssl/cert.pem"),
            ("http.sslCAPath", "/opt/av/git/empty"),
            ("http.followRedirects", "false"),
            ("http.proxy", ""),
            ("protocol.allow", "never"),
            ("protocol.https.allow", "always"),
        ] {
            args.extend(["-c".into(), format!("{key}={value}")]);
        }
        args.extend(tail.into_iter().map(String::from));
        if phase == "push" {
            args.push(format!("{oid}:refs/heads/main"));
        }
        Ok(args)
    }
}

fn valid_url(value: &str) -> bool {
    let Some(path) = value
        .strip_prefix("https://github.com/")
        .and_then(|p| p.strip_suffix(".git"))
    else {
        return false;
    };
    let parts: Vec<_> = path.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && *p != "."
                && *p != ".."
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        })
}

pub(crate) fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub(crate) fn environment(objects: &str, nonce: &str) -> BTreeMap<String, String> {
    [
        ("PATH", "/opt/av/git/bin:/usr/bin:/bin"),
        ("HOME", "/opt/av/git/empty"),
        ("XDG_CONFIG_HOME", "/opt/av/git/empty"),
        ("GH_CONFIG_DIR", "/opt/av/git/empty"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_EXEC_PATH", "/opt/av/git/bin"),
        ("GIT_DIR", REPOSITORY),
        ("GIT_OBJECT_DIRECTORY", objects),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_PAGER", "cat"),
        ("LC_ALL", "C"),
        ("AV_GIT_NONCE", nonce),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_has_a_positive_surface_and_no_ambient_configuration() {
        let url = "https://github.com/automic-vault/automic-vault.git";
        for command in ["clone", "fetch", "pull", "push"] {
            let mut args = vec![command.into(), url.into()];
            if command == "clone" {
                args.push("destination".into());
            }
            let op = Operation::parse(&args).unwrap();
            let phase = if command == "push" { "push" } else { "fetch" };
            let invocation = op.arguments(phase, &"a".repeat(40)).unwrap();
            assert!(
                invocation
                    .windows(2)
                    .any(|v| v == ["-c", "credential.helper="])
            );
            assert!(
                !invocation
                    .iter()
                    .any(|v| v == "--force" || v == "--recurse-submodules")
            );
            assert!(op.arguments(phase, "HEAD").is_err());
            assert!(op.arguments("credential", "").is_err());
            args.push("--upload-pack=evil".into());
            assert!(Operation::parse(&args).is_err());
        }
        for url in [
            "https://github.com.evil/a/b.git",
            "https://evil/a/b.git",
            "http://github.com/a/b.git",
            "https://u@github.com/a/b.git",
            "https://github.com/a/b.git?x",
            "https://github.com/a/%2e.git",
            "https://github.com/../b.git",
            "https://github.com/a/b.git/",
            "https://github.com:443/a/b.git",
        ] {
            assert!(Operation::parse(&["fetch".into(), url.into()]).is_err());
        }
        let env = environment("/tmp/objects", "nonce");
        assert_eq!(env["GIT_DIR"], REPOSITORY);
        assert_eq!(env["GIT_OBJECT_DIRECTORY"], "/tmp/objects");
        assert!(!env.contains_key("GIT_TRACE_CURL"));
        assert!(!env.contains_key("GH_TOKEN"));
    }
}
