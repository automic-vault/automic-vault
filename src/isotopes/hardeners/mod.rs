pub(crate) mod aliyun_cli;
pub(crate) mod aws_cli;
pub(crate) mod aws_release;
pub(crate) mod codex;
pub(crate) mod docker;
pub(crate) mod env_wrapper;
pub(crate) mod fastly_cli;
pub(crate) mod gh_cli;
pub(crate) mod goat;
pub(crate) mod homebrew;
pub(crate) mod isotope;
pub(crate) mod kubectl;
mod migrations;
pub(crate) mod openhue_cli;
pub(crate) mod ordercli;
pub(crate) mod oxide_cli;
pub(crate) mod plumber;
pub(crate) mod podman;
pub(crate) mod railway;
pub(crate) mod rclone;
pub(crate) mod stripe_cli;
pub(crate) mod sudo;
pub(crate) mod supabase;
pub(crate) mod terraform;
pub(crate) mod terraform_release;
pub(crate) mod uaa_cli;
pub(crate) mod wakatime_cli;

unsafe extern "C" {
    fn geteuid() -> u32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivilegeMode {
    RootOnly,
    Mixed,
    UserOnly,
}

impl PrivilegeMode {
    pub(crate) fn require_user(self, hardener: &str, test_override: bool) -> Result<(), String> {
        if effective_uid() != 0 || test_override {
            return Ok(());
        }
        match self {
            Self::Mixed => Err(format!(
                "run `av harden {hardener}` without sudo; av will request elevation when needed"
            )),
            Self::UserOnly => Err(format!("`av harden {hardener}` cannot be run as root")),
            Self::RootOnly => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootOnlyOutcome {
    Previewed,
    Hardened,
}

pub(crate) fn effective_uid() -> u32 {
    crate::test_env_string("AUTOMIC_VAULT_TEST_EUID")
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| unsafe { geteuid() })
}

pub(crate) struct HardenerMetadata {
    pub(crate) name: &'static str,
    pub(crate) documentation: &'static str,
    pub(crate) detection: HardenerDetection,
    pub(crate) secret_gate: Option<SecretGateDescriptor>,
}

pub(crate) struct SecretGateDescriptor {
    pub(crate) id: &'static str,
    pub(crate) key_patterns: Vec<String>,
    pub(crate) routes: Vec<SecretGateRoute>,
}

pub(crate) struct SecretGateRoute {
    pub(crate) operation: &'static str,
    pub(crate) script_path: Option<String>,
    pub(crate) target_path: String,
    pub(crate) caller_identifiers: Vec<&'static str>,
    pub(crate) key_patterns: Vec<String>,
    pub(crate) replace_existing_env: bool,
    pub(crate) allow_missing_keys: bool,
}

pub(crate) struct HardenerDetection {
    pub(crate) hardened: bool,
    pub(crate) applicable: bool,
    pub(crate) stub_path: Option<String>,
    pub(crate) target_path: Option<String>,
    pub(crate) commands: Vec<HardenerCommand>,
    pub(crate) diagnostics: Vec<HardenerDiagnostic>,
}

pub(crate) struct HardenerDiagnostic {
    pub(crate) kind: &'static str,
    pub(crate) message: String,
    pub(crate) remediation: String,
    pub(crate) path: Option<String>,
}

#[derive(Clone)]
pub(crate) struct HardenerCommand {
    pub(crate) name: String,
    pub(crate) hardened: bool,
    pub(crate) stub_valid: bool,
    pub(crate) stub_path: Option<String>,
    pub(crate) target_path: String,
    pub(crate) required_paths: Vec<RequiredExecutable>,
    pub(crate) stub_requirements: Option<StubRequirements>,
    pub(crate) injected_keys: Vec<String>,
    pub(crate) assignment_keys: Vec<String>,
    pub(crate) isotope: Option<isotope::Doctor>,
}

#[derive(Clone)]
pub(crate) struct RequiredExecutable {
    pub(crate) name: &'static str,
    pub(crate) path: String,
}

#[derive(Clone)]
pub(crate) struct StubRequirements {
    pub(crate) mode: u32,
    pub(crate) owner: RequiredIdentity,
    pub(crate) group: RequiredIdentity,
}

#[derive(Clone)]
pub(crate) struct RequiredIdentity {
    pub(crate) name: &'static str,
    pub(crate) id: Option<u32>,
}

pub(crate) fn write_secret_gate_notice(stdout: &mut dyn std::io::Write, gate_id: &str) {
    let protection = if gate_id == "kubectl" {
        "Approval Required"
    } else if gate_id == "brew" {
        "Read & Update"
    } else {
        "Read Only"
    };
    writeln!(
        stdout,
        "\n◇ `{gate_id}` defaults to {protection}, adjust this in the app: `av open --secret-gate {gate_id}`"
    )
    .ok();
}

impl HardenerDetection {
    pub(crate) fn command(
        hardened: bool,
        name: impl Into<String>,
        stub_path: Option<String>,
        target_path: String,
    ) -> Self {
        let applicable = stub_path
            .as_deref()
            .is_some_and(|path| Path::new(path).exists())
            || Path::new(&target_path).exists();
        Self {
            hardened,
            applicable,
            stub_path: stub_path.clone(),
            target_path: Some(target_path.clone()),
            commands: vec![HardenerCommand {
                name: name.into(),
                hardened,
                stub_valid: hardened,
                stub_path,
                target_path,
                required_paths: Vec::new(),
                stub_requirements: None,
                injected_keys: Vec::new(),
                assignment_keys: Vec::new(),
                isotope: None,
            }],
            diagnostics: Vec::new(),
        }
    }

    pub(crate) fn commands(hardened: bool, commands: Vec<HardenerCommand>) -> Self {
        let applicable = commands.iter().any(|command| {
            command
                .stub_path
                .as_deref()
                .is_some_and(|path| Path::new(path).exists())
                || Path::new(&command.target_path).exists()
        });
        let primary = commands.first();
        Self {
            hardened,
            applicable,
            stub_path: primary.and_then(|command| command.stub_path.clone()),
            target_path: primary.map(|command| command.target_path.clone()),
            commands,
            diagnostics: Vec::new(),
        }
    }

    pub(crate) fn configuration(
        hardened: bool,
        applicable: bool,
        target_path: Option<String>,
    ) -> Self {
        Self {
            hardened,
            applicable,
            stub_path: None,
            target_path,
            commands: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(crate) fn executable(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

pub(crate) struct ConfigRewrite<'a> {
    pub(crate) path: &'a Path,
    pub(crate) existed: bool,
    pub(crate) original: &'a str,
    pub(crate) replacement: &'a str,
}

pub(crate) fn rewrite_configs_with_rollback(
    rewrites: &[ConfigRewrite<'_>],
    mut write: impl FnMut(&Path, &str) -> Result<(), String>,
    mut remove: impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let mut attempted = Vec::new();
    for rewrite in rewrites {
        attempted.push(rewrite);
        if let Err(error) = write(rewrite.path, rewrite.replacement) {
            return match restore_config_rewrites(&attempted, &mut write, &mut remove) {
                Ok(()) => Err(format!(
                    "config migration failed and was rolled back: {error}"
                )),
                Err(rollback) => Err(format!(
                    "config migration failed ({error}); rollback also failed: {rollback}"
                )),
            };
        }
    }
    Ok(())
}

pub(crate) fn restore_config_rewrites(
    rewrites: &[&ConfigRewrite<'_>],
    mut write: impl FnMut(&Path, &str) -> Result<(), String>,
    mut remove: impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let errors = rewrites
        .iter()
        .rev()
        .filter_map(|rewrite| {
            let result = if rewrite.existed {
                write(rewrite.path, rewrite.original)
            } else {
                remove(rewrite.path)
            };
            result.err()
        })
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

macro_rules! gated_hardener {
    ($module:ident, $name:literal) => {
        HardenerMetadata {
            name: $name,
            documentation: include_str!(concat!(stringify!($module), ".md")),
            detection: $module::detect(),
            secret_gate: Some($module::secret_gate()),
        }
    };
}

macro_rules! ungated_hardener {
    ($module:ident, $name:literal) => {
        HardenerMetadata {
            name: $name,
            documentation: include_str!(concat!(stringify!($module), ".md")),
            detection: $module::detect(),
            secret_gate: None,
        }
    };
}

pub(crate) fn metadata() -> Vec<HardenerMetadata> {
    let mut metadata = vec![
        gated_hardener!(aliyun_cli, "aliyun-cli"),
        gated_hardener!(aws_cli, "aws"),
        ungated_hardener!(codex, "codex"),
        gated_hardener!(docker, "docker"),
        gated_hardener!(goat, "goat"),
        gated_hardener!(ordercli, "ordercli"),
        gated_hardener!(openhue_cli, "openhue-cli"),
        gated_hardener!(plumber, "plumber"),
        gated_hardener!(podman, "podman"),
        gated_hardener!(uaa_cli, "uaa-cli"),
        gated_hardener!(railway, "railway"),
        gated_hardener!(rclone, "rclone"),
        gated_hardener!(kubectl, "kubectl"),
        gated_hardener!(oxide_cli, "oxide-cli"),
        gated_hardener!(fastly_cli, "fastly-cli"),
        gated_hardener!(homebrew, "brew"),
        gated_hardener!(gh_cli, "gh"),
        gated_hardener!(stripe_cli, "stripe"),
        ungated_hardener!(sudo, "sudo"),
        gated_hardener!(supabase, "supabase"),
        gated_hardener!(wakatime_cli, "wakatime-cli"),
        HardenerMetadata {
            name: "terraform",
            documentation: include_str!("terraform.md"),
            detection: terraform::detect(terraform::Tool::Terraform),
            secret_gate: Some(terraform::secret_gate(terraform::Tool::Terraform)),
        },
        HardenerMetadata {
            name: "opentofu",
            documentation: include_str!("opentofu.md"),
            detection: terraform::detect(terraform::Tool::OpenTofu),
            secret_gate: Some(terraform::secret_gate(terraform::Tool::OpenTofu)),
        },
    ];
    metadata.extend(env_wrapper::metadata());
    metadata
}

pub(crate) fn secret_gates() -> Vec<SecretGateDescriptor> {
    let mut gates = vec![
        gpg_signing_gate(),
        aliyun_cli::secret_gate(),
        aws_cli::secret_gate(),
        docker::secret_gate(),
        goat::secret_gate(),
        ordercli::secret_gate(),
        openhue_cli::secret_gate(),
        plumber::secret_gate(),
        podman::secret_gate(),
        uaa_cli::secret_gate(),
        railway::secret_gate(),
        rclone::secret_gate(),
        kubectl::secret_gate(),
        oxide_cli::secret_gate(),
        fastly_cli::secret_gate(),
        homebrew::secret_gate(),
        gh_cli::secret_gate(),
        stripe_cli::secret_gate(),
        supabase::secret_gate(),
        wakatime_cli::secret_gate(),
        terraform::secret_gate(terraform::Tool::Terraform),
        terraform::secret_gate(terraform::Tool::OpenTofu),
    ];
    gates.extend(env_wrapper::secret_gates());
    gates
}

fn gpg_signing_gate() -> SecretGateDescriptor {
    let keys = vec!["AV_GPG_*".to_string()];
    let target_path = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .unwrap_or_else(|_| "/Applications/Automic Vault.app/Contents/MacOS/av".into())
        .to_string_lossy()
        .into_owned();
    SecretGateDescriptor {
        id: "gpg-signing",
        key_patterns: keys.clone(),
        routes: vec![SecretGateRoute {
            operation: "gpg-sign",
            script_path: None,
            target_path,
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: keys,
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    #[test]
    fn secret_gate_notices_match_the_policy_defaults() {
        let mut aws = Vec::new();
        super::write_secret_gate_notice(&mut aws, "aws");
        assert_eq!(
            String::from_utf8(aws).unwrap(),
            "\n◇ `aws` defaults to Read Only, adjust this in the app: `av open --secret-gate aws`\n"
        );

        let mut brew = Vec::new();
        super::write_secret_gate_notice(&mut brew, "brew");
        assert_eq!(
            String::from_utf8(brew).unwrap(),
            "\n◇ `brew` defaults to Read & Update, adjust this in the app: `av open --secret-gate brew`\n"
        );

        let mut kubectl = Vec::new();
        super::write_secret_gate_notice(&mut kubectl, "kubectl");
        assert_eq!(
            String::from_utf8(kubectl).unwrap(),
            "\n◇ `kubectl` defaults to Approval Required, adjust this in the app: `av open --secret-gate kubectl`\n"
        );
    }

    #[test]
    fn config_rewrites_restore_every_attempted_path_after_failure() {
        let first = PathBuf::from("first");
        let second = PathBuf::from("second");
        let files = RefCell::new(BTreeMap::from([
            (first.clone(), "one".to_string()),
            (second.clone(), "two".to_string()),
        ]));
        let writes = Cell::new(0);
        let rewrites = [
            super::ConfigRewrite {
                path: &first,
                existed: true,
                original: "one",
                replacement: "ONE",
            },
            super::ConfigRewrite {
                path: &second,
                existed: true,
                original: "two",
                replacement: "TWO",
            },
        ];
        let result = super::rewrite_configs_with_rollback(
            &rewrites,
            |path, contents| {
                writes.set(writes.get() + 1);
                if writes.get() == 2 {
                    files
                        .borrow_mut()
                        .insert(path.to_path_buf(), contents.into());
                    return Err("injected failure after replacement".into());
                }
                files
                    .borrow_mut()
                    .insert(path.to_path_buf(), contents.into());
                Ok(())
            },
            |path: &Path| {
                files.borrow_mut().remove(path);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(files.borrow().get(&first).unwrap(), "one");
        assert_eq!(files.borrow().get(&second).unwrap(), "two");
    }
}
