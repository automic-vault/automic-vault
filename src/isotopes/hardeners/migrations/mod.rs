#![allow(dead_code, unexpected_cfgs)]

mod akamai;
mod algolia;
mod argocd;
mod ast_cli;
mod buf;
mod censys;
mod checkov;
mod circleci;
mod civo;
mod cloudsmith_cli;
mod composer;
mod doctl;
mod flyctl;
mod glab;
mod gotify;
mod gptcommit;
mod grafanactl;
mod hcloud;
mod heroku;
mod huggingface_cli;
mod jfrog_cli;
mod k6;
mod luarocks;
mod minio_mc;
mod netlify_cli;
mod node;
mod pnpm;
mod pulumi;
mod qwen_code;
mod runpodctl;
mod s3cmd;
mod sentry_cli;
mod snowflake_cli;
mod snyk;
mod transifex_cli;
mod travis;
mod twine;
mod vagrant;
mod vault;
mod virustotal_cli;
mod vultr;
mod wsk;

type Migration = fn() -> Result<(), String>;

const MIGRATIONS: &[(&str, Migration)] = &[
    ("akamai", akamai::migrate_credentials),
    ("algolia", algolia::migrate_credentials),
    ("argocd", argocd::migrate_credentials),
    ("ast-cli", ast_cli::migrate_credentials),
    ("buf", buf::migrate_credentials),
    ("censys", censys::migrate_credentials),
    ("checkov", checkov::migrate_credentials),
    ("circleci", circleci::migrate_credentials),
    ("civo", civo::migrate_credentials),
    ("cloudsmith-cli", cloudsmith_cli::migrate_credentials),
    ("composer", composer::migrate_credentials),
    ("doctl", doctl::migrate_credentials),
    ("flyctl", flyctl::migrate_credentials),
    ("glab", glab::migrate_credentials),
    ("gotify", gotify::migrate_credentials),
    ("gptcommit", gptcommit::migrate_credentials),
    ("grafanactl", grafanactl::migrate_credentials),
    ("hcloud", hcloud::migrate_credentials),
    ("heroku", heroku::migrate_credentials),
    ("huggingface-cli", huggingface_cli::migrate_credentials),
    ("jfrog-cli", jfrog_cli::migrate_credentials),
    ("k6", k6::migrate_credentials),
    ("luarocks", luarocks::migrate_credentials),
    ("minio-mc", minio_mc::migrate_credentials),
    ("netlify-cli", netlify_cli::migrate_credentials),
    ("node", node::migrate_credentials),
    ("pnpm", pnpm::migrate_credentials),
    ("pulumi", pulumi::migrate_credentials),
    ("qwen-code", qwen_code::migrate_credentials),
    ("runpodctl", runpodctl::migrate_credentials),
    ("s3cmd", s3cmd::migrate_credentials),
    ("sentry-cli", sentry_cli::migrate_credentials),
    ("snowflake-cli", snowflake_cli::migrate_credentials),
    ("snyk", snyk::migrate_credentials),
    ("transifex-cli", transifex_cli::migrate_credentials),
    ("travis", travis::migrate_credentials),
    ("twine", twine::migrate_credentials),
    ("vagrant", vagrant::migrate_credentials),
    ("vault", vault::migrate_credentials),
    ("virustotal-cli", virustotal_cli::migrate_credentials),
    ("vultr", vultr::migrate_credentials),
    ("wsk", wsk::migrate_credentials),
];

pub(super) fn run(name: &str) -> Option<Result<(), String>> {
    MIGRATIONS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, migrate)| migrate())
}

pub(super) fn names() -> impl Iterator<Item = &'static str> {
    MIGRATIONS.iter().map(|(name, _)| *name)
}

pub(super) fn akamai_caller_has_credentials(
    edgerc: Option<&std::path::Path>,
    section: &str,
) -> bool {
    akamai::caller_has_credentials(edgerc, section)
}

pub(super) fn akamai_command_is_installed(command: &str) -> bool {
    akamai::command_is_installed(command)
}

pub(super) fn wsk_selected_props_have_auth() -> bool {
    wsk::selected_props_have_auth()
}

pub(super) fn vultr_config_has_api_key(path: Option<&std::path::Path>) -> bool {
    vultr::config_has_api_key(path)
}

pub(super) fn virustotal_default_config_is_safe_for_api_key() -> bool {
    virustotal_cli::default_config_is_safe_for_api_key()
}

pub(super) fn travis_default_config_is_safe_for_token() -> bool {
    travis::default_config_is_safe_for_token()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn isotope_store_generic_password_json(
    service: *const std::ffi::c_char,
    account: *const std::ffi::c_char,
    value: *const std::ffi::c_char,
    error: *mut *mut std::ffi::c_char,
) -> bool {
    let result = (|| {
        if service.is_null() || account.is_null() || value.is_null() {
            return Err("invalid secret storage arguments".to_string());
        }
        let service = unsafe { std::ffi::CStr::from_ptr(service) }
            .to_str()
            .map_err(|_| "invalid secret storage service".to_string())?;
        if service != "com.automicvault.isotope" {
            return Err(format!("invalid secret storage service: {service}"));
        }
        let account = unsafe { std::ffi::CStr::from_ptr(account) }
            .to_str()
            .map_err(|_| "invalid secret name".to_string())?;
        let value = unsafe { std::ffi::CStr::from_ptr(value) }
            .to_str()
            .map_err(|_| "invalid secret value".to_string())?;
        crate::secrets::store_secret(account, value)
    })();

    if let Err(message) = result {
        if !error.is_null() {
            let message = std::ffi::CString::new(message)
                .unwrap_or_else(|_| std::ffi::CString::new("secret storage write failed").unwrap());
            unsafe { *error = message.into_raw() };
        }
        false
    } else {
        true
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn isotope_free_c_string(value: *mut std::ffi::c_char) {
    if !value.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(value) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_migration_name_is_unique() {
        let mut names = names().collect::<Vec<_>>();
        names.sort_unstable();
        let len = names.len();
        names.dedup();
        assert_eq!(names.len(), len);
    }
}
