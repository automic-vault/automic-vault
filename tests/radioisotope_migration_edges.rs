#![cfg(coverage)]
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, OnceLock};

fn global_test_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
}

struct EnvGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            std::env::remove_var(key);
        }
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

macro_rules! radioisotope_source {
    ($path:literal) => {
        concat!(env!("AUTOMIC_VAULT_GENERATED_RADIOISOTOPES_REPO"), $path)
    };
}

macro_rules! migration_keychain_extra_tests {
    () => {
        #[cfg(test)]
        mod av_keychain_extra_tests {
            use super::*;
            use std::fs;
            use std::time::{SystemTime, UNIX_EPOCH};

            fn temp_root(label: &str) -> std::path::PathBuf {
                let suffix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                std::env::temp_dir().join(format!(
                    "radioisotope-migrate-{label}-{}-{suffix}",
                    module_path!().replace("::", "_")
                ))
            }

            #[test]
            fn covers_keys_and_coverage_keychain_stub() {
                let declared_keys = keys();
                assert!(!declared_keys.is_empty());

                let store = KeychainCredentialStore;
                let err = store.store_secret(declared_keys[0], "value").unwrap_err();
                assert!(err.contains("keychain"));
            }

            #[test]
            fn covers_top_level_missing_default_locations() {
                let _lock = crate::global_test_env_lock().lock().unwrap();
                let root = temp_root("empty-defaults");
                let home = root.join("home");
                let xdg_cache = root.join("xdg-cache");
                let xdg_config = root.join("xdg-config");
                let xdg_runtime = root.join("xdg-runtime");
                let xdg_state = root.join("xdg-state");
                fs::create_dir_all(&home).unwrap();
                fs::create_dir_all(&xdg_cache).unwrap();
                fs::create_dir_all(&xdg_config).unwrap();
                fs::create_dir_all(&xdg_runtime).unwrap();
                fs::create_dir_all(&xdg_state).unwrap();

                let _env_guards = [
                    crate::EnvGuard::set("HOME", &home),
                    crate::EnvGuard::set("XDG_CACHE_HOME", &xdg_cache),
                    crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg_config),
                    crate::EnvGuard::set("XDG_RUNTIME_DIR", &xdg_runtime),
                    crate::EnvGuard::set("XDG_STATE_HOME", &xdg_state),
                    crate::EnvGuard::remove("AKAMAI_EDGERC"),
                    crate::EnvGuard::remove("ANSIBLE_GALAXY_TOKEN_PATH"),
                    crate::EnvGuard::remove("ARGOCD_CONFIG_DIR"),
                    crate::EnvGuard::remove("BITWARDENCLI_APPDATA_DIR"),
                    crate::EnvGuard::remove("CARGO_HOME"),
                    crate::EnvGuard::remove("CAROOT"),
                    crate::EnvGuard::remove("CIVO_CONFIG"),
                    crate::EnvGuard::remove("COMPOSER_HOME"),
                    crate::EnvGuard::remove("CX_CONFIG_FILE_PATH"),
                    crate::EnvGuard::remove("DCOS_DIR"),
                    crate::EnvGuard::remove("DIGITALOCEAN_CONFIG"),
                    crate::EnvGuard::remove("GLAB_CONFIG_DIR"),
                    crate::EnvGuard::remove("HCLOUD_CONFIG"),
                    crate::EnvGuard::remove("HELM_CONFIG_HOME"),
                    crate::EnvGuard::remove("HELM_REPOSITORY_CONFIG"),
                    crate::EnvGuard::remove("KUBECONFIG"),
                    crate::EnvGuard::remove("MCP_REMOTE_CONFIG_DIR"),
                    crate::EnvGuard::remove("NETRC"),
                    crate::EnvGuard::remove("NPM_CONFIG_USERCONFIG"),
                    crate::EnvGuard::remove("OCI_CLI_CONFIG_FILE"),
                    crate::EnvGuard::remove("PULUMI_CREDENTIALS_PATH"),
                    crate::EnvGuard::remove("PULUMI_HOME"),
                    crate::EnvGuard::remove("RCLONE_CONFIG"),
                    crate::EnvGuard::remove("REGISTRY_AUTH_FILE"),
                    crate::EnvGuard::remove("TALOSCONFIG"),
                    crate::EnvGuard::remove("TALOS_HOME"),
                    crate::EnvGuard::remove("UV_CREDENTIALS_DIR"),
                    crate::EnvGuard::remove("VAGRANT_HOME"),
                ];

                migrate_credentials().unwrap();
                fs::remove_dir_all(root).unwrap();
            }
        }
    };
}

macro_rules! migration_keychain_module_extra_tests {
    ($module:ident, $path:literal) => {
        mod $module {
            include!(radioisotope_source!($path));
            migration_keychain_extra_tests!();
        }
    };
}

migration_keychain_module_extra_tests!(acli_migrate_keychain, "/acli/migrate.rs");
migration_keychain_module_extra_tests!(aliyun_cli_migrate_keychain, "/aliyun-cli/migrate.rs");
migration_keychain_module_extra_tests!(ast_cli_migrate_keychain, "/ast-cli/migrate.rs");
migration_keychain_module_extra_tests!(astra_migrate_keychain, "/astra/migrate.rs");
migration_keychain_module_extra_tests!(bitwarden_cli_migrate_keychain, "/bitwarden-cli/migrate.rs");
migration_keychain_module_extra_tests!(buf_migrate_keychain, "/buf/migrate.rs");
migration_keychain_module_extra_tests!(censys_migrate_keychain, "/censys/migrate.rs");
migration_keychain_module_extra_tests!(checkov_migrate_keychain, "/checkov/migrate.rs");
migration_keychain_module_extra_tests!(circleci_migrate_keychain, "/circleci/migrate.rs");
migration_keychain_module_extra_tests!(civo_migrate_keychain, "/civo/migrate.rs");
migration_keychain_module_extra_tests!(
    cloudsmith_cli_migrate_keychain,
    "/cloudsmith-cli/migrate.rs"
);
migration_keychain_module_extra_tests!(composer_migrate_keychain, "/composer/migrate.rs");
migration_keychain_module_extra_tests!(dcos_cli_migrate_keychain, "/dcos-cli/migrate.rs");
migration_keychain_module_extra_tests!(
    dropbox_uploader_migrate_keychain,
    "/dropbox-uploader/migrate.rs"
);
migration_keychain_module_extra_tests!(fastly_migrate_keychain, "/fastly/migrate.rs");
migration_keychain_module_extra_tests!(fauna_shell_migrate_keychain, "/fauna-shell/migrate.rs");
migration_keychain_module_extra_tests!(firebase_cli_migrate_keychain, "/firebase-cli/migrate.rs");
migration_keychain_module_extra_tests!(flyctl_migrate_keychain, "/flyctl/migrate.rs");
migration_keychain_module_extra_tests!(gcli_migrate_keychain, "/gcli/migrate.rs");
migration_keychain_module_extra_tests!(gallery_dl_migrate_keychain, "/gallery-dl/migrate.rs");
migration_keychain_module_extra_tests!(goat_migrate_keychain, "/goat/migrate.rs");
migration_keychain_module_extra_tests!(gotify_migrate_keychain, "/gotify/migrate.rs");
migration_keychain_module_extra_tests!(gptcommit_migrate_keychain, "/gptcommit/migrate.rs");
migration_keychain_module_extra_tests!(graphite_migrate_keychain, "/graphite/migrate.rs");
migration_keychain_module_extra_tests!(hcloud_migrate_keychain, "/hcloud/migrate.rs");
migration_keychain_module_extra_tests!(helm_migrate_keychain, "/helm/migrate.rs");
migration_keychain_module_extra_tests!(heroku_migrate_keychain, "/heroku/migrate.rs");
migration_keychain_module_extra_tests!(
    huggingface_cli_migrate_keychain,
    "/huggingface-cli/migrate.rs"
);
migration_keychain_module_extra_tests!(imap_backup_migrate_keychain, "/imap-backup/migrate.rs");
migration_keychain_module_extra_tests!(k6_migrate_keychain, "/k6/migrate.rs");
migration_keychain_module_extra_tests!(
    kubernetes_cli_migrate_keychain,
    "/kubernetes-cli/migrate.rs"
);
migration_keychain_module_extra_tests!(mariadb_migrate_keychain, "/mariadb/migrate.rs");
migration_keychain_module_extra_tests!(maven_migrate_keychain, "/maven/migrate.rs");
migration_keychain_module_extra_tests!(mcp_remote_migrate_keychain, "/mcp-remote/migrate.rs");
migration_keychain_module_extra_tests!(mercurial_migrate_keychain, "/mercurial/migrate.rs");
migration_keychain_module_extra_tests!(mkcert_migrate_keychain, "/mkcert/migrate.rs");
migration_keychain_module_extra_tests!(mycli_migrate_keychain, "/mycli/migrate.rs");
migration_keychain_module_extra_tests!(mysql_client_migrate_keychain, "/mysql-client/migrate.rs");
migration_keychain_module_extra_tests!(mysql_migrate_keychain, "/mysql/migrate.rs");
migration_keychain_module_extra_tests!(mysql_8_0_migrate_keychain, "/mysql@8.0/migrate.rs");
migration_keychain_module_extra_tests!(mysql_8_4_migrate_keychain, "/mysql@8.4/migrate.rs");
migration_keychain_module_extra_tests!(netlify_cli_migrate_keychain, "/netlify-cli/migrate.rs");
migration_keychain_module_extra_tests!(node_migrate_keychain, "/node/migrate.rs");
migration_keychain_module_extra_tests!(node_18_migrate_keychain, "/node@18/migrate.rs");
migration_keychain_module_extra_tests!(oci_cli_migrate_keychain, "/oci-cli/migrate.rs");
migration_keychain_module_extra_tests!(openhue_cli_migrate_keychain, "/openhue-cli/migrate.rs");
migration_keychain_module_extra_tests!(ordercli_migrate_keychain, "/ordercli/migrate.rs");
migration_keychain_module_extra_tests!(ossutil_migrate_keychain, "/ossutil/migrate.rs");
migration_keychain_module_extra_tests!(oxide_cli_migrate_keychain, "/oxide-cli/migrate.rs");
migration_keychain_module_extra_tests!(phylum_cli_migrate_keychain, "/phylum-cli/migrate.rs");
migration_keychain_module_extra_tests!(plumber_migrate_keychain, "/plumber/migrate.rs");
migration_keychain_module_extra_tests!(pnpm_migrate_keychain, "/pnpm/migrate.rs");
migration_keychain_module_extra_tests!(pulumi_migrate_keychain, "/pulumi/migrate.rs");
migration_keychain_module_extra_tests!(railway_migrate_keychain, "/railway/migrate.rs");
migration_keychain_module_extra_tests!(rclone_migrate_keychain, "/rclone/migrate.rs");
migration_keychain_module_extra_tests!(runpodctl_migrate_keychain, "/runpodctl/migrate.rs");
migration_keychain_module_extra_tests!(sbt_migrate_keychain, "/sbt/migrate.rs");
migration_keychain_module_extra_tests!(sentry_cli_migrate_keychain, "/sentry-cli/migrate.rs");
migration_keychain_module_extra_tests!(shodan_migrate_keychain, "/shodan/migrate.rs");
migration_keychain_module_extra_tests!(soracom_cli_migrate_keychain, "/soracom-cli/migrate.rs");
migration_keychain_module_extra_tests!(sqlcmd_migrate_keychain, "/sqlcmd/migrate.rs");
migration_keychain_module_extra_tests!(sslmate_migrate_keychain, "/sslmate/migrate.rs");
migration_keychain_module_extra_tests!(talosctl_migrate_keychain, "/talosctl/migrate.rs");
migration_keychain_module_extra_tests!(
    terraform_core_migrate_keychain,
    "/terraform-core/migrate.rs"
);
migration_keychain_module_extra_tests!(todoist_cli_migrate_keychain, "/todoist-cli/migrate.rs");
migration_keychain_module_extra_tests!(travis_migrate_keychain, "/travis/migrate.rs");
migration_keychain_module_extra_tests!(uaa_cli_migrate_keychain, "/uaa-cli/migrate.rs");
migration_keychain_module_extra_tests!(uv_migrate_keychain, "/uv/migrate.rs");
migration_keychain_module_extra_tests!(vagrant_migrate_keychain, "/vagrant/migrate.rs");
migration_keychain_module_extra_tests!(vault_migrate_keychain, "/vault/migrate.rs");
migration_keychain_module_extra_tests!(
    virustotal_cli_migrate_keychain,
    "/virustotal-cli/migrate.rs"
);
migration_keychain_module_extra_tests!(vultr_migrate_keychain, "/vultr/migrate.rs");
migration_keychain_module_extra_tests!(wsk_migrate_keychain, "/wsk/migrate.rs");

mod snyk_migrate {
    include!(radioisotope_source!("/snyk/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;

        #[test]
        fn covers_secret_detection_and_assignment_errors() {
            assert_eq!(keys(), &["SNYK_ENV_ASSIGNMENTS"]);
            assert!(config_has_secrets(r#"{"clientSecret":"secret"}"#));
            assert!(config_has_secrets(r#"{"api":"secret"}"#));
            assert!(!config_has_secrets(r#"{"api":""}"#));
            assert!(!json_string_key_has_nonempty_value(
                r#"{"api" "missing-colon"}"#,
                "api"
            ));
            assert!(!json_string_key_has_nonempty_value(r#"{"api": 12}"#, "api"));

            assert!(
                snyk_env_assignments(r#"{"oci-registry-password":"secret"}"#)
                    .unwrap_err()
                    .contains("registry passwords")
            );
            assert!(
                snyk_env_assignments(r#"{"api":"one","token":"two"}"#)
                    .unwrap_err()
                    .contains("conflicting")
            );
            assert!(
                snyk_env_assignments("{\"api\":\"line\\nbreak\"}")
                    .unwrap_err()
                    .contains("SNYK_TOKEN")
            );

            let sanitized = sanitized_config_json(r#"{"api":"one","oauthToken":"two"}"#).unwrap();
            assert!(sanitized.contains("\"api\": \"\""));
            assert!(sanitized.contains("\"oauthToken\": \"\""));
        }
    }
}

mod algolia_migrate {
    include!(radioisotope_source!("/algolia/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;

        #[test]
        fn covers_profile_parser_and_env_errors() {
            assert_eq!(keys(), &["ALGOLIA_ENV_ASSIGNMENTS"]);
            assert!(config_contains_secret("api_key = 'secret'"));
            assert!(!config_contains_secret("api_key = ''"));
            assert!(!toml_string_field_is_present(
                "not an assignment",
                "api_key"
            ));
            assert_eq!(toml_string_value(r#""a\"b""#).unwrap(), "a\"b");
            assert!(toml_string_value("bare").is_none());
            assert!(toml_string_value("\"unterminated").is_none());

            assert!(
                algolia_env_assignments("[one]\napi_key='a'\n[two]\napi_key='b'\n")
                    .unwrap_err()
                    .contains("multiple profiles")
            );
            assert!(
                algolia_env_assignments("[default]\napi_key='a'\n")
                    .unwrap_err()
                    .contains("application_id")
            );
            assert!(
                algolia_env_assignments("[default]\ncrawler_api_key='a'\n")
                    .unwrap_err()
                    .contains("crawler_user_id")
            );
            assert!(reject_env_line_breaks("ALGOLIA_API_KEY", "a\nb").is_err());

            let sanitized =
                sanitized_config_toml("[default]\napi_key = 'secret' # keep\nunknown = 'x'\n");
            assert!(sanitized.contains("api_key = \"\""));
            assert!(sanitized.contains("unknown = 'x'"));
        }
    }
}

mod akamai_migrate {
    include!(radioisotope_source!("/akamai/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;

        #[test]
        fn covers_section_and_assignment_edges() {
            assert_eq!(keys(), &["AKAMAI_ENV_ASSIGNMENTS"]);
            assert!(config_has_edgegrid_secrets("client_token = 'token'"));
            assert!(!config_has_edgegrid_secrets("client_token = ''"));
            assert_eq!(unquote_ini_value("'quoted'"), "quoted");
            assert_eq!(unquote_ini_value("plain"), "plain");
            assert_eq!(env_section_prefix("default").unwrap(), "");
            assert_eq!(env_section_prefix("prod_1").unwrap(), "PROD_1_");
            assert!(env_section_prefix("bad-name").is_err());

            let mut assignments = Vec::new();
            push_assignment(
                &mut assignments,
                "AKAMAI_HOST".to_string(),
                "one".to_string(),
            )
            .unwrap();
            push_assignment(
                &mut assignments,
                "AKAMAI_HOST".to_string(),
                "one".to_string(),
            )
            .unwrap();
            assert!(
                push_assignment(
                    &mut assignments,
                    "AKAMAI_HOST".to_string(),
                    "two".to_string()
                )
                .unwrap_err()
                .contains("conflicting")
            );
            assert!(
                push_assignment(
                    &mut assignments,
                    "AKAMAI_TOKEN".to_string(),
                    "a\nb".to_string()
                )
                .unwrap_err()
                .contains("line breaks")
            );

            let missing = edgerc_migration(
                "[default]\nclient_token = token\nclient_secret = secret\naccess_token = access\n",
            )
            .unwrap_err();
            assert!(missing.contains("host"));
            let unsafe_section = edgerc_migration(
                "[bad-name]\nhost = h\nclient_token = t\nclient_secret = s\naccess_token = a\n",
            )
            .unwrap_err();
            assert!(unsafe_section.contains("safe environment variable"));
        }
    }
}

mod twine_migrate {
    include!(radioisotope_source!("/twine/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;

        #[test]
        fn covers_repository_userinfo_and_conflicts() {
            assert_eq!(keys(), &["TWINE_ENV_ASSIGNMENTS"]);
            assert_eq!(sanitize_line("# comment"), "# comment");
            assert_eq!(
                sanitize_line("repository https://example.test"),
                "repository https://example.test"
            );
            assert_eq!(
                strip_url_userinfo("https://user:pass@example.test/simple"),
                "https://example.test/simple"
            );
            assert_eq!(
                strip_url_userinfo("https://example.test/simple"),
                "https://example.test/simple"
            );
            assert_eq!(
                repository_userinfo("https://user@example.test/simple")
                    .unwrap()
                    .username
                    .as_deref(),
                Some("user")
            );
            assert!(repository_userinfo("https://example.test/path@later").is_none());

            assert!(twine_env_assignments("[one]\nusername=a\npassword=b\nrepository=https://one.test\n[two]\nusername=a\npassword=b\nrepository=https://two.test\n")
                .unwrap_err()
                .contains("multiple repositories"));
            assert!(
                twine_env_assignments("[private]\npassword=b\nrepository=https://private.test\n")
                    .unwrap_err()
                    .contains("without a username")
            );
            assert!(twine_env_assignments("[pypi]\nusername=a\nrepository=https://a:other@upload.pypi.org/legacy/\npassword=b\n")
                .unwrap_err()
                .contains("conflicting password"));
            assert!(reject_env_line_breaks("TWINE_PASSWORD", "a\nb").is_err());
        }
    }
}

mod luarocks_migrate {
    include!(radioisotope_source!("/luarocks/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::path::{Path, PathBuf};

        #[test]
        fn covers_assignment_parser_edges() {
            assert_eq!(keys(), &["LUAROCKS_API_KEY"]);
            assert!(parse_key_assignment("-- key = 'secret'").is_none());
            assert!(parse_key_assignment("not_key = 'secret'").is_none());
            assert!(parse_key_assignment("key = nil").is_none());
            assert!(parse_key_assignment("key = ''").is_none());
            assert_eq!(
                parse_key_assignment("upload.key = \"sec\\\"ret\"")
                    .unwrap()
                    .value,
                "sec\\\"ret"
            );
            assert!(key_side_names_key("upload['key']"));
            assert!(!key_side_names_key("monkey"));
            assert_eq!(
                upload_config_path_for_user_config(Path::new("luarocks.lua")),
                PathBuf::from("upload_config.lua")
            );

            assert!(
                upload_config_migration("key = 'one'\nkey = 'two'\n")
                    .unwrap_err()
                    .contains("multiple distinct")
            );
            assert!(upload_config_migration("key = 'one'\n").unwrap().is_some());
            assert!(upload_config_migration("return {}\n").unwrap().is_none());
        }
    }
}

mod midnight_commander_migrate {
    include!(radioisotope_source!("/midnight-commander/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;

        #[test]
        fn covers_profile_secret_detection_edges() {
            assert_eq!(keys(), &["MC_INI", "MC_HOTLIST", "MC_PANELS_INI"]);
            assert!(profile_has_secrets("ftpfs_password = secret\n"));
            assert!(!profile_has_secrets("ftpfs_password = <hidden>\n"));
            assert!(contains_url_password("ftp://user:pass@example.test/path"));
            assert!(contains_url_password("sftp:user:pass@example.test/path"));
            assert!(!contains_url_password("ftp://user:@example.test/path"));
            assert!(!contains_url_password("plain text"));
            assert!(line_has_password_setting(" password = secret "));
            assert!(!line_has_password_setting(" password =  "));
        }
    }
}

mod snowflake_cli_migrate {
    include!(radioisotope_source!("/snowflake-cli/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;
        use std::fs;
        use std::path::PathBuf;

        #[derive(Default)]
        struct Store {
            values: RefCell<Vec<(String, String)>>,
            fail: bool,
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                if self.fail {
                    return Err("store failed".to_string());
                }
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        #[test]
        fn covers_line_parsing_bundle_and_storage_edges() {
            assert_eq!(keys(), &["SNOWFLAKE_ENV_ASSIGNMENTS"]);
            assert!(
                keychain_store_secret("service", "account", "value")
                    .unwrap_err()
                    .contains("keychain")
            );
            assert_eq!(section_name(" [ default ] "), Some("default"));
            assert!(toml_value_is_nonempty("'secret'"));
            assert!(!toml_value_is_nonempty("''"));
            assert_eq!(toml_string_value(r#""a\"b""#).as_deref(), Some("a\"b"));
            assert_eq!(toml_string_value("'abc'").as_deref(), Some("abc"));
            assert!(toml_string_value("\"unterminated").is_none());
            assert_eq!(env_connection_suffix("prod_1").unwrap(), "PROD_1");
            assert!(env_connection_suffix("").is_err());
            assert!(env_connection_suffix("prod-west").is_err());
            assert!(reject_env_line_breaks("a\rb").is_err());

            let no_change = file_migration(
                "[connections.default]\nuser = 'me'\n",
                ConfigFileKind::ConfigToml,
            )
            .unwrap();
            assert!(!no_change.changed);
            assert_eq!(no_change.sanitized, "[connections.default]\nuser = 'me'\n");

            let outside =
                file_migration("password = 'secret'\n", ConfigFileKind::ConfigToml).unwrap_err();
            assert!(outside.contains("outside a connection"));
            assert!(
                file_migration(
                    "[connections.default]\nprivate_key_file_pwd = ''\n",
                    ConfigFileKind::ConfigToml,
                )
                .unwrap()
                .assignments
                .is_empty()
            );

            let dedup = file_migration(
                "[connections.default]\npassword = 'secret'\npassword = 'secret'\n",
                ConfigFileKind::ConfigToml,
            )
            .unwrap();
            assert_eq!(dedup.assignments.len(), 1);

            let bundle = ConfigBundle {
                dir: PathBuf::from("snowflake"),
                config: Some(FileState {
                    path: PathBuf::from("config.toml"),
                    sanitized: String::new(),
                    changed: false,
                    assignments: vec!["A=1".to_string()],
                }),
                connections: Some(FileState {
                    path: PathBuf::from("connections.toml"),
                    sanitized: String::new(),
                    changed: false,
                    assignments: vec!["A=1".to_string(), "B=2".to_string()],
                }),
            };
            assert!(!bundle.has_sensitive_values());
            assert_eq!(
                bundle.assignments(),
                vec!["A=1".to_string(), "B=2".to_string()]
            );

            let empty_assignment_bundle = ConfigBundle {
                dir: PathBuf::from("snowflake"),
                config: Some(FileState {
                    path: PathBuf::from("config.toml"),
                    sanitized: String::new(),
                    changed: true,
                    assignments: Vec::new(),
                }),
                connections: None,
            };
            assert!(!migrate_bundle(empty_assignment_bundle, &Store::default()).unwrap());

            let write_dir =
                std::env::temp_dir().join(format!("snowflake-write-dir-{}", std::process::id()));
            let _ = fs::remove_dir_all(&write_dir);
            fs::create_dir_all(&write_dir).unwrap();
            let write_error_bundle = ConfigBundle {
                dir: write_dir.clone(),
                config: Some(FileState {
                    path: write_dir.clone(),
                    sanitized: String::new(),
                    changed: true,
                    assignments: vec!["A=1".to_string()],
                }),
                connections: None,
            };
            assert!(
                migrate_bundle(write_error_bundle, &Store::default())
                    .unwrap_err()
                    .contains("failed to write")
            );
            fs::remove_dir_all(write_dir).unwrap();

            let store_error_bundle = ConfigBundle {
                dir: PathBuf::from("snowflake"),
                config: Some(FileState {
                    path: PathBuf::from("config.toml"),
                    sanitized: String::new(),
                    changed: false,
                    assignments: vec!["A=1".to_string()],
                }),
                connections: None,
            };
            assert!(
                migrate_bundle(
                    store_error_bundle,
                    &Store {
                        values: RefCell::new(Vec::new()),
                        fail: true,
                    },
                )
                .unwrap_err()
                .contains("store failed")
            );
        }

        #[test]
        fn covers_default_directory_selection_and_multi_match_error() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            {
                let _home = crate::EnvGuard::remove("HOME");
                assert!(candidate_directories().unwrap_err().contains("HOME"));
            }

            let home = std::env::temp_dir().join(format!("snowflake-home-{}", std::process::id()));
            let _ = fs::remove_dir_all(&home);
            fs::create_dir_all(home.join(".snowflake")).unwrap();
            fs::create_dir_all(home.join(".config/snowflake")).unwrap();
            fs::write(
                home.join(".snowflake/config.toml"),
                "[connections.default]\npassword = 'one'\n",
            )
            .unwrap();
            fs::write(
                home.join(".config/snowflake/connections.toml"),
                "[prod]\npassword = 'two'\n",
            )
            .unwrap();
            let _home = crate::EnvGuard::set("HOME", &home);
            assert_eq!(candidate_directories().unwrap().len(), 3);
            assert!(
                migrate_default_configs(&Store::default())
                    .unwrap_err()
                    .contains("multiple Snowflake")
            );
            fs::remove_dir_all(home).unwrap();
        }
    }
}

mod grafanactl_migrate {
    include!(radioisotope_source!("/grafanactl/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;
        use std::fs;

        #[derive(Default)]
        struct Store {
            values: RefCell<Vec<(String, String)>>,
            fail: bool,
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                if self.fail {
                    return Err("store failed".to_string());
                }
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        #[test]
        fn covers_path_detection_secret_parsing_and_env_edges() {
            assert_eq!(keys(), &["GRAFANACTL_ENV_ASSIGNMENTS"]);
            assert!(
                keychain_store_secret("service", "account", "value")
                    .unwrap_err()
                    .contains("keychain")
            );
            assert!(config_contains_secret("token: 'secret' # comment"));
            assert!(yaml_secret_line_is_present("password: \"secret\""));
            assert!(!yaml_secret_line_is_present("password:"));
            assert!(!yaml_secret_line_is_present("not yaml"));
            assert_eq!(unquote_yaml_scalar("'quoted'"), "quoted");
            assert_eq!(unquote_yaml_scalar("plain"), "plain");
            assert!(reject_env_line_breaks("GRAFANA_TOKEN", "a\nb").is_err());

            let token_linebreak = GrafanaContext {
                name: "default".to_string(),
                token: Some("a\rb".to_string()),
                user: None,
                password: None,
            };
            assert!(
                token_linebreak
                    .env_assignments()
                    .unwrap_err()
                    .contains("line breaks")
            );
            let user_linebreak = GrafanaContext {
                name: "default".to_string(),
                token: None,
                user: Some("a\nb".to_string()),
                password: Some("secret".to_string()),
            };
            assert!(
                user_linebreak
                    .env_assignments()
                    .unwrap_err()
                    .contains("GRAFANA_USER")
            );
            let password_linebreak = GrafanaContext {
                name: "default".to_string(),
                token: None,
                user: Some("admin".to_string()),
                password: Some("a\rb".to_string()),
            };
            assert!(
                password_linebreak
                    .env_assignments()
                    .unwrap_err()
                    .contains("GRAFANA_PASSWORD")
            );

            let contexts = grafana_secret_contexts(
                "outside: true\ncontexts:\n  default:\n    grafana:\n      token: ''\n      user: admin\n      password: secret\n",
            );
            assert_eq!(contexts.len(), 1);
            assert_eq!(contexts[0].name, "default");

            assert_eq!(
                sanitized_config_yaml("contexts:\n  default:\n    grafana:\n      token: secret"),
                "contexts:\n  default:\n    grafana:\n      token: \"\""
            );
        }

        #[test]
        fn covers_config_paths_and_file_errors() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = std::env::temp_dir().join(format!("grafanactl-home-{}", std::process::id()));
            let xdg = root.join("xdg");
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&xdg).unwrap();
            {
                let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg);
                let _home = crate::EnvGuard::remove("HOME");
                assert_eq!(
                    grafanactl_config_path().unwrap(),
                    xdg.join("grafanactl/config.yaml")
                );
            }
            {
                let _xdg = crate::EnvGuard::remove("XDG_CONFIG_HOME");
                let _home = crate::EnvGuard::remove("HOME");
                assert!(grafanactl_config_path().unwrap_err().contains("HOME"));
            }

            let path = root.join("config.yaml");
            fs::write(
                &path,
                "contexts:\n  default:\n    grafana:\n      token: secret\n",
            )
            .unwrap();
            assert!(
                migrate_config_file(
                    &path,
                    &Store {
                        values: RefCell::new(Vec::new()),
                        fail: true,
                    },
                )
                .unwrap_err()
                .contains("store failed")
            );
            assert!(
                migrate_config_file(&root, &Store::default())
                    .unwrap_err()
                    .contains("failed to read")
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod nuget_migrate {
    include!(radioisotope_source!("/nuget/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;
        use std::fs;

        struct ErrorStore;

        impl CredentialStore for ErrorStore {
            fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
                Err("store failed".to_string())
            }
        }

        #[derive(Default)]
        struct Store {
            values: RefCell<Vec<(String, String)>>,
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        #[test]
        fn covers_xml_helpers_and_secret_detectors() {
            assert_eq!(
                keys(),
                &[
                    "NUGET_MONO_CONFIG_XML",
                    "NUGET_DOTNET_CONFIG_XML",
                    "NUGET_PACKAGE_SOURCE_CREDENTIALS_JSON"
                ]
            );
            assert!(
                keychain_store_secret("service", "account", "value")
                    .unwrap_err()
                    .contains("keychain")
            );
            assert!(config_has_secrets(
                r#"<configuration><config><add key="http_proxy.password" value="secret" /></config></configuration>"#,
            ));
            assert!(config_has_secrets(
                r#"<configuration><clientCertificates><certificate password="secret" /></clientCertificates></configuration>"#,
            ));
            assert!(!has_configured_api_key(
                r#"<apikeys><add key="x" value="" /></apikeys>"#
            ));
            assert!(package_source_credentials("<configuration />").is_empty());
            assert!(xml_section("<configuration />", "missing").is_none());
            assert!(
                xml_section_range("<apikeys><add /></apikeys>", "packageSourceCredentials")
                    .is_none()
            );
            assert!(xml_section_body_range("<apikeys><add />", "apikeys").is_none());
            assert!(add_tags("<add key=\"x\"").is_empty());
            assert!(xml_attr(r#"<add key=value value='secret' />"#, "value").is_none());
            assert_eq!(
                xml_attr(r#"<add value='secret' />"#, "value"),
                Some("secret".to_string())
            );
            assert_eq!(
                decode_xml_element_name("private_x0020_feed"),
                "private feed"
            );
            assert_eq!(decode_xml_element_name("bad_xzzzz_tail"), "bad_xzzzz_tail");
            assert_eq!(xml_unescape("&lt;&gt;&amp;&quot;&apos;"), "<>&\"'");
            assert_eq!(
                sanitize_package_source_credentials(
                    "<configuration><apikeys><add key=\"x\" value=\"s\" /></apikeys></configuration>"
                ),
                "<configuration />\n"
            );
            assert_eq!(
                sanitize_config_for_storage("<configuration></configuration>"),
                "<configuration></configuration>\n"
            );

            let credentials = vec![SourceCredential {
                name: "private".to_string(),
                uri: None,
                username: "user".to_string(),
                password: "pass".to_string(),
            }];
            assert!(
                source_credentials_json(&credentials)
                    .unwrap()
                    .contains("private")
            );
        }

        #[test]
        fn covers_env_paths_and_migration_error_edges() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            {
                let _home = crate::EnvGuard::remove("HOME");
                let _xdg = crate::EnvGuard::remove("XDG_CONFIG_HOME");
                assert!(user_home().unwrap_err().contains("HOME"));
            }

            let root = std::env::temp_dir().join(format!("nuget-home-{}", std::process::id()));
            let xdg = root.join("xdg");
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&xdg).unwrap();
            let _home = crate::EnvGuard::set("HOME", &root);
            let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let configs = nuget_configs().unwrap();
            assert_eq!(configs[0].path, xdg.join("NuGet/NuGet.Config"));

            let config = root.join("NuGet.Config");
            fs::write(
                &config,
                r#"<configuration><packageSourceCredentials><private><add key="Username" value="u" /><add key="Password" value="p" /></private></packageSourceCredentials></configuration>"#,
            )
            .unwrap();
            let configs = vec![NuGetConfig {
                path: config.clone(),
                env_key: NUGET_MONO_CONFIG_ENV_KEY,
            }];
            assert!(
                migrate_credentials_files(&configs, &ErrorStore)
                    .unwrap_err()
                    .contains("store failed")
            );

            let missing = root.join("missing.config");
            assert!(
                !migrate_credentials_files(
                    &[NuGetConfig {
                        path: missing,
                        env_key: NUGET_MONO_CONFIG_ENV_KEY,
                    }],
                    &Store::default(),
                )
                .unwrap()
            );
            assert!(
                migrate_credentials_files(
                    &[NuGetConfig {
                        path: root.clone(),
                        env_key: NUGET_MONO_CONFIG_ENV_KEY,
                    }],
                    &Store::default(),
                )
                .unwrap_err()
                .contains("failed to read")
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod aws_cli_migrate {
    include!(radioisotope_source!("/aws-cli/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;
        use std::fs;

        struct Store {
            values: RefCell<Vec<(String, String)>>,
            fail_on_secret: bool,
        }

        impl Default for Store {
            fn default() -> Self {
                Self {
                    values: RefCell::new(Vec::new()),
                    fail_on_secret: false,
                }
            }
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                if self.fail_on_secret && key == AWS_SECRET_ACCESS_KEY_ENV_KEY {
                    return Err("secret store failed".to_string());
                }
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        #[test]
        fn covers_ini_json_and_config_helpers() {
            assert!(
                keychain_store_secret("service", "account", "value")
                    .unwrap_err()
                    .contains("keychain")
            );
            assert!(
                default_credentials("[default\nkey=value\n", Path::new("aws"))
                    .unwrap_err()
                    .contains("invalid section")
            );
            assert!(
                default_credentials("[]\nkey=value\n", Path::new("aws"))
                    .unwrap_err()
                    .contains("empty section")
            );
            assert!(
                default_credentials("key=value\n", Path::new("aws"))
                    .unwrap_err()
                    .contains("before any section")
            );
            assert!(
                default_credentials("[default]\naws_access_key_id = AKIA\n", Path::new("aws"))
                    .unwrap_err()
                    .contains("missing aws_secret")
            );
            assert!(
                default_credentials(
                    "[default]\naws_secret_access_key = secret\n",
                    Path::new("aws")
                )
                .unwrap_err()
                .contains("missing aws_access")
            );
            assert_eq!(
                split_ini_assignment(" key = value "),
                Some(("key", "value"))
            );
            assert_eq!(parse_section_header("[ default ]"), Some("default"));
            assert!(parse_section_header("[]").is_none());
            assert!(is_plaintext_aws_key("aws_access_key_id"));
            assert!(!is_plaintext_aws_key("region"));
            assert!(login_cache_file_has_credentials(
                r#"{"AWS_ACCESS_KEY_ID":"AKIA"}"#
            ));
            assert!(!contains_json_string_value(
                r#"{"AWS_ACCESS_KEY_ID":""}"#,
                "AWS_ACCESS_KEY_ID"
            ));
            assert!(!contains_json_string_value(
                r#"{"AWS_ACCESS_KEY_ID""#,
                "AWS_ACCESS_KEY_ID"
            ));

            assert_eq!(
                remove_default_plaintext_key_lines(
                    "[default]\naws_access_key_id = AKIA\nregion = us\n[dev]\naws_secret_access_key = keep\n"
                ),
                "[default]\nregion = us\n[dev]\naws_secret_access_key = keep\n"
            );
            assert_eq!(
                upsert_default_credential_process("[default]\n\nregion = us\n"),
                "[default]\n\nregion = us\ncredential_process = /usr/local/bin/av credential-helper aws\n"
            );
            assert_eq!(
                upsert_default_credential_process(
                    "[default]\ncredential_process = /usr/local/bin/av credential-helper aws\n"
                ),
                "[default]\ncredential_process = /usr/local/bin/av credential-helper aws\n"
            );
        }

        #[test]
        fn covers_store_home_login_cache_and_file_errors() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            {
                let _home = crate::EnvGuard::remove("HOME");
                assert!(home_path().unwrap_err().contains("HOME"));
            }

            let credentials = AwsCredentials {
                access_key_id: "AKIA".to_string(),
                secret_access_key: "secret".to_string(),
            };
            assert!(
                store_credentials(
                    &Store {
                        values: RefCell::new(Vec::new()),
                        fail_on_secret: true,
                    },
                    &credentials,
                )
                .unwrap_err()
                .contains("secret store failed")
            );

            let root = std::env::temp_dir().join(format!("aws-extra-{}", std::process::id()));
            let cache = root.join(AWS_LOGIN_CACHE_PATH);
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&cache).unwrap();
            fs::write(cache.join("ignore.txt"), "not json").unwrap();
            fs::write(cache.join("empty.json"), r#"{"accessKeyId":""}"#).unwrap();
            assert!(!warn_about_login_cache(&cache).unwrap());
            fs::write(cache.join("creds.json"), r#"{"secretAccessKey":"secret"}"#).unwrap();
            assert!(!warn_about_login_cache(&cache).unwrap());
            assert!(!warn_about_login_cache(&root.join("missing-cache")).unwrap());
            fs::write(root.join("not-dir"), "").unwrap();
            assert!(
                warn_about_login_cache(&root.join("not-dir"))
                    .unwrap_err()
                    .contains("failed to read")
            );

            let config = root.join("config");
            fs::write(
                &config,
                "[default]\ncredential_process = /usr/local/bin/av credential-helper aws\n",
            )
            .unwrap();
            ensure_credential_process_config(&config).unwrap();
            assert!(
                ensure_credential_process_config(&root)
                    .unwrap_err()
                    .contains("failed to read")
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod openstack_migrate {
    include!(radioisotope_source!("/openstackclient/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;
        use std::path::PathBuf;

        #[derive(Default)]
        struct Store {
            values: RefCell<Vec<(String, String)>>,
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        fn state(original: &str) -> FileState {
            FileState {
                path: PathBuf::from("clouds.yaml"),
                original: original.to_string(),
                sanitized: sanitized_config(original),
                changed: sanitized_config(original) != original,
            }
        }

        #[test]
        fn covers_yaml_parser_and_env_assignment_edges() {
            assert_eq!(
                keys(),
                &[
                    "OPENSTACK_ENV_ASSIGNMENTS",
                    "OPENSTACK_CLOUDS_YAML",
                    "OPENSTACK_SECURE_YAML"
                ]
            );
            assert_eq!(
                sanitized_config("clouds:\n  prod:\n    region_name: us\n"),
                "clouds:\n  prod:\n    region_name: us\n"
            );
            let mut changed = false;
            assert_eq!(
                sanitize_line("  - password: secret", &mut changed),
                "  - password: \"\""
            );
            assert!(changed);
            assert_eq!(trim_yaml_list_marker("- token: secret"), "token: secret");

            assert!(
                parse_openstack_config("not-yaml\nclouds:\n  prod:\n    token: t\n")
                    .unwrap()
                    .secrets
                    .len()
                    == 1
            );
            assert!(
                simple_yaml_scalar("|\n  multiline")
                    .unwrap_err()
                    .contains("multiline")
            );
            assert!(
                simple_yaml_scalar("{nested: value}")
                    .unwrap_err()
                    .contains("structured")
            );
            assert_eq!(
                simple_yaml_scalar("'quoted'").unwrap().as_deref(),
                Some("quoted")
            );
            assert_eq!(
                simple_yaml_scalar("\"quoted\"").unwrap().as_deref(),
                Some("quoted")
            );
            assert_eq!(simple_yaml_scalar("\"\"").unwrap(), None);

            let multi_cloud = state("clouds:\n  one:\n    token: t\n  two:\n    token: t\n");
            assert!(env_migration(Some(&multi_cloud), None).unwrap().is_none());
            let line_break = state("clouds:\n  prod:\n    token: \"a\rb\"\n");
            assert!(
                env_migration(Some(&line_break), None)
                    .unwrap_err()
                    .contains("line breaks")
            );
        }

        #[test]
        fn covers_file_state_errors_and_secure_payload_fallback() {
            let _guard = crate::global_test_env_lock().lock().unwrap();
            let home = std::env::temp_dir().join(format!(
                "openstack-extra-{}-{}",
                module_path!().replace("::", "_"),
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&home);
            let config_dir = home.join(".config/openstack");
            std::fs::create_dir_all(&config_dir).unwrap();
            assert!(
                load_file_state(&config_dir.join("missing.yaml"))
                    .unwrap()
                    .is_none()
            );
            assert!(
                load_file_state(&config_dir)
                    .unwrap_err()
                    .contains("failed to read")
            );

            let secure = config_dir.join("secure.yaml");
            std::fs::write(&secure, "clouds:\n  prod:\n    password: secret\n").unwrap();
            let _home = crate::EnvGuard::set("HOME", &home);

            let store = Store::default();
            assert!(migrate_default_configs(&store).unwrap());

            assert_eq!(store.values.borrow()[0].0, "OPENSTACK_SECURE_YAML");
            assert!(store.values.borrow()[0].1.contains("password: secret"));
            assert!(
                std::fs::read_to_string(&secure)
                    .unwrap()
                    .contains("password: \"\"")
            );
            std::fs::remove_dir_all(home).unwrap();
        }
    }
}

mod ansible_migrate {
    include!(radioisotope_source!("/ansible/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;

        #[derive(Default)]
        struct Store {
            values: RefCell<Vec<(String, String)>>,
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        #[test]
        fn covers_path_parser_no_token_and_fallback_edges() {
            let _guard = crate::global_test_env_lock().lock().unwrap();
            let temp = std::env::temp_dir().join(format!(
                "ansible-extra-{}-{}",
                module_path!().replace("::", "_"),
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&temp);
            std::fs::create_dir_all(&temp).unwrap();

            {
                let _home = crate::EnvGuard::set("HOME", temp.join("home"));
                let _token_path =
                    crate::EnvGuard::set("ANSIBLE_GALAXY_TOKEN_PATH", temp.join("custom-token"));
                let paths = candidate_token_paths().unwrap();
                assert!(paths.contains(&temp.join("custom-token")));
                assert!(
                    paths
                        .iter()
                        .any(|path| path.ends_with(".ansible/galaxy_token"))
                );
            }

            {
                let _home = crate::EnvGuard::remove("HOME");
                let _token_path = crate::EnvGuard::remove("ANSIBLE_GALAXY_TOKEN_PATH");
                assert_eq!(home_dir().unwrap_err(), "HOME is not set");
                assert_eq!(candidate_token_paths().unwrap_err(), "HOME is not set");
            }

            assert_eq!(keys(), &["ANSIBLE_GALAXY_TOKEN"]);
            assert_eq!(
                galaxy_token_value("\n# comment\nnot-token\nserver: ignored\ntoken: #comment\ntoken: null\ntoken: ~\n")
                    .unwrap(),
                None
            );
            assert_eq!(
                galaxy_token_value("token: 'abc123'\n").unwrap().as_deref(),
                Some("abc123")
            );
            assert!(
                reject_env_line_breaks("a\nb")
                    .unwrap_err()
                    .contains("line breaks")
            );

            let dir = temp.join("dir");
            std::fs::create_dir_all(&dir).unwrap();
            assert!(
                migrate_token_files(&[dir], &Store::default())
                    .unwrap_err()
                    .contains("failed to read")
            );
            let empty = temp.join("empty-token");
            std::fs::write(&empty, "token: null\n").unwrap();
            assert!(
                !migrate_token_files(&[temp.join("missing"), empty], &Store::default()).unwrap()
            );
            assert!(
                keychain_store_secret("service", "account", "value")
                    .unwrap_err()
                    .contains("keychain integration")
            );

            std::fs::remove_dir_all(temp).unwrap();
        }
    }
}

mod argocd_migrate {
    include!(radioisotope_source!("/argocd/migrate.rs"));
    migration_keychain_extra_tests!();
}

mod doctl_migrate {
    include!(radioisotope_source!("/doctl/migrate.rs"));
}

mod glab_migrate {
    include!(radioisotope_source!("/glab/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;

        #[derive(Default)]
        struct Store {
            values: RefCell<Vec<(String, String)>>,
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        #[test]
        fn covers_config_paths_file_edges_and_host_token_parser() {
            let _guard = crate::global_test_env_lock().lock().unwrap();
            let temp = std::env::temp_dir().join(format!(
                "glab-extra-{}-{}",
                module_path!().replace("::", "_"),
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&temp);
            std::fs::create_dir_all(&temp).unwrap();

            {
                let _glab_config_dir = crate::EnvGuard::set("GLAB_CONFIG_DIR", temp.join("glab"));
                assert_eq!(
                    candidate_config_paths().unwrap(),
                    vec![temp.join("glab/config.yml")]
                );
            }

            {
                let _glab_config_dir = crate::EnvGuard::remove("GLAB_CONFIG_DIR");
                let _home = crate::EnvGuard::set("HOME", temp.join("home"));
                let _xdg_config_home = crate::EnvGuard::set("XDG_CONFIG_HOME", temp.join("xdg"));
                let paths = candidate_config_paths().unwrap();
                assert_eq!(paths.len(), 3);
            }

            assert!(glab_config_contains_token(
                "hosts:\n  gitlab.com:\n    token: abc\n"
            ));
            assert!(glab_config_contains_oauth_refresh_token(
                "oauth2_refresh_token: refresh\n"
            ));
            assert_eq!(unquote_yaml_scalar("'quoted'"), "quoted");
            assert_eq!(
                glab_env_assignments("hosts:\n  gitlab.com:\n    token: abc\n").unwrap(),
                vec![
                    "GITLAB_TOKEN=abc".to_string(),
                    "GITLAB_HOST=gitlab.com".to_string()
                ]
            );
            assert!(
                glab_env_assignments(
                    "hosts:\n  one.example:\n    token: one\n  two.example:\n    token: two\n"
                )
                .unwrap_err()
                .contains("multiple host tokens")
            );
            assert_eq!(
                sanitized_glab_config("hosts:\n  gitlab.com:\n    token: abc\n"),
                "hosts:\n  gitlab.com:\n    token: \"\"\n"
            );

            let missing = temp.join("missing.yml");
            assert!(!migrate_credentials_file(&missing, &Store::default()).unwrap());
            let config = temp.join("config.yml");
            std::fs::write(&config, "hosts:\n  gitlab.com:\n    token: abc\n").unwrap();
            let store = Store::default();
            assert!(migrate_credentials_file(&config, &store).unwrap());
            assert_eq!(store.values.borrow()[0].0, "GLAB_ENV_ASSIGNMENTS");
            assert!(
                std::fs::read_to_string(&config)
                    .unwrap()
                    .contains("token: \"\"")
            );

            std::fs::remove_dir_all(temp).unwrap();
        }
    }

    migration_keychain_extra_tests!();
}

mod jfrog_cli_migrate {
    include!(radioisotope_source!("/jfrog-cli/migrate.rs"));
}

mod maestro_migrate {
    include!(radioisotope_source!("/maestro/migrate.rs"));
    migration_keychain_extra_tests!();
}

mod minio_mc_migrate {
    include!(radioisotope_source!("/minio-mc/migrate.rs"));
}

mod opentofu_migrate {
    include!(radioisotope_source!("/opentofu/migrate.rs"));
}

mod podman_migrate {
    include!(radioisotope_source!("/podman/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;

        #[derive(Default)]
        struct Store {
            values: RefCell<Vec<(String, String)>>,
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        #[test]
        fn covers_candidate_paths_and_auth_json_error_shapes() {
            let _guard = crate::global_test_env_lock().lock().unwrap();
            let temp = std::env::temp_dir().join(format!(
                "podman-extra-{}-{}",
                module_path!().replace("::", "_"),
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&temp);
            std::fs::create_dir_all(&temp).unwrap();

            {
                let _registry_auth_file =
                    crate::EnvGuard::set("REGISTRY_AUTH_FILE", temp.join("auth.json"));
                assert_eq!(
                    candidate_auth_paths().unwrap(),
                    vec![temp.join("auth.json")]
                );
            }

            {
                let _registry_auth_file = crate::EnvGuard::remove("REGISTRY_AUTH_FILE");
                let _runtime = crate::EnvGuard::set("XDG_RUNTIME_DIR", temp.join("runtime"));
                let _config = crate::EnvGuard::set("XDG_CONFIG_HOME", temp.join("xdg"));
                let _home = crate::EnvGuard::set("HOME", temp.join("home"));
                assert_eq!(candidate_auth_paths().unwrap().len(), 3);
            }

            assert!(!auth_json_contains_secret("not json"));
            assert!(!auth_entry_contains_secret(&serde_json::json!(
                "not object"
            )));
            assert_eq!(
                auth_json_with_credential_helpers(r#"{"auths":{}}"#).unwrap(),
                r#"{"auths":{}}"#
            );
            assert!(
                auth_json_with_credential_helpers("[]")
                    .unwrap_err()
                    .contains("root must be an object")
            );
            assert!(
                auth_json_with_credential_helpers(r#"{"auths":[]}"#)
                    .unwrap_err()
                    .contains("auths field must be an object")
            );
            assert!(auth_json_with_credential_helpers(
                r#"{"auths":{"registry.example":{"auth":"base64"}},"credHelpers":{"registry.example":"other"}}"#
            )
            .unwrap_err()
            .contains("refusing to overwrite"));

            let missing = temp.join("missing.json");
            assert!(!migrate_credentials_file(&missing, &Store::default()).unwrap());
            let auth = temp.join("auth.json");
            std::fs::write(
                &auth,
                r#"{"auths":{"registry.example":{"identityToken":"token"}}}"#,
            )
            .unwrap();
            let store = Store::default();
            assert!(migrate_credentials_file(&auth, &store).unwrap());
            assert_eq!(store.values.borrow()[0].0, "PODMAN_AUTH_JSON");
            assert!(
                std::fs::read_to_string(&auth)
                    .unwrap()
                    .contains("av-podman")
            );

            std::fs::remove_dir_all(temp).unwrap();
        }
    }

    migration_keychain_extra_tests!();
}

mod qwen_code_migrate {
    include!(radioisotope_source!("/qwen-code/migrate.rs"));
}

mod rust_migrate {
    include!(radioisotope_source!("/rust/migrate.rs"));
}

mod s3cmd_migrate {
    include!(radioisotope_source!("/s3cmd/migrate.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::cell::RefCell;

        #[derive(Default)]
        struct Store {
            values: RefCell<Vec<(String, String)>>,
        }

        impl CredentialStore for Store {
            fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
                self.values
                    .borrow_mut()
                    .push((key.to_string(), value.to_string()));
                Ok(())
            }
        }

        #[test]
        fn covers_config_path_parser_validation_and_file_migration_edges() {
            let _guard = crate::global_test_env_lock().lock().unwrap();
            let temp = std::env::temp_dir().join(format!(
                "s3cmd-extra-{}-{}",
                module_path!().replace("::", "_"),
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&temp);
            std::fs::create_dir_all(&temp).unwrap();

            {
                let _home = crate::EnvGuard::remove("HOME");
                assert_eq!(s3cmd_config_path().unwrap_err(), "HOME is not set");
            }
            {
                let _home = crate::EnvGuard::set("HOME", &temp);
                assert_eq!(s3cmd_config_path().unwrap(), temp.join(".s3cfg"));
            }

            assert_eq!(keys(), &["S3CMD_ENV_ASSIGNMENTS"]);
            assert_eq!(sanitized_config("# comment\n"), "# comment\n");
            assert_eq!(
                sanitized_config("gpg_passphrase = pass\n"),
                "gpg_passphrase = $S3CMD_GPG_PASSPHRASE\n"
            );
            let mut changed = false;
            assert_eq!(
                sanitize_line("missing equals", &mut changed),
                "missing equals"
            );
            assert_eq!(
                sanitize_line("access_key = ", &mut changed),
                "access_key = "
            );
            assert!(
                s3cmd_env_assignments(
                    "# comment\nmissing equals\nunknown = value\naccess_key = \n"
                )
                .unwrap()
                .is_empty()
            );
            assert_eq!(unquote_config_value("\"quoted\""), "quoted");
            assert!(
                s3cmd_env_assignments("access_key = only\n")
                    .unwrap_err()
                    .contains("both be present")
            );
            assert!(
                s3cmd_env_assignments("session_token = token\n")
                    .unwrap_err()
                    .contains("without access_key")
            );
            assert!(
                s3cmd_env_assignments("access_key = one\naccess_key = two\n")
                    .unwrap_err()
                    .contains("multiple s3cmd values")
            );
            assert!(reject_env_line_breaks("AWS_ACCESS_KEY_ID", "a\nb").is_err());

            let missing = temp.join("missing");
            assert!(!migrate_config_file(&missing, &Store::default()).unwrap());
            let config = temp.join("config");
            std::fs::write(
                &config,
                "access_key = key\nsecret_key = secret\nsession_token = token\n",
            )
            .unwrap();
            let store = Store::default();
            assert!(migrate_config_file(&config, &store).unwrap());
            assert_eq!(store.values.borrow()[0].0, "S3CMD_ENV_ASSIGNMENTS");
            assert!(
                std::fs::read_to_string(&config)
                    .unwrap()
                    .contains("access_key = ")
            );

            std::fs::remove_dir_all(temp).unwrap();
        }
    }
}

mod skopeo_migrate {
    include!(radioisotope_source!("/skopeo/migrate.rs"));
    migration_keychain_extra_tests!();
}

mod terraform_migrate {
    include!(radioisotope_source!("/terraform/migrate.rs"));
}

mod transifex_cli_migrate {
    include!(radioisotope_source!("/transifex-cli/migrate.rs"));
    migration_keychain_extra_tests!();
}

mod wakatime_cli_migrate {
    include!(radioisotope_source!("/wakatime-cli/migrate.rs"));
}
