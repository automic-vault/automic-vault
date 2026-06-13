#![cfg(coverage)]
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn global_test_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("radioisotope-detect-{label}-{suffix}"))
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

macro_rules! top_level_file_detector_tests {
    ($module:ident, $source:literal, $paths:expr, $contents:expr) => {
        mod $module {
            include!(radioisotope_source!($source));

            #[cfg(test)]
            mod av_extra_tests {
                use super::*;
                use std::fs;

                #[test]
                fn covers_top_level_detection_with_temp_paths() {
                    let _lock = crate::global_test_env_lock().lock().unwrap();
                    let root = crate::unique_temp_dir(stringify!($module));
                    let home = root.join("home");
                    let xdg_config = root.join("xdg-config");
                    let xdg_data = root.join("xdg-data");
                    let xdg_state = root.join("xdg-state");
                    fs::create_dir_all(&home).unwrap();
                    fs::create_dir_all(&xdg_config).unwrap();
                    fs::create_dir_all(&xdg_data).unwrap();
                    fs::create_dir_all(&xdg_state).unwrap();

                    let _home = crate::EnvGuard::set("HOME", &home);
                    let _xdg_config = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg_config);
                    let _xdg_data = crate::EnvGuard::set("XDG_DATA_HOME", &xdg_data);
                    let _xdg_state = crate::EnvGuard::set("XDG_STATE_HOME", &xdg_state);
                    let _custom_guards = [
                        crate::EnvGuard::remove("ARGOCD_CONFIG_DIR"),
                        crate::EnvGuard::remove("AZURE_CONFIG_DIR"),
                        crate::EnvGuard::remove("CIVO_CONFIG"),
                        crate::EnvGuard::remove("COMPOSER_HOME"),
                        crate::EnvGuard::remove("CX_CONFIG_FILE_PATH"),
                        crate::EnvGuard::remove("DIGITALOCEAN_CONFIG"),
                        crate::EnvGuard::remove("HELM_CONFIG_HOME"),
                        crate::EnvGuard::remove("HELM_REPOSITORY_CONFIG"),
                        crate::EnvGuard::remove("LUAROCKS_CONFIG"),
                        crate::EnvGuard::remove("LUAROCKS_CONFIG_SYSTEM"),
                        crate::EnvGuard::remove("LUAROCKS_CONFIG_USER"),
                    ];

                    let paths: Vec<std::path::PathBuf> = $paths;
                    assert!(!paths.is_empty());
                    for path in &paths {
                        fs::create_dir_all(path.parent().unwrap()).unwrap();
                        fs::write(path, $contents).unwrap();
                    }

                    let reasons = install_insecurity_reasons().unwrap();
                    assert!(
                        !reasons.is_empty(),
                        "expected detector reason for {paths:?}"
                    );

                    fs::remove_dir_all(root).unwrap();
                }
            }
        }
    };
}

top_level_file_detector_tests!(
    acli_detect,
    "/acli/detect.rs",
    acli_configs()
        .unwrap()
        .into_iter()
        .map(|config| config.path)
        .collect::<Vec<_>>(),
    "profiles:\n  - token: fake-atlassian-token\n"
);

top_level_file_detector_tests!(
    algolia_detect,
    "/algolia/detect.rs",
    vec![algolia_config_path().unwrap()],
    "api_key = \"fake-algolia-key\"\n"
);

top_level_file_detector_tests!(
    aliyun_cli_detect,
    "/aliyun-cli/detect.rs",
    vec![aliyun_config_path().unwrap()],
    r#"{"profiles":[{"access_key_secret":"secret","oauth_refresh_token":"refresh"}]}"#
);

top_level_file_detector_tests!(
    argocd_detect,
    "/argocd/detect.rs",
    candidate_config_paths().unwrap(),
    "users:\n- name: prod\n  auth-token: token\n"
);

top_level_file_detector_tests!(
    ast_cli_detect,
    "/ast-cli/detect.rs",
    vec![checkmarx_config_path().unwrap()],
    "cx_apikey: ast_secret\n"
);

top_level_file_detector_tests!(
    astra_detect,
    "/astra/detect.rs",
    vec![astra_config_path().unwrap()],
    "token=AstraCS:fake-test-token\n"
);

top_level_file_detector_tests!(
    azure_cli_detect,
    "/azure-cli/detect.rs",
    candidate_cache_files()
        .unwrap()
        .into_iter()
        .map(|file| file.path)
        .collect::<Vec<_>>(),
    r#"{"secret":"access-token","client_secret":"client-secret"}"#
);

top_level_file_detector_tests!(
    civo_detect,
    "/civo/detect.rs",
    vec![civo_config_path().unwrap()],
    r#"{"apikey":"fake-civo-key","region":"NYC1"}"#
);

top_level_file_detector_tests!(
    composer_detect,
    "/composer/detect.rs",
    candidate_auth_paths().unwrap(),
    r#"{"github-oauth":{"github.com":"token"}}"#
);

top_level_file_detector_tests!(
    doctl_detect,
    "/doctl/detect.rs",
    vec![doctl_config_path().unwrap()],
    "access-token: do_secret\n"
);

top_level_file_detector_tests!(
    helm_detect,
    "/helm/detect.rs",
    vec![helm_repository_config_path().unwrap()],
    "repositories:\n- name: private\n  password: secret\n"
);

top_level_file_detector_tests!(
    luarocks_detect,
    "/luarocks/detect.rs",
    upload_config_paths().unwrap(),
    "return {\n  key = \"lr_secret\",\n}\n"
);

mod httpie_detect {
    include!(radioisotope_source!("/httpie/detect.rs"));
}

mod openssh_detect {
    include!(radioisotope_source!("/openssh/detect.rs"));
}

mod openvpn_detect {
    include!(radioisotope_source!("/openvpn/detect.rs"));
}

mod docker_detect {
    include!(radioisotope_source!("/docker/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn covers_config_parsers_and_json_edges() {
            assert!(docker_config_contains_inline_secret(
                r#"{"auths":{"registry":{"identityToken":"token"}}}"#,
            ));
            assert!(!docker_config_contains_inline_secret(
                r#"{"auths":{"registry":{"auth":""}}}"#,
            ));
            assert!(docker_legacy_config_contains_secret(
                r#"{"registry":{"identitytoken":"token"}}"#,
            ));
            assert_eq!(
                credential_helper_values(r#"{"credHelpers":{"a":"av","b":"desktop"}}"#),
                vec!["av".to_string(), "desktop".to_string()]
            );
            assert!(config_has_default_helper(Some(
                r#"{"credsStore":"desktop"}"#
            )));
            assert!(!config_has_default_helper(Some(r#"{"credsStore":""}"#)));
            assert!(!config_has_default_helper(None));
            assert!(is_av_helper(" Automic-Vault-Docker "));
            assert!(!is_av_helper("desktop"));
            assert!(object_for_key(r#"{"auths":[]}"#, "auths").is_none());
            assert_eq!(
                object_value(r#"{"nested":{"quote":"a\"b"}} tail"#),
                Some(r#"{"nested":{"quote":"a\"b"}}"#)
            );
            assert!(object_value("not-object").is_none());
            assert_eq!(
                string_values_for_key(
                    r#"{"credsStore":"desktop","credsStore":"av"}"#,
                    "credsStore"
                ),
                vec!["desktop".to_string(), "av".to_string()]
            );
            assert_eq!(json_string_value(r#""a\"b" tail"#), Some(r#"a\"b"#));
            assert!(json_string_value("not-string").is_none());
        }

        #[cfg(unix)]
        #[test]
        fn covers_unix_group_socket_and_metadata_edges() {
            assert_eq!(
                group_file_line_name_and_gid(" docker :x:123: "),
                Some(("docker", 123))
            );
            assert!(group_file_line_name_and_gid("# comment").is_none());
            assert!(group_file_line_name_and_gid(":x:123:").is_none());
            assert!(group_file_line_name_and_gid("docker:x:not-a-gid:").is_none());
            assert!(group_file_contains_named_group_id(
                "docker:x:123:\n",
                "docker",
                &[123]
            ));
            assert!(!group_file_contains_named_group_id(
                "docker:x:123:\n",
                "docker",
                &[124]
            ));
            assert_eq!(docker_host_unix_socket_path("unix://"), None);
            assert_eq!(
                docker_host_unix_socket_path("unix:///tmp/docker.sock"),
                Some(PathBuf::from("/tmp/docker.sock"))
            );

            let _lock = crate::global_test_env_lock().lock().unwrap();
            let previous_host = std::env::var_os("DOCKER_HOST");
            unsafe {
                std::env::set_var("DOCKER_HOST", "unix:///tmp/docker-extra.sock");
            }
            assert!(docker_socket_paths().contains(&PathBuf::from("/tmp/docker-extra.sock")));
            unsafe {
                match previous_host {
                    Some(value) => std::env::set_var("DOCKER_HOST", value),
                    None => std::env::remove_var("DOCKER_HOST"),
                }
            }

            let path = std::env::temp_dir().join(format!("docker-metadata-{}", std::process::id()));
            fs::write(&path, "socket").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let metadata = fs::metadata(&path).unwrap();
            assert!(metadata_is_writable_by_current_user(&metadata, &[]));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            let metadata = fs::metadata(&path).unwrap();
            assert!(!metadata_is_writable_by_current_user(&metadata, &[]));
            fs::remove_file(path).unwrap();
        }

        #[test]
        fn covers_env_paths_and_top_level_detection_edges() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root =
                std::env::temp_dir().join(format!("docker-detect-extra-{}", std::process::id()));
            let docker_config = root.join("custom-docker");
            let home = root.join("home");
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&docker_config).unwrap();
            fs::create_dir_all(&home).unwrap();
            fs::write(docker_config.join("config.json"), r#"{"credsStore":"av"}"#).unwrap();
            fs::write(home.join(".dockercfg"), r#"{"registry":{"auth":"secret"}}"#).unwrap();

            let previous_home = std::env::var_os("HOME");
            let previous_docker_config = std::env::var_os("DOCKER_CONFIG");
            unsafe {
                std::env::set_var("HOME", &home);
                std::env::set_var("DOCKER_CONFIG", &docker_config);
            }
            assert_eq!(
                docker_config_path().unwrap(),
                docker_config.join("config.json")
            );
            assert!(install_is_insecure().unwrap());
            assert!(
                install_insecurity_reasons()
                    .unwrap()
                    .iter()
                    .any(|reason| reason.contains("legacy config"))
            );
            assert!(
                read_to_string(&root)
                    .unwrap_err()
                    .contains("failed to read")
            );

            unsafe {
                std::env::remove_var("HOME");
                std::env::remove_var("DOCKER_CONFIG");
            }
            assert!(home_dir().unwrap_err().contains("HOME"));
            assert!(docker_config_path().unwrap_err().contains("HOME"));
            assert!(docker_desktop_is_installed().unwrap_err().contains("HOME"));

            unsafe {
                match previous_home {
                    Some(value) => std::env::set_var("HOME", value),
                    None => std::env::remove_var("HOME"),
                }
                match previous_docker_config {
                    Some(value) => std::env::set_var("DOCKER_CONFIG", value),
                    None => std::env::remove_var("DOCKER_CONFIG"),
                }
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod aws_cli_detect {
    include!(radioisotope_source!("/aws-cli/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_credentials_and_login_cache_edges() {
            assert!(is_credentials_file_secret_key("aws_access_key_id"));
            assert!(!is_credentials_file_secret_key("region"));
            assert!(contains_json_string_value(
                r#"{"Credentials":{"AWS_SECRET_ACCESS_KEY":"secret"}}"#,
                "AWS_SECRET_ACCESS_KEY"
            ));
            assert!(!contains_json_string_value(
                r#"{"AWS_SECRET_ACCESS_KEY":""}"#,
                "AWS_SECRET_ACCESS_KEY"
            ));
            assert!(!contains_json_string_value(
                r#"{"AWS_SECRET_ACCESS_KEY""#,
                "AWS_SECRET_ACCESS_KEY"
            ));

            let root =
                std::env::temp_dir().join(format!("aws-detect-extra-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            let credentials = root.join("credentials");
            fs::write(
                &credentials,
                "[profile dev]\naws_access_key_id = DEV\n[default]\nregion = us\n",
            )
            .unwrap();
            assert!(!credentials_file_is_insecure(&credentials).unwrap());
            fs::write(&credentials, "[default]\naws_access_key_id = AKIA\n").unwrap();
            assert!(credentials_file_is_insecure(&credentials).unwrap());
            assert!(
                credentials_file_is_insecure(&root)
                    .unwrap_err()
                    .contains("failed to read")
            );

            assert!(!login_cache_is_insecure(&root.join("missing")).unwrap());
            let not_dir = root.join("not-dir");
            fs::write(&not_dir, "").unwrap();
            assert!(
                login_cache_is_insecure(&not_dir)
                    .unwrap_err()
                    .contains("failed to read")
            );
            let cache = root.join("cache");
            fs::create_dir_all(&cache).unwrap();
            fs::write(cache.join("ignore.txt"), "secretAccessKey").unwrap();
            fs::write(cache.join("empty.json"), r#"{"secretAccessKey":""}"#).unwrap();
            assert!(!login_cache_is_insecure(&cache).unwrap());
            fs::write(cache.join("creds.json"), r#"{"accessKeyId":"AKIA"}"#).unwrap();
            assert!(login_cache_is_insecure(&cache).unwrap());
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn covers_top_level_env_selection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = std::env::temp_dir().join(format!("aws-detect-env-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            let credentials = root.join("custom-credentials");
            fs::write(&credentials, "[default]\naws_secret_access_key = secret\n").unwrap();

            let previous_home = std::env::var_os("HOME");
            let previous_credentials = std::env::var_os("AWS_SHARED_CREDENTIALS_FILE");
            unsafe {
                std::env::remove_var("HOME");
                std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
            }
            assert!(install_insecurity_reasons().unwrap_err().contains("HOME"));
            unsafe {
                std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &credentials);
            }
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(install_is_insecure().unwrap());

            unsafe {
                match previous_home {
                    Some(value) => std::env::set_var("HOME", value),
                    None => std::env::remove_var("HOME"),
                }
                match previous_credentials {
                    Some(value) => std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", value),
                    None => std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE"),
                }
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod pulumi_detect {
    include!(radioisotope_source!("/pulumi/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_path_selection_and_top_level_errors() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root =
                std::env::temp_dir().join(format!("pulumi-detect-extra-{}", std::process::id()));
            let credentials_dir = root.join("credentials-dir");
            let pulumi_home = root.join("pulumi-home");
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&credentials_dir).unwrap();
            fs::create_dir_all(&pulumi_home).unwrap();
            fs::write(
                credentials_dir.join("credentials.json"),
                r#"{"accessTokens":{"https://api.pulumi.com":"pul-secret"}}"#,
            )
            .unwrap();

            let previous_home = std::env::var_os("HOME");
            let previous_credentials_path = std::env::var_os("PULUMI_CREDENTIALS_PATH");
            let previous_pulumi_home = std::env::var_os("PULUMI_HOME");
            unsafe {
                std::env::set_var("PULUMI_CREDENTIALS_PATH", &credentials_dir);
                std::env::set_var("PULUMI_HOME", &pulumi_home);
                std::env::remove_var("HOME");
            }
            assert_eq!(
                pulumi_credentials_path().unwrap(),
                credentials_dir.join("credentials.json")
            );
            assert!(install_is_insecure().unwrap());
            unsafe {
                std::env::remove_var("PULUMI_CREDENTIALS_PATH");
            }
            assert_eq!(
                pulumi_credentials_path().unwrap(),
                pulumi_home.join("credentials.json")
            );
            unsafe {
                std::env::remove_var("PULUMI_HOME");
            }
            assert!(pulumi_credentials_path().unwrap_err().contains("HOME"));
            assert!(
                read_to_string(&root)
                    .unwrap_err()
                    .contains("failed to read")
            );

            unsafe {
                match previous_home {
                    Some(value) => std::env::set_var("HOME", value),
                    None => std::env::remove_var("HOME"),
                }
                match previous_credentials_path {
                    Some(value) => std::env::set_var("PULUMI_CREDENTIALS_PATH", value),
                    None => std::env::remove_var("PULUMI_CREDENTIALS_PATH"),
                }
                match previous_pulumi_home {
                    Some(value) => std::env::set_var("PULUMI_HOME", value),
                    None => std::env::remove_var("PULUMI_HOME"),
                }
            }
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn covers_json_parser_edges() {
            assert!(!pulumi_credentials_contains_access_token(
                r#"{"accessTokens""#
            ));
            assert!(!pulumi_credentials_contains_access_token(
                r#"{"accessTokens":[]}"#
            ));
            assert!(matching_object_end(r#"{"nested":"a\"b"} tail"#).is_some());
            assert!(matching_object_end(r#"{"unterminated":true"#).is_none());
            assert!(!object_contains_non_empty_string_value("not-json"));
            assert!(!object_contains_non_empty_string_value(r#""key" "value""#));
            assert!(!object_contains_non_empty_string_value(r#""key": true"#));
            assert!(object_contains_non_empty_string_value(
                r#""empty":"", "token":"secret""#
            ));
            assert_eq!(skip_json_space_and_commas(" ,\n\tkey", 0), 4);
            assert_eq!(skip_json_space(" \n\tkey", 0), 3);
            assert_eq!(
                parse_json_string(r#""a\"b" tail"#, 0),
                Some((r#"a"b"#.to_string(), 6))
            );
            assert!(parse_json_string("unterminated", 0).is_none());
        }
    }
}

mod ansible_detect {
    include!(radioisotope_source!("/ansible/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_env_path_detection_and_file_errors() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("ansible");
            let home = root.join("home");
            let token = root.join("galaxy-token");
            fs::create_dir_all(&home).unwrap();
            fs::write(&token, "token: galaxy-token-value\n").unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _token = crate::EnvGuard::set("ANSIBLE_GALAXY_TOKEN_PATH", &token);

            let paths = candidate_token_paths().unwrap();
            assert!(paths.contains(&token));
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("galaxy-token"));
            assert!(
                read_to_string(&root)
                    .unwrap_err()
                    .contains("failed to read")
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod certbot_detect {
    include!(radioisotope_source!("/certbot/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_recursive_scan_and_top_level_reasons() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("certbot");
            let home = root.join("home");
            let live = home.join(".config/letsencrypt/live/example.test");
            fs::create_dir_all(&live).unwrap();
            fs::write(
                live.join("privkey.pem"),
                "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----\n",
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("privkey.pem"));

            let mut skipped = Vec::new();
            scan_dir(&live, MAX_SCAN_DEPTH + 1, &mut skipped).unwrap();
            assert!(skipped.is_empty());

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod opencode_detect {
    include!(radioisotope_source!("/opencode/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_xdg_auth_path_and_json_errors() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("opencode");
            let home = root.join("home");
            let xdg = root.join("xdg");
            let opencode = xdg.join("opencode");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&opencode).unwrap();
            let auth = opencode.join("auth.json");
            fs::write(
                &auth,
                r#"{"accounts":{"main":{"credential":{"access":"opencode-access-token"}}}}"#,
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_DATA_HOME", &xdg);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("auth.json"));

            fs::write(&auth, "{not json").unwrap();
            assert!(
                install_insecurity_reasons()
                    .unwrap_err()
                    .contains("opencode auth JSON")
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod mongodb_atlas_cli_detect {
    include!(radioisotope_source!("/mongodb-atlas-cli/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_xdg_config_path_and_read_error() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("atlas");
            let home = root.join("home");
            let xdg = root.join("xdg");
            let config_dir = xdg.join("atlascli");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(
                config_dir.join("config.toml"),
                "client_secret = 'atlas-client-secret'\n",
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("atlascli"));
            assert!(
                read_to_string(&root)
                    .unwrap_err()
                    .contains("failed to read")
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod pianobar_detect {
    include!(radioisotope_source!("/pianobar/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_xdg_config_path_and_space_assignment() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("pianobar");
            let home = root.join("home");
            let xdg = root.join("xdg");
            let config_dir = xdg.join("pianobar");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(config_dir.join("config"), "password supersecret\n").unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("pianobar"));
            assert_eq!(
                parse_assignment("password supersecret"),
                Some(("password", "supersecret"))
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod stripe_cli_detect {
    include!(radioisotope_source!("/stripe-cli/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_xdg_config_path_and_home_errors() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("stripe");
            let home = root.join("home");
            let xdg = root.join("xdg");
            let config_dir = xdg.join("stripe");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(
                config_dir.join("config.toml"),
                "secret_key = 'sk_test_123456789'\n",
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("stripe"));
            assert!(
                read_to_string(&root)
                    .unwrap_err()
                    .contains("failed to read")
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod skopeo_detect {
    include!(radioisotope_source!("/skopeo/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_auth_file_detection_and_home_error() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("skopeo");
            let home = root.join("home");
            let auth_dir = home.join(".config/containers");
            fs::create_dir_all(&auth_dir).unwrap();
            fs::write(
                auth_dir.join("auth.json"),
                r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}"#,
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("auth.json"));
            drop(_home);
            let _no_home = crate::EnvGuard::remove("HOME");
            assert!(install_insecurity_reasons().unwrap_err().contains("HOME"));

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod maestro_detect {
    include!(radioisotope_source!("/maestro/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_both_token_files_and_home_error() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("maestro");
            let home = root.join("home");
            let mobiledev = home.join(".mobiledev");
            fs::create_dir_all(&mobiledev).unwrap();
            fs::write(mobiledev.join("authtoken"), "maestro-cloud-token\n").unwrap();
            fs::write(mobiledev.join("openaitoken"), "sk-test-openai-token\n").unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 2);
            assert!(reasons.iter().any(|reason| reason.contains("Cloud")));
            assert!(reasons.iter().any(|reason| reason.contains("OpenAI")));

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod kubernetes_cli_detect {
    include!(radioisotope_source!("/kubernetes-cli/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_explicit_kubeconfig_path_and_list_marker_values() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("kube");
            fs::create_dir_all(&root).unwrap();
            let config = root.join("kubeconfig");
            fs::write(&config, "users:\n- password: kube-password\n").unwrap();

            let _kubeconfig = crate::EnvGuard::set("KUBECONFIG", &config);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("kubeconfig"));
            assert_eq!(trim_yaml_list_marker("- token: abc"), "token: abc");

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod fauna_shell_detect {
    include!(radioisotope_source!("/fauna-shell/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_secret_and_account_key_files() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("fauna");
            let home = root.join("home");
            let credentials = home.join(".fauna/credentials");
            fs::create_dir_all(&credentials).unwrap();
            fs::write(
                credentials.join("account_keys"),
                r#"{"default":{"accountKey":"fake-fauna-account-key"}}"#,
            )
            .unwrap();
            fs::write(
                credentials.join("secret_keys"),
                r#"{"db":{"accessToken":"fake-fauna-access-token"}}"#,
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 2);
            assert!(json_string_key_has_nonempty_value(
                r#"{"refreshToken":"fake-refresh"}"#,
                "refreshToken"
            ));

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod git_detect {
    include!(radioisotope_source!("/git/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_store_helper_paths_and_top_level_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("git");
            let home = root.join("home");
            fs::create_dir_all(&home).unwrap();
            fs::write(
                home.join(".gitconfig"),
                "[credential]\nhelper = store --file ~/.custom-git-credentials\n",
            )
            .unwrap();
            fs::write(
                home.join(".custom-git-credentials"),
                "https://user:secret@example.com/repo.git\n",
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::remove("XDG_CONFIG_HOME");
            let _disable_probe =
                crate::EnvGuard::remove("AUTOMIC_VAULT_TEST_GIT_CREDENTIAL_FILL_DETECTOR");
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("custom-git-credentials"));
            assert_eq!(
                store_helper_file_path("store --file ~/.custom-git-credentials")
                    .unwrap()
                    .unwrap(),
                home.join(".custom-git-credentials")
            );
            assert_eq!(expand_home_path("~/tokens").unwrap(), home.join("tokens"));

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod k6_detect {
    include!(radioisotope_source!("/k6/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_cloud_token_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("k6");
            let home = root.join("home");
            let config_dir = home.join("Library/Application Support/k6");
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(
                config_dir.join("config.json"),
                r#"{"token":"k6-cloud-token"}"#,
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("config.json"));
            assert!(install_is_insecure().unwrap());

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod tailscale_detect {
    include!(radioisotope_source!("/tailscale/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_plaintext_state_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("tailscale");
            let home = root.join("home");
            let xdg_data = root.join("xdg-data");
            let state_dir = xdg_data.join("tailscale");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&state_dir).unwrap();
            fs::write(
                state_dir.join("tailscaled.state"),
                r#"{"_machinekey":"mkey:plaintext"}"#,
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_DATA_HOME", &xdg_data);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("tailscaled.state"));
            assert!(!tailscale_state_contains_plaintext_identity("[]").unwrap());

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod mariadb_detect {
    include!(radioisotope_source!("/mariadb/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_defaults_file_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("mariadb");
            let home = root.join("home");
            fs::create_dir_all(&home).unwrap();
            fs::write(home.join(".my.cnf"), "[client]\npassword = real-secret\n").unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains(".my.cnf"));
            assert!(
                read_to_string(&root)
                    .unwrap_err()
                    .contains("failed to read")
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod poetry_detect {
    include!(radioisotope_source!("/poetry/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_auth_file_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("poetry");
            let home = root.join("home");
            let xdg_config = root.join("xdg-config");
            let auth_dir = xdg_config.join("pypoetry");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&auth_dir).unwrap();
            fs::write(
                auth_dir.join("auth.toml"),
                "[http-basic.private]\nusername = \"u\"\npassword = \"real-secret\"\n",
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg_config);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("auth.toml"));
            assert!(!poetry_auth_contains_secret(
                "[pypi-token]\ntoken = \"${TOKEN}\"\n"
            ));

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod cloudflared_detect {
    include!(radioisotope_source!("/cloudflared/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_recursive_file_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("cloudflared");
            let home = root.join("home");
            let config_home = root.join("xdg-config");
            let config_dir = config_home.join("cloudflared/nested");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(
                config_dir.join("cert.pem"),
                "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
            )
            .unwrap();
            fs::write(
                config_dir.join("tunnel.json"),
                r#"{"TunnelSecret":"secret"}"#,
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &config_home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 2);
            assert!(reasons.iter().any(|reason| reason.contains("cert.pem")));
            assert!(reasons.iter().any(|reason| reason.contains("tunnel.json")));
            assert_eq!(json_string_value(r#""a\"b" tail"#), Some(r#"a\"b"#));

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod databricks_detect {
    include!(radioisotope_source!("/databricks/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_profile_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("databricks");
            let home = root.join("home");
            let xdg_config = root.join("xdg-config");
            let config_dir = xdg_config.join("databricks");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(
                config_dir.join("config"),
                "[prod]\nhost = https://example.cloud.databricks.com\nclient_secret = 'real-secret'\n",
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg_config);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("databricks"));
            assert!(!databricks_config_contains_secret(
                "token = ${DATABRICKS_TOKEN}\n"
            ));

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod docker_machine_detect {
    include!(radioisotope_source!("/docker-machine/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_recursive_key_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("docker-machine");
            let home = root.join("home");
            let machine_dir = home.join(".docker/machine/machines/default");
            fs::create_dir_all(&machine_dir).unwrap();
            fs::write(
                machine_dir.join("id_rsa"),
                "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----\n",
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("id_rsa"));
            assert!(file_contains_unencrypted_private_key(&machine_dir.join("id_rsa")).unwrap());

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod imap_backup_detect {
    include!(radioisotope_source!("/imap-backup/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_password_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("imap-backup");
            let home = root.join("home");
            let config_dir = home.join(".imap-backup");
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(
                config_dir.join("config.json"),
                r#"{"accounts":[{"username":"a@example.com","password":"real-secret"}]}"#,
            )
            .unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("config.json"));
            assert_eq!(
                parse_json_string(r#""pa\\ss" tail"#),
                Some(r#"pa\ss"#.to_string())
            );

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod rclone_detect {
    include!(radioisotope_source!("/rclone/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_explicit_config_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("rclone");
            fs::create_dir_all(&root).unwrap();
            let config = root.join("rclone.conf");
            fs::write(&config, "[remote]\nclient_secret = real-secret\n").unwrap();

            let _config = crate::EnvGuard::set("RCLONE_CONFIG", &config);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("rclone.conf"));
            assert!(line_has_secret_value("refresh_token = real-secret"));

            fs::remove_dir_all(root).unwrap();
        }
    }
}

mod wget2_detect {
    include!(radioisotope_source!("/wget2/detect.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::fs;

        #[test]
        fn covers_top_level_netrc_and_config_detection() {
            let _lock = crate::global_test_env_lock().lock().unwrap();
            let root = crate::unique_temp_dir("wget2");
            let home = root.join("home");
            let xdg_config = root.join("xdg-config");
            let wget_dir = xdg_config.join("wget2");
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&wget_dir).unwrap();
            fs::write(
                home.join(".netrc"),
                "machine example.com login me password supersecret\n",
            )
            .unwrap();
            fs::write(wget_dir.join("wget2rc"), "proxy-password = anothersecret\n").unwrap();

            let _home = crate::EnvGuard::set("HOME", &home);
            let _xdg = crate::EnvGuard::set("XDG_CONFIG_HOME", &xdg_config);
            let reasons = install_insecurity_reasons().unwrap();
            assert_eq!(reasons.len(), 2);
            assert!(reasons.iter().any(|reason| reason.contains(".netrc")));
            assert!(reasons.iter().any(|reason| reason.contains("wget2rc")));
            assert!(password_key_name("--https-password"));
            assert!(!secret_value_is_real("placeholder-secret"));

            fs::remove_dir_all(root).unwrap();
        }
    }
}
