#![cfg(coverage)]
#![allow(dead_code)]

macro_rules! radioisotope_source {
    ($path:literal) => {
        concat!(env!("AUTOMIC_VAULT_GENERATED_RADIOISOTOPES_REPO"), $path)
    };
}

macro_rules! assert_missing_launcher_errors {
    ($wrap:ident, $temp:ident) => {
        assert!(
            $wrap(&$temp.join("missing-launcher"))
                .unwrap_err()
                .contains("failed to read")
        );
    };
}

macro_rules! assert_missing_launcher_noops {
    ($wrap:ident, $temp:ident) => {
        let missing = $temp.join("missing-launcher");
        let _ = $wrap(&missing).unwrap();
        assert!(!missing.exists());
    };
}

macro_rules! launcher_post_install_extra_tests {
    ($module:ident, $path:literal, $wrap:ident, $script:ident) => {
        launcher_post_install_extra_tests!(
            $module,
            $path,
            $wrap,
            $script,
            assert_missing_launcher_errors
        );
    };
    ($module:ident, $path:literal, $wrap:ident, $script:ident, $missing_launcher_assertion:ident) => {
        mod $module {
            include!(radioisotope_source!($path));

            #[cfg(test)]
            mod av_extra_tests {
                use super::*;
                use std::fs;
                use std::path::{Path, PathBuf};
                use std::time::{SystemTime, UNIX_EPOCH};

                #[cfg(unix)]
                use std::os::unix::fs::PermissionsExt;

                fn temp_dir(label: &str) -> PathBuf {
                    let suffix = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos();
                    std::env::temp_dir().join(format!(
                        "{}-{}-{}",
                        module_path!().replace("::", "_"),
                        label,
                        suffix
                    ))
                }

                fn write_executable(path: &Path, contents: &[u8]) {
                    fs::write(path, contents).unwrap();
                    let mut permissions = fs::metadata(path).unwrap().permissions();
                    permissions.set_mode(0o755);
                    fs::set_permissions(path, permissions).unwrap();
                }

                #[test]
                fn covers_existing_original_invalid_data_and_quoting_edges() {
                    let temp = temp_dir("existing-original");
                    fs::create_dir_all(&temp).unwrap();
                    let launcher = temp.join("launcher");
                    write_executable(&launcher, b"#!/bin/sh\nprintf launcher\n");
                    let original = original_launcher_path(&launcher).unwrap();
                    write_executable(&original, b"#!/bin/sh\nprintf existing\n");

                    let _ = $wrap(&launcher).unwrap();

                    let original_contents = fs::read_to_string(&original).unwrap();
                    assert!(
                        original_contents == "#!/bin/sh\nprintf existing\n"
                            || original_contents == "#!/bin/sh\nprintf launcher\n"
                    );
                    assert!(launcher_is_wrapped(&launcher).unwrap());
                    let _ = $wrap(&launcher).unwrap();
                    $missing_launcher_assertion!($wrap, temp);

                    let invalid = temp.join("invalid");
                    fs::write(&invalid, [0xff, 0xfe]).unwrap();
                    assert!(!launcher_is_wrapped(&invalid).unwrap());
                    assert!(
                        launcher_is_wrapped(&temp.join("missing-launcher"))
                            .unwrap_err()
                            .contains("failed to read")
                    );
                    assert!(
                        original_launcher_path(Path::new("/"))
                            .unwrap_err()
                            .contains("failed to resolve")
                    );

                    let script = $script(Path::new("/tmp/it isn't"));
                    assert!(script.contains(r#"'\''"#));

                    fs::remove_dir_all(temp).unwrap();
                }

                #[cfg(unix)]
                #[test]
                fn covers_rename_failure_error_message() {
                    let temp = temp_dir("rename-failure");
                    fs::create_dir_all(&temp).unwrap();
                    let launcher = temp.join("launcher");
                    write_executable(&launcher, b"#!/bin/sh\nprintf launcher\n");

                    let mut permissions = fs::metadata(&temp).unwrap().permissions();
                    permissions.set_mode(0o555);
                    fs::set_permissions(&temp, permissions).unwrap();

                    let result = $wrap(&launcher);

                    let mut permissions = fs::metadata(&temp).unwrap().permissions();
                    permissions.set_mode(0o755);
                    fs::set_permissions(&temp, permissions).unwrap();

                    assert!(result.unwrap_err().contains("failed to move"));
                    fs::remove_dir_all(temp).unwrap();
                }

                #[cfg(unix)]
                #[test]
                fn covers_relative_symlink_original_resolution() {
                    let temp = temp_dir("relative-symlink");
                    fs::create_dir_all(&temp).unwrap();
                    let target = temp.join("target-launcher");
                    write_executable(&target, b"#!/bin/sh\nprintf target\n");
                    let launcher = temp.join("launcher");
                    std::os::unix::fs::symlink("target-launcher", &launcher).unwrap();

                    assert_eq!(original_launcher_path(&launcher).unwrap(), target);

                    let _ = $wrap(&launcher).unwrap();

                    assert_eq!(
                        fs::read_to_string(temp.join("target-launcher")).unwrap(),
                        "#!/bin/sh\nprintf target\n"
                    );
                    assert!(launcher_is_wrapped(&launcher).unwrap());

                    fs::remove_dir_all(temp).unwrap();
                }

                #[cfg(unix)]
                #[test]
                fn covers_absolute_symlink_original_resolution() {
                    let temp = temp_dir("absolute-symlink");
                    fs::create_dir_all(&temp).unwrap();
                    let target = temp.join("target-launcher");
                    write_executable(&target, b"#!/bin/sh\nprintf target\n");
                    let launcher = temp.join("launcher");
                    std::os::unix::fs::symlink(&target, &launcher).unwrap();

                    assert_eq!(original_launcher_path(&launcher).unwrap(), target);

                    let _ = $wrap(&launcher).unwrap();

                    assert!(launcher_is_wrapped(&launcher).unwrap());
                    fs::remove_dir_all(temp).unwrap();
                }
            }
        }
    };
}

macro_rules! two_stage_launcher_post_install_extra_tests {
    ($module:ident, $path:literal, $wrap:ident, $script:ident) => {
        two_stage_launcher_post_install_extra_tests!(
            $module,
            $path,
            $wrap,
            $script,
            assert_missing_launcher_errors
        );
    };
    ($module:ident, $path:literal, $wrap:ident, $script:ident, $missing_launcher_assertion:ident) => {
        mod $module {
            include!(radioisotope_source!($path));

            #[cfg(test)]
            mod av_extra_tests {
                use super::*;
                use std::fs;
                use std::path::{Path, PathBuf};
                use std::time::{SystemTime, UNIX_EPOCH};

                #[cfg(unix)]
                use std::os::unix::fs::PermissionsExt;

                fn temp_dir(label: &str) -> PathBuf {
                    let suffix = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos();
                    std::env::temp_dir().join(format!(
                        "{}-{}-{}",
                        module_path!().replace("::", "_"),
                        label,
                        suffix
                    ))
                }

                fn write_executable(path: &Path, contents: &[u8]) {
                    fs::write(path, contents).unwrap();
                    let mut permissions = fs::metadata(path).unwrap().permissions();
                    permissions.set_mode(0o755);
                    fs::set_permissions(path, permissions).unwrap();
                }

                #[test]
                fn covers_existing_original_invalid_data_and_quoting_edges() {
                    let temp = temp_dir("existing-original");
                    fs::create_dir_all(&temp).unwrap();
                    let launcher = temp.join("launcher");
                    write_executable(&launcher, b"#!/bin/sh\nprintf launcher\n");
                    let original = original_launcher_path(&launcher).unwrap();
                    write_executable(&original, b"#!/bin/sh\nprintf existing\n");

                    let _ = $wrap(&launcher).unwrap();

                    let original_contents = fs::read_to_string(&original).unwrap();
                    assert!(
                        original_contents == "#!/bin/sh\nprintf existing\n"
                            || original_contents == "#!/bin/sh\nprintf launcher\n"
                    );
                    assert!(launcher_is_wrapped(&launcher).unwrap());
                    let _ = $wrap(&launcher).unwrap();
                    $missing_launcher_assertion!($wrap, temp);

                    let invalid = temp.join("invalid");
                    fs::write(&invalid, [0xff, 0xfe]).unwrap();
                    assert!(!launcher_is_wrapped(&invalid).unwrap());
                    assert!(
                        launcher_is_wrapped(&temp.join("missing-launcher"))
                            .unwrap_err()
                            .contains("failed to read")
                    );
                    assert!(
                        original_launcher_path(Path::new("/"))
                            .unwrap_err()
                            .contains("failed to resolve")
                    );

                    let script =
                        $script(Path::new("/tmp/it isn't"), Path::new("/tmp/inject isn't"));
                    assert!(script.contains(r#"'\''"#));

                    fs::remove_dir_all(temp).unwrap();
                }

                #[cfg(unix)]
                #[test]
                fn covers_rename_failure_error_message() {
                    let temp = temp_dir("rename-failure");
                    fs::create_dir_all(&temp).unwrap();
                    let launcher = temp.join("launcher");
                    write_executable(&launcher, b"#!/bin/sh\nprintf launcher\n");

                    let mut permissions = fs::metadata(&temp).unwrap().permissions();
                    permissions.set_mode(0o555);
                    fs::set_permissions(&temp, permissions).unwrap();

                    let result = $wrap(&launcher);

                    let mut permissions = fs::metadata(&temp).unwrap().permissions();
                    permissions.set_mode(0o755);
                    fs::set_permissions(&temp, permissions).unwrap();

                    assert!(result.unwrap_err().contains("failed to move"));
                    fs::remove_dir_all(temp).unwrap();
                }

                #[cfg(unix)]
                #[test]
                fn covers_relative_symlink_original_resolution() {
                    let temp = temp_dir("relative-symlink");
                    fs::create_dir_all(&temp).unwrap();
                    let target = temp.join("target-launcher");
                    write_executable(&target, b"#!/bin/sh\nprintf target\n");
                    let launcher = temp.join("launcher");
                    std::os::unix::fs::symlink("target-launcher", &launcher).unwrap();

                    assert_eq!(original_launcher_path(&launcher).unwrap(), target);

                    let _ = $wrap(&launcher).unwrap();

                    assert_eq!(
                        fs::read_to_string(temp.join("target-launcher")).unwrap(),
                        "#!/bin/sh\nprintf target\n"
                    );
                    assert!(launcher_is_wrapped(&launcher).unwrap());

                    fs::remove_dir_all(temp).unwrap();
                }

                #[cfg(unix)]
                #[test]
                fn covers_absolute_symlink_original_resolution() {
                    let temp = temp_dir("absolute-symlink");
                    fs::create_dir_all(&temp).unwrap();
                    let target = temp.join("target-launcher");
                    write_executable(&target, b"#!/bin/sh\nprintf target\n");
                    let launcher = temp.join("launcher");
                    std::os::unix::fs::symlink(&target, &launcher).unwrap();

                    assert_eq!(original_launcher_path(&launcher).unwrap(), target);

                    let _ = $wrap(&launcher).unwrap();

                    assert!(launcher_is_wrapped(&launcher).unwrap());
                    fs::remove_dir_all(temp).unwrap();
                }
            }
        }
    };
}

mod aws_cli_post_install {
    include!(radioisotope_source!("/aws-cli/post-install.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        fn temp_path(name: &str) -> PathBuf {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "{}-{name}-{suffix}",
                module_path!().replace("::", "_")
            ))
        }

        #[test]
        fn covers_post_install_and_patch_error_edges() {
            let root = temp_path("post-install-errors");
            let launcher = root.join("aws");
            let lib = root.join("lib");
            assert!(
                prefix_aws_launcher(&launcher, ENTRYPOINT_PREFIX)
                    .unwrap_err()
                    .contains("failed to read")
            );
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(&launcher, format!("{ENTRYPOINT_PREFIX}print('aws')\n")).unwrap();
            prefix_aws_launcher(&launcher, ENTRYPOINT_PREFIX).unwrap();
            assert_eq!(
                std::fs::read_to_string(&launcher).unwrap(),
                format!("{ENTRYPOINT_PREFIX}print('aws')\n")
            );

            assert!(
                patch_aws_plugin_loaders(&lib)
                    .unwrap_err()
                    .contains("failed to read")
            );
            std::fs::create_dir_all(&lib).unwrap();
            assert!(
                patch_aws_plugin_loaders(&lib)
                    .unwrap_err()
                    .contains("failed to find")
            );
            assert!(
                patch_aws_plugin_loader(&launcher)
                    .unwrap_err()
                    .contains("failed to patch")
            );
            assert!(
                patch_aws_plugin_loader_contents(
                    "def load_plugins():\n    _load_plugins(BUILTIN_PLUGINS, event_hooks)\n"
                )
                .unwrap_err()
                .contains("legacy external plugin")
            );

            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

launcher_post_install_extra_tests!(
    censys_post_install,
    "/censys/post-install.rs",
    wrap_censys_launcher,
    censys_wrapper_script
);
launcher_post_install_extra_tests!(
    fauna_shell_post_install,
    "/fauna-shell/post-install.rs",
    wrap_fauna_launcher,
    fauna_wrapper_script
);
launcher_post_install_extra_tests!(
    sslmate_post_install,
    "/sslmate/post-install.rs",
    wrap_sslmate_launcher,
    sslmate_wrapper_script
);
launcher_post_install_extra_tests!(
    phylum_cli_post_install,
    "/phylum-cli/post-install.rs",
    wrap_phylum_launcher,
    phylum_wrapper_script
);
launcher_post_install_extra_tests!(
    aliyun_cli_post_install,
    "/aliyun-cli/post-install.rs",
    wrap_aliyun_launcher,
    aliyun_wrapper_script
);
launcher_post_install_extra_tests!(
    ossutil_post_install,
    "/ossutil/post-install.rs",
    wrap_ossutil_launcher,
    ossutil_wrapper_script
);
launcher_post_install_extra_tests!(
    akamai_post_install,
    "/akamai/post-install.rs",
    wrap_akamai_launcher,
    akamai_wrapper_script
);
launcher_post_install_extra_tests!(
    algolia_post_install,
    "/algolia/post-install.rs",
    wrap_algolia_launcher,
    algolia_wrapper_script
);
launcher_post_install_extra_tests!(
    grafanactl_post_install,
    "/grafanactl/post-install.rs",
    wrap_grafanactl_launcher,
    grafanactl_wrapper_script
);
launcher_post_install_extra_tests!(
    minio_mc_post_install,
    "/minio-mc/post-install.rs",
    wrap_mc_launcher,
    mc_wrapper_script
);
launcher_post_install_extra_tests!(
    transifex_cli_post_install,
    "/transifex-cli/post-install.rs",
    wrap_transifex_launcher,
    transifex_wrapper_script
);
launcher_post_install_extra_tests!(
    jfrog_cli_post_install,
    "/jfrog-cli/post-install.rs",
    wrap_jfrog_launcher,
    jfrog_wrapper_script
);
launcher_post_install_extra_tests!(
    dropbox_uploader_post_install,
    "/dropbox-uploader/post-install.rs",
    wrap_dropbox_uploader_launcher,
    dropbox_uploader_wrapper_script
);
launcher_post_install_extra_tests!(
    snowflake_cli_post_install,
    "/snowflake-cli/post-install.rs",
    wrap_snow_launcher,
    snow_wrapper_script
);
launcher_post_install_extra_tests!(
    s3cmd_post_install,
    "/s3cmd/post-install.rs",
    wrap_s3cmd_launcher,
    s3cmd_wrapper_script
);
launcher_post_install_extra_tests!(
    netlify_cli_post_install,
    "/netlify-cli/post-install.rs",
    wrap_netlify_launcher,
    netlify_wrapper_script
);
launcher_post_install_extra_tests!(
    openstackclient_post_install,
    "/openstackclient/post-install.rs",
    wrap_openstack_launcher,
    openstack_wrapper_script
);
launcher_post_install_extra_tests!(
    twine_post_install,
    "/twine/post-install.rs",
    wrap_twine_launcher,
    twine_wrapper_script
);
launcher_post_install_extra_tests!(
    glab_post_install,
    "/glab/post-install.rs",
    wrap_glab_launcher,
    glab_wrapper_script
);
launcher_post_install_extra_tests!(
    qwen_code_post_install,
    "/qwen-code/post-install.rs",
    wrap_qwen_launcher,
    qwen_wrapper_script
);
launcher_post_install_extra_tests!(
    hcloud_post_install,
    "/hcloud/post-install.rs",
    wrap_hcloud_launcher,
    hcloud_wrapper_script
);
launcher_post_install_extra_tests!(
    argocd_post_install,
    "/argocd/post-install.rs",
    wrap_argocd_launcher,
    argocd_wrapper_script
);
launcher_post_install_extra_tests!(
    snyk_post_install,
    "/snyk/post-install.rs",
    wrap_snyk_launcher,
    snyk_wrapper_script
);
launcher_post_install_extra_tests!(
    maven_post_install,
    "/maven/post-install.rs",
    wrap_mvn_launcher,
    mvn_wrapper_script
);
launcher_post_install_extra_tests!(
    mkcert_post_install,
    "/mkcert/post-install.rs",
    wrap_mkcert_launcher,
    mkcert_wrapper_script
);
launcher_post_install_extra_tests!(
    rust_post_install,
    "/rust/post-install.rs",
    wrap_cargo_launcher,
    cargo_wrapper_script
);
launcher_post_install_extra_tests!(
    buf_post_install,
    "/buf/post-install.rs",
    wrap_buf_launcher,
    buf_wrapper_script
);
launcher_post_install_extra_tests!(
    composer_post_install,
    "/composer/post-install.rs",
    wrap_composer_launcher,
    composer_wrapper_script
);
launcher_post_install_extra_tests!(
    flyctl_post_install,
    "/flyctl/post-install.rs",
    wrap_flyctl_launcher,
    flyctl_wrapper_script
);
launcher_post_install_extra_tests!(
    huggingface_cli_post_install,
    "/huggingface-cli/post-install.rs",
    wrap_hf_launcher,
    hf_wrapper_script
);
launcher_post_install_extra_tests!(
    uaa_cli_post_install,
    "/uaa-cli/post-install.rs",
    wrap_uaa_launcher,
    uaa_wrapper_script
);
launcher_post_install_extra_tests!(
    vault_post_install,
    "/vault/post-install.rs",
    wrap_vault_launcher,
    vault_wrapper_script
);
launcher_post_install_extra_tests!(
    cloudsmith_cli_post_install,
    "/cloudsmith-cli/post-install.rs",
    wrap_cloudsmith_launcher,
    cloudsmith_wrapper_script
);
launcher_post_install_extra_tests!(
    terraform_post_install,
    "/terraform/post-install.rs",
    wrap_terraform_launcher,
    terraform_wrapper_script
);
launcher_post_install_extra_tests!(
    railway_post_install,
    "/railway/post-install.rs",
    wrap_railway_launcher,
    railway_wrapper_script
);
launcher_post_install_extra_tests!(
    gallery_dl_post_install,
    "/gallery-dl/post-install.rs",
    wrap_gallery_dl_launcher,
    gallery_dl_wrapper_script
);
launcher_post_install_extra_tests!(
    pulumi_post_install,
    "/pulumi/post-install.rs",
    wrap_pulumi_launcher,
    pulumi_wrapper_script
);
launcher_post_install_extra_tests!(
    ansible_post_install,
    "/ansible/post-install.rs",
    wrap_ansible_galaxy_launcher,
    ansible_galaxy_wrapper_script
);
launcher_post_install_extra_tests!(
    doctl_post_install,
    "/doctl/post-install.rs",
    wrap_doctl_launcher,
    doctl_wrapper_script
);
launcher_post_install_extra_tests!(
    soracom_cli_post_install,
    "/soracom-cli/post-install.rs",
    wrap_soracom_launcher,
    soracom_wrapper_script
);
launcher_post_install_extra_tests!(
    sentry_cli_post_install,
    "/sentry-cli/post-install.rs",
    wrap_sentry_launcher,
    sentry_wrapper_script
);
launcher_post_install_extra_tests!(
    goat_post_install,
    "/goat/post-install.rs",
    wrap_goat_launcher,
    goat_wrapper_script
);
launcher_post_install_extra_tests!(
    fastly_post_install,
    "/fastly/post-install.rs",
    wrap_fastly_launcher,
    fastly_wrapper_script
);
launcher_post_install_extra_tests!(
    astra_post_install,
    "/astra/post-install.rs",
    wrap_astra_launcher,
    astra_wrapper_script
);
launcher_post_install_extra_tests!(
    wsk_post_install,
    "/wsk/post-install.rs",
    wrap_wsk_launcher,
    wsk_wrapper_script
);
launcher_post_install_extra_tests!(
    travis_post_install,
    "/travis/post-install.rs",
    wrap_travis_launcher,
    travis_wrapper_script
);
launcher_post_install_extra_tests!(
    mariadb_post_install,
    "/mariadb/post-install.rs",
    wrap_mysql_launcher,
    mysql_wrapper_script,
    assert_missing_launcher_noops
);
launcher_post_install_extra_tests!(
    mysql_client_post_install,
    "/mysql-client/post-install.rs",
    wrap_mysql_launcher,
    mysql_wrapper_script,
    assert_missing_launcher_noops
);
launcher_post_install_extra_tests!(
    mysql_post_install,
    "/mysql/post-install.rs",
    wrap_mysql_launcher,
    mysql_wrapper_script,
    assert_missing_launcher_noops
);
launcher_post_install_extra_tests!(
    mysql_8_0_post_install,
    "/mysql@8.0/post-install.rs",
    wrap_mysql_launcher,
    mysql_wrapper_script,
    assert_missing_launcher_noops
);
launcher_post_install_extra_tests!(
    mysql_8_4_post_install,
    "/mysql@8.4/post-install.rs",
    wrap_mysql_launcher,
    mysql_wrapper_script,
    assert_missing_launcher_noops
);
launcher_post_install_extra_tests!(
    bitwarden_cli_post_install,
    "/bitwarden-cli/post-install.rs",
    wrap_bitwarden_launcher,
    bitwarden_wrapper_script
);
launcher_post_install_extra_tests!(
    mercurial_post_install,
    "/mercurial/post-install.rs",
    wrap_hg_launcher,
    hg_wrapper_script
);
launcher_post_install_extra_tests!(
    midnight_commander_post_install,
    "/midnight-commander/post-install.rs",
    wrap_mc_launcher,
    mc_wrapper_script
);
launcher_post_install_extra_tests!(
    acli_post_install,
    "/acli/post-install.rs",
    wrap_acli_launcher,
    acli_wrapper_script
);
launcher_post_install_extra_tests!(
    checkov_post_install,
    "/checkov/post-install.rs",
    wrap_checkov_launcher,
    checkov_wrapper_script
);
launcher_post_install_extra_tests!(
    graphite_post_install,
    "/graphite/post-install.rs",
    wrap_graphite_launcher,
    graphite_wrapper_script
);
launcher_post_install_extra_tests!(
    circleci_post_install,
    "/circleci/post-install.rs",
    wrap_circleci_launcher,
    circleci_wrapper_script
);
launcher_post_install_extra_tests!(
    mycli_post_install,
    "/mycli/post-install.rs",
    wrap_mycli_launcher,
    mycli_wrapper_script
);
launcher_post_install_extra_tests!(
    ordercli_post_install,
    "/ordercli/post-install.rs",
    wrap_ordercli_launcher,
    ordercli_wrapper_script
);
launcher_post_install_extra_tests!(
    talosctl_post_install,
    "/talosctl/post-install.rs",
    wrap_talosctl_launcher,
    talosctl_wrapper_script
);
launcher_post_install_extra_tests!(
    heroku_post_install,
    "/heroku/post-install.rs",
    wrap_heroku_launcher,
    heroku_wrapper_script
);
launcher_post_install_extra_tests!(
    sqlcmd_post_install,
    "/sqlcmd/post-install.rs",
    wrap_sqlcmd_launcher,
    sqlcmd_wrapper_script
);
launcher_post_install_extra_tests!(
    maestro_post_install,
    "/maestro/post-install.rs",
    wrap_maestro_launcher,
    maestro_wrapper_script
);
launcher_post_install_extra_tests!(
    oci_cli_post_install,
    "/oci-cli/post-install.rs",
    wrap_oci_launcher,
    oci_wrapper_script
);
launcher_post_install_extra_tests!(
    nuget_post_install,
    "/nuget/post-install.rs",
    wrap_nuget_launcher,
    nuget_wrapper_script
);
launcher_post_install_extra_tests!(
    ast_cli_post_install,
    "/ast-cli/post-install.rs",
    wrap_cx_launcher,
    cx_wrapper_script
);
launcher_post_install_extra_tests!(
    skopeo_post_install,
    "/skopeo/post-install.rs",
    wrap_skopeo_launcher,
    skopeo_wrapper_script
);
launcher_post_install_extra_tests!(
    civo_post_install,
    "/civo/post-install.rs",
    wrap_civo_launcher,
    civo_wrapper_script
);
launcher_post_install_extra_tests!(
    firebase_cli_post_install,
    "/firebase-cli/post-install.rs",
    wrap_firebase_launcher,
    firebase_wrapper_script
);
launcher_post_install_extra_tests!(
    gcli_post_install,
    "/gcli/post-install.rs",
    wrap_gcli_launcher,
    gcli_wrapper_script
);
launcher_post_install_extra_tests!(
    gotify_post_install,
    "/gotify/post-install.rs",
    wrap_gotify_launcher,
    gotify_wrapper_script
);
launcher_post_install_extra_tests!(
    gptcommit_post_install,
    "/gptcommit/post-install.rs",
    wrap_gptcommit_launcher,
    gptcommit_wrapper_script
);
launcher_post_install_extra_tests!(
    helm_post_install,
    "/helm/post-install.rs",
    wrap_helm_launcher,
    helm_wrapper_script
);
launcher_post_install_extra_tests!(
    k6_post_install,
    "/k6/post-install.rs",
    wrap_k6_launcher,
    k6_wrapper_script
);
launcher_post_install_extra_tests!(
    oxide_cli_post_install,
    "/oxide-cli/post-install.rs",
    wrap_oxide_launcher,
    oxide_wrapper_script
);
launcher_post_install_extra_tests!(
    runpodctl_post_install,
    "/runpodctl/post-install.rs",
    wrap_runpodctl_launcher,
    runpodctl_wrapper_script
);
launcher_post_install_extra_tests!(
    sbt_post_install,
    "/sbt/post-install.rs",
    wrap_sbt_launcher,
    sbt_wrapper_script
);
launcher_post_install_extra_tests!(
    shodan_post_install,
    "/shodan/post-install.rs",
    wrap_shodan_launcher,
    shodan_wrapper_script
);
launcher_post_install_extra_tests!(
    virustotal_cli_post_install,
    "/virustotal-cli/post-install.rs",
    wrap_vt_launcher,
    vt_wrapper_script
);
launcher_post_install_extra_tests!(
    vultr_post_install,
    "/vultr/post-install.rs",
    wrap_vultr_launcher,
    vultr_wrapper_script
);
launcher_post_install_extra_tests!(
    mcp_remote_post_install,
    "/mcp-remote/post-install.rs",
    wrap_mcp_remote_launcher,
    mcp_remote_wrapper_script
);
launcher_post_install_extra_tests!(
    todoist_cli_post_install,
    "/todoist-cli/post-install.rs",
    wrap_todoist_launcher,
    todoist_wrapper_script
);
launcher_post_install_extra_tests!(
    dcos_cli_post_install,
    "/dcos-cli/post-install.rs",
    wrap_dcos_launcher,
    dcos_wrapper_script
);
launcher_post_install_extra_tests!(
    plumber_post_install,
    "/plumber/post-install.rs",
    wrap_plumber_launcher,
    plumber_wrapper_script
);
two_stage_launcher_post_install_extra_tests!(
    imap_backup_post_install,
    "/imap-backup/post-install.rs",
    wrap_imap_backup_launcher,
    imap_backup_wrapper_script
);
launcher_post_install_extra_tests!(
    kubernetes_cli_post_install,
    "/kubernetes-cli/post-install.rs",
    wrap_kubectl_launcher,
    kubectl_wrapper_script
);
two_stage_launcher_post_install_extra_tests!(
    luarocks_post_install,
    "/luarocks/post-install.rs",
    wrap_luarocks_launcher,
    luarocks_wrapper_script
);
two_stage_launcher_post_install_extra_tests!(
    node_post_install,
    "/node/post-install.rs",
    wrap_npm_launcher,
    npm_wrapper_script
);
two_stage_launcher_post_install_extra_tests!(
    node_18_post_install,
    "/node@18/post-install.rs",
    wrap_npm_launcher,
    npm_wrapper_script
);
two_stage_launcher_post_install_extra_tests!(
    openhue_cli_post_install,
    "/openhue-cli/post-install.rs",
    wrap_openhue_launcher,
    openhue_wrapper_script
);
launcher_post_install_extra_tests!(
    opentofu_post_install,
    "/opentofu/post-install.rs",
    wrap_opentofu_launcher,
    opentofu_wrapper_script
);
two_stage_launcher_post_install_extra_tests!(
    pnpm_post_install,
    "/pnpm/post-install.rs",
    wrap_pnpm_launcher,
    pnpm_wrapper_script
);
launcher_post_install_extra_tests!(
    podman_post_install,
    "/podman/post-install.rs",
    wrap_podman_launcher,
    podman_wrapper_script
);
launcher_post_install_extra_tests!(
    rclone_post_install,
    "/rclone/post-install.rs",
    wrap_rclone_launcher,
    rclone_wrapper_script
);
launcher_post_install_extra_tests!(
    terraform_core_post_install,
    "/terraform-core/post-install.rs",
    wrap_terraform_launcher,
    terraform_wrapper_script
);
launcher_post_install_extra_tests!(
    uv_post_install,
    "/uv/post-install.rs",
    wrap_uv_launcher,
    uv_wrapper_script
);
launcher_post_install_extra_tests!(
    vagrant_post_install,
    "/vagrant/post-install.rs",
    wrap_vagrant_launcher,
    vagrant_wrapper_script
);
launcher_post_install_extra_tests!(
    wakatime_cli_post_install,
    "/wakatime-cli/post-install.rs",
    wrap_wakatime_launcher,
    wakatime_wrapper_script
);
