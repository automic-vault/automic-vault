#![allow(dead_code)]

use std::cell::RefCell;
use std::ffi::OsString;

macro_rules! radioisotope_source {
    ($path:literal) => {
        concat!(env!("AUTOMIC_VAULT_GENERATED_RADIOISOTOPES_REPO"), $path)
    };
}

mod isotope {
    use std::collections::BTreeMap;
    use std::path::Path;

    #[derive(Debug)]
    pub(crate) struct CredentialHelperCallerContext {
        pub(crate) token: Option<String>,
        pub(crate) parent_executable_path: Option<String>,
        pub(crate) parent_command: Option<String>,
    }

    pub(crate) struct CredentialHelperInvocation<'a> {
        pub(crate) args: Vec<std::ffi::OsString>,
        pub(crate) caller: CredentialHelperCallerContext,
        pub(crate) store: &'a dyn CredentialHelperSecretStore,
    }

    pub(crate) trait CredentialHelperSecretStore {
        fn load_secret(&self, key: &str) -> Result<String, String>;
        fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
            Err("credential helper store is read-only".to_string())
        }
    }

    pub(crate) fn load_credentials(
        store: &dyn CredentialHelperSecretStore,
        keys: &[String],
    ) -> Result<BTreeMap<String, String>, String> {
        keys.iter()
            .map(|key| store.load_secret(key).map(|value| (key.clone(), value)))
            .collect()
    }

    pub(crate) fn zeroize_credentials(credentials: &mut BTreeMap<String, String>) {
        for value in credentials.values_mut() {
            value.clear();
        }
    }

    pub(crate) fn validate_root_controlled_path(path: &Path) -> Result<(), String> {
        if path.as_os_str().is_empty() {
            Err("empty helper parent path".to_string())
        } else {
            Ok(())
        }
    }
}

macro_rules! docker_extra_tests {
    ($label:literal, $launcher:literal, $original:literal) => {
        #[cfg(test)]
        mod av_extra_tests {
            use super::*;
            use std::ffi::OsString;
            use std::io;

            #[cfg(unix)]
            use std::os::unix::ffi::OsStringExt;

            struct ErrorStore;

            impl crate::isotope::CredentialHelperSecretStore for ErrorStore {
                fn load_secret(&self, _key: &str) -> Result<String, String> {
                    Err("permission denied".to_string())
                }

                fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
                    Err("write denied".to_string())
                }
            }

            #[test]
            fn covers_invocation_validation_and_arg_edges() {
                let store = crate::MemoryStore::default();
                credential_helper(crate::invocation(&["--help"], Some("/tmp/unused"), &store))
                    .unwrap();
                credential_helper(crate::invocation(&["--version"], Some("/tmp/unused"), &store))
                    .unwrap();

                assert!(parse_docker_helper_args(&[OsString::from("get"), OsString::from("extra")])
                    .unwrap_err()
                    .contains("one verb"));

                #[cfg(unix)]
                assert!(parse_docker_helper_args(&[OsString::from_vec(vec![0xff])])
                    .unwrap_err()
                    .contains("valid UTF-8"));

                let missing_token = crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("list")],
                    caller: crate::isotope::CredentialHelperCallerContext {
                        token: None,
                        parent_executable_path: Some($launcher.to_string()),
                        parent_command: None,
                    },
                    store: &store,
                };
                assert!(validate_caller_context(&missing_token)
                    .unwrap_err()
                    .contains("approval token"));

                let short_token = crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("list")],
                    caller: crate::isotope::CredentialHelperCallerContext {
                        token: Some("short".to_string()),
                        parent_executable_path: Some($original.to_string()),
                        parent_command: None,
                    },
                    store: &store,
                };
                assert!(validate_caller_context(&short_token)
                    .unwrap_err()
                    .contains("invalid"));
            }

            #[test]
            fn covers_auth_json_errors_and_docker_shapes() {
                assert!(credential_store_miss("not found in store"));
                assert!(credential_store_miss("missing stub credential"));
                assert!(!credential_store_miss("permission denied"));

                assert_eq!(
                    load_auth_root_or_empty(&crate::MemoryStore::default()).unwrap(),
                    serde_json::json!({ "auths": {} })
                );
                assert!(load_auth_root(&crate::MemoryStore::with("not json"))
                    .unwrap_err()
                    .contains("decode"));
                assert!(load_auth_root_or_empty(&ErrorStore)
                    .unwrap_err()
                    .contains("permission denied"));

                let empty = crate::MemoryStore::with(r#"{"auths":{}}"#);
                assert!(registry_credentials(&empty, "")
                    .unwrap_err()
                    .contains("empty"));
                assert!(registry_credentials(&empty, "missing.example")
                    .unwrap_err()
                    .contains("not found"));

                let hub = crate::MemoryStore::with(
                    r#"{"auths":{"https://index.docker.io/v1/":{"username":"hubuser","password":"hubpass"},"capital.example":{"identityToken":"cap-token"},"invalid.example":{"auth":"???"},"no-colon.example":{"auth":"bm9jb2xvbg=="}}}"#,
                );
                assert!(registry_credentials(&hub, "docker.io")
                    .unwrap()
                    .contains("hubpass"));
                assert!(registry_credentials(&hub, "registry-1.docker.io")
                    .unwrap()
                    .contains("hubuser"));
                assert!(registry_credentials(&hub, "capital.example")
                    .unwrap()
                    .contains("cap-token"));
                assert!(registry_credentials(&hub, "invalid.example").is_err());
                assert!(registry_credentials(&hub, "no-colon.example").is_err());

                assert!(store_registry_credentials(&crate::MemoryStore::with("[]"), r#"{"ServerURL":"s","Username":"u","Secret":"p"}"#)
                    .unwrap_err()
                    .contains("auth root"));
                assert!(store_registry_credentials(&crate::MemoryStore::with(r#"{"auths":[]}"#), r#"{"ServerURL":"s","Username":"u","Secret":"p"}"#)
                    .unwrap_err()
                    .contains("auths field"));
                assert!(store_registry_credentials(&crate::MemoryStore::default(), "not json")
                    .unwrap_err()
                    .contains("decode"));
                assert!(store_registry_credentials(&crate::MemoryStore::default(), r#"{"Username":"u","Secret":"p"}"#)
                    .unwrap_err()
                    .contains("ServerURL"));
                assert!(store_registry_credentials(&crate::MemoryStore::default(), r#"{"ServerURL":"s","Secret":"p"}"#)
                    .unwrap_err()
                    .contains("Username"));
                assert!(store_registry_credentials(&crate::MemoryStore::default(), r#"{"ServerURL":"s","Username":"u"}"#)
                    .unwrap_err()
                    .contains("Secret"));

                let token_store = crate::MemoryStore::default();
                store_registry_credentials(
                    &token_store,
                    r#"{"ServerURL":"token.example","Username":"<token>","Secret":"tok"}"#,
                )
                .unwrap();
                assert!(token_store
                    .value
                    .borrow()
                    .as_deref()
                    .unwrap()
                    .contains("identitytoken"));

                assert!(erase_registry_credentials(&crate::MemoryStore::default(), "")
                    .unwrap_err()
                    .contains("empty"));
                let erase_store = crate::MemoryStore::with(
                    r#"{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcjpwYXNz"},"other.example":{"auth":"dXNlcjpwYXNz"}}}"#,
                );
                erase_registry_credentials(&erase_store, "docker.io").unwrap();
                let erased = erase_store.value.borrow().clone().unwrap();
                assert!(!erased.contains("index.docker.io"));
                assert!(erased.contains("other.example"));

                let list_store = crate::MemoryStore::with(
                    r#"{"auths":{"text":"value","bad":{"auth":"!!!"},"good":{"username":"u","password":"p"}}}"#,
                );
                assert_eq!(list_registry_credentials(&list_store).unwrap(), r#"{"good":"u"}"#);

                assert_eq!(base64_encode(b"u"), "dQ==");
                assert_eq!(base64_encode(b"us"), "dXM=");
                assert_eq!(base64_decode("d X N l c g ==").unwrap(), b"user");
                assert!(base64_decode("!!!").is_err());

                let _ = io::ErrorKind::Other;
            }
        }
    };
}

mod podman_helper {
    include!(radioisotope_source!("/podman/credential-helper.rs"));

    docker_extra_tests!(
        "podman",
        "/opt/podman/bin/podman",
        "/opt/podman/bin/podman.av-orig"
    );
}

mod skopeo_helper {
    include!(radioisotope_source!("/skopeo/credential-helper.rs"));

    docker_extra_tests!(
        "skopeo",
        "/opt/skopeo/bin/skopeo",
        "/opt/skopeo/bin/skopeo.av-orig"
    );
}

mod aws_cli_helper {
    include!(radioisotope_source!("/aws-cli/credential-helper.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::path::Path;

        struct MissingSecretStore;

        impl crate::isotope::CredentialHelperSecretStore for MissingSecretStore {
            fn load_secret(&self, key: &str) -> Result<String, String> {
                if key == AWS_ACCESS_KEY_ID_ENV_KEY {
                    Ok("AKIAEXAMPLE".to_string())
                } else {
                    Err(format!("missing {key}"))
                }
            }
        }

        fn caller() -> crate::isotope::CredentialHelperCallerContext {
            crate::isotope::CredentialHelperCallerContext {
                token: Some("x".repeat(MIN_CREDENTIAL_HELPER_TOKEN_LEN)),
                parent_executable_path: Some(AWS_CLI_PYTHON_PATH.to_string()),
                parent_command: Some(format!(
                    "{AWS_CLI_PYTHON_PATH} {AWS_CLI_PYTHON_ISOLATED_FLAG} {AWS_CLI_LAUNCHER_PATH} sts get-caller-identity"
                )),
            }
        }

        #[test]
        fn covers_top_level_dispatch_and_validation_errors() {
            let store = MissingSecretStore;
            credential_helper_with_validator(
                crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("--help")],
                    caller: caller(),
                    store: &store,
                },
                |_| Ok(()),
            )
            .unwrap();
            credential_helper_with_validator(
                crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("--version")],
                    caller: caller(),
                    store: &store,
                },
                |_| Ok(()),
            )
            .unwrap();
            assert!(
                credential_helper_with_validator(
                    crate::isotope::CredentialHelperInvocation {
                        args: vec![OsString::from("extra")],
                        caller: caller(),
                        store: &store,
                    },
                    |_| Ok(()),
                )
                .unwrap_err()
                .contains("does not accept arguments")
            );
            assert!(
                credential_helper_with_validator(
                    crate::isotope::CredentialHelperInvocation {
                        args: Vec::new(),
                        caller: caller(),
                        store: &store,
                    },
                    |path: &Path| Err(format!("untrusted {}", path.display())),
                )
                .unwrap_err()
                .contains("untrusted")
            );
            assert!(
                credential_helper_with_validator(
                    crate::isotope::CredentialHelperInvocation {
                        args: Vec::new(),
                        caller: caller(),
                        store: &store,
                    },
                    |_| Ok(()),
                )
                .unwrap_err()
                .contains(AWS_SECRET_ACCESS_KEY_ENV_KEY)
            );
        }
    }
}

mod kubernetes_cli_helper {
    include!(radioisotope_source!("/kubernetes-cli/credential-helper.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::ffi::OsString;

        #[cfg(unix)]
        use std::os::unix::ffi::OsStringExt;

        struct ErrorStore;

        impl crate::isotope::CredentialHelperSecretStore for ErrorStore {
            fn load_secret(&self, _key: &str) -> Result<String, String> {
                Err("kube store denied".to_string())
            }
        }

        #[test]
        fn covers_validation_json_and_response_edges() {
            assert!(is_kubectl_parent_executable(
                "/opt/kubernetes-cli/bin/kubectl"
            ));
            assert!(is_kubectl_parent_executable(
                "/opt/kubernetes-cli/bin/kubectl.av-orig"
            ));
            assert!(!is_kubectl_parent_executable("/tmp/kubectl"));

            assert!(
                parse_kubernetes_helper_args(&[])
                    .unwrap_err()
                    .contains("expects one")
            );
            assert!(
                parse_kubernetes_helper_args(&[OsString::from("   ")])
                    .unwrap_err()
                    .contains("empty")
            );
            #[cfg(unix)]
            assert!(
                parse_kubernetes_helper_args(&[OsString::from_vec(vec![0xff])])
                    .unwrap_err()
                    .contains("valid UTF-8")
            );

            assert!(
                validate_caller_context(&crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("dev")],
                    caller: crate::isotope::CredentialHelperCallerContext {
                        token: Some("short".to_string()),
                        parent_executable_path: Some("/opt/kubernetes-cli/bin/kubectl".to_string()),
                        parent_command: None,
                    },
                    store: &crate::MemoryStore::default(),
                })
                .unwrap_err()
                .contains("invalid")
            );
            assert!(
                validate_caller_context(&crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("dev")],
                    caller: crate::isotope::CredentialHelperCallerContext {
                        token: Some("x".repeat(32)),
                        parent_executable_path: Some("/tmp/not-kubectl".to_string()),
                        parent_command: None,
                    },
                    store: &crate::MemoryStore::default(),
                })
                .unwrap_err()
                .contains("kubectl")
            );

            assert!(
                kubernetes_credential_for_user(&ErrorStore, "dev")
                    .unwrap_err()
                    .contains("kube store denied")
            );
            assert!(
                kubernetes_credential_for_user(&crate::MemoryStore::with("not json"), "dev")
                    .unwrap_err()
                    .contains("decode")
            );
            assert!(
                kubernetes_credential_for_user(&crate::MemoryStore::with(r#"{"users":{}}"#), "dev")
                    .unwrap_err()
                    .contains("missing users")
            );
            assert!(
                kubernetes_credential_for_user(
                    &crate::MemoryStore::with(r#"{"users":[{"name":"other"}]}"#),
                    "dev"
                )
                .unwrap_err()
                .contains("not found")
            );
            let certificate = KubernetesCredential {
                token: None,
                client_certificate_data: Some("cert".to_string()),
                client_key_data: Some("key".to_string()),
            };
            let response = exec_credential_json(&certificate).unwrap();
            assert!(response.contains("clientCertificateData"));
        }
    }
}

mod nuget_helper {
    include!(radioisotope_source!("/nuget/credential-helper.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::ffi::OsString;

        #[cfg(unix)]
        use std::os::unix::ffi::OsStringExt;

        struct ErrorStore;

        impl crate::isotope::CredentialHelperSecretStore for ErrorStore {
            fn load_secret(&self, _key: &str) -> Result<String, String> {
                Err("nuget store denied".to_string())
            }
        }

        #[test]
        fn covers_uri_validation_store_and_match_edges() {
            assert_eq!(
                parse_nuget_provider_uri(&[
                    OsString::from("-Uri"),
                    OsString::from("https://example.test/index.json")
                ])
                .unwrap(),
                Some("https://example.test/index.json".to_string())
            );
            assert_eq!(
                parse_nuget_provider_uri(&[OsString::from("-Uri:https://example.test/")]).unwrap(),
                Some("https://example.test/".to_string())
            );
            assert_eq!(
                parse_nuget_provider_uri(&[OsString::from("-Uri"), OsString::from("   ")]).unwrap(),
                None
            );
            assert!(
                parse_nuget_provider_uri(&[OsString::from("-Uri")])
                    .unwrap_err()
                    .contains("missing a value")
            );
            #[cfg(unix)]
            assert!(
                parse_nuget_provider_uri(&[OsString::from_vec(vec![0xff])])
                    .unwrap_err()
                    .contains("valid UTF-8")
            );
            assert!(is_nuget_parent_executable("/opt/nuget/bin/nuget"));
            assert!(is_nuget_parent_executable("/opt/nuget/bin/nuget.av-orig"));
            assert!(!is_nuget_parent_executable("/tmp/nuget"));
            assert!(credential_store_miss("not found in store"));
            assert!(credential_store_miss("missing stub credential"));
            assert!(!credential_store_miss("permission denied"));
            assert_eq!(
                normalize_uri("HTTPS://EXAMPLE.TEST/"),
                "https://example.test"
            );

            assert!(
                validate_caller_context(&crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("-Uri"), OsString::from("source")],
                    caller: crate::isotope::CredentialHelperCallerContext {
                        token: None,
                        parent_executable_path: Some("/opt/nuget/bin/nuget".to_string()),
                        parent_command: None,
                    },
                    store: &crate::MemoryStore::default(),
                })
                .unwrap_err()
                .contains("approval token")
            );
            assert!(
                validate_caller_context(&crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("-Uri"), OsString::from("source")],
                    caller: crate::isotope::CredentialHelperCallerContext {
                        token: Some("x".repeat(32)),
                        parent_executable_path: Some("/tmp/not-nuget".to_string()),
                        parent_command: None,
                    },
                    store: &crate::MemoryStore::default(),
                })
                .unwrap_err()
                .contains("NuGet launcher")
            );

            assert_eq!(
                nuget_credentials_for_uri(&crate::MemoryStore::default(), "source").unwrap(),
                None
            );
            assert!(
                nuget_credentials_for_uri(&ErrorStore, "source")
                    .unwrap_err()
                    .contains("nuget store denied")
            );
            assert!(
                nuget_credentials_for_uri(&crate::MemoryStore::with("not json"), "source")
                    .unwrap_err()
                    .contains("decode")
            );
            assert_eq!(
                nuget_credentials_for_uri(&crate::MemoryStore::with(r#"{"sources":{}}"#), "source")
                    .unwrap(),
                None
            );
            assert_eq!(
                nuget_credentials_for_uri(
                    &crate::MemoryStore::with(
                        r#"{"sources":[{"name":"source","username":"u"},{"uri":"https://example.test/","password":"p"}]}"#
                    ),
                    "source"
                )
                .unwrap(),
                None
            );
        }
    }
}

mod terraform_helper {
    include!(radioisotope_source!("/terraform/credential-helper.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::ffi::OsString;

        #[cfg(unix)]
        use std::os::unix::ffi::OsStringExt;

        struct ErrorStore;
        struct WriteErrorStore;

        impl crate::isotope::CredentialHelperSecretStore for ErrorStore {
            fn load_secret(&self, _key: &str) -> Result<String, String> {
                Err("terraform store denied".to_string())
            }
        }

        impl crate::isotope::CredentialHelperSecretStore for WriteErrorStore {
            fn load_secret(&self, _key: &str) -> Result<String, String> {
                Err("missing stub credential".to_string())
            }

            fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
                Err("terraform write denied".to_string())
            }
        }

        #[test]
        fn covers_parse_validation_and_store_shape_edges() {
            assert!(is_terraform_parent_executable(
                "/opt/terraform/bin/terraform"
            ));
            assert!(is_terraform_parent_executable(
                "/opt/terraform/bin/terraform.av-orig"
            ));
            assert!(!is_terraform_parent_executable("/tmp/terraform"));
            assert!(
                parse_terraform_helper_args(&[])
                    .unwrap_err()
                    .contains("<verb> <hostname>")
            );
            assert!(
                parse_terraform_helper_args(&[OsString::from("get"), OsString::from(" ")])
                    .unwrap_err()
                    .contains("empty")
            );
            #[cfg(unix)]
            assert!(
                parse_terraform_helper_args(&[OsString::from_vec(vec![0xff]), OsString::from("h")])
                    .unwrap_err()
                    .contains("valid UTF-8")
            );
            assert!(
                validate_caller_context(&crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("get"), OsString::from("host")],
                    caller: crate::isotope::CredentialHelperCallerContext {
                        token: Some("short".to_string()),
                        parent_executable_path: Some("/opt/terraform/bin/terraform".to_string()),
                        parent_command: None,
                    },
                    store: &crate::MemoryStore::default(),
                })
                .unwrap_err()
                .contains("invalid")
            );
            assert!(
                load_terraform_credentials_root(&ErrorStore)
                    .unwrap_err()
                    .contains("terraform store denied")
            );
            assert!(
                load_terraform_credentials_root(&crate::MemoryStore::with("not json"))
                    .unwrap_err()
                    .contains("decode")
            );
            assert!(
                store_terraform_credentials_for_host(
                    &crate::MemoryStore::with("[]"),
                    "host",
                    r#"{"token":"secret"}"#
                )
                .unwrap_err()
                .contains("root must be a JSON object")
            );
            assert!(
                store_terraform_credentials_for_host(
                    &crate::MemoryStore::with(r#"{"credentials":[]}"#),
                    "host",
                    r#"{"token":"secret"}"#
                )
                .unwrap_err()
                .contains("field must be a JSON object")
            );
            assert!(
                store_terraform_credentials_for_host(
                    &WriteErrorStore,
                    "host",
                    r#"{"token":"secret"}"#
                )
                .unwrap_err()
                .contains("terraform write denied")
            );
        }
    }
}

mod opentofu_helper {
    include!(radioisotope_source!("/opentofu/credential-helper.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::ffi::OsString;

        struct ErrorStore;
        struct WriteErrorStore;

        impl crate::isotope::CredentialHelperSecretStore for ErrorStore {
            fn load_secret(&self, _key: &str) -> Result<String, String> {
                Err("opentofu store denied".to_string())
            }
        }

        impl crate::isotope::CredentialHelperSecretStore for WriteErrorStore {
            fn load_secret(&self, _key: &str) -> Result<String, String> {
                Err("missing stub credential".to_string())
            }

            fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
                Err("opentofu write denied".to_string())
            }
        }

        #[test]
        fn covers_parse_validation_and_store_shape_edges() {
            assert!(is_opentofu_parent_executable("/opt/opentofu/bin/tofu"));
            assert!(is_opentofu_parent_executable(
                "/opt/opentofu/bin/tofu.av-orig"
            ));
            assert!(!is_opentofu_parent_executable("/tmp/tofu"));
            assert!(
                parse_opentofu_helper_args(&[])
                    .unwrap_err()
                    .contains("<verb> <hostname>")
            );
            assert!(
                parse_opentofu_helper_args(&[OsString::from("get"), OsString::from(" ")])
                    .unwrap_err()
                    .contains("empty")
            );
            assert!(
                validate_caller_context(&crate::isotope::CredentialHelperInvocation {
                    args: vec![OsString::from("get"), OsString::from("host")],
                    caller: crate::isotope::CredentialHelperCallerContext {
                        token: Some("short".to_string()),
                        parent_executable_path: Some("/opt/opentofu/bin/tofu".to_string()),
                        parent_command: None,
                    },
                    store: &crate::MemoryStore::default(),
                })
                .unwrap_err()
                .contains("invalid")
            );
            assert!(
                load_opentofu_credentials_root(&ErrorStore)
                    .unwrap_err()
                    .contains("opentofu store denied")
            );
            assert!(
                load_opentofu_credentials_root(&crate::MemoryStore::with("not json"))
                    .unwrap_err()
                    .contains("decode")
            );
            assert!(
                store_opentofu_credentials_for_host(
                    &crate::MemoryStore::with("[]"),
                    "host",
                    r#"{"token":"secret"}"#
                )
                .unwrap_err()
                .contains("root must be a JSON object")
            );
            assert!(
                store_opentofu_credentials_for_host(
                    &crate::MemoryStore::with(r#"{"credentials":[]}"#),
                    "host",
                    r#"{"token":"secret"}"#
                )
                .unwrap_err()
                .contains("field must be a JSON object")
            );
            assert!(
                store_opentofu_credentials_for_host(
                    &WriteErrorStore,
                    "host",
                    r#"{"token":"secret"}"#
                )
                .unwrap_err()
                .contains("opentofu write denied")
            );
        }
    }
}

mod cargo_helper {
    include!(radioisotope_source!("/rust/credential-helper.rs"));

    #[cfg(test)]
    mod av_extra_tests {
        use super::*;
        use std::ffi::OsString;
        use std::io::{self, Write};

        struct ErrorStore;

        impl crate::isotope::CredentialHelperSecretStore for ErrorStore {
            fn load_secret(&self, _key: &str) -> Result<String, String> {
                Err("load denied".to_string())
            }

            fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
                Err("store denied".to_string())
            }
        }

        fn cargo_request(kind: &str) -> serde_json::Value {
            serde_json::json!({
                "v": 1,
                "kind": kind,
                "registry": {
                    "index-url": "sparse+https://index.crates.io/",
                    "name": "crates-io"
                }
            })
        }

        #[test]
        fn covers_cargo_response_edges() {
            let store = crate::MemoryStore::with("cargo-token");

            let mut name_only = cargo_request("get");
            name_only["registry"] = serde_json::json!({ "name": "crates-io" });
            assert_eq!(
                cargo_credential_response(&store, &name_only)["Ok"]["token"],
                serde_json::json!("cargo-token")
            );

            assert_eq!(
                cargo_credential_response(&store, &serde_json::json!({ "v": 2 })),
                serde_json::json!({ "Err": { "kind": "operation-not-supported" } })
            );
            assert_eq!(
                cargo_credential_response(&store, &serde_json::json!({ "v": 1, "kind": "get" })),
                serde_json::json!({ "Err": { "kind": "url-not-supported" } })
            );
            assert_eq!(
                cargo_credential_response(
                    &store,
                    &serde_json::json!({ "v": 1, "kind": "get", "registry": { "name": "custom" } })
                ),
                serde_json::json!({ "Err": { "kind": "url-not-supported" } })
            );
            assert_eq!(
                cargo_credential_response(&store, &cargo_request("publish")),
                serde_json::json!({ "Err": { "kind": "operation-not-supported" } })
            );
            assert!(
                cargo_credential_response(&store, &cargo_request("login"))["Err"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("did not provide")
            );
            assert_eq!(
                cargo_credential_response(&crate::MemoryStore::with("   "), &cargo_request("get")),
                serde_json::json!({ "Err": { "kind": "not-found" } })
            );
            assert!(
                cargo_credential_response(&ErrorStore, &cargo_request("get"))["Err"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("load denied")
            );

            let mut login = cargo_request("login");
            login["token"] = serde_json::json!("new-token");
            assert!(
                cargo_credential_response(&ErrorStore, &login)["Err"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("store denied")
            );
            assert!(
                cargo_credential_response(&ErrorStore, &cargo_request("logout"))["Err"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("store denied")
            );
        }

        #[test]
        fn covers_cargo_validation_and_writer_edges() {
            let store = crate::MemoryStore::default();
            let missing_token = crate::isotope::CredentialHelperInvocation {
                args: vec![OsString::from("--cargo-plugin")],
                caller: crate::isotope::CredentialHelperCallerContext {
                    token: None,
                    parent_executable_path: Some("/opt/rust/bin/cargo.av-orig".to_string()),
                    parent_command: None,
                },
                store: &store,
            };
            assert!(
                validate_caller_context(&missing_token)
                    .unwrap_err()
                    .contains("approval token")
            );
            assert!(is_cargo_parent_executable("/opt/rust/bin/cargo.av-orig"));
            assert!(!is_cargo_parent_executable("/tmp/cargo"));

            let mut output = Vec::new();
            write_cargo_response(
                &mut output,
                &serde_json::json!({ "Ok": { "kind": "logout" } }),
            )
            .unwrap();
            assert!(String::from_utf8(output).unwrap().ends_with('\n'));

            struct FailAlways;
            impl Write for FailAlways {
                fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                    Err(io::Error::other("encode failed"))
                }

                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            assert!(
                write_cargo_response(&mut FailAlways, &serde_json::json!({ "Ok": {} }))
                    .unwrap_err()
                    .contains("encode")
            );

            struct FailNewline;
            impl Write for FailNewline {
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    if buf == b"\n" {
                        Err(io::Error::other("newline failed"))
                    } else {
                        Ok(buf.len())
                    }
                }

                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            assert!(
                write_cargo_response(&mut FailNewline, &serde_json::json!({ "Ok": {} }))
                    .unwrap_err()
                    .contains("write")
            );

            assert!(request_is_crates_io(&serde_json::json!({
                "registry": { "index-url": "https://github.com/rust-lang/crates.io-index" }
            })));
            assert!(!request_is_crates_io(&serde_json::json!({
                "registry": { "index-url": "https://example.test/index" }
            })));
            assert!(!request_is_crates_io(
                &serde_json::json!({ "registry": [] })
            ));
            assert!(credential_store_miss("not found in store"));
            assert!(credential_store_miss("missing stub credential"));
            assert!(!credential_store_miss("permission denied"));
            assert_eq!(
                load_cargo_token(&crate::MemoryStore::default()).unwrap(),
                None
            );
            assert_eq!(
                cargo_err("custom"),
                serde_json::json!({ "Err": { "kind": "custom" } })
            );
            assert_eq!(
                cargo_other_err("message"),
                serde_json::json!({ "Err": { "kind": "other", "message": "message" } })
            );
        }
    }
}

mod wakatime_cli_helper {
    include!(radioisotope_source!("/wakatime-cli/credential-helper.rs"));
}

#[derive(Default)]
struct MemoryStore {
    value: RefCell<Option<String>>,
}

impl MemoryStore {
    fn with(value: &str) -> Self {
        Self {
            value: RefCell::new(Some(value.to_string())),
        }
    }
}

impl isotope::CredentialHelperSecretStore for MemoryStore {
    fn load_secret(&self, _key: &str) -> Result<String, String> {
        self.value
            .borrow()
            .clone()
            .ok_or_else(|| "missing stub credential".to_string())
    }

    fn store_secret(&self, _key: &str, value: &str) -> Result<(), String> {
        self.value.replace(Some(value.to_string()));
        Ok(())
    }
}

fn invocation<'a>(
    args: &[&str],
    parent_executable_path: Option<&str>,
    store: &'a MemoryStore,
) -> isotope::CredentialHelperInvocation<'a> {
    isotope::CredentialHelperInvocation {
        args: args.iter().map(OsString::from).collect(),
        caller: isotope::CredentialHelperCallerContext {
            token: Some("x".repeat(32)),
            parent_executable_path: parent_executable_path.map(str::to_string),
            parent_command: None,
        },
        store,
    }
}

fn assert_token_and_parent_validation(
    helper_name: &str,
    helper: fn(isotope::CredentialHelperInvocation<'_>) -> Result<(), String>,
    valid_args: &[&str],
    valid_parent: &str,
) {
    let store = MemoryStore::default();
    let missing_parent = helper(invocation(valid_args, None, &store)).unwrap_err();
    assert!(
        missing_parent.to_ascii_lowercase().contains("parent"),
        "{helper_name} should reject missing parent, got {missing_parent}"
    );

    let wrong_parent = helper(invocation(valid_args, Some("/tmp/not-launcher"), &store))
        .unwrap_err()
        .to_ascii_lowercase();
    assert!(
        wrong_parent.contains("launcher") || wrong_parent.contains(helper_name),
        "{helper_name} should reject wrong parent, got {wrong_parent}"
    );

    let parse_error = helper(invocation(&[], Some(valid_parent), &store)).unwrap_err();
    assert!(
        parse_error.contains("expects") || parse_error.contains("--cargo-plugin"),
        "{helper_name} should reject malformed helper args, got {parse_error}"
    );
}

#[test]
fn docker_credential_helpers_cover_public_protocol_branches() {
    let auth = r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"},"docker.io":{"identitytoken":"tok"}}}"#;

    let podman_store = MemoryStore::with(auth);
    podman_helper::credential_helper(invocation(
        &["list"],
        Some("/opt/podman/bin/podman"),
        &podman_store,
    ))
    .unwrap();
    let podman_error = podman_helper::credential_helper(invocation(
        &["bogus"],
        Some("/opt/podman/bin/podman.av-orig"),
        &podman_store,
    ))
    .unwrap_err();
    assert!(podman_error.contains("unsupported Docker credentials helper verb"));
    assert_token_and_parent_validation(
        "podman",
        podman_helper::credential_helper,
        &["list"],
        "/opt/podman/bin/podman",
    );

    let skopeo_store = MemoryStore::with(auth);
    skopeo_helper::credential_helper(invocation(
        &["list"],
        Some("/opt/skopeo/bin/skopeo"),
        &skopeo_store,
    ))
    .unwrap();
    let skopeo_error = skopeo_helper::credential_helper(invocation(
        &["bogus"],
        Some("/opt/skopeo/bin/skopeo.av-orig"),
        &skopeo_store,
    ))
    .unwrap_err();
    assert!(skopeo_error.contains("unsupported Docker credentials helper verb"));
    assert_token_and_parent_validation(
        "skopeo",
        skopeo_helper::credential_helper,
        &["list"],
        "/opt/skopeo/bin/skopeo",
    );
}

#[test]
fn terraform_style_helpers_cover_get_forget_and_errors() {
    let terraform_store = MemoryStore::with(
        r#"{"credentials":{"app.terraform.io":{"token":"tf-secret"},"other.example":{}}}"#,
    );
    terraform_helper::credential_helper(invocation(
        &["get", "app.terraform.io"],
        Some("/opt/terraform/bin/terraform"),
        &terraform_store,
    ))
    .unwrap();
    terraform_helper::credential_helper(invocation(
        &["forget", "app.terraform.io"],
        Some("/opt/terraform/bin/terraform.av-orig"),
        &terraform_store,
    ))
    .unwrap();
    let terraform_error = terraform_helper::credential_helper(invocation(
        &["bogus", "app.terraform.io"],
        Some("/opt/terraform/bin/terraform"),
        &terraform_store,
    ))
    .unwrap_err();
    assert!(terraform_error.contains("unsupported Terraform credentials helper verb"));
    assert_token_and_parent_validation(
        "terraform",
        terraform_helper::credential_helper,
        &["get", "app.terraform.io"],
        "/opt/terraform/bin/terraform",
    );

    let opentofu_store = MemoryStore::with(
        r#"{"credentials":{"app.terraform.io":{"token":"tofu-secret"},"other.example":{}}}"#,
    );
    opentofu_helper::credential_helper(invocation(
        &["get", "app.terraform.io"],
        Some("/opt/opentofu/bin/tofu"),
        &opentofu_store,
    ))
    .unwrap();
    opentofu_helper::credential_helper(invocation(
        &["forget", "app.terraform.io"],
        Some("/opt/opentofu/bin/tofu.av-orig"),
        &opentofu_store,
    ))
    .unwrap();
    let opentofu_error = opentofu_helper::credential_helper(invocation(
        &["bogus", "app.terraform.io"],
        Some("/opt/opentofu/bin/tofu"),
        &opentofu_store,
    ))
    .unwrap_err();
    assert!(opentofu_error.contains("unsupported OpenTofu credentials helper verb"));
    assert_token_and_parent_validation(
        "opentofu",
        opentofu_helper::credential_helper,
        &["get", "app.terraform.io"],
        "/opt/opentofu/bin/tofu",
    );
}

#[test]
fn cargo_helper_covers_public_validation_after_parent_checks() {
    let store = MemoryStore::with("cargo-secret");
    cargo_helper::credential_helper(invocation(&["--help"], Some("/tmp/not-used"), &store))
        .unwrap();
    cargo_helper::credential_helper(invocation(&["--version"], Some("/tmp/not-used"), &store))
        .unwrap();

    let err = cargo_helper::credential_helper(invocation(
        &["not-plugin"],
        Some("/opt/rust/bin/cargo"),
        &store,
    ))
    .unwrap_err();
    assert!(err.contains("--cargo-plugin"));

    assert_token_and_parent_validation(
        "cargo",
        cargo_helper::credential_helper,
        &["--cargo-plugin"],
        "/opt/rust/bin/cargo",
    );

    let short_token = isotope::CredentialHelperInvocation {
        args: vec![OsString::from("--cargo-plugin")],
        caller: isotope::CredentialHelperCallerContext {
            token: Some("short".to_string()),
            parent_executable_path: Some("/opt/rust/bin/cargo".to_string()),
            parent_command: None,
        },
        store: &store,
    };
    assert!(
        cargo_helper::credential_helper(short_token)
            .unwrap_err()
            .contains("invalid Cargo credential provider approval token")
    );
}
