struct TestDir(std::path::PathBuf);
impl TestDir {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "e-navigator-connection-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
use super::*;

fn literal(value: &str) -> OtlpValueSource {
    OtlpValueSource::Literal {
        literal: value.into(),
    }
}
fn config() -> HttpExporterConfig {
    HttpExporterConfig {
        endpoint: "http://127.0.0.1:4318/v1/logs".into(),
        headers: Vec::new(),
        header_sources: BTreeMap::new(),
        auth: OtlpAuthConfig::None,
        tls: OtlpTlsConfig {
            allow_plaintext_auth: true,
            ..Default::default()
        },
        batch_size: 1,
        queue_capacity: 1,
        timeout_millis: 1000,
        max_retries: 0,
        tls_insecure_skip_verify: false,
    }
}
#[test]
fn bearer_basic_and_custom_headers_are_sensitive() {
    let mut cfg = config();
    cfg.auth = OtlpAuthConfig::Bearer {
        token: literal("abc_123-./+="),
    };
    cfg.header_sources
        .insert("X-Tenant".into(), literal("tenant"));
    let headers = Connection::new(&cfg).unwrap().headers().unwrap();
    assert_eq!(headers[AUTHORIZATION], "Bearer abc_123-./+=");
    assert_eq!(headers["x-tenant"], "tenant");
    assert!(headers.values().all(HeaderValue::is_sensitive));
    cfg.auth = OtlpAuthConfig::Basic {
        username: literal("user"),
        password: literal("pass:word"),
    };
    let headers = Connection::new(&cfg).unwrap().headers().unwrap();
    assert_eq!(
        headers[AUTHORIZATION],
        format!("Basic {}", STANDARD.encode("user:pass:word"))
    );
    assert!(headers[AUTHORIZATION].is_sensitive());
}
#[test]
fn rejects_invalid_bearer_and_basic_username_without_leaking_values() {
    for token in ["token with space", "token@value", "token\nvalue", ""] {
        let mut cfg = config();
        cfg.auth = OtlpAuthConfig::Bearer {
            token: literal(token),
        };
        assert!(Connection::new(&cfg).is_err());
    }
    let mut cfg = config();
    cfg.auth = OtlpAuthConfig::Basic {
        username: literal("bad:user"),
        password: literal("secret-password"),
    };
    let error = Connection::new(&cfg).unwrap_err();
    assert!(!format!("{error:?}").contains("secret-password"));
}
#[test]
fn file_values_are_bounded_utf8_and_trim_exactly_one_line_ending() {
    let dir = TestDir::new();
    let path = dir.path().join("value");
    let source = OtlpValueSource::File { file: path.clone() };
    assert!(read_value(&source).is_err());
    for bytes in [
        vec![],
        vec![0xff],
        vec![b'x'; 4099],
        b"one\ntwo".to_vec(),
        b"token\n\n".to_vec(),
        b"token\r".to_vec(),
        b"\n".to_vec(),
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(read_value(&source).is_err());
    }
    for bytes in [b"token".as_slice(), b"token\n", b"token\r\n"] {
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(read_value(&source).unwrap(), "token");
    }
    std::fs::write(&path, format!("{}\r\n", "x".repeat(4096))).unwrap();
    assert_eq!(read_value(&source).unwrap().len(), 4096);
    assert!(
        read_value(&OtlpValueSource::File {
            file: dir.path().to_path_buf()
        })
        .is_err()
    );
}
#[test]
fn token_file_rotation_uses_atomic_replacement_and_deletion_fails_closed() {
    let dir = TestDir::new();
    let path = dir.path().join("token");
    std::fs::write(&path, "old").unwrap();
    let mut cfg = config();
    cfg.auth = OtlpAuthConfig::Bearer {
        token: OtlpValueSource::File { file: path.clone() },
    };
    let connection = Connection::new(&cfg).unwrap();
    assert_eq!(connection.headers().unwrap()[AUTHORIZATION], "Bearer old");
    let replacement = dir.path().join("replacement");
    std::fs::write(&replacement, "new\n").unwrap();
    std::fs::rename(replacement, &path).unwrap();
    assert_eq!(connection.headers().unwrap()[AUTHORIZATION], "Bearer new");
    std::fs::remove_file(&path).unwrap();
    assert!(connection.headers().is_err());
}
#[test]
fn debug_redacts_raw_headers_resolved_sources_and_endpoint() {
    let mut cfg = config();
    cfg.endpoint = "https://private-host/v1/logs".into();
    cfg.headers
        .push(("X-Secret".into(), "private-value".into()));
    cfg.auth = OtlpAuthConfig::Bearer {
        token: literal("private-token"),
    };
    let connection = Connection::new(&cfg).unwrap();
    for debug in [format!("{cfg:?}"), format!("{connection:?}")] {
        for secret in ["private-host", "private-value", "private-token"] {
            assert!(!debug.contains(secret));
        }
    }
}
#[test]
fn combined_raw_and_source_headers_obey_budgets_and_duplicates() {
    let mut cfg = config();
    cfg.headers = (0..32).map(|i| (format!("raw-{i}"), "x".into())).collect();
    cfg.header_sources = (0..33)
        .map(|i| (format!("source-{i}"), literal("x")))
        .collect();
    assert!(Connection::new(&cfg).is_err());
    cfg.headers = (0..4)
        .map(|i| (format!("raw-{i}"), "x".repeat(4096)))
        .collect();
    cfg.header_sources = (0..4)
        .map(|i| (format!("source-{i}"), literal(&"x".repeat(4096))))
        .collect();
    assert!(Connection::new(&cfg).is_err());
    cfg.headers = vec![("X-Tenant".into(), "one".into())];
    cfg.header_sources = BTreeMap::from([("x-tenant".into(), literal("two"))]);
    assert!(Connection::new(&cfg).is_err());
}
#[test]
fn typed_auth_rejects_raw_authorization_during_configuration_validation() {
    let mut cfg = config();
    cfg.auth = OtlpAuthConfig::Bearer {
        token: literal("token"),
    };
    cfg.headers.push(("aUtHoRiZaTiOn".into(), "other".into()));
    assert!(cfg.validate().is_err());
}
#[test]
fn validates_tls_pairing_https_policy_and_credential_urls() {
    let mut cfg = config();
    cfg.tls.client_key_file = Some("key.pem".into());
    assert!(cfg.validate().is_err());
    cfg.tls = OtlpTlsConfig::default();
    cfg.auth = OtlpAuthConfig::Bearer {
        token: literal("token"),
    };
    assert!(cfg.validate().is_err());
    cfg.endpoint = "https://localhost/v1/logs".into();
    assert!(cfg.validate().is_ok());
    for endpoint in [
        "https://user:pass@localhost/v1/logs",
        "https://localhost/v1/logs#fragment",
    ] {
        cfg.endpoint = endpoint.into();
        assert!(cfg.validate().is_err());
    }
    cfg.endpoint = "http://localhost/v1/logs".into();
    cfg.auth = OtlpAuthConfig::None;
    cfg.tls.allow_plaintext_auth = true;
    cfg.tls.ca_file = Some("ca.pem".into());
    assert!(cfg.validate().is_err());
}
#[test]
fn environment_sources_fail_for_missing_values_and_snapshot_existing_values() {
    let mut cfg = config();
    cfg.header_sources.insert(
        "x-value".into(),
        OtlpValueSource::Env {
            env: "E_NAVIGATOR_TEST_MISSING_ENV_D6A4B8B7_553E_4143".into(),
        },
    );
    assert!(Connection::new(&cfg).is_err());
    if let Ok(path) = std::env::var("PATH") {
        cfg.header_sources.insert(
            "x-value".into(),
            OtlpValueSource::Env { env: "PATH".into() },
        );
        assert_eq!(
            Connection::new(&cfg).unwrap().headers().unwrap()["x-value"],
            path
        );
    }
}
#[test]
fn invalid_tls_files_fail_client_construction() {
    let dir = TestDir::new();
    let path = dir.path().join("invalid.pem");
    std::fs::write(&path, "not a certificate").unwrap();
    let mut cfg = config();
    cfg.endpoint = "https://localhost/v1/logs".into();
    cfg.tls.ca_file = Some(path.clone());
    assert!(client(&cfg).is_err());
    cfg.tls.ca_file = None;
    cfg.tls.client_certificate_file = Some(path.clone());
    cfg.tls.client_key_file = Some(path);
    assert!(client(&cfg).is_err());
}

#[test]
fn low_level_raw_headers_follow_reserved_and_cross_source_rules() {
    for name in [
        "Host",
        "Content-Type",
        "Transfer-Encoding",
        "Proxy-Authorization",
    ] {
        let mut cfg = config();
        cfg.headers.push((name.into(), "value".into()));
        assert!(cfg.validate().is_err());
    }
    let mut cfg = config();
    cfg.headers.push(("X-Tenant".into(), "raw".into()));
    cfg.header_sources
        .insert("x-tenant".into(), literal("source"));
    assert!(cfg.validate().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn fifo_sources_are_rejected_without_waiting_for_a_writer() {
    let dir = TestDir::new();
    let path = dir.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let source = OtlpValueSource::File { file: path.clone() };
    let handle = std::thread::spawn(move || {
        tx.send(read_value(&source).is_err()).unwrap();
    });
    let result = rx.recv_timeout(std::time::Duration::from_millis(200));
    if result.is_err() {
        // Unblock the broken implementation so the regression itself never hangs.
        let _writer = rustix::fs::open(
            &path,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let _ = rx.recv_timeout(std::time::Duration::from_secs(1));
    }
    handle.join().unwrap();
    assert_eq!(result, Ok(true), "a credential FIFO must fail immediately");
}
