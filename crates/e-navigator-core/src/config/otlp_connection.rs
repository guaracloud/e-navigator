use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};

/// A value resolved only at the export boundary. Diagnostics always redact its contents.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum OtlpValueSource {
    Literal { literal: String },
    Env { env: String },
    File { file: PathBuf },
}
impl fmt::Debug for OtlpValueSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtlpValueSource([REDACTED])")
    }
}
impl Serialize for OtlpValueSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        let selector = match self {
            Self::Literal { .. } => "literal",
            Self::Env { .. } => "env",
            Self::File { .. } => "file",
        };
        map.serialize_entry(selector, "[REDACTED]")?;
        map.end()
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OtlpAuthConfig {
    #[default]
    None,
    Bearer {
        token: OtlpValueSource,
    },
    Basic {
        username: OtlpValueSource,
        password: OtlpValueSource,
    },
}
impl<'de> Deserialize<'de> for OtlpAuthConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            None {},
            Bearer {
                token: OtlpValueSource,
            },
            Basic {
                username: OtlpValueSource,
                password: OtlpValueSource,
            },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::None {} => Self::None,
            Wire::Bearer { token } => Self::Bearer { token },
            Wire::Basic { username, password } => Self::Basic { username, password },
        })
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OtlpTlsConfig {
    pub ca_file: Option<PathBuf>,
    pub client_certificate_file: Option<PathBuf>,
    pub client_key_file: Option<PathBuf>,
    pub insecure_skip_verify: Option<bool>,
    pub allow_plaintext_auth: bool,
}

impl OtlpValueSource {
    fn validate(&self) -> Result<(), String> {
        let valid = match self {
            Self::Literal { literal } => {
                !literal.is_empty()
                    && literal.len() <= 4096
                    && !literal.bytes().any(|b| b.is_ascii_control())
            }
            Self::Env { env } => {
                !env.is_empty()
                    && env.len() <= 128
                    && env.bytes().enumerate().all(|(i, b)| {
                        b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                    })
            }
            Self::File { file } => valid_path(file),
        };
        if valid {
            Ok(())
        } else {
            Err("invalid OTLP value source".into())
        }
    }
}
fn valid_path(path: &std::path::Path) -> bool {
    !path.as_os_str().is_empty()
        && path.as_os_str().len() <= 4096
        && !path
            .as_os_str()
            .to_string_lossy()
            .chars()
            .any(char::is_control)
}
pub(super) fn validate_connection(
    auth: &OtlpAuthConfig,
    headers: &BTreeMap<String, OtlpValueSource>,
    tls: &OtlpTlsConfig,
) -> Result<(), String> {
    if headers.len() > 64 {
        return Err("too many OTLP headers".into());
    }
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || !seen.insert(name.clone())
        {
            return Err("invalid or duplicate OTLP header name".into());
        }
        if matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "content-type"
                | "content-encoding"
                | "proxy-authorization"
                | "upgrade"
                | "trailer"
                | "te"
                | "keep-alive"
        ) {
            return Err("reserved OTLP header".into());
        }
        if name == "authorization" && !matches!(auth, OtlpAuthConfig::None) {
            return Err("OTLP authorization header conflicts with authentication".into());
        }
        value.validate()?;
        total += name.len()
            + match value {
                OtlpValueSource::Literal { literal } => literal.len(),
                _ => 0,
            };
    }
    if total > 32768 {
        return Err("OTLP headers exceed total byte limit".into());
    }
    match auth {
        OtlpAuthConfig::None => {}
        OtlpAuthConfig::Bearer { token } => token.validate()?,
        OtlpAuthConfig::Basic { username, password } => {
            username.validate()?;
            password.validate()?;
        }
    }
    if tls.client_certificate_file.is_some() != tls.client_key_file.is_some()
        || [
            &tls.ca_file,
            &tls.client_certificate_file,
            &tls.client_key_file,
        ]
        .into_iter()
        .flatten()
        .any(|p| !valid_path(p))
    {
        return Err("OTLP TLS requires valid paths and paired client certificate and key".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selectors_are_exclusive_and_strict() {
        for text in [
            "literal = 'x'\nenv = 'TOKEN'",
            "literal = 'x'\nextra = true",
            "",
        ] {
            assert!(toml::from_str::<OtlpValueSource>(text).is_err());
        }
        assert!(toml::from_str::<OtlpValueSource>("file = '/secret'").is_ok());
    }
    #[test]
    fn diagnostics_and_serialization_redact_sources() {
        for value in [
            OtlpValueSource::Literal {
                literal: "private-value".into(),
            },
            OtlpValueSource::Env {
                env: "private-value".into(),
            },
            OtlpValueSource::File {
                file: "private-value".into(),
            },
        ] {
            assert!(!format!("{value:?}").contains("private-value"));
            assert!(!toml::to_string(&value).unwrap().contains("private-value"));
        }
    }
    #[test]
    fn headers_reject_duplicates_reserved_and_auth_conflicts() {
        let literal = || OtlpValueSource::Literal {
            literal: "value".into(),
        };
        for name in ["Host", "content-type", "bad name", "é", ""] {
            assert!(
                validate_connection(
                    &OtlpAuthConfig::None,
                    &BTreeMap::from([(name.into(), literal())]),
                    &OtlpTlsConfig::default()
                )
                .is_err()
            );
        }
        let mut headers =
            BTreeMap::from([("X-Test".into(), literal()), ("x-test".into(), literal())]);
        assert!(
            validate_connection(&OtlpAuthConfig::None, &headers, &OtlpTlsConfig::default())
                .is_err()
        );
        headers = BTreeMap::from([("Authorization".into(), literal())]);
        assert!(
            validate_connection(
                &OtlpAuthConfig::Bearer { token: literal() },
                &headers,
                &OtlpTlsConfig::default()
            )
            .is_err()
        );
    }
    #[test]
    fn validates_sources_limits_and_tls_pairs() {
        for value in [
            OtlpValueSource::Literal { literal: "".into() },
            OtlpValueSource::Literal {
                literal: "x\r\ny".into(),
            },
            OtlpValueSource::Env {
                env: "1TOKEN".into(),
            },
            OtlpValueSource::File { file: "".into() },
        ] {
            assert!(value.validate().is_err());
        }
        let headers = (0..65)
            .map(|i| {
                (
                    format!("x-{i}"),
                    OtlpValueSource::Literal {
                        literal: "x".into(),
                    },
                )
            })
            .collect();
        assert!(
            validate_connection(&OtlpAuthConfig::None, &headers, &OtlpTlsConfig::default())
                .is_err()
        );
        let tls = OtlpTlsConfig {
            client_key_file: Some("key.pem".into()),
            ..Default::default()
        };
        assert!(validate_connection(&OtlpAuthConfig::None, &BTreeMap::new(), &tls).is_err());
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use crate::OtlpHttpConfig;
    #[test]
    fn validates_enabled_families_only_and_preserves_defaults() {
        let mut config = OtlpHttpConfig {
            logs_auth: OtlpAuthConfig::Bearer {
                token: OtlpValueSource::Env { env: "".into() },
            },
            ..Default::default()
        };
        assert!(config.validate_connections().is_ok());
        config.logs_enabled = true;
        assert!(config.validate_connections().is_err());
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;
    #[test]
    fn valid_auth_and_tls_deserialize_and_unknown_fields_fail() {
        let bearer: OtlpAuthConfig =
            toml::from_str("type = 'bearer'\ntoken = { env = 'TOKEN' }").unwrap();
        assert!(matches!(bearer, OtlpAuthConfig::Bearer { .. }));
        let basic: OtlpAuthConfig = toml::from_str(
            "type = 'basic'\nusername = { literal = 'user' }\npassword = { file = '/run/secret' }",
        )
        .unwrap();
        assert!(validate_connection(&basic, &BTreeMap::new(), &OtlpTlsConfig::default()).is_ok());
        for text in [
            "type = 'bearer'",
            "type = 'none'\ntoken = { env = 'TOKEN' }",
            "type = 'bearer'\ntoken = { env = 'TOKEN' }\nextra = true",
        ] {
            assert!(toml::from_str::<OtlpAuthConfig>(text).is_err());
        }
        assert!(toml::from_str::<OtlpTlsConfig>("extra = true").is_err());
        let tls = OtlpTlsConfig {
            ca_file: Some("ca.pem".into()),
            client_certificate_file: Some("cert.pem".into()),
            client_key_file: Some("key.pem".into()),
            ..Default::default()
        };
        assert!(validate_connection(&basic, &BTreeMap::new(), &tls).is_ok());
    }
    #[test]
    fn enforces_literal_header_and_total_limits() {
        let source = |size| OtlpValueSource::Literal {
            literal: "x".repeat(size),
        };
        assert!(source(4096).validate().is_ok());
        assert!(source(4097).validate().is_err());
        let test = |headers| {
            validate_connection(&OtlpAuthConfig::None, &headers, &OtlpTlsConfig::default())
        };
        assert!(test(BTreeMap::from([("x".repeat(128), source(1))])).is_ok());
        assert!(test(BTreeMap::from([("x".repeat(129), source(1))])).is_err());
        assert!(test((0..64).map(|i| (format!("x-{i}"), source(1))).collect()).is_ok());
        assert!(test((0..8).map(|i| (format!("x-{i}"), source(4096))).collect()).is_err());
    }
    #[test]
    fn additive_settings_parse_without_changing_existing_defaults() {
        let config: crate::OtlpHttpConfig = toml::from_str("endpoint = 'https://example.com/v1/traces'\n[logs_auth]\ntype = 'bearer'\ntoken = { file = '/run/token' }\n[logs_headers]\nX-Tenant = { literal = 'tenant-a' }\n[logs_tls]\nca_file = '/run/ca.pem'").unwrap();
        assert_eq!(config.endpoint, "https://example.com/v1/traces");
        assert!(!config.logs_enabled);
        assert_eq!(config.logs_headers.len(), 1);
        assert_eq!(config.traces_auth, OtlpAuthConfig::None);
        assert!(config.validate_connections().is_ok());
    }
}
