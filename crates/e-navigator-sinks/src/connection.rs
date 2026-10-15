//! HTTP-boundary credentials and TLS. Files are read on the blocking pool at send time.
use std::{collections::BTreeMap, io::Read, path::Path};

use base64::{Engine, engine::general_purpose::STANDARD};
use e_navigator_core::{OtlpAuthConfig, OtlpTlsConfig, OtlpValueSource};
use reqwest::{
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
};

use crate::{ExporterError, HttpExporterConfig};

const MAX_VALUE: usize = 4096;
const MAX_HEADERS_BYTES: usize = 32768;
const MAX_PEM_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct PreparedConnection {
    pub(crate) config: HttpExporterConfig,
    pub(crate) client: Client,
    pub(crate) connection: Connection,
}
impl PreparedConnection {
    pub(crate) fn new(config: HttpExporterConfig) -> Result<Self, ExporterError> {
        config.validate()?;
        let connection = Connection::new(&config)?;
        let client = client(&config)?;
        Ok(Self {
            config,
            client,
            connection,
        })
    }
}

#[derive(Clone)]
pub(crate) struct Connection {
    headers: BTreeMap<String, OtlpValueSource>,
    auth: OtlpAuthConfig,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Connection([REDACTED])")
    }
}

impl Connection {
    pub(crate) fn new(config: &HttpExporterConfig) -> Result<Self, ExporterError> {
        let mut headers = config.header_sources.clone();
        for (name, value) in &config.headers {
            if headers.keys().any(|key| key.eq_ignore_ascii_case(name)) {
                return Err(invalid("duplicate HTTP header"));
            }
            headers.insert(
                name.clone(),
                OtlpValueSource::Literal {
                    literal: value.clone(),
                },
            );
        }
        for value in headers.values_mut() {
            snapshot_env(value)?;
        }
        let mut auth = config.auth.clone();
        match &mut auth {
            OtlpAuthConfig::None => {}
            OtlpAuthConfig::Bearer { token } => snapshot_env(token)?,
            OtlpAuthConfig::Basic { username, password } => {
                snapshot_env(username)?;
                snapshot_env(password)?;
            }
        }
        let connection = Self { headers, auth };
        // Fail construction before workers start if any active source is unavailable.
        connection.headers()?;
        Ok(connection)
    }

    pub(crate) fn headers(&self) -> Result<HeaderMap, ExporterError> {
        let mut headers = HeaderMap::new();
        let mut total = 0usize;
        for (name, source) in &self.headers {
            let value = read_value(source)?;
            insert(&mut headers, name, &value, &mut total)?;
        }
        match &self.auth {
            OtlpAuthConfig::None => {}
            OtlpAuthConfig::Bearer { token } => {
                let token = read_value(token)?;
                if !token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
                {
                    return Err(invalid("invalid bearer credential"));
                }
                insert(
                    &mut headers,
                    AUTHORIZATION.as_str(),
                    &format!("Bearer {token}"),
                    &mut total,
                )?;
            }
            OtlpAuthConfig::Basic { username, password } => {
                let username = read_value(username)?;
                let password = read_value(password)?;
                if username.contains(':') {
                    return Err(invalid("invalid Basic username"));
                }
                let encoded = STANDARD.encode(format!("{username}:{password}"));
                insert(
                    &mut headers,
                    AUTHORIZATION.as_str(),
                    &format!("Basic {encoded}"),
                    &mut total,
                )?;
            }
        }
        Ok(headers)
    }
}

fn invalid(message: &'static str) -> ExporterError {
    ExporterError::InvalidConfig(message)
}

fn snapshot_env(source: &mut OtlpValueSource) -> Result<(), ExporterError> {
    if let OtlpValueSource::Env { env } = source {
        let value = std::env::var(env.as_str())
            .map_err(|_| invalid("HTTP credential environment source unavailable"))?;
        *source = OtlpValueSource::Literal { literal: value };
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ExporterError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    let file = options
        .open(path)
        .map_err(|_| invalid("HTTP connection file unavailable"))?;
    if !file
        .metadata()
        .map_err(|_| invalid("HTTP connection file unavailable"))?
        .is_file()
    {
        return Err(invalid("HTTP connection source must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("HTTP connection file unreadable"))?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(invalid("HTTP connection file size invalid"));
    }
    Ok(bytes)
}

fn read_value(source: &OtlpValueSource) -> Result<String, ExporterError> {
    let value = match source {
        OtlpValueSource::Literal { literal } => literal.clone(),
        OtlpValueSource::Env { .. } => return Err(invalid("HTTP environment source not resolved")),
        OtlpValueSource::File { file } => {
            let bytes = read_bounded(file, MAX_VALUE + 2)?;
            let mut value = String::from_utf8(bytes)
                .map_err(|_| invalid("HTTP connection value must be UTF-8"))?;
            // Accommodate secret files produced by echo, without silently trimming credentials.
            if value.ends_with('\n') {
                value.pop();
                if value.ends_with('\r') {
                    value.pop();
                }
            }
            value
        }
    };
    if value.is_empty() || value.len() > MAX_VALUE || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(invalid(
            "HTTP connection value is empty, oversized or contains controls",
        ));
    }
    Ok(value)
}

fn insert(
    map: &mut HeaderMap,
    name: &str,
    value: &str,
    total: &mut usize,
) -> Result<(), ExporterError> {
    let name =
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid("invalid HTTP header name"))?;
    let mut value =
        HeaderValue::from_str(value).map_err(|_| invalid("invalid HTTP header value"))?;
    if value.len() > MAX_VALUE {
        return Err(invalid("HTTP header value exceeds limit"));
    }
    *total = total
        .saturating_add(name.as_str().len())
        .saturating_add(value.len());
    if *total > MAX_HEADERS_BYTES || map.len() >= 64 {
        return Err(invalid("HTTP headers exceed budget"));
    }
    value.set_sensitive(true);
    if map.insert(name, value).is_some() {
        return Err(invalid("duplicate HTTP header"));
    }
    Ok(())
}

pub(crate) fn client(config: &HttpExporterConfig) -> Result<Client, ExporterError> {
    let tls = &config.tls;
    let mut builder = Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(
            tls.insecure_skip_verify
                .unwrap_or(config.tls_insecure_skip_verify),
        );
    if let Some(path) = &tls.ca_file {
        let pem = read_bounded(path, MAX_PEM_BYTES)?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|_| invalid("invalid HTTP CA certificate"))?;
        if certificates.is_empty() {
            return Err(invalid("empty HTTP CA certificate bundle"));
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    if let (Some(cert), Some(key)) = (&tls.client_certificate_file, &tls.client_key_file) {
        let mut pem = read_bounded(cert, MAX_PEM_BYTES)?;
        pem.push(b'\n');
        pem.extend(read_bounded(key, MAX_PEM_BYTES)?);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|_| invalid("invalid HTTP client identity"))?;
        builder = builder.identity(identity);
    }
    builder
        .build()
        .map_err(|_| invalid("cannot build HTTP connection"))
}

pub(crate) fn validate(config: &HttpExporterConfig) -> Result<(), ExporterError> {
    // Reuse core boundary rules for callers of the public low-level exporter too.
    let mut headers = config.header_sources.clone();
    for (name, value) in &config.headers {
        if headers.keys().any(|key| key.eq_ignore_ascii_case(name)) {
            return Err(invalid("duplicate HTTP header"));
        }
        headers.insert(
            name.clone(),
            OtlpValueSource::Literal {
                literal: value.clone(),
            },
        );
    }
    let core = e_navigator_core::OtlpHttpConfig {
        logs_enabled: true,
        metrics_enabled: false,
        traces_enabled: false,
        profiles_enabled: false,
        logs_auth: config.auth.clone(),
        logs_headers: headers,
        logs_tls: config.tls.clone(),
        ..Default::default()
    };
    core.validate_connections()
        .map_err(|_| invalid("invalid HTTP connection configuration"))?;
    let url =
        reqwest::Url::parse(&config.endpoint).map_err(|_| invalid("invalid HTTP endpoint"))?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(invalid(
            "HTTP endpoint must not contain credentials or a fragment",
        ));
    }
    let has_headers = !config.headers.is_empty()
        || !config.header_sources.is_empty()
        || !matches!(config.auth, OtlpAuthConfig::None);
    if has_headers && url.scheme() != "https" && !config.tls.allow_plaintext_auth {
        return Err(invalid(
            "HTTP credentials and headers require HTTPS or explicit allow_plaintext_auth",
        ));
    }
    let OtlpTlsConfig {
        ca_file,
        client_certificate_file,
        client_key_file,
        ..
    } = &config.tls;
    if url.scheme() != "https"
        && (ca_file.is_some() || client_certificate_file.is_some() || client_key_file.is_some())
    {
        return Err(invalid("HTTP TLS files require an HTTPS endpoint"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
