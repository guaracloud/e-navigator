use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

const MAX_KAFKA_TAGS: usize = 16;
const MAX_VARINT_BYTES: usize = 5;
const MAX_KAFKA_RESPONSE_ENTRIES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKafkaRequest {
    pub protocol: ProtocolKind,
    pub operation: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKafkaResponse {
    pub protocol: ProtocolKind,
    pub operation: String,
    pub status_code: String,
    pub error_type: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KafkaExtraction {
    FrameTooLong,
    InvalidUtf8,
    MalformedFrame,
    ClientIdTooLong,
    UnsupportedApiKey,
    UnsupportedApiVersion,
}

pub fn parse_kafka_request(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaRequest, KafkaExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let header = request_header(body, config.max_request_line_bytes)?;
    validate_request_body(body, &header, config)?;
    let operation = api_key_name(header.api_key)
        .ok_or(KafkaExtraction::UnsupportedApiKey)?
        .to_string();
    let api_key = header.api_key.to_string();
    let api_version = header.api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some(&operation),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some(&api_key),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.client_id_present",
        header.client_id_present.then_some("true"),
    );

    Ok(ParsedKafkaRequest {
        protocol: ProtocolKind::Kafka,
        operation: Some(operation),
        warning: None,
        attributes,
    })
}

pub fn parse_kafka_api_versions_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = api_versions_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_key = "18";
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("api_versions"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some(api_key),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "api_versions".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_create_topics_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(2..=4).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = create_topics_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("create_topics"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("19"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "create_topics".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_create_partitions_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = create_partitions_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("create_partitions"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("37"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "create_partitions".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_create_acls_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = create_acls_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("create_acls"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("30"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "create_acls".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_describe_acls_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = describe_acls_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("describe_acls"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("29"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "describe_acls".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_delete_acls_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = delete_acls_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("delete_acls"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("31"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "delete_acls".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_describe_configs_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(1..=3).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = describe_configs_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("describe_configs"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("32"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "describe_configs".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_alter_configs_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = alter_configs_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("alter_configs"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("33"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "alter_configs".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_alter_replica_log_dirs_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = alter_replica_log_dirs_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("alter_replica_log_dirs"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("34"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "alter_replica_log_dirs".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_describe_log_dirs_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = describe_log_dirs_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("describe_log_dirs"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("35"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "describe_log_dirs".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_create_delegation_token_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = create_delegation_token_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("create_delegation_token"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("38"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "create_delegation_token".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_renew_delegation_token_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = renew_delegation_token_response_error_code(body)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("renew_delegation_token"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("39"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "renew_delegation_token".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_expire_delegation_token_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = expire_delegation_token_response_error_code(body)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("expire_delegation_token"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("40"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "expire_delegation_token".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_describe_delegation_token_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = describe_delegation_token_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("describe_delegation_token"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("41"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "describe_delegation_token".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_elect_leaders_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = elect_leaders_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("elect_leaders"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("43"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "elect_leaders".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_incremental_alter_configs_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = incremental_alter_configs_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("incremental_alter_configs"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("44"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "incremental_alter_configs".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_alter_partition_reassignments_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = alter_partition_reassignments_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("alter_partition_reassignments"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("45"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "alter_partition_reassignments".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_list_partition_reassignments_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = list_partition_reassignments_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("list_partition_reassignments"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("46"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "list_partition_reassignments".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_produce_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=7).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = produce_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("produce"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("0"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "produce".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_fetch_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=5).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = fetch_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("fetch"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("1"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "fetch".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_list_offsets_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(1..=5).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = list_offsets_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("list_offsets"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("2"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "list_offsets".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_delete_records_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = delete_records_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("delete_records"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("21"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "delete_records".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_delete_topics_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(1..=3).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = delete_topics_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("delete_topics"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("20"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "delete_topics".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_join_group_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=5).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = join_group_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("join_group"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("11"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "join_group".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_find_coordinator_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=2).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = find_coordinator_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("find_coordinator"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("10"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "find_coordinator".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_heartbeat_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=3).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = heartbeat_response_error_code(body, api_version)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("heartbeat"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("12"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "heartbeat".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_leave_group_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=3).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = leave_group_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("leave_group"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("13"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "leave_group".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_sync_group_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=3).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = sync_group_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("sync_group"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("14"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "sync_group".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_describe_groups_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=4).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = describe_groups_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("describe_groups"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("15"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "describe_groups".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_delete_groups_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = delete_groups_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("delete_groups"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("42"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "delete_groups".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_sasl_handshake_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = sasl_handshake_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("sasl_handshake"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("17"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "sasl_handshake".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_init_producer_id_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = init_producer_id_response_error_code(body)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("init_producer_id"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("22"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "init_producer_id".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_add_partitions_to_txn_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=2).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = add_partitions_to_txn_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("add_partitions_to_txn"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("24"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "add_partitions_to_txn".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_add_offsets_to_txn_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=2).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = throttled_response_error_code(body)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("add_offsets_to_txn"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("25"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "add_offsets_to_txn".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_end_txn_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=2).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = throttled_response_error_code(body)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("end_txn"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("26"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "end_txn".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_txn_offset_commit_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=2).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = txn_offset_commit_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("txn_offset_commit"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("28"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "txn_offset_commit".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_write_txn_markers_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(1..=2).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = write_txn_markers_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("write_txn_markers"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("27"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "write_txn_markers".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_sasl_authenticate_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = sasl_authenticate_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("sasl_authenticate"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("36"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "sasl_authenticate".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_offset_commit_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(2..=7).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = offset_commit_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("offset_commit"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("8"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "offset_commit".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_offset_fetch_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(1..=5).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = offset_fetch_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("offset_fetch"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("9"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "offset_fetch".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_offset_delete_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = offset_delete_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("offset_delete"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("47"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "offset_delete".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_describe_client_quotas_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = describe_client_quotas_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("describe_client_quotas"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("48"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "describe_client_quotas".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_alter_client_quotas_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=1).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = alter_client_quotas_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("alter_client_quotas"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("49"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "alter_client_quotas".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_describe_user_scram_credentials_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = describe_user_scram_credentials_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("describe_user_scram_credentials"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("50"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "describe_user_scram_credentials".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_alter_user_scram_credentials_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if api_version != 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = alter_user_scram_credentials_response_error_code(body, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("alter_user_scram_credentials"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("51"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "alter_user_scram_credentials".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_describe_quorum_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=2).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = describe_quorum_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("describe_quorum"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("55"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "describe_quorum".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_update_features_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=2).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = update_features_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("update_features"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("57"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "update_features".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_list_groups_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=3).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = list_groups_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("list_groups"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("16"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "list_groups".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

pub fn parse_kafka_metadata_response(
    bytes: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedKafkaResponse, KafkaExtraction> {
    if !(0..=8).contains(&api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if bytes.len() > config.max_header_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    let body = frame_body(bytes, config.max_header_bytes)?;
    let error_code = metadata_response_error_code(body, api_version, config)?;
    let status_code = error_code.to_string();
    let error_type = (error_code != 0).then(|| status_code.clone());
    let api_version = api_version.to_string();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("kafka"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        Some("metadata"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_key",
        Some("3"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.api_version",
        Some(&api_version),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.kafka.response.error_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedKafkaResponse {
        protocol: ProtocolKind::Kafka,
        operation: "metadata".to_string(),
        status_code,
        error_type,
        attributes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KafkaRequestHeader {
    api_key: i16,
    api_version: i16,
    client_id_present: bool,
    body_start: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KafkaClientId {
    present: bool,
    cursor: usize,
}

fn frame_body(bytes: &[u8], max_frame_bytes: usize) -> Result<&[u8], KafkaExtraction> {
    if bytes.len() < 4 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let message_len = read_i32_be(bytes, 0)? as isize;
    if message_len <= 0 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let message_len = message_len as usize;
    let total_len = message_len
        .checked_add(4)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    if total_len > max_frame_bytes {
        return Err(KafkaExtraction::FrameTooLong);
    }
    if bytes.len() < total_len {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(&bytes[4..total_len])
}

fn request_header(
    body: &[u8],
    max_client_id_bytes: usize,
) -> Result<KafkaRequestHeader, KafkaExtraction> {
    if body.len() < 8 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let api_key = read_i16_be(body, 0)?;
    let api_version = read_i16_be(body, 2)?;
    let _correlation_id = read_i32_be(body, 4)?;
    let client = parse_client_id(body, 8, max_client_id_bytes)?;
    Ok(KafkaRequestHeader {
        api_key,
        api_version,
        client_id_present: client.present,
        body_start: client.cursor,
    })
}

fn validate_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    match header.api_key {
        0 => validate_produce_request_body(body, header, config),
        1 => validate_fetch_request_body(body, header, config),
        2 => validate_list_offsets_request_body(body, header, config),
        3 => validate_metadata_request_body(body, header, config),
        8 => validate_offset_commit_request_body(body, header, config),
        9 => validate_offset_fetch_request_body(body, header, config),
        10 => validate_find_coordinator_request_body(body, header, config),
        11 => validate_join_group_request_body(body, header, config),
        12 => validate_heartbeat_request_body(body, header, config),
        13 => validate_leave_group_request_body(body, header, config),
        14 => validate_sync_group_request_body(body, header, config),
        15 => validate_describe_groups_request_body(body, header, config),
        16 => validate_empty_request_body(body, header),
        17 => validate_sasl_handshake_request_body(body, header, config),
        18 => validate_api_versions_request_body(body, header, config),
        19 => validate_create_topics_request_body(body, header, config),
        20 => validate_delete_topics_request_body(body, header, config),
        21 => validate_delete_records_request_body(body, header, config),
        22 => validate_init_producer_id_request_body(body, header, config),
        24 => validate_add_partitions_to_txn_request_body(body, header, config),
        25 => validate_add_offsets_to_txn_request_body(body, header, config),
        26 => validate_end_txn_request_body(body, header, config),
        27 => validate_write_txn_markers_request_body(body, header, config),
        28 => validate_txn_offset_commit_request_body(body, header, config),
        29 => validate_describe_acls_request_body(body, header, config),
        30 => validate_create_acls_request_body(body, header, config),
        31 => validate_delete_acls_request_body(body, header, config),
        32 => validate_describe_configs_request_body(body, header, config),
        33 => validate_alter_configs_request_body(body, header, config),
        34 => validate_alter_replica_log_dirs_request_body(body, header, config),
        35 => validate_describe_log_dirs_request_body(body, header, config),
        36 => validate_sasl_authenticate_request_body(body, header, config),
        37 => validate_create_partitions_request_body(body, header, config),
        38 => validate_create_delegation_token_request_body(body, header, config),
        39 => validate_renew_delegation_token_request_body(body, header, config),
        40 => validate_expire_delegation_token_request_body(body, header, config),
        41 => validate_describe_delegation_token_request_body(body, header, config),
        42 => validate_delete_groups_request_body(body, header, config),
        43 => validate_elect_leaders_request_body(body, header, config),
        44 => validate_incremental_alter_configs_request_body(body, header, config),
        45 => validate_alter_partition_reassignments_request_body(body, header, config),
        46 => validate_list_partition_reassignments_request_body(body, header, config),
        47 => validate_offset_delete_request_body(body, header, config),
        48 => validate_describe_client_quotas_request_body(body, header, config),
        49 => validate_alter_client_quotas_request_body(body, header, config),
        50 => validate_describe_user_scram_credentials_request_body(body, header, config),
        51 => validate_alter_user_scram_credentials_request_body(body, header, config),
        55 => validate_describe_quorum_request_body(body, header, config),
        57 => validate_update_features_request_body(body, header, config),
        _ => Ok(()),
    }
}

fn validate_api_versions_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    let mut cursor = header.body_start;
    if header.api_version >= 3 {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_empty_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 3 {
        return Ok(());
    }
    if header.body_start != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_fetch_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=5).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_bytes(body, &mut cursor, 12)?;
    if header.api_version >= 3 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    if header.api_version >= 4 {
        skip_bytes(body, &mut cursor, 1)?;
    }

    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 12)?;
            if header.api_version >= 5 {
                skip_bytes(body, &mut cursor, 8)?;
            }
            skip_bytes(body, &mut cursor, 4)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_list_offsets_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 5 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_bytes(body, &mut cursor, 4)?;
    if header.api_version >= 2 {
        skip_bytes(body, &mut cursor, 1)?;
    }

    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            if header.api_version >= 4 {
                skip_bytes(body, &mut cursor, 4)?;
            }
            skip_bytes(body, &mut cursor, 8)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_delete_records_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 12)?;
        }
    }
    skip_bytes(body, &mut cursor, 4)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_create_topics_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 2 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 4 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 6)?;
        let assignment_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..assignment_count {
            skip_bytes(body, &mut cursor, 4)?;
            skip_int32_array(body, &mut cursor)?;
        }
        let config_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..config_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    skip_bytes(body, &mut cursor, 5)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_delete_topics_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 3 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_bytes(body, &mut cursor, 4)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_create_partitions_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 4)?;
        if let Some(assignment_count) = read_nullable_request_array_len(body, &mut cursor)? {
            for _ in 0..assignment_count {
                skip_int32_array(body, &mut cursor)?;
            }
        }
    }
    skip_bytes(body, &mut cursor, 5)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_create_acls_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let creation_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..creation_count {
        skip_bytes(body, &mut cursor, 1)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 1)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 2)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_describe_acls_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_bytes(body, &mut cursor, 1)?;
    skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 1)?;
    skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 2)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_delete_acls_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let filter_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..filter_count {
        skip_bytes(body, &mut cursor, 1)?;
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 1)?;
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 2)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_describe_configs_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 3 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let resource_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..resource_count {
        skip_bytes(body, &mut cursor, 1)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        if let Some(key_count) = read_nullable_request_array_len(body, &mut cursor)? {
            for _ in 0..key_count {
                skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            }
        }
    }
    skip_bytes(body, &mut cursor, 1)?;
    if header.api_version >= 3 {
        skip_bytes(body, &mut cursor, 1)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_alter_configs_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let resource_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..resource_count {
        skip_bytes(body, &mut cursor, 1)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let config_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..config_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    skip_bytes(body, &mut cursor, 1)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_alter_replica_log_dirs_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    let dir_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..dir_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let topic_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..topic_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_int32_array(body, &mut cursor)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_describe_log_dirs_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    if let Some(topic_count) = read_nullable_request_array_len(body, &mut cursor)? {
        for _ in 0..topic_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_int32_array(body, &mut cursor)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_create_delegation_token_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    let renewer_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..renewer_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_bytes(body, &mut cursor, 8)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_renew_delegation_token_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    skip_bytes(body, &mut cursor, 8)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_expire_delegation_token_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    skip_bytes(body, &mut cursor, 8)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_describe_delegation_token_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    if let Some(owner_count) = read_nullable_request_array_len(body, &mut cursor)? {
        for _ in 0..owner_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_metadata_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 8 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let topic_count = if header.api_version == 0 {
        Some(read_request_array_len(body, &mut cursor)?)
    } else {
        read_nullable_request_array_len(body, &mut cursor)?
    };

    if let Some(topic_count) = topic_count {
        for _ in 0..topic_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if header.api_version >= 4 {
        skip_bytes(body, &mut cursor, 1)?;
    }
    if header.api_version >= 8 {
        skip_bytes(body, &mut cursor, 2)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_offset_commit_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(2..=7).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    if header.api_version >= 7 {
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if header.api_version <= 4 {
        skip_bytes(body, &mut cursor, 8)?;
    }

    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 12)?;
            if header.api_version >= 6 {
                skip_bytes(body, &mut cursor, 4)?;
            }
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_offset_fetch_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 1 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 5 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    let topic_count = if header.api_version == 1 {
        Some(read_request_array_len(body, &mut cursor)?)
    } else {
        read_nullable_request_array_len(body, &mut cursor)?
    };

    if let Some(topic_count) = topic_count {
        for _ in 0..topic_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_int32_array(body, &mut cursor)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_offset_delete_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_int32_array(body, &mut cursor)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_find_coordinator_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 2 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    if header.api_version >= 1 {
        skip_bytes(body, &mut cursor, 1)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_join_group_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 5 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    if header.api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    if header.api_version >= 5 {
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;

    let protocol_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..protocol_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_heartbeat_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 3 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    if header.api_version >= 3 {
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_leave_group_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 3 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    if header.api_version <= 2 {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    } else {
        let member_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..member_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_sync_group_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 3 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    if header.api_version >= 3 {
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    let assignment_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..assignment_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_describe_groups_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 4 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let group_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..group_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if header.api_version >= 3 {
        skip_bytes(body, &mut cursor, 1)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_delete_groups_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let group_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..group_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_elect_leaders_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=1).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    if header.api_version >= 1 {
        skip_bytes(body, &mut cursor, 1)?;
    }
    if let Some(topic_count) = read_nullable_request_array_len(body, &mut cursor)? {
        for _ in 0..topic_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_int32_array(body, &mut cursor)?;
        }
    }
    skip_bytes(body, &mut cursor, 4)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_incremental_alter_configs_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=1).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    if header.api_version == 0 {
        let resource_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..resource_count {
            skip_bytes(body, &mut cursor, 1)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            let config_count = read_request_array_len(body, &mut cursor)?;
            for _ in 0..config_count {
                skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_bytes(body, &mut cursor, 1)?;
                skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            }
        }
        skip_bytes(body, &mut cursor, 1)?;
    } else {
        let resource_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..resource_count {
            skip_bytes(body, &mut cursor, 1)?;
            skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
            let config_count = read_compact_array_len(body, &mut cursor)?;
            for _ in 0..config_count {
                skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_bytes(body, &mut cursor, 1)?;
                skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
            }
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_bytes(body, &mut cursor, 1)?;
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_alter_partition_reassignments_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=1).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_bytes(body, &mut cursor, 4)?;
    if header.api_version >= 1 {
        skip_bytes(body, &mut cursor, 1)?;
    }
    let topic_count = read_compact_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            skip_compact_nullable_int32_array(body, &mut cursor)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_list_partition_reassignments_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_bytes(body, &mut cursor, 4)?;
    if let Some(topic_count) = read_compact_nullable_array_len(body, &mut cursor)? {
        for _ in 0..topic_count {
            skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_compact_int32_array(body, &mut cursor)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_describe_client_quotas_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=1).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    if header.api_version == 0 {
        let component_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..component_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 1)?;
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_bytes(body, &mut cursor, 1)?;
    } else {
        let component_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..component_count {
            skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 1)?;
            skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_bytes(body, &mut cursor, 1)?;
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_alter_client_quotas_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=1).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    if header.api_version == 0 {
        let entry_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..entry_count {
            let entity_count = read_request_array_len(body, &mut cursor)?;
            for _ in 0..entity_count {
                skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            }
            let op_count = read_request_array_len(body, &mut cursor)?;
            for _ in 0..op_count {
                skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_bytes(body, &mut cursor, 8)?;
                skip_bytes(body, &mut cursor, 1)?;
            }
        }
        skip_bytes(body, &mut cursor, 1)?;
    } else {
        let entry_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..entry_count {
            let entity_count = read_compact_array_len(body, &mut cursor)?;
            for _ in 0..entity_count {
                skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
            }
            let op_count = read_compact_array_len(body, &mut cursor)?;
            for _ in 0..op_count {
                skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_bytes(body, &mut cursor, 8)?;
                skip_bytes(body, &mut cursor, 1)?;
                skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
            }
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_bytes(body, &mut cursor, 1)?;
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_describe_user_scram_credentials_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    if let Some(user_count) = read_compact_nullable_array_len(body, &mut cursor)? {
        for _ in 0..user_count {
            skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_alter_user_scram_credentials_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version != 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    let deletion_count = read_compact_array_len(body, &mut cursor)?;
    for _ in 0..deletion_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 1)?;
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    let upsertion_count = read_compact_array_len(body, &mut cursor)?;
    for _ in 0..upsertion_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 1)?;
        skip_bytes(body, &mut cursor, 4)?;
        skip_compact_bytes(body, &mut cursor, config.max_header_bytes)?;
        skip_compact_bytes(body, &mut cursor, config.max_header_bytes)?;
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_describe_quorum_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=2).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    let topic_count = read_compact_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_update_features_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=2).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_bytes(body, &mut cursor, 4)?;
    let update_count = read_compact_array_len(body, &mut cursor)?;
    for _ in 0..update_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 3)?;
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if header.api_version >= 1 {
        skip_bytes(body, &mut cursor, 1)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_sasl_handshake_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(0..=1).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_init_producer_id_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_add_partitions_to_txn_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 2 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 10)?;
    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_int32_array(body, &mut cursor)?;
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_add_offsets_to_txn_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 2 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 10)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_end_txn_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 2 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 11)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_txn_offset_commit_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 2 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 10)?;
    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 12)?;
            if header.api_version >= 2 {
                skip_bytes(body, &mut cursor, 4)?;
            }
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_write_txn_markers_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if !(1..=2).contains(&header.api_version) {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }

    let mut cursor = header.body_start;
    let marker_count = read_compact_array_len(body, &mut cursor)?;
    for _ in 0..marker_count {
        skip_bytes(body, &mut cursor, 11)?;
        let topic_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..topic_count {
            skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
            let partition_count = read_compact_array_len(body, &mut cursor)?;
            skip_bytes(body, &mut cursor, partition_count.saturating_mul(4))?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_bytes(body, &mut cursor, 4)?;
        if header.api_version >= 2 {
            skip_bytes(body, &mut cursor, 1)?;
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_sasl_authenticate_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 1 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn validate_produce_request_body(
    body: &[u8],
    header: &KafkaRequestHeader,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    if header.api_version < 0 {
        return Err(KafkaExtraction::UnsupportedApiVersion);
    }
    if header.api_version > 2 {
        return Ok(());
    }

    let mut cursor = header.body_start;
    let _acks = read_i16_be_cursor(body, &mut cursor)?;
    skip_bytes(body, &mut cursor, 4)?;
    let topic_count = read_request_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_request_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            skip_nullable_bytes(body, &mut cursor, config.max_header_bytes)?;
        }
    }
    if cursor != body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    Ok(())
}

fn api_versions_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 3 {
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    let error_code = read_i16_be(body, cursor)?;
    Ok(error_code)
}

fn create_topics_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    Ok(first_error_code.unwrap_or(0))
}

fn create_partitions_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    Ok(first_error_code.unwrap_or(0))
}

fn create_acls_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let result_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..result_count {
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    Ok(first_error_code.unwrap_or(0))
}

fn describe_acls_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;

    let resource_count = read_response_array_len(body, &mut cursor)?;
    for _ in 0..resource_count {
        skip_bytes(body, &mut cursor, 1)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 1)?;
        let acl_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..acl_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 2)?;
        }
    }
    Ok(error_code)
}

fn delete_acls_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let filter_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..filter_count {
        let filter_error_code = read_i16_be_cursor(body, &mut cursor)?;
        if filter_error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(filter_error_code);
        }
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let acl_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..acl_count {
            let acl_error_code = read_i16_be_cursor(body, &mut cursor)?;
            if acl_error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(acl_error_code);
            }
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 1)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 1)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 2)?;
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn describe_configs_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let result_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..result_count {
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 1)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;

        let config_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..config_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 3)?;
            let synonym_count = read_response_array_len(body, &mut cursor)?;
            for _ in 0..synonym_count {
                skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_bytes(body, &mut cursor, 1)?;
            }
            if api_version >= 3 {
                skip_bytes(body, &mut cursor, 1)?;
                skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            }
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn alter_configs_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let response_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..response_count {
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 1)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    Ok(first_error_code.unwrap_or(0))
}

fn alter_replica_log_dirs_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(error_code);
            }
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn describe_log_dirs_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let result_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..result_count {
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let topic_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..topic_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            let partition_count = read_response_array_len(body, &mut cursor)?;
            for _ in 0..partition_count {
                skip_bytes(body, &mut cursor, 21)?;
            }
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn create_delegation_token_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 24)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    Ok(error_code)
}

fn renew_delegation_token_response_error_code(body: &[u8]) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_bytes(body, &mut cursor, 12)?;
    Ok(error_code)
}

fn expire_delegation_token_response_error_code(body: &[u8]) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_bytes(body, &mut cursor, 12)?;
    Ok(error_code)
}

fn describe_delegation_token_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    let token_count = read_response_array_len(body, &mut cursor)?;
    for _ in 0..token_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 24)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
        let renewer_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..renewer_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    skip_bytes(body, &mut cursor, 4)?;
    Ok(error_code)
}

fn produce_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;

    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(error_code);
            }
            skip_bytes(body, &mut cursor, 8)?;
            if api_version >= 2 {
                skip_bytes(body, &mut cursor, 8)?;
            }
            if api_version >= 5 {
                skip_bytes(body, &mut cursor, 8)?;
            }
        }
    }

    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }

    Ok(first_error_code.unwrap_or(0))
}

fn fetch_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;

    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(error_code);
            }
            skip_bytes(body, &mut cursor, 8)?;
            if api_version >= 4 {
                skip_bytes(body, &mut cursor, 8)?;
            }
            if api_version >= 5 {
                skip_bytes(body, &mut cursor, 8)?;
            }
            if api_version >= 4 {
                let aborted_count = read_response_array_len(body, &mut cursor)?;
                for _ in 0..aborted_count {
                    skip_bytes(body, &mut cursor, 16)?;
                }
            }
            skip_nullable_bytes(body, &mut cursor, config.max_header_bytes)?;
        }
    }

    Ok(first_error_code.unwrap_or(0))
}

fn list_offsets_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 2 {
        skip_bytes(body, &mut cursor, 4)?;
    }

    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(error_code);
            }
            skip_bytes(body, &mut cursor, 16)?;
            if api_version >= 4 {
                skip_bytes(body, &mut cursor, 4)?;
            }
        }
    }

    Ok(first_error_code.unwrap_or(0))
}

fn delete_records_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;

    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 12)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(error_code);
            }
        }
    }

    Ok(first_error_code.unwrap_or(0))
}

fn delete_topics_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;

    let response_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..response_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
    }

    Ok(first_error_code.unwrap_or(0))
}

fn join_group_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 2 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_bytes(body, &mut cursor, 4)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;

    let member_count = read_response_array_len(body, &mut cursor)?;
    for _ in 0..member_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    }
    Ok(error_code)
}

fn find_coordinator_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    if api_version >= 1 {
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_bytes(body, &mut cursor, 4)?;
    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    Ok(error_code)
}

fn heartbeat_response_error_code(body: &[u8], api_version: i16) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    read_i16_be_cursor(body, &mut cursor)
}

fn leave_group_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let top_level_error_code = read_i16_be_cursor(body, &mut cursor)?;
    if top_level_error_code != 0 {
        return Ok(top_level_error_code);
    }
    if api_version >= 3 {
        let member_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..member_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            let member_error_code = read_i16_be_cursor(body, &mut cursor)?;
            if member_error_code != 0 {
                return Ok(member_error_code);
            }
        }
    }
    Ok(0)
}

fn sync_group_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    Ok(error_code)
}

fn describe_groups_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let group_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..group_count {
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let member_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..member_count {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            if api_version >= 4 {
                skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            }
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
            skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
        }
        if api_version >= 3 {
            skip_bytes(body, &mut cursor, 4)?;
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn offset_commit_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 3 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(error_code);
            }
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn offset_fetch_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 3 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_partition_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 12)?;
            if api_version >= 5 {
                skip_bytes(body, &mut cursor, 4)?;
            }
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_partition_error_code.is_none() {
                first_partition_error_code = Some(error_code);
            }
        }
    }
    if api_version >= 2 {
        let top_level_error_code = read_i16_be_cursor(body, &mut cursor)?;
        if top_level_error_code != 0 {
            return Ok(top_level_error_code);
        }
    }
    Ok(first_partition_error_code.unwrap_or(0))
}

fn offset_delete_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let top_level_error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_bytes(body, &mut cursor, 4)?;
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_partition_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_partition_error_code.is_none() {
                first_partition_error_code = Some(error_code);
            }
        }
    }
    if top_level_error_code != 0 {
        return Ok(top_level_error_code);
    }
    Ok(first_partition_error_code.unwrap_or(0))
}

fn describe_client_quotas_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_bytes(body, &mut cursor, 4)?;
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    if api_version == 0 {
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        if let Some(entry_count) = read_nullable_request_array_len(body, &mut cursor)? {
            for _ in 0..entry_count {
                let entity_count = read_response_array_len(body, &mut cursor)?;
                for _ in 0..entity_count {
                    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                    skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                }
                let value_count = read_response_array_len(body, &mut cursor)?;
                for _ in 0..value_count {
                    skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                    skip_bytes(body, &mut cursor, 8)?;
                }
            }
        }
    } else {
        skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
        if let Some(entry_count) = read_compact_nullable_array_len(body, &mut cursor)? {
            for _ in 0..entry_count {
                let entity_count = read_compact_array_len(body, &mut cursor)?;
                for _ in 0..entity_count {
                    skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
                    skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
                    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
                }
                let value_count = read_compact_array_len(body, &mut cursor)?;
                for _ in 0..value_count {
                    skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
                    skip_bytes(body, &mut cursor, 8)?;
                    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
                }
                skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
            }
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    Ok(error_code)
}

fn alter_client_quotas_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_bytes(body, &mut cursor, 4)?;
    let entry_count = if api_version == 0 {
        read_response_array_len(body, &mut cursor)?
    } else {
        read_compact_array_len(body, &mut cursor)?
    };
    let mut first_error_code = None;
    for _ in 0..entry_count {
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        if api_version == 0 {
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            let entity_count = read_response_array_len(body, &mut cursor)?;
            for _ in 0..entity_count {
                skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            }
        } else {
            skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
            let entity_count = read_compact_array_len(body, &mut cursor)?;
            for _ in 0..entity_count {
                skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
            }
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if api_version >= 1 {
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    Ok(first_error_code.unwrap_or(0))
}

fn describe_user_scram_credentials_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    let top_level_error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
    let result_count = read_compact_array_len(body, &mut cursor)?;
    let mut first_user_error_code = None;
    for _ in 0..result_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_user_error_code.is_none() {
            first_user_error_code = Some(error_code);
        }
        skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
        let credential_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..credential_count {
            skip_bytes(body, &mut cursor, 5)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if top_level_error_code != 0 {
        return Ok(top_level_error_code);
    }
    Ok(first_user_error_code.unwrap_or(0))
}

fn alter_user_scram_credentials_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    let result_count = read_compact_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..result_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    Ok(first_error_code.unwrap_or(0))
}

fn describe_quorum_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    let top_level_error_code = read_i16_be_cursor(body, &mut cursor)?;
    if api_version >= 2 {
        skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
    }

    let topic_count = read_compact_array_len(body, &mut cursor)?;
    let mut first_partition_error_code = None;
    for _ in 0..topic_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_partition_error_code.is_none() {
                first_partition_error_code = Some(error_code);
            }
            if api_version >= 2 {
                skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
            }
            skip_bytes(body, &mut cursor, 16)?;
            skip_describe_quorum_replica_states(body, &mut cursor, api_version, config)?;
            skip_describe_quorum_replica_states(body, &mut cursor, api_version, config)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }

    if api_version >= 2 {
        let node_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..node_count {
            skip_bytes(body, &mut cursor, 4)?;
            let listener_count = read_compact_array_len(body, &mut cursor)?;
            for _ in 0..listener_count {
                skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
                skip_bytes(body, &mut cursor, 2)?;
                skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
            }
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if top_level_error_code != 0 {
        return Ok(top_level_error_code);
    }
    Ok(first_partition_error_code.unwrap_or(0))
}

fn skip_describe_quorum_replica_states(
    body: &[u8],
    cursor: &mut usize,
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<(), KafkaExtraction> {
    let state_count = read_compact_array_len(body, cursor)?;
    let state_bytes = match api_version {
        0 => 12,
        1 => 28,
        2 => 44,
        _ => return Err(KafkaExtraction::UnsupportedApiVersion),
    };
    for _ in 0..state_count {
        skip_bytes(body, cursor, state_bytes)?;
        skip_tagged_fields(body, cursor, config.max_request_line_bytes)?;
    }
    Ok(())
}

fn update_features_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    let top_level_error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;

    let mut first_feature_error_code = None;
    if api_version <= 1 {
        let result_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..result_count {
            skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_feature_error_code.is_none() {
                first_feature_error_code = Some(error_code);
            }
            skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if top_level_error_code != 0 {
        return Ok(top_level_error_code);
    }
    Ok(first_feature_error_code.unwrap_or(0))
}

fn delete_groups_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let group_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..group_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn elect_leaders_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let top_level_error_code = if api_version >= 1 {
        read_i16_be_cursor(body, &mut cursor)?
    } else {
        0
    };
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_partition_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_partition_error_code.is_none() {
                first_partition_error_code = Some(error_code);
            }
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if top_level_error_code != 0 {
        return Ok(top_level_error_code);
    }
    Ok(first_partition_error_code.unwrap_or(0))
}

fn incremental_alter_configs_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_bytes(body, &mut cursor, 4)?;
    let response_count = if api_version == 0 {
        read_response_array_len(body, &mut cursor)?
    } else {
        read_compact_array_len(body, &mut cursor)?
    };
    let mut first_error_code = None;
    for _ in 0..response_count {
        let error_code = read_i16_be_cursor(body, &mut cursor)?;
        if error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(error_code);
        }
        if api_version == 0 {
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 1)?;
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        } else {
            skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_bytes(body, &mut cursor, 1)?;
            skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if api_version >= 1 {
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    Ok(first_error_code.unwrap_or(0))
}

fn alter_partition_reassignments_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 1)?;
    }
    let top_level_error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
    let topic_count = read_compact_array_len(body, &mut cursor)?;
    let mut first_partition_error_code = None;
    for _ in 0..topic_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_partition_error_code.is_none() {
                first_partition_error_code = Some(error_code);
            }
            skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    if top_level_error_code != 0 {
        return Ok(top_level_error_code);
    }
    Ok(first_partition_error_code.unwrap_or(0))
}

fn list_partition_reassignments_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    skip_bytes(body, &mut cursor, 4)?;
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_compact_nullable_string(body, &mut cursor, config.max_request_line_bytes)?;
    let topic_count = read_compact_array_len(body, &mut cursor)?;
    for _ in 0..topic_count {
        skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            skip_compact_int32_array(body, &mut cursor)?;
            skip_compact_int32_array(body, &mut cursor)?;
            skip_compact_int32_array(body, &mut cursor)?;
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    Ok(error_code)
}

fn sasl_handshake_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    let mechanism_count = read_response_array_len(body, &mut cursor)?;
    for _ in 0..mechanism_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    Ok(error_code)
}

fn init_producer_id_response_error_code(body: &[u8]) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_bytes(body, &mut cursor, 10)?;
    Ok(error_code)
}

fn add_partitions_to_txn_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(error_code);
            }
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn throttled_response_error_code(body: &[u8]) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    read_i16_be_cursor(body, &mut cursor)
}

fn txn_offset_commit_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_bytes(body, &mut cursor, 4)?;
    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            skip_bytes(body, &mut cursor, 4)?;
            let error_code = read_i16_be_cursor(body, &mut cursor)?;
            if error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(error_code);
            }
        }
    }
    Ok(first_error_code.unwrap_or(0))
}

fn write_txn_markers_response_error_code(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    let marker_count = read_compact_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..marker_count {
        skip_bytes(body, &mut cursor, 8)?;
        let topic_count = read_compact_array_len(body, &mut cursor)?;
        for _ in 0..topic_count {
            skip_compact_string(body, &mut cursor, config.max_request_line_bytes)?;
            let partition_count = read_compact_array_len(body, &mut cursor)?;
            for _ in 0..partition_count {
                skip_bytes(body, &mut cursor, 4)?;
                let error_code = read_i16_be_cursor(body, &mut cursor)?;
                if error_code != 0 && first_error_code.is_none() {
                    first_error_code = Some(error_code);
                }
                skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
            }
            skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
        }
        skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    }
    skip_tagged_fields(body, &mut cursor, config.max_request_line_bytes)?;
    Ok(first_error_code.unwrap_or(0))
}

fn sasl_authenticate_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    skip_kafka_bytes(body, &mut cursor, config.max_header_bytes)?;
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 8)?;
    }
    Ok(error_code)
}

fn list_groups_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }
    let error_code = read_i16_be_cursor(body, &mut cursor)?;
    let group_count = read_response_array_len(body, &mut cursor)?;
    for _ in 0..group_count {
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        if api_version >= 3 {
            skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    Ok(error_code)
}

fn metadata_response_error_code(
    body: &[u8],
    api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<i16, KafkaExtraction> {
    let mut cursor = 4;
    if body.len() < cursor {
        return Err(KafkaExtraction::MalformedFrame);
    }
    if api_version >= 3 {
        skip_bytes(body, &mut cursor, 4)?;
    }

    let broker_count = read_response_array_len(body, &mut cursor)?;
    for _ in 0..broker_count {
        skip_bytes(body, &mut cursor, 4)?;
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 4)?;
        if api_version >= 1 {
            skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        }
    }
    if api_version >= 2 {
        skip_nullable_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
    }
    if api_version >= 1 {
        skip_bytes(body, &mut cursor, 4)?;
    }

    let topic_count = read_response_array_len(body, &mut cursor)?;
    let mut first_error_code = None;
    for _ in 0..topic_count {
        let topic_error_code = read_i16_be_cursor(body, &mut cursor)?;
        if topic_error_code != 0 && first_error_code.is_none() {
            first_error_code = Some(topic_error_code);
        }
        skip_kafka_string(body, &mut cursor, config.max_request_line_bytes)?;
        if api_version >= 1 {
            skip_bytes(body, &mut cursor, 1)?;
        }

        let partition_count = read_response_array_len(body, &mut cursor)?;
        for _ in 0..partition_count {
            let partition_error_code = read_i16_be_cursor(body, &mut cursor)?;
            if partition_error_code != 0 && first_error_code.is_none() {
                first_error_code = Some(partition_error_code);
            }
            skip_bytes(body, &mut cursor, 8)?;
            if api_version >= 7 {
                skip_bytes(body, &mut cursor, 4)?;
            }
            skip_int32_array(body, &mut cursor)?;
            skip_int32_array(body, &mut cursor)?;
            if api_version >= 5 {
                skip_int32_array(body, &mut cursor)?;
            }
        }
        if api_version >= 8 {
            skip_bytes(body, &mut cursor, 4)?;
        }
    }
    if api_version >= 8 {
        skip_bytes(body, &mut cursor, 4)?;
    }

    Ok(first_error_code.unwrap_or(0))
}

fn read_response_array_len(body: &[u8], cursor: &mut usize) -> Result<usize, KafkaExtraction> {
    read_request_array_len(body, cursor)
}

fn read_request_array_len(body: &[u8], cursor: &mut usize) -> Result<usize, KafkaExtraction> {
    let len = read_i32_be_cursor(body, cursor)?;
    if len < 0 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = len as usize;
    if len > MAX_KAFKA_RESPONSE_ENTRIES {
        return Err(KafkaExtraction::FrameTooLong);
    }
    Ok(len)
}

fn read_compact_array_len(body: &[u8], cursor: &mut usize) -> Result<usize, KafkaExtraction> {
    let encoded_len = read_unsigned_varint(body, cursor)?;
    if encoded_len == 0 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = encoded_len
        .checked_sub(1)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    if len > MAX_KAFKA_RESPONSE_ENTRIES {
        return Err(KafkaExtraction::FrameTooLong);
    }
    Ok(len)
}

fn read_compact_nullable_array_len(
    body: &[u8],
    cursor: &mut usize,
) -> Result<Option<usize>, KafkaExtraction> {
    let encoded_len = read_unsigned_varint(body, cursor)?;
    if encoded_len == 0 {
        return Ok(None);
    }
    let len = encoded_len
        .checked_sub(1)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    if len > MAX_KAFKA_RESPONSE_ENTRIES {
        return Err(KafkaExtraction::FrameTooLong);
    }
    Ok(Some(len))
}

fn read_nullable_request_array_len(
    body: &[u8],
    cursor: &mut usize,
) -> Result<Option<usize>, KafkaExtraction> {
    let len = read_i32_be_cursor(body, cursor)?;
    if len == -1 {
        return Ok(None);
    }
    if len < -1 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = len as usize;
    if len > MAX_KAFKA_RESPONSE_ENTRIES {
        return Err(KafkaExtraction::FrameTooLong);
    }
    Ok(Some(len))
}

fn skip_kafka_string(
    body: &[u8],
    cursor: &mut usize,
    max_string_bytes: usize,
) -> Result<(), KafkaExtraction> {
    let len = read_i16_be_cursor(body, cursor)?;
    if len < 0 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = len as usize;
    if len > max_string_bytes {
        return Err(KafkaExtraction::ClientIdTooLong);
    }
    skip_bytes(body, cursor, len)
}

fn skip_nullable_kafka_string(
    body: &[u8],
    cursor: &mut usize,
    max_string_bytes: usize,
) -> Result<(), KafkaExtraction> {
    let len = read_i16_be_cursor(body, cursor)?;
    if len == -1 {
        return Ok(());
    }
    if len < -1 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = len as usize;
    if len > max_string_bytes {
        return Err(KafkaExtraction::ClientIdTooLong);
    }
    skip_bytes(body, cursor, len)
}

fn skip_int32_array(body: &[u8], cursor: &mut usize) -> Result<(), KafkaExtraction> {
    let len = read_response_array_len(body, cursor)?;
    skip_bytes(body, cursor, len.saturating_mul(4))
}

fn skip_compact_int32_array(body: &[u8], cursor: &mut usize) -> Result<(), KafkaExtraction> {
    let len = read_compact_array_len(body, cursor)?;
    skip_bytes(body, cursor, len.saturating_mul(4))
}

fn skip_compact_bytes(
    body: &[u8],
    cursor: &mut usize,
    max_len: usize,
) -> Result<(), KafkaExtraction> {
    let encoded_len = read_unsigned_varint(body, cursor)?;
    if encoded_len == 0 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = encoded_len
        .checked_sub(1)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    if len > max_len {
        return Err(KafkaExtraction::FrameTooLong);
    }
    skip_bytes(body, cursor, len)
}

fn skip_nullable_bytes(
    body: &[u8],
    cursor: &mut usize,
    max_len: usize,
) -> Result<(), KafkaExtraction> {
    let len = read_i32_be_cursor(body, cursor)?;
    if len == -1 {
        return Ok(());
    }
    if len < -1 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = len as usize;
    if len > max_len {
        return Err(KafkaExtraction::FrameTooLong);
    }
    skip_bytes(body, cursor, len)
}

fn skip_kafka_bytes(
    body: &[u8],
    cursor: &mut usize,
    max_len: usize,
) -> Result<(), KafkaExtraction> {
    let len = read_i32_be_cursor(body, cursor)?;
    if len < 0 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = len as usize;
    if len > max_len {
        return Err(KafkaExtraction::FrameTooLong);
    }
    skip_bytes(body, cursor, len)
}

fn skip_bytes(body: &[u8], cursor: &mut usize, len: usize) -> Result<(), KafkaExtraction> {
    let end = cursor
        .checked_add(len)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    if end > body.len() {
        return Err(KafkaExtraction::MalformedFrame);
    }
    *cursor = end;
    Ok(())
}

fn parse_client_id(
    body: &[u8],
    cursor: usize,
    max_client_id_bytes: usize,
) -> Result<KafkaClientId, KafkaExtraction> {
    let non_flexible = parse_nullable_string(body, cursor, max_client_id_bytes);
    if let Ok(client_id_present) = non_flexible {
        return Ok(client_id_present);
    }

    let flexible = parse_compact_nullable_string(body, cursor, max_client_id_bytes);
    match (non_flexible, flexible) {
        (_, Ok(client_id_present)) => Ok(client_id_present),
        (Err(KafkaExtraction::ClientIdTooLong), Err(_)) => Err(KafkaExtraction::ClientIdTooLong),
        (Err(KafkaExtraction::InvalidUtf8), Err(_)) => Err(KafkaExtraction::InvalidUtf8),
        (Err(error), Err(_)) => Err(error),
        (Ok(_), _) => unreachable!("non-flexible parse returned above"),
    }
}

fn parse_nullable_string(
    body: &[u8],
    mut cursor: usize,
    max_client_id_bytes: usize,
) -> Result<KafkaClientId, KafkaExtraction> {
    let len = read_i16_be(body, cursor)?;
    cursor += 2;
    if len == -1 {
        return Ok(KafkaClientId {
            present: false,
            cursor,
        });
    }
    if len < -1 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = len as usize;
    if len > max_client_id_bytes {
        return Err(KafkaExtraction::ClientIdTooLong);
    }
    let end = cursor
        .checked_add(len)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    let raw = body
        .get(cursor..end)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    std::str::from_utf8(raw).map_err(|_| KafkaExtraction::InvalidUtf8)?;
    Ok(KafkaClientId {
        present: len > 0,
        cursor: end,
    })
}

fn parse_compact_nullable_string(
    body: &[u8],
    mut cursor: usize,
    max_client_id_bytes: usize,
) -> Result<KafkaClientId, KafkaExtraction> {
    let encoded_len = read_unsigned_varint(body, &mut cursor)?;
    let client_id_present = encoded_len != 0;
    if client_id_present {
        let len = encoded_len
            .checked_sub(1)
            .ok_or(KafkaExtraction::MalformedFrame)?;
        if len > max_client_id_bytes {
            return Err(KafkaExtraction::ClientIdTooLong);
        }
        let end = cursor
            .checked_add(len)
            .ok_or(KafkaExtraction::MalformedFrame)?;
        let raw = body
            .get(cursor..end)
            .ok_or(KafkaExtraction::MalformedFrame)?;
        std::str::from_utf8(raw).map_err(|_| KafkaExtraction::InvalidUtf8)?;
        cursor = end;
    }
    skip_tagged_fields(body, &mut cursor, max_client_id_bytes)?;
    Ok(KafkaClientId {
        present: client_id_present,
        cursor,
    })
}

fn skip_compact_string(
    body: &[u8],
    cursor: &mut usize,
    max_string_bytes: usize,
) -> Result<(), KafkaExtraction> {
    let encoded_len = read_unsigned_varint(body, cursor)?;
    if encoded_len == 0 {
        return Err(KafkaExtraction::MalformedFrame);
    }
    let len = encoded_len
        .checked_sub(1)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    if len > max_string_bytes {
        return Err(KafkaExtraction::ClientIdTooLong);
    }
    let end = cursor
        .checked_add(len)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    let raw = body
        .get(*cursor..end)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    std::str::from_utf8(raw).map_err(|_| KafkaExtraction::InvalidUtf8)?;
    *cursor = end;
    Ok(())
}

fn skip_compact_nullable_string(
    body: &[u8],
    cursor: &mut usize,
    max_string_bytes: usize,
) -> Result<(), KafkaExtraction> {
    let encoded_len = read_unsigned_varint(body, cursor)?;
    if encoded_len == 0 {
        return Ok(());
    }
    let len = encoded_len
        .checked_sub(1)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    if len > max_string_bytes {
        return Err(KafkaExtraction::ClientIdTooLong);
    }
    let end = cursor
        .checked_add(len)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    let raw = body
        .get(*cursor..end)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    std::str::from_utf8(raw).map_err(|_| KafkaExtraction::InvalidUtf8)?;
    *cursor = end;
    Ok(())
}

fn skip_compact_nullable_int32_array(
    body: &[u8],
    cursor: &mut usize,
) -> Result<(), KafkaExtraction> {
    let encoded_len = read_unsigned_varint(body, cursor)?;
    if encoded_len == 0 {
        return Ok(());
    }
    let len = encoded_len
        .checked_sub(1)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    if len > MAX_KAFKA_RESPONSE_ENTRIES {
        return Err(KafkaExtraction::FrameTooLong);
    }
    skip_bytes(body, cursor, len.saturating_mul(4))
}

fn skip_tagged_fields(
    body: &[u8],
    cursor: &mut usize,
    max_tag_value_bytes: usize,
) -> Result<(), KafkaExtraction> {
    let tag_count = read_unsigned_varint(body, cursor)?;
    if tag_count > MAX_KAFKA_TAGS {
        return Err(KafkaExtraction::MalformedFrame);
    }
    for _ in 0..tag_count {
        let _tag_id = read_unsigned_varint(body, cursor)?;
        let len = read_unsigned_varint(body, cursor)?;
        if len > max_tag_value_bytes {
            return Err(KafkaExtraction::FrameTooLong);
        }
        let end = cursor
            .checked_add(len)
            .ok_or(KafkaExtraction::MalformedFrame)?;
        if end > body.len() {
            return Err(KafkaExtraction::MalformedFrame);
        }
        *cursor = end;
    }
    Ok(())
}

fn read_unsigned_varint(bytes: &[u8], cursor: &mut usize) -> Result<usize, KafkaExtraction> {
    let mut value = 0usize;
    for shift in (0..MAX_VARINT_BYTES * 7).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or(KafkaExtraction::MalformedFrame)?;
        *cursor += 1;
        value |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(KafkaExtraction::MalformedFrame)
}

fn read_i16_be(bytes: &[u8], offset: usize) -> Result<i16, KafkaExtraction> {
    let end = offset
        .checked_add(2)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    let raw = bytes
        .get(offset..end)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    Ok(i16::from_be_bytes([raw[0], raw[1]]))
}

fn read_i16_be_cursor(bytes: &[u8], cursor: &mut usize) -> Result<i16, KafkaExtraction> {
    let value = read_i16_be(bytes, *cursor)?;
    *cursor = cursor
        .checked_add(2)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    Ok(value)
}

fn read_i32_be(bytes: &[u8], offset: usize) -> Result<i32, KafkaExtraction> {
    let end = offset
        .checked_add(4)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    let raw = bytes
        .get(offset..end)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    Ok(i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_i32_be_cursor(bytes: &[u8], cursor: &mut usize) -> Result<i32, KafkaExtraction> {
    let value = read_i32_be(bytes, *cursor)?;
    *cursor = cursor
        .checked_add(4)
        .ok_or(KafkaExtraction::MalformedFrame)?;
    Ok(value)
}

fn api_key_name(api_key: i16) -> Option<&'static str> {
    match api_key {
        0 => Some("produce"),
        1 => Some("fetch"),
        2 => Some("list_offsets"),
        3 => Some("metadata"),
        8 => Some("offset_commit"),
        9 => Some("offset_fetch"),
        10 => Some("find_coordinator"),
        11 => Some("join_group"),
        12 => Some("heartbeat"),
        13 => Some("leave_group"),
        14 => Some("sync_group"),
        15 => Some("describe_groups"),
        16 => Some("list_groups"),
        17 => Some("sasl_handshake"),
        18 => Some("api_versions"),
        19 => Some("create_topics"),
        20 => Some("delete_topics"),
        21 => Some("delete_records"),
        22 => Some("init_producer_id"),
        24 => Some("add_partitions_to_txn"),
        25 => Some("add_offsets_to_txn"),
        26 => Some("end_txn"),
        27 => Some("write_txn_markers"),
        28 => Some("txn_offset_commit"),
        29 => Some("describe_acls"),
        30 => Some("create_acls"),
        31 => Some("delete_acls"),
        32 => Some("describe_configs"),
        33 => Some("alter_configs"),
        34 => Some("alter_replica_log_dirs"),
        35 => Some("describe_log_dirs"),
        36 => Some("sasl_authenticate"),
        37 => Some("create_partitions"),
        38 => Some("create_delegation_token"),
        39 => Some("renew_delegation_token"),
        40 => Some("expire_delegation_token"),
        41 => Some("describe_delegation_token"),
        42 => Some("delete_groups"),
        43 => Some("elect_leaders"),
        44 => Some("incremental_alter_configs"),
        45 => Some("alter_partition_reassignments"),
        46 => Some("list_partition_reassignments"),
        47 => Some("offset_delete"),
        48 => Some("describe_client_quotas"),
        49 => Some("alter_client_quotas"),
        50 => Some("describe_user_scram_credentials"),
        51 => Some("alter_user_scram_credentials"),
        55 => Some("describe_quorum"),
        57 => Some("update_features"),
        _ => None,
    }
}

fn push_attribute(
    attributes: &mut Vec<TraceAttribute>,
    max_attributes: usize,
    key: &str,
    value: Option<&str>,
) {
    if attributes.len() >= max_attributes {
        return;
    }
    if let Some(value) = value {
        attributes.push(TraceAttribute {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
}
