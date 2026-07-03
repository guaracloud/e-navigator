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
        3 => validate_metadata_request_body(body, header, config),
        18 => validate_api_versions_request_body(body, header, config),
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
        28 => Some("txn_offset_commit"),
        29 => Some("describe_acls"),
        30 => Some("create_acls"),
        31 => Some("delete_acls"),
        32 => Some("describe_configs"),
        33 => Some("alter_configs"),
        36 => Some("sasl_authenticate"),
        37 => Some("create_partitions"),
        42 => Some("delete_groups"),
        44 => Some("incremental_alter_configs"),
        47 => Some("offset_delete"),
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
