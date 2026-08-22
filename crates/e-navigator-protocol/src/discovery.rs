//! Bounded, content-based protocol discovery for unconfigured TCP ports.

use crate::{
    ProtocolExtractionConfig,
    http::{parse_http_request, parse_http_response},
    kafka::parse_kafka_request,
    mongodb::{parse_mongodb_message, parse_mongodb_response},
    mysql::{parse_mysql_command, parse_mysql_response},
    nats::{parse_nats_command, parse_nats_response},
    postgres::{parse_postgres_message, parse_postgres_response},
    redis::{parse_redis_command, parse_redis_response},
    stream::{StreamDirection, StreamProtocol},
};

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Returns a protocol only when the bounded prefix identifies exactly one
/// supported protocol. Unknown and ambiguous prefixes deliberately produce
/// no classification.
pub fn classify_protocol_prefix(
    bytes: &[u8],
    direction: StreamDirection,
    config: &ProtocolExtractionConfig,
) -> Option<StreamProtocol> {
    if bytes.len() > config.max_header_bytes || bytes.is_empty() {
        return None;
    }
    // Both NATS and Redis accept inline PING commands. A port assignment or
    // a later protocol-unique frame is required to distinguish them.
    if direction == StreamDirection::Request && bytes.eq_ignore_ascii_case(b"PING\r\n") {
        return None;
    }
    if direction == StreamDirection::Request && bytes.starts_with(HTTP2_PREFACE) {
        return Some(StreamProtocol::Http2);
    }

    let mut match_found = None;
    let mut ambiguous = false;
    let mut record = |protocol: StreamProtocol, matches: bool| {
        if !matches {
            return;
        }
        if match_found.is_some_and(|existing| existing != protocol) {
            ambiguous = true;
        } else {
            match_found = Some(protocol);
        }
    };

    match direction {
        StreamDirection::Request => {
            record(
                StreamProtocol::Http1,
                parse_http_request(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Kafka,
                parse_kafka_request(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Mongodb,
                parse_mongodb_message(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Mysql,
                parse_mysql_command(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Nats,
                parse_nats_command(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Postgresql,
                parse_postgres_message(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Redis,
                bytes.starts_with(b"*") && parse_redis_command(bytes, config).is_ok(),
            );
        }
        StreamDirection::Response => {
            record(
                StreamProtocol::Http1,
                parse_http_response(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Mongodb,
                parse_mongodb_response(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Mysql,
                parse_mysql_response(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Nats,
                parse_nats_response(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Postgresql,
                parse_postgres_response(bytes, config).is_ok(),
            );
            record(
                StreamProtocol::Redis,
                parse_redis_response(bytes, config).is_ok(),
            );
        }
    }

    (!ambiguous).then_some(match_found).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn classifies_supported_request_protocols_from_bounded_wire_frames() {
        let config = ProtocolExtractionConfig::default();
        let fixtures = [
            (
                StreamProtocol::Http1,
                b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
            ),
            (
                StreamProtocol::Http2,
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            ),
            (StreamProtocol::Kafka, kafka_request()),
            (StreamProtocol::Mongodb, mongodb_request()),
            (StreamProtocol::Mysql, vec![1, 0, 0, 0, 0x0e]),
            (StreamProtocol::Nats, b"PUB orders 0\r\n\r\n".to_vec()),
            (StreamProtocol::Postgresql, postgres_query()),
            (StreamProtocol::Redis, b"*1\r\n$4\r\nPING\r\n".to_vec()),
        ];

        for (expected, frame) in fixtures {
            assert_eq!(
                classify_protocol_prefix(&frame, StreamDirection::Request, &config),
                Some(expected),
                "fixture for {expected:?}"
            );
        }
    }

    #[test]
    fn ambiguous_or_unknown_prefixes_fail_closed() {
        let config = ProtocolExtractionConfig::default();
        assert_eq!(
            classify_protocol_prefix(b"PING\r\n", StreamDirection::Request, &config),
            None
        );
        assert_eq!(
            classify_protocol_prefix(b"not a protocol", StreamDirection::Request, &config),
            None
        );
    }

    #[test]
    fn classifies_unique_http_response_signature() {
        let config = ProtocolExtractionConfig::default();
        assert_eq!(
            classify_protocol_prefix(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
                StreamDirection::Response,
                &config,
            ),
            Some(StreamProtocol::Http1)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_prefixes_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..=8193),
            request_direction in any::<bool>(),
        ) {
            let direction = if request_direction {
                StreamDirection::Request
            } else {
                StreamDirection::Response
            };
            let _ = classify_protocol_prefix(
                &bytes,
                direction,
                &ProtocolExtractionConfig::default(),
            );
        }
    }

    fn kafka_request() -> Vec<u8> {
        let mut body = vec![0, 18, 0, 0];
        body.extend_from_slice(&7_i32.to_be_bytes());
        body.extend_from_slice(&[0xff, 0xff]);
        let mut frame = (body.len() as i32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    fn mongodb_request() -> Vec<u8> {
        let document = [
            17, 0, 0, 0, 0x02, b'f', b'i', b'n', b'd', 0, 2, 0, 0, 0, b'x', 0, 0,
        ];
        let message_len = 16 + 5 + document.len();
        let mut frame = (message_len as i32).to_le_bytes().to_vec();
        frame.extend_from_slice(&7_i32.to_le_bytes());
        frame.extend_from_slice(&0_i32.to_le_bytes());
        frame.extend_from_slice(&2013_i32.to_le_bytes());
        frame.extend_from_slice(&0_u32.to_le_bytes());
        frame.push(0);
        frame.extend_from_slice(&document);
        frame
    }

    fn postgres_query() -> Vec<u8> {
        let query = b"select 1\0";
        let mut frame = vec![b'Q'];
        frame.extend_from_slice(&((query.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(query);
        frame
    }
}
