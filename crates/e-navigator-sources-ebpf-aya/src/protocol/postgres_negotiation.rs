use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PostgresNegotiation {
    Ssl,
    GssEncryption,
}

impl PostgresNegotiation {
    pub(super) fn accepts(self, response: u8) -> bool {
        matches!(
            (self, response),
            (Self::Ssl, b'S') | (Self::GssEncryption, b'G')
        )
    }
}

pub(super) fn begin_postgres_negotiation(
    stream: &mut ConnectionStream,
    negotiation: PostgresNegotiation,
    counters: &mut ProtocolRegistryCounters,
) {
    if stream.postgres_negotiation.is_some() || !stream.in_flight.is_empty() {
        counters.postgres_negotiation_failures += 1;
        stream.postgres_transport_opaque = true;
        return;
    }
    stream.postgres_negotiation = Some(negotiation);
    stream
        .response_decoder
        .expect_postgres_negotiation_response();
}

pub(super) fn handle_postgres_negotiation_response(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    counters: &mut ProtocolRegistryCounters,
) -> bool {
    let Some(negotiation) = stream.postgres_negotiation else {
        return false;
    };
    if truncated {
        stream.postgres_negotiation = None;
        stream.postgres_transport_opaque = true;
        counters.postgres_negotiation_failures += 1;
        return true;
    }

    match frame {
        [b'N'] => {
            stream.postgres_negotiation = None;
            counters.postgres_encryption_negotiation_rejected += 1;
        }
        [response] if negotiation.accepts(*response) => {
            stream.postgres_negotiation = None;
            stream.postgres_transport_opaque = true;
            counters.postgres_encryption_negotiation_accepted += 1;
        }
        bytes if bytes.first() == Some(&b'E') => {
            stream.postgres_negotiation = None;
            stream.postgres_transport_opaque = true;
            counters.postgres_negotiation_failures += 1;
        }
        _ => {
            stream.postgres_negotiation = None;
            stream.postgres_transport_opaque = true;
            counters.postgres_negotiation_failures += 1;
        }
    }
    true
}
