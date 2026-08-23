use crate::ProtocolExtractionConfig;

use super::{
    MAX_REDIS_ARRAY_ITEMS, MAX_REDIS_COMMAND_BYTES, ParsedRedisResponse, RedisExtraction,
    RedisResponseRole, line_end, parse_decimal_line, parse_redis_command_frame,
    parse_redis_response, redis_response_role,
};

/// Bounded response state for one Redis command.
///
/// Ordinary RESP3 pushes and attributes remain out of band. Pub/Sub
/// subscription commands are the exception: Redis acknowledges each explicit
/// channel or pattern with a pushed message, so this lifecycle retains the
/// command until every protocol-defined confirmation arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisResponseLifecycle {
    kind: RedisResponseKind,
}

/// Observable progress of one Redis command response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisResponseProgress {
    Continue,
    Complete(ParsedRedisResponse),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedisResponseKind {
    Standard,
    SubscriptionConfirmations {
        kind: RedisSubscriptionKind,
        remaining: usize,
    },
    NoCorrelatedResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedisSubscriptionKind {
    Subscribe,
    Psubscribe,
    Ssubscribe,
    Unsubscribe,
    Punsubscribe,
    Sunsubscribe,
}

impl RedisResponseLifecycle {
    /// Creates lifecycle state from one complete Redis command frame.
    pub fn from_request(
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<Self, RedisExtraction> {
        let frame = parse_redis_command_frame(bytes, config)?;
        let command = frame.command.as_deref().unwrap_or_default();
        let kind = match subscription_kind(command) {
            Some((_, true)) if frame.argument_count == 0 => RedisResponseKind::NoCorrelatedResponse,
            Some((kind, _)) if frame.argument_count > 0 => {
                RedisResponseKind::SubscriptionConfirmations {
                    kind,
                    remaining: frame.argument_count,
                }
            }
            _ => RedisResponseKind::Standard,
        };
        Ok(Self { kind })
    }

    /// Whether this command has a response that can be correlated safely.
    #[must_use]
    pub fn expects_response(&self) -> bool {
        self.kind != RedisResponseKind::NoCorrelatedResponse
    }

    /// Consumes one complete Redis server frame without retaining its values.
    pub fn observe_response(
        &mut self,
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<RedisResponseProgress, RedisExtraction> {
        if self.kind == RedisResponseKind::NoCorrelatedResponse {
            return Err(RedisExtraction::UnsupportedFrame);
        }

        let role = redis_response_role(bytes)?;
        let response = parse_redis_response(bytes, config)?;
        let confirmation = redis_subscription_confirmation(bytes)?;

        match self.kind {
            RedisResponseKind::Standard => {
                if role == RedisResponseRole::Reply && confirmation.is_none() {
                    Ok(RedisResponseProgress::Complete(response))
                } else {
                    Ok(RedisResponseProgress::Continue)
                }
            }
            RedisResponseKind::SubscriptionConfirmations {
                kind,
                ref mut remaining,
            } => {
                if response.error_type.is_some() {
                    return Ok(RedisResponseProgress::Complete(response));
                }
                if confirmation != Some(kind) {
                    return Ok(RedisResponseProgress::Continue);
                }
                *remaining = remaining
                    .checked_sub(1)
                    .ok_or(RedisExtraction::MalformedFrame)?;
                if *remaining == 0 {
                    Ok(RedisResponseProgress::Complete(response))
                } else {
                    Ok(RedisResponseProgress::Continue)
                }
            }
            RedisResponseKind::NoCorrelatedResponse => Err(RedisExtraction::UnsupportedFrame),
        }
    }
}

fn subscription_kind(command: &str) -> Option<(RedisSubscriptionKind, bool)> {
    if command.eq_ignore_ascii_case("SUBSCRIBE") {
        Some((RedisSubscriptionKind::Subscribe, false))
    } else if command.eq_ignore_ascii_case("PSUBSCRIBE") {
        Some((RedisSubscriptionKind::Psubscribe, false))
    } else if command.eq_ignore_ascii_case("SSUBSCRIBE") {
        Some((RedisSubscriptionKind::Ssubscribe, false))
    } else if command.eq_ignore_ascii_case("UNSUBSCRIBE") {
        Some((RedisSubscriptionKind::Unsubscribe, true))
    } else if command.eq_ignore_ascii_case("PUNSUBSCRIBE") {
        Some((RedisSubscriptionKind::Punsubscribe, true))
    } else if command.eq_ignore_ascii_case("SUNSUBSCRIBE") {
        Some((RedisSubscriptionKind::Sunsubscribe, true))
    } else {
        None
    }
}

fn redis_subscription_confirmation(
    bytes: &[u8],
) -> Result<Option<RedisSubscriptionKind>, RedisExtraction> {
    if !matches!(bytes.first(), Some(b'>' | b'*')) {
        return Ok(None);
    }
    let mut cursor = 1;
    let item_count = parse_decimal_line(bytes, &mut cursor)?;
    if item_count <= 0 || item_count as usize > MAX_REDIS_ARRAY_ITEMS {
        return Ok(None);
    }
    let Some(kind) = redis_string_at(bytes, &mut cursor)? else {
        return Ok(None);
    };

    Ok(if kind.eq_ignore_ascii_case(b"subscribe") {
        Some(RedisSubscriptionKind::Subscribe)
    } else if kind.eq_ignore_ascii_case(b"psubscribe") {
        Some(RedisSubscriptionKind::Psubscribe)
    } else if kind.eq_ignore_ascii_case(b"ssubscribe") {
        Some(RedisSubscriptionKind::Ssubscribe)
    } else if kind.eq_ignore_ascii_case(b"unsubscribe") {
        Some(RedisSubscriptionKind::Unsubscribe)
    } else if kind.eq_ignore_ascii_case(b"punsubscribe") {
        Some(RedisSubscriptionKind::Punsubscribe)
    } else if kind.eq_ignore_ascii_case(b"sunsubscribe") {
        Some(RedisSubscriptionKind::Sunsubscribe)
    } else {
        None
    })
}

fn redis_string_at<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<Option<&'a [u8]>, RedisExtraction> {
    match bytes.get(*cursor) {
        Some(b'+') => {
            *cursor += 1;
            let end = line_end(bytes, *cursor).ok_or(RedisExtraction::MalformedFrame)?;
            let value = bytes
                .get(*cursor..end)
                .ok_or(RedisExtraction::MalformedFrame)?;
            Ok((value.len() <= MAX_REDIS_COMMAND_BYTES).then_some(value))
        }
        Some(b'$') => {
            *cursor += 1;
            let len = parse_decimal_line(bytes, cursor)?;
            if len < 0 {
                return Ok(None);
            }
            let len = len as usize;
            if len > MAX_REDIS_COMMAND_BYTES {
                return Ok(None);
            }
            let end = (*cursor)
                .checked_add(len)
                .ok_or(RedisExtraction::MalformedFrame)?;
            let value = bytes
                .get(*cursor..end)
                .ok_or(RedisExtraction::MalformedFrame)?;
            Ok(Some(value))
        }
        Some(_) => Ok(None),
        None => Err(RedisExtraction::MalformedFrame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBSCRIBE_TWO: &[u8] = b"*3\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n$1\r\nb\r\n";

    #[test]
    fn explicit_subscribe_completes_after_every_confirmation() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = RedisResponseLifecycle::from_request(SUBSCRIBE_TWO, &config)
            .expect("subscribe starts lifecycle");

        assert_eq!(
            lifecycle.observe_response(b">3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n", &config,),
            Ok(RedisResponseProgress::Continue)
        );
        assert!(matches!(
            lifecycle.observe_response(b">3\r\n$9\r\nsubscribe\r\n$1\r\nb\r\n:2\r\n", &config,),
            Ok(RedisResponseProgress::Complete(_))
        ));
    }

    #[test]
    fn resp2_subscription_confirmation_is_correlated() {
        let config = ProtocolExtractionConfig::default();
        let request = b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n";
        let mut lifecycle = RedisResponseLifecycle::from_request(request, &config)
            .expect("subscribe starts lifecycle");

        assert!(matches!(
            lifecycle.observe_response(b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n", &config,),
            Ok(RedisResponseProgress::Complete(_))
        ));
    }

    #[test]
    fn ordinary_push_and_attribute_frames_remain_out_of_band() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = RedisResponseLifecycle::from_request(b"*1\r\n$4\r\nPING\r\n", &config)
            .expect("ping starts lifecycle");

        assert_eq!(
            lifecycle.observe_response(b">2\r\n+notice\r\n+value\r\n", &config),
            Ok(RedisResponseProgress::Continue)
        );
        assert_eq!(
            lifecycle.observe_response(b"|1\r\n+meta\r\n+value\r\n", &config),
            Ok(RedisResponseProgress::Continue)
        );
        assert!(matches!(
            lifecycle.observe_response(b"+PONG\r\n", &config),
            Ok(RedisResponseProgress::Complete(_))
        ));
    }

    #[test]
    fn zero_argument_unsubscribe_is_not_fifo_correlated() {
        let config = ProtocolExtractionConfig::default();
        let lifecycle =
            RedisResponseLifecycle::from_request(b"*1\r\n$11\r\nUNSUBSCRIBE\r\n", &config)
                .expect("unsubscribe command parses");

        assert!(!lifecycle.expects_response());
    }

    #[test]
    fn subscription_error_is_terminal() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = RedisResponseLifecycle::from_request(SUBSCRIBE_TWO, &config)
            .expect("subscribe starts lifecycle");

        assert!(matches!(
            lifecycle.observe_response(b"-ERR subscription rejected\r\n", &config),
            Ok(RedisResponseProgress::Complete(ParsedRedisResponse {
                error_type: Some(_),
                ..
            }))
        ));
    }
}
