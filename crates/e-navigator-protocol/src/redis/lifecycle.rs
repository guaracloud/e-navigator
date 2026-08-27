use crate::ProtocolExtractionConfig;

use super::{
    ParsedRedisResponse, RedisExtraction, RedisResponseRole, RedisSubscriptionKind,
    RedisSubscriptionState, parse_redis_command_frame, parse_redis_response,
    parse_redis_subscription_confirmation, redis_connection_response_role,
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
    Continue {
        subscription_state: Option<RedisSubscriptionState>,
    },
    Complete {
        response: ParsedRedisResponse,
        subscription_state: Option<RedisSubscriptionState>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedisResponseKind {
    Standard,
    Reset,
    SubscriptionConfirmations {
        kind: RedisSubscriptionKind,
        remaining: usize,
    },
    NoCorrelatedResponse(RedisSubscriptionKind),
}

impl RedisResponseLifecycle {
    /// Creates lifecycle state from one complete Redis command frame.
    pub fn from_request(
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<Self, RedisExtraction> {
        let frame = parse_redis_command_frame(bytes, config)?;
        let command = frame.command.as_deref().unwrap_or_default();
        let kind = if command.eq_ignore_ascii_case("RESET") && frame.argument_count == 0 {
            RedisResponseKind::Reset
        } else {
            match subscription_kind(command) {
                Some((kind, true)) if frame.argument_count == 0 => {
                    RedisResponseKind::NoCorrelatedResponse(kind)
                }
                Some((kind, _)) if frame.argument_count > 0 => {
                    RedisResponseKind::SubscriptionConfirmations {
                        kind,
                        remaining: frame.argument_count,
                    }
                }
                _ => RedisResponseKind::Standard,
            }
        };
        Ok(Self { kind })
    }

    /// Whether this command has a response that can be correlated safely.
    #[must_use]
    pub fn expects_response(&self) -> bool {
        !matches!(self.kind, RedisResponseKind::NoCorrelatedResponse(_))
    }

    /// Returns a connection-state transition only when this request lifecycle
    /// owns the exact subscription confirmation.
    ///
    /// Ordinary command results are allowed to have the same array shape and
    /// must never change connection state. Zero-argument unsubscribe commands
    /// have no provable terminal confirmation when other subscription kinds
    /// remain, so callers must fail that connection state closed.
    fn subscription_state_update(
        &self,
        bytes: &[u8],
    ) -> Result<Option<RedisSubscriptionState>, RedisExtraction> {
        let expected = match self.kind {
            RedisResponseKind::SubscriptionConfirmations { kind, .. }
            | RedisResponseKind::NoCorrelatedResponse(kind) => kind,
            RedisResponseKind::Reset => {
                return Ok(bytes
                    .eq_ignore_ascii_case(b"+RESET\r\n")
                    .then_some(RedisSubscriptionState::None));
            }
            RedisResponseKind::Standard => return Ok(None),
        };
        let Some(confirmation) = parse_redis_subscription_confirmation(bytes)? else {
            return Ok(None);
        };
        if confirmation.kind != expected {
            return Ok(None);
        }
        if !confirmation.has_name {
            return Err(RedisExtraction::MalformedFrame);
        }
        Ok(Some(confirmation.state))
    }

    /// Consumes one complete Redis server frame without retaining its values.
    pub fn observe_response(
        &mut self,
        bytes: &[u8],
        subscription_state: RedisSubscriptionState,
        config: &ProtocolExtractionConfig,
    ) -> Result<RedisResponseProgress, RedisExtraction> {
        if matches!(self.kind, RedisResponseKind::NoCorrelatedResponse(_)) {
            return Err(RedisExtraction::UnsupportedFrame);
        }

        let role = redis_connection_response_role(bytes, subscription_state)?;
        let response = parse_redis_response(bytes, config)?;
        let subscription_update = self.subscription_state_update(bytes)?;

        match self.kind {
            RedisResponseKind::Standard | RedisResponseKind::Reset => {
                if role == RedisResponseRole::Reply {
                    Ok(RedisResponseProgress::Complete {
                        response,
                        subscription_state: subscription_update,
                    })
                } else {
                    Ok(RedisResponseProgress::Continue {
                        subscription_state: None,
                    })
                }
            }
            RedisResponseKind::SubscriptionConfirmations {
                ref mut remaining, ..
            } => {
                if response.error_type.is_some() {
                    return Ok(RedisResponseProgress::Complete {
                        response,
                        subscription_state: None,
                    });
                }
                if subscription_update.is_none() {
                    return Ok(RedisResponseProgress::Continue {
                        subscription_state: None,
                    });
                }
                *remaining = remaining
                    .checked_sub(1)
                    .ok_or(RedisExtraction::MalformedFrame)?;
                if *remaining == 0 {
                    Ok(RedisResponseProgress::Complete {
                        response,
                        subscription_state: subscription_update,
                    })
                } else {
                    Ok(RedisResponseProgress::Continue {
                        subscription_state: subscription_update,
                    })
                }
            }
            RedisResponseKind::NoCorrelatedResponse(_) => Err(RedisExtraction::UnsupportedFrame),
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
            lifecycle.observe_response(
                b">3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Continue {
                subscription_state: Some(RedisSubscriptionState::Resp3),
            })
        );
        assert!(matches!(
            lifecycle.observe_response(
                b">3\r\n$9\r\nsubscribe\r\n$1\r\nb\r\n:2\r\n",
                RedisSubscriptionState::Resp3,
                &config,
            ),
            Ok(RedisResponseProgress::Complete {
                subscription_state: Some(RedisSubscriptionState::Resp3),
                ..
            })
        ));
    }

    #[test]
    fn resp2_subscription_confirmation_is_correlated() {
        let config = ProtocolExtractionConfig::default();
        let request = b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n";
        let mut lifecycle = RedisResponseLifecycle::from_request(request, &config)
            .expect("subscribe starts lifecycle");

        assert!(matches!(
            lifecycle.observe_response(
                b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Complete {
                subscription_state: Some(RedisSubscriptionState::Resp2),
                ..
            })
        ));
    }

    #[test]
    fn malformed_subscribe_confirmations_do_not_advance_the_lifecycle() {
        let config = ProtocolExtractionConfig::default();
        let request = b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n";
        let mut lifecycle = RedisResponseLifecycle::from_request(request, &config)
            .expect("subscribe starts lifecycle");

        for malformed in [
            b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:0\r\n".as_slice(),
            b"*3\r\n$9\r\nsubscribe\r\n$-1\r\n:1\r\n".as_slice(),
        ] {
            assert_eq!(
                lifecycle.observe_response(malformed, RedisSubscriptionState::None, &config),
                Err(RedisExtraction::MalformedFrame)
            );
        }

        assert!(matches!(
            lifecycle.observe_response(
                b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Complete { .. })
        ));
    }

    #[test]
    fn explicit_unsubscribe_requires_a_named_confirmation() {
        let config = ProtocolExtractionConfig::default();
        let request = b"*2\r\n$11\r\nUNSUBSCRIBE\r\n$1\r\na\r\n";
        let mut lifecycle = RedisResponseLifecycle::from_request(request, &config)
            .expect("unsubscribe starts lifecycle");

        assert_eq!(
            lifecycle.observe_response(
                b"*3\r\n$11\r\nunsubscribe\r\n$-1\r\n:0\r\n",
                RedisSubscriptionState::Resp2,
                &config,
            ),
            Err(RedisExtraction::MalformedFrame)
        );
        assert!(matches!(
            lifecycle.observe_response(
                b"*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:0\r\n",
                RedisSubscriptionState::Resp2,
                &config,
            ),
            Ok(RedisResponseProgress::Complete {
                subscription_state: Some(RedisSubscriptionState::None),
                ..
            })
        ));
    }

    #[test]
    fn mismatched_subscription_confirmation_does_not_advance_the_lifecycle() {
        let config = ProtocolExtractionConfig::default();
        let request = b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n";
        let mut lifecycle = RedisResponseLifecycle::from_request(request, &config)
            .expect("subscribe starts lifecycle");

        assert_eq!(
            lifecycle.observe_response(
                b"*3\r\n$10\r\npsubscribe\r\n$1\r\na\r\n:1\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Continue {
                subscription_state: None,
            })
        );
        assert!(matches!(
            lifecycle.observe_response(
                b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Complete { .. })
        ));
    }

    #[test]
    fn ordinary_push_and_attribute_frames_remain_out_of_band() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = RedisResponseLifecycle::from_request(b"*1\r\n$4\r\nPING\r\n", &config)
            .expect("ping starts lifecycle");

        assert_eq!(
            lifecycle.observe_response(
                b">2\r\n+notice\r\n+value\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Continue {
                subscription_state: None,
            })
        );
        assert_eq!(
            lifecycle.observe_response(
                b"|1\r\n+meta\r\n+value\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Continue {
                subscription_state: None,
            })
        );
        assert!(matches!(
            lifecycle.observe_response(b"+PONG\r\n", RedisSubscriptionState::None, &config),
            Ok(RedisResponseProgress::Complete {
                subscription_state: None,
                ..
            })
        ));
    }

    #[test]
    fn ordinary_confirmation_shaped_array_completes_the_standard_command() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle =
            RedisResponseLifecycle::from_request(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n", &config)
                .expect("get starts lifecycle");

        assert!(matches!(
            lifecycle.observe_response(
                b"*3\r\n$9\r\nsubscribe\r\n$7\r\nchannel\r\n:1\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Complete {
                subscription_state: None,
                ..
            })
        ));
    }

    #[test]
    fn zero_argument_unsubscribe_forms_are_not_fifo_correlated() {
        let config = ProtocolExtractionConfig::default();
        for request in [
            b"*1\r\n$11\r\nUNSUBSCRIBE\r\n".as_slice(),
            b"*1\r\n$12\r\nPUNSUBSCRIBE\r\n".as_slice(),
            b"*1\r\n$12\r\nSUNSUBSCRIBE\r\n".as_slice(),
        ] {
            let lifecycle = RedisResponseLifecycle::from_request(request, &config)
                .expect("unsubscribe command parses");
            assert!(!lifecycle.expects_response());
        }
    }

    #[test]
    fn reset_response_proves_the_connection_left_subscription_mode() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = RedisResponseLifecycle::from_request(b"*1\r\n$5\r\nRESET\r\n", &config)
            .expect("reset command parses");

        assert!(matches!(
            lifecycle.observe_response(b"+RESET\r\n", RedisSubscriptionState::Resp2, &config),
            Ok(RedisResponseProgress::Complete {
                subscription_state: Some(RedisSubscriptionState::None),
                ..
            })
        ));
    }

    #[test]
    fn failed_or_malformed_reset_does_not_claim_a_state_transition() {
        let config = ProtocolExtractionConfig::default();
        let request = b"*1\r\n$5\r\nRESET\r\n";
        let mut rejected =
            RedisResponseLifecycle::from_request(request, &config).expect("reset command parses");
        assert!(matches!(
            rejected.observe_response(
                b"-ERR reset rejected\r\n",
                RedisSubscriptionState::Resp2,
                &config,
            ),
            Ok(RedisResponseProgress::Complete {
                response: ParsedRedisResponse {
                    error_type: Some(_),
                    ..
                },
                subscription_state: None,
            })
        ));

        let mut malformed =
            RedisResponseLifecycle::from_request(request, &config).expect("reset command parses");
        assert_eq!(
            malformed.observe_response(b"+RESET", RedisSubscriptionState::Resp2, &config,),
            Err(RedisExtraction::MalformedFrame)
        );
    }

    #[test]
    fn subscription_error_is_terminal() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = RedisResponseLifecycle::from_request(SUBSCRIBE_TWO, &config)
            .expect("subscribe starts lifecycle");

        assert!(matches!(
            lifecycle.observe_response(
                b"-ERR subscription rejected\r\n",
                RedisSubscriptionState::None,
                &config,
            ),
            Ok(RedisResponseProgress::Complete {
                response: ParsedRedisResponse {
                    error_type: Some(_),
                    ..
                },
                subscription_state: None,
            })
        ));
    }
}
