use super::{
    ParsedPostgresResponse, PostgresExtraction, ProtocolExtractionConfig, frame_body,
    merge_unique_attributes, parse_postgres_message, parse_postgres_response,
    parse_postgres_startup_message,
};

/// Bounded response state for PostgreSQL session startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresStartupLifecycle;

/// Observable progress of a PostgreSQL startup response sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresStartupProgress {
    Continue,
    Complete(ParsedPostgresResponse),
}

/// Bounded response state for one PostgreSQL simple-query command cycle.
///
/// A Query message can contain multiple SQL statements. `CommandComplete` and
/// `ErrorResponse` therefore do not end the frontend command cycle;
/// `ReadyForQuery` does. The first error is retained without its message text
/// and emitted only when readiness closes the cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresSimpleQueryLifecycle {
    pending_error: Option<ParsedPostgresResponse>,
}

/// Observable progress of one PostgreSQL simple-query response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresSimpleQueryProgress {
    Continue,
    Complete(ParsedPostgresResponse),
}

/// Bounded response state for one typed PostgreSQL frontend message.
///
/// PostgreSQL assigns different terminal backend messages to Parse, Bind,
/// Describe, Execute, Close, Sync, authentication, and the legacy function
/// call cycle. Keeping that distinction here prevents a payload frame or a
/// later pipeline response from being attributed to the wrong request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresRequestLifecycle {
    kind: PostgresRequestKind,
    phase: PostgresRequestPhase,
    pending_response: Option<ParsedPostgresResponse>,
}

/// Observable progress for one typed PostgreSQL frontend message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresRequestProgress {
    Continue,
    Complete {
        response: ParsedPostgresResponse,
        /// Extended-query errors make the backend discard subsequent
        /// frontend messages until the next Sync message.
        discard_until_sync: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresRequestKind {
    Parse,
    Bind,
    DescribeStatement,
    DescribePortal,
    Close,
    Execute,
    FunctionCall,
    Password,
    Sync,
    NoResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresRequestPhase {
    Initial,
    ParameterDescription,
}

impl PostgresStartupLifecycle {
    /// Creates lifecycle state from a protocol 3.0 `StartupMessage`.
    pub fn from_request(
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<Self, PostgresExtraction> {
        let startup = parse_postgres_startup_message(bytes, config)?;
        if startup.kind != super::PostgresStartupKind::Startup {
            return Err(PostgresExtraction::UnsupportedMessage);
        }
        Ok(Self)
    }

    /// Consumes one backend startup frame without retaining authentication,
    /// parameter, notice, or backend-key values.
    pub fn observe_response(
        &mut self,
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<PostgresStartupProgress, PostgresExtraction> {
        let response = parse_postgres_response(bytes, config)?;
        match bytes.first() {
            Some(b'E' | b'Z') => Ok(PostgresStartupProgress::Complete(response)),
            Some(b'K' | b'N' | b'R' | b'S' | b'v') => Ok(PostgresStartupProgress::Continue),
            Some(_) => Err(PostgresExtraction::UnexpectedMessage),
            None => Err(PostgresExtraction::MalformedFrame),
        }
    }
}

impl PostgresSimpleQueryLifecycle {
    /// Creates lifecycle state from one complete frontend Query frame.
    pub fn from_request(
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<Self, PostgresExtraction> {
        if bytes.first() != Some(&b'Q') {
            return Err(PostgresExtraction::UnsupportedMessage);
        }
        parse_postgres_message(bytes, config)?;
        Ok(Self {
            pending_error: None,
        })
    }

    /// Consumes one complete backend frame without retaining response text.
    pub fn observe_response(
        &mut self,
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<PostgresSimpleQueryProgress, PostgresExtraction> {
        let response = parse_postgres_response(bytes, config)?;
        match bytes.first() {
            Some(b'E') if self.pending_error.is_none() => {
                self.pending_error = Some(response);
                Ok(PostgresSimpleQueryProgress::Continue)
            }
            Some(b'E') => Err(PostgresExtraction::UnexpectedMessage),
            Some(b'Z') => {
                let response = match self.pending_error.take() {
                    Some(mut error) => {
                        merge_unique_attributes(
                            &mut error.attributes,
                            response.attributes,
                            config.max_attributes,
                        );
                        error
                    }
                    None => response,
                };
                Ok(PostgresSimpleQueryProgress::Complete(response))
            }
            Some(_) => Ok(PostgresSimpleQueryProgress::Continue),
            None => Err(PostgresExtraction::MalformedFrame),
        }
    }
}

impl PostgresRequestLifecycle {
    /// Creates lifecycle state from one complete, non-Query frontend frame.
    pub fn from_request(
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<Self, PostgresExtraction> {
        parse_postgres_message(bytes, config)?;
        let kind = match bytes.first() {
            Some(b'P') => PostgresRequestKind::Parse,
            Some(b'B') => PostgresRequestKind::Bind,
            Some(b'D') => match frame_body(bytes, config.max_header_bytes)?.first() {
                Some(b'S') => PostgresRequestKind::DescribeStatement,
                Some(b'P') => PostgresRequestKind::DescribePortal,
                _ => return Err(PostgresExtraction::MalformedFrame),
            },
            Some(b'C') => PostgresRequestKind::Close,
            Some(b'E') => PostgresRequestKind::Execute,
            Some(b'F') => PostgresRequestKind::FunctionCall,
            Some(b'p') => PostgresRequestKind::Password,
            Some(b'S') => PostgresRequestKind::Sync,
            Some(b'd' | b'c' | b'f' | b'H' | b'X') => PostgresRequestKind::NoResponse,
            Some(b'Q') => return Err(PostgresExtraction::UnsupportedMessage),
            Some(_) => return Err(PostgresExtraction::UnsupportedMessage),
            None => return Err(PostgresExtraction::MalformedFrame),
        };
        Ok(Self {
            kind,
            phase: PostgresRequestPhase::Initial,
            pending_response: None,
        })
    }

    /// Whether the frontend message has a distinct backend response.
    #[must_use]
    pub fn expects_response(&self) -> bool {
        self.kind != PostgresRequestKind::NoResponse
    }

    /// Whether this message is the extended-query resynchronization point.
    #[must_use]
    pub fn is_sync(&self) -> bool {
        self.kind == PostgresRequestKind::Sync
    }

    /// Consumes one complete backend frame without retaining response data.
    pub fn observe_response(
        &mut self,
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<PostgresRequestProgress, PostgresExtraction> {
        let response = parse_postgres_response(bytes, config)?;
        let message_type = *bytes.first().ok_or(PostgresExtraction::MalformedFrame)?;

        if matches!(message_type, b'A' | b'K' | b'N' | b'S') {
            return Ok(PostgresRequestProgress::Continue);
        }

        if message_type == b'E' {
            return match self.kind {
                PostgresRequestKind::Parse
                | PostgresRequestKind::Bind
                | PostgresRequestKind::DescribeStatement
                | PostgresRequestKind::DescribePortal
                | PostgresRequestKind::Close
                | PostgresRequestKind::Execute => Ok(PostgresRequestProgress::Complete {
                    response,
                    discard_until_sync: true,
                }),
                PostgresRequestKind::FunctionCall | PostgresRequestKind::Sync => {
                    self.retain_cycle_response(response)?;
                    Ok(PostgresRequestProgress::Continue)
                }
                PostgresRequestKind::Password => Ok(PostgresRequestProgress::Complete {
                    response,
                    discard_until_sync: false,
                }),
                PostgresRequestKind::NoResponse => Err(PostgresExtraction::UnexpectedMessage),
            };
        }

        match self.kind {
            PostgresRequestKind::Parse if message_type == b'1' => {
                Ok(complete_postgres_request(response))
            }
            PostgresRequestKind::Bind if message_type == b'2' => {
                Ok(complete_postgres_request(response))
            }
            PostgresRequestKind::DescribeStatement => {
                self.observe_statement_description(message_type, response)
            }
            PostgresRequestKind::DescribePortal if matches!(message_type, b'T' | b'n') => {
                Ok(complete_postgres_request(response))
            }
            PostgresRequestKind::Close if message_type == b'3' => {
                Ok(complete_postgres_request(response))
            }
            PostgresRequestKind::Execute if matches!(message_type, b'C' | b'I' | b's') => {
                Ok(complete_postgres_request(response))
            }
            PostgresRequestKind::Execute
                if matches!(message_type, b'D' | b'G' | b'H' | b'W' | b'c' | b'd') =>
            {
                Ok(PostgresRequestProgress::Continue)
            }
            PostgresRequestKind::FunctionCall if message_type == b'V' => {
                self.retain_cycle_response(response)?;
                Ok(PostgresRequestProgress::Continue)
            }
            PostgresRequestKind::FunctionCall | PostgresRequestKind::Sync
                if message_type == b'Z' =>
            {
                self.complete_cycle(response, config.max_attributes)
            }
            PostgresRequestKind::Password if message_type == b'R' => {
                Ok(complete_postgres_request(response))
            }
            _ => Err(PostgresExtraction::UnexpectedMessage),
        }
    }

    fn observe_statement_description(
        &mut self,
        message_type: u8,
        response: ParsedPostgresResponse,
    ) -> Result<PostgresRequestProgress, PostgresExtraction> {
        match (self.phase, message_type) {
            (PostgresRequestPhase::Initial, b't') => {
                self.phase = PostgresRequestPhase::ParameterDescription;
                Ok(PostgresRequestProgress::Continue)
            }
            (PostgresRequestPhase::ParameterDescription, b'T' | b'n') => {
                Ok(complete_postgres_request(response))
            }
            _ => Err(PostgresExtraction::UnexpectedMessage),
        }
    }

    fn retain_cycle_response(
        &mut self,
        response: ParsedPostgresResponse,
    ) -> Result<(), PostgresExtraction> {
        if self.pending_response.is_some() {
            return Err(PostgresExtraction::UnexpectedMessage);
        }
        self.pending_response = Some(response);
        Ok(())
    }

    fn complete_cycle(
        &mut self,
        ready: ParsedPostgresResponse,
        max_attributes: usize,
    ) -> Result<PostgresRequestProgress, PostgresExtraction> {
        let response = match self.kind {
            PostgresRequestKind::Sync => match self.pending_response.take() {
                Some(mut pending) => {
                    merge_unique_attributes(
                        &mut pending.attributes,
                        ready.attributes,
                        max_attributes,
                    );
                    pending
                }
                None => ready,
            },
            PostgresRequestKind::FunctionCall => {
                let Some(mut pending) = self.pending_response.take() else {
                    return Err(PostgresExtraction::UnexpectedMessage);
                };
                merge_unique_attributes(&mut pending.attributes, ready.attributes, max_attributes);
                pending
            }
            _ => return Err(PostgresExtraction::UnexpectedMessage),
        };
        Ok(complete_postgres_request(response))
    }
}

fn complete_postgres_request(response: ParsedPostgresResponse) -> PostgresRequestProgress {
    PostgresRequestProgress::Complete {
        response,
        discard_until_sync: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(message_type: u8, body: &[u8]) -> Vec<u8> {
        let length = u32::try_from(body.len() + 4)
            .expect("test frame length fits u32")
            .to_be_bytes();
        let mut frame = Vec::with_capacity(body.len() + 5);
        frame.push(message_type);
        frame.extend_from_slice(&length);
        frame.extend_from_slice(body);
        frame
    }

    fn simple_query() -> Vec<u8> {
        frame(b'Q', b"SELECT 1\0")
    }

    fn execute() -> Vec<u8> {
        frame(b'E', &[0, 0, 0, 0, 0])
    }

    #[test]
    fn simple_query_completes_only_at_ready_for_query() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = PostgresSimpleQueryLifecycle::from_request(&simple_query(), &config)
            .expect("query starts lifecycle");

        assert_eq!(
            lifecycle.observe_response(&frame(b'C', b"SELECT 1\0"), &config),
            Ok(PostgresSimpleQueryProgress::Continue)
        );
        assert!(matches!(
            lifecycle.observe_response(&frame(b'Z', b"I"), &config),
            Ok(PostgresSimpleQueryProgress::Complete(_))
        ));
    }

    #[test]
    fn execute_retains_data_rows_until_command_complete() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = PostgresRequestLifecycle::from_request(&execute(), &config)
            .expect("execute starts lifecycle");

        assert_eq!(
            lifecycle.observe_response(&frame(b'D', &[0, 0]), &config),
            Ok(PostgresRequestProgress::Continue)
        );
        assert!(matches!(
            lifecycle.observe_response(&frame(b'C', b"SELECT 1\0"), &config),
            Ok(PostgresRequestProgress::Complete {
                discard_until_sync: false,
                ..
            })
        ));
    }

    #[test]
    fn extended_query_error_requests_discard_until_sync() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle = PostgresRequestLifecycle::from_request(&execute(), &config)
            .expect("execute starts lifecycle");
        let error = [
            b'S', b'E', b'R', b'R', b'O', b'R', 0, b'C', b'2', b'3', b'5', b'0', b'5', 0, 0,
        ];

        assert!(matches!(
            lifecycle.observe_response(&frame(b'E', &error), &config),
            Ok(PostgresRequestProgress::Complete {
                discard_until_sync: true,
                ..
            })
        ));
    }

    #[test]
    fn copy_data_has_no_distinct_response() {
        let config = ProtocolExtractionConfig::default();
        let lifecycle = PostgresRequestLifecycle::from_request(&frame(b'd', b"payload"), &config)
            .expect("copy data starts lifecycle");

        assert!(!lifecycle.expects_response());
    }
}
