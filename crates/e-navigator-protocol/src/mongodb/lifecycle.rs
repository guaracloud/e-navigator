use super::{
    MongodbExtraction, ParsedMongodbCommand, ParsedMongodbResponse, ProtocolExtractionConfig,
    parse_mongodb_message,
};

/// Bounded response state for one MongoDB request.
///
/// Ordinary requests complete on one response. Fire-and-forget `OP_MSG`
/// requests complete immediately, while exhaust requests retain the original
/// request until a response clears `moreToCome`. Only a first error outcome is
/// retained; response documents and raw error text never enter lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongodbResponseLifecycle {
    request_id: i32,
    kind: MongodbResponseKind,
    first_error: Option<ParsedMongodbResponse>,
}

/// Observable progress through one MongoDB request's response stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MongodbResponseProgress {
    Continue,
    Complete(ParsedMongodbResponse),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MongodbResponseKind {
    Single,
    Exhaust,
    NoResponse,
}

impl MongodbResponseLifecycle {
    /// Creates lifecycle state from one complete MongoDB request frame.
    pub fn from_request(
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<Self, MongodbExtraction> {
        Self::from_command(parse_mongodb_message(bytes, config)?)
    }

    fn from_command(command: ParsedMongodbCommand) -> Result<Self, MongodbExtraction> {
        let kind = if !command.expects_response {
            MongodbResponseKind::NoResponse
        } else if command.allows_multiple_responses {
            MongodbResponseKind::Exhaust
        } else {
            MongodbResponseKind::Single
        };
        Ok(Self {
            request_id: command.request_id,
            kind,
            first_error: None,
        })
    }

    /// Wire request identifier used by every response in this lifecycle.
    #[must_use]
    pub fn request_id(&self) -> i32 {
        self.request_id
    }

    /// Whether this request can be correlated with a server response.
    #[must_use]
    pub fn expects_response(&self) -> bool {
        self.kind != MongodbResponseKind::NoResponse
    }

    /// Consumes one parsed response without retaining its BSON document.
    pub fn observe_response(
        &mut self,
        response: ParsedMongodbResponse,
    ) -> Result<MongodbResponseProgress, MongodbExtraction> {
        if !self.expects_response()
            || response.response_to != self.request_id
            || (response.more_to_come && self.kind != MongodbResponseKind::Exhaust)
        {
            return Err(MongodbExtraction::UnexpectedResponse);
        }

        if response.error_type.is_some() && self.first_error.is_none() {
            self.first_error = Some(response.clone());
        }
        if response.more_to_come {
            return Ok(MongodbResponseProgress::Continue);
        }

        Ok(MongodbResponseProgress::Complete(
            self.first_error.take().unwrap_or(response),
        ))
    }
}
