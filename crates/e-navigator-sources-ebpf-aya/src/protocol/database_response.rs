use super::*;

pub(super) struct DatabaseResponseContext<'a> {
    pub(super) extraction: &'a ProtocolExtractionConfig,
    pub(super) host: &'a Option<String>,
    pub(super) counters: &'a mut ProtocolRegistryCounters,
    pub(super) observed_unix_nanos: u64,
    pub(super) signals: &'a mut Vec<SignalEnvelope>,
}

/// Routes database frames that need protocol-specific lifecycle tracking.
///
/// Returning `true` means the frame belonged to one of these protocols even
/// when it was malformed or out of band. The generic FIFO matcher must not
/// process it again.
pub(super) fn handle_database_response(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    declared_len: u64,
    context: &mut DatabaseResponseContext<'_>,
) -> bool {
    match stream.protocol {
        StreamProtocol::Redis
            if stream.in_flight.is_empty()
                || stream
                    .in_flight
                    .front()
                    .is_some_and(|entry| entry.redis_response.is_some()) =>
        {
            handle_redis_response(stream, frame, truncated, context);
        }
        StreamProtocol::Mysql
            if stream.in_flight.is_empty()
                || stream
                    .in_flight
                    .front()
                    .is_some_and(|entry| entry.mysql_response.is_some()) =>
        {
            handle_mysql_response(stream, frame, truncated, declared_len, context);
        }
        StreamProtocol::Postgresql
            if stream
                .in_flight
                .front()
                .is_some_and(|entry| entry.postgres_startup_response.is_some()) =>
        {
            handle_postgres_startup_response(stream, frame, truncated, context);
        }
        StreamProtocol::Postgresql
            if stream
                .in_flight
                .front()
                .is_some_and(|entry| entry.postgres_simple_response.is_some()) =>
        {
            handle_postgres_simple_query_response(stream, frame, truncated, context);
        }
        StreamProtocol::Postgresql
            if stream
                .in_flight
                .front()
                .is_some_and(|entry| entry.postgres_request_response.is_some()) =>
        {
            handle_postgres_request_response(stream, frame, truncated, context);
        }
        _ => return false,
    }
    true
}

/// Advances session startup through authentication and parameter setup, then
/// emits one CONNECT observation at ReadyForQuery (or ErrorResponse).
fn handle_postgres_startup_response(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    context: &mut DatabaseResponseContext<'_>,
) {
    if truncated {
        context.counters.unparsed_responses += 1;
        return;
    }
    let Some(lifecycle) = stream
        .in_flight
        .front_mut()
        .and_then(|entry| entry.postgres_startup_response.as_mut())
    else {
        context.counters.unparsed_responses += 1;
        return;
    };
    let response = match lifecycle.observe_response(frame, context.extraction) {
        Ok(PostgresStartupProgress::Continue) => {
            context.counters.response_continuations += 1;
            return;
        }
        Ok(PostgresStartupProgress::Complete(response)) => response,
        Err(_) => {
            context.counters.unparsed_responses += 1;
            return;
        }
    };
    let Some(entry) = stream.in_flight.pop_front() else {
        context.counters.orphan_responses += 1;
        return;
    };
    emit_completed_postgres_request(entry, response, &stream.context, context);
}

/// Advances the oldest Redis command while keeping unrelated RESP3 pushes and
/// attributes out of the FIFO queue. Explicit Pub/Sub subscriptions complete
/// only after every pushed acknowledgement has arrived.
fn handle_redis_response(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    context: &mut DatabaseResponseContext<'_>,
) {
    if truncated {
        context.counters.unparsed_responses += 1;
        return;
    }
    if stream.redis_transport_opaque {
        context.counters.unparsed_responses += 1;
        return;
    }
    if stream.in_flight.is_empty() {
        let role = match redis_connection_response_role(frame, stream.redis_subscription) {
            Ok(role) => role,
            Err(_) => {
                context.counters.unparsed_responses += 1;
                return;
            }
        };
        match role {
            RedisResponseRole::Push | RedisResponseRole::Attribute => {
                context.counters.response_continuations += 1;
            }
            RedisResponseRole::Reply => context.counters.orphan_responses += 1,
        }
        return;
    }
    let subscription_state = stream.redis_subscription;
    let Some(lifecycle) = stream
        .in_flight
        .front_mut()
        .and_then(|entry| entry.redis_response.as_mut())
    else {
        context.counters.unparsed_responses += 1;
        return;
    };
    let (response, subscription_update) =
        match lifecycle.observe_response(frame, subscription_state, context.extraction) {
            Ok(RedisResponseProgress::Continue { subscription_state }) => {
                if let Some(subscription) = subscription_state {
                    stream.redis_subscription = subscription;
                }
                context.counters.response_continuations += 1;
                return;
            }
            Ok(RedisResponseProgress::Complete {
                response,
                subscription_state,
            }) => (response, subscription_state),
            Err(_) => {
                context.counters.unparsed_responses += 1;
                return;
            }
        };
    if let Some(subscription) = subscription_update {
        stream.redis_subscription = subscription;
    }

    let Some(entry) = stream.in_flight.pop_front() else {
        context.counters.orphan_responses += 1;
        return;
    };
    emit_completed_request(
        entry,
        ParsedResponseFrame {
            protocol: None,
            signal_status_code: None,
            status_code: response.status_code,
            error_type: response.error_type,
            attributes: response.attributes,
        },
        &stream.context,
        context,
    );
}

/// Advances the lifecycle of the oldest MySQL command. Intermediate result
/// metadata and row packets retain the request; only a protocol-defined
/// terminal packet emits the correlated observation.
fn handle_mysql_response(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    declared_len: u64,
    context: &mut DatabaseResponseContext<'_>,
) {
    if stream.in_flight.is_empty() {
        context.counters.orphan_responses += 1;
        return;
    }
    let Some(lifecycle) = stream
        .in_flight
        .front_mut()
        .and_then(|entry| entry.mysql_response.as_mut())
    else {
        context.counters.unparsed_responses += 1;
        return;
    };
    let progress = if truncated {
        lifecycle.observe_response_prefix(frame, declared_len)
    } else {
        lifecycle.observe_packet(frame, context.extraction)
    };
    let response = match progress {
        Ok(MysqlResponseProgress::Continue) => {
            context.counters.response_continuations += 1;
            if truncated {
                context.counters.mysql_logical_response_continuations += 1;
            }
            return;
        }
        Ok(MysqlResponseProgress::Complete(response)) => response,
        Err(_) => {
            context.counters.unparsed_responses += 1;
            if truncated {
                context.counters.mysql_logical_sequence_failures += 1;
            }
            return;
        }
    };

    let Some(entry) = stream.in_flight.pop_front() else {
        context.counters.orphan_responses += 1;
        return;
    };
    emit_completed_request(
        entry,
        ParsedResponseFrame {
            protocol: None,
            signal_status_code: None,
            status_code: Some(response.status_code),
            error_type: response.error_type,
            attributes: response.attributes,
        },
        &stream.context,
        context,
    );
}

/// Advances a PostgreSQL simple-query cycle through every backend message and
/// emits only when `ReadyForQuery` closes the cycle.
fn handle_postgres_simple_query_response(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    context: &mut DatabaseResponseContext<'_>,
) {
    if frame.first() == Some(&b'E') {
        stream.postgres_copy_in = false;
    }
    if truncated {
        context.counters.unparsed_responses += 1;
        return;
    }

    let Some(lifecycle) = stream
        .in_flight
        .front_mut()
        .and_then(|entry| entry.postgres_simple_response.as_mut())
    else {
        context.counters.unparsed_responses += 1;
        return;
    };
    let response = match lifecycle.observe_response(frame, context.extraction) {
        Ok(PostgresSimpleQueryProgress::Continue) => {
            if frame.first() == Some(&b'G') {
                enter_postgres_copy_in(stream, context);
            }
            context.counters.response_continuations += 1;
            return;
        }
        Ok(PostgresSimpleQueryProgress::Complete(response)) => response,
        Err(_) => {
            context.counters.unparsed_responses += 1;
            return;
        }
    };

    let Some(entry) = stream.in_flight.pop_front() else {
        context.counters.orphan_responses += 1;
        return;
    };
    emit_completed_postgres_request(entry, response, &stream.context, context);
}

/// Advances one typed PostgreSQL request through its exact protocol terminal.
fn handle_postgres_request_response(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    context: &mut DatabaseResponseContext<'_>,
) {
    if frame.first() == Some(&b'E') {
        stream.postgres_copy_in = false;
    }
    if truncated {
        context.counters.unparsed_responses += 1;
        return;
    }

    let Some(lifecycle) = stream
        .in_flight
        .front_mut()
        .and_then(|entry| entry.postgres_request_response.as_mut())
    else {
        context.counters.unparsed_responses += 1;
        return;
    };
    let (response, discard_until_sync) = match lifecycle.observe_response(frame, context.extraction)
    {
        Ok(PostgresRequestProgress::Continue) => {
            if frame.first() == Some(&b'G') {
                enter_postgres_copy_in(stream, context);
            }
            context.counters.response_continuations += 1;
            return;
        }
        Ok(PostgresRequestProgress::Complete {
            response,
            discard_until_sync,
        }) => (response, discard_until_sync),
        Err(_) => {
            context.counters.unparsed_responses += 1;
            return;
        }
    };

    let Some(entry) = stream.in_flight.pop_front() else {
        context.counters.orphan_responses += 1;
        return;
    };
    emit_completed_postgres_request(entry, response, &stream.context, context);
    if discard_until_sync {
        discard_postgres_pipeline_until_sync(stream, context);
    }
}

fn enter_postgres_copy_in(
    stream: &mut ConnectionStream,
    context: &mut DatabaseResponseContext<'_>,
) {
    stream.postgres_copy_in = true;
    while stream.in_flight.len() > 1 {
        let is_ignored_sync = stream
            .in_flight
            .get(1)
            .and_then(|entry| entry.postgres_request_response.as_ref())
            .is_some_and(PostgresRequestLifecycle::is_sync);
        if !is_ignored_sync {
            break;
        }
        let _ignored = stream.in_flight.remove(1);
        context.counters.postgres_copy_ignored_controls += 1;
    }
}

fn discard_postgres_pipeline_until_sync(
    stream: &mut ConnectionStream,
    context: &mut DatabaseResponseContext<'_>,
) {
    while stream.in_flight.front().is_some_and(|entry| {
        !entry
            .postgres_request_response
            .as_ref()
            .is_some_and(PostgresRequestLifecycle::is_sync)
    }) {
        let Some(mut skipped) = stream.in_flight.pop_front() else {
            break;
        };
        skipped
            .parsed
            .warning
            .get_or_insert_with(|| POSTGRES_SKIPPED_AFTER_ERROR_WARNING.to_string());
        context.counters.postgres_skipped_requests += 1;
        context.signals.push(build_observation(
            context.host.clone(),
            &stream.context,
            skipped.parsed,
            skipped.started_unix_nanos,
            None,
        ));
    }
    stream.postgres_discarding_until_sync = stream.in_flight.front().is_none_or(|entry| {
        !entry
            .postgres_request_response
            .as_ref()
            .is_some_and(PostgresRequestLifecycle::is_sync)
    });
}

fn emit_completed_postgres_request(
    entry: InFlightRequest,
    response: e_navigator_protocol::postgres::ParsedPostgresResponse,
    stream_context: &ObservationContext,
    context: &mut DatabaseResponseContext<'_>,
) {
    emit_completed_request(
        entry,
        ParsedResponseFrame {
            protocol: None,
            signal_status_code: None,
            status_code: Some(response.status_code),
            error_type: response.error_type,
            attributes: response.attributes,
        },
        stream_context,
        context,
    );
}

fn emit_completed_request(
    entry: InFlightRequest,
    response: ParsedResponseFrame,
    stream_context: &ObservationContext,
    context: &mut DatabaseResponseContext<'_>,
) {
    let mut parsed = entry.parsed;
    context.counters.matched_responses += 1;
    merge_response_attributes(&mut parsed, &response, context.extraction.max_attributes);
    context.signals.push(build_observation(
        context.host.clone(),
        stream_context,
        parsed,
        entry.started_unix_nanos,
        Some(context.observed_unix_nanos),
    ));
}
