use super::{ConfigError, ConfigResult};

pub(super) fn validate_protocol_ports<'a>(
    surface: &'static str,
    lists: impl IntoIterator<Item = (&'static str, &'a [u16])>,
    field_for_protocol: fn(&str) -> &'static str,
    max_total_ports: usize,
) -> ConfigResult<()> {
    let mut seen_ports = std::collections::BTreeMap::new();
    let mut total_ports = 0_usize;
    for (protocol, ports) in lists {
        let field = field_for_protocol(protocol);
        for port in ports {
            if *port == 0 {
                return Err(ConfigError::invalid_value(
                    field,
                    format!("{field} must not contain port 0"),
                ));
            }
            if let Some(existing) = seen_ports.insert(*port, protocol) {
                return Err(ConfigError::invalid_value(
                    field,
                    format!(
                        "port {port} is assigned to both {existing} and {protocol}; each port must map to exactly one protocol"
                    ),
                ));
            }
            total_ports += 1;
        }
    }
    if total_ports > max_total_ports {
        let message = format!(
            "{surface} port lists declare {total_ports} ports; at most {max_total_ports} are supported"
        );
        return Err(ConfigError::invalid_value(surface, message));
    }
    Ok(())
}
