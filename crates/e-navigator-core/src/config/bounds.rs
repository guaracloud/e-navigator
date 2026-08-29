use std::fmt::Display;

use super::{ConfigError, ConfigResult};

pub(super) fn validate_inclusive<T>(
    path: &'static str,
    value: T,
    minimum: T,
    maximum: T,
) -> ConfigResult<()>
where
    T: Copy + Display + PartialOrd,
{
    if value < minimum || value > maximum {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must be between {minimum} and {maximum}"),
        ));
    }
    Ok(())
}

pub(super) fn validate_nonzero_bounded<T>(
    path: &'static str,
    value: T,
    maximum: T,
) -> ConfigResult<()>
where
    T: Copy + Display + From<u8> + PartialOrd,
{
    if value < T::from(1) {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must be greater than zero"),
        ));
    }
    if value > maximum {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must be less than or equal to {maximum}"),
        ));
    }
    Ok(())
}
