use std::fmt;

pub type ConfigResult<T> = Result<T, ConfigError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    field: &'static str,
    category: ConfigErrorKind,
    message: String,
}

impl ConfigError {
    pub fn invalid_value(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            category: ConfigErrorKind::InvalidValue,
            message: message.into(),
        }
    }

    pub fn invalid_reference(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            category: ConfigErrorKind::InvalidReference,
            message: message.into(),
        }
    }

    pub fn field(&self) -> &'static str {
        self.field
    }

    pub fn category(&self) -> ConfigErrorKind {
        self.category
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorKind {
    InvalidValue,
    InvalidReference,
}
