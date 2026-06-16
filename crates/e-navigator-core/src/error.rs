use thiserror::Error;

use crate::ConfigError;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid config: {0}")]
    InvalidConfig(#[from] ConfigError),

    #[error("module failed: {module}: {message}")]
    ModuleFailed { module: String, message: String },

    #[error("pipeline closed")]
    PipelineClosed,
}
