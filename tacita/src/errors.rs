use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TacitaError {
    MissingRegistration { role: &'static str },

    InvalidState { message: &'static str },

    Validation { message: &'static str },

    Primitive {
        primitive: &'static str,
        source: String,
    },

    VersionSplitBlocked { details: &'static str },

    NotYetImplemented { stage: &'static str },
}

impl Display for TacitaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRegistration { role } => {
                write!(f, "missing registration material for {role}")
            }
            Self::InvalidState { message } => write!(f, "invalid protocol state: {message}"),
            Self::Validation { message } => write!(f, "validation failed: {message}"),
            Self::Primitive { primitive, source } => {
                write!(f, "primitive backend `{primitive}` failed: {source}")
            }
            Self::VersionSplitBlocked { details } => {
                write!(
                    f,
                    "integration blocked by the current arkworks version split: {details}"
                )
            }
            Self::NotYetImplemented { stage } => write!(f, "not yet implemented: {stage}"),
        }
    }
}

impl Error for TacitaError {}

impl TacitaError {
    pub fn primitive(primitive: &'static str, source: impl ToString) -> Self {
        Self::Primitive {
            primitive,
            source: source.to_string(),
        }
    }

    pub fn todo(stage: &'static str) -> Self {
        Self::NotYetImplemented { stage }
    }
}
