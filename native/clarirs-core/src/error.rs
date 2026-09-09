use std::sync::PoisonError;

use clarirs_num::BitVecError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClarirsError {
    #[error("Cache lock poisoned")]
    CacheLockPoisoned,
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),
    #[error("Division by zero error")]
    DivisionByZero,
    #[error("Invalid extract bounds: upper: {upper}, lower: {lower}, length: {length}")]
    InvalidExtractBounds { upper: u32, lower: u32, length: u32 },
    #[error("BitVector length {size} must be a multiple of {bits}.")]
    InvalidChopSize { size: u32, bits: u32 },
    #[error("Type error: {:?}", .0)]
    TypeError(String),
    #[error("BitVector not byte-sized: {length:?} is not a multiple of 8")]
    BitVectorNotByteSized { length: u32 },
    #[error("BitVector lengths must match: {left} != {right}")]
    MismatchedLengths { left: u32, right: u32 },
    #[error("Conversion error: {:?}", .0)]
    ConversionError(String),
    #[error("UNSAT")]
    Unsat,
    #[error("Solver returned unknown: {0}")]
    SolverUnknown(String),
    #[error("Empty traversal result")]
    EmptyTraversal,
    #[error("Backend error ({0}): {1}")]
    BackendError(&'static str, String),
    #[error("Missing child at index {0}")]
    MissingChild(usize),
}

impl<T> From<PoisonError<T>> for ClarirsError {
    fn from(_: PoisonError<T>) -> Self {
        ClarirsError::CacheLockPoisoned
    }
}

impl From<BitVecError> for ClarirsError {
    fn from(e: BitVecError) -> Self {
        match e {
            BitVecError::BitVectorNotByteSized { length } => {
                ClarirsError::BitVectorNotByteSized { length }
            }
            BitVecError::InvalidExtractBounds {
                upper,
                lower,
                length,
            } => ClarirsError::InvalidExtractBounds {
                upper,
                lower,
                length,
            },
            BitVecError::InvalidChopSize { size, bits } => {
                ClarirsError::InvalidChopSize { size, bits }
            }
            BitVecError::DivisionByZero => ClarirsError::DivisionByZero,
            BitVecError::ConversionError => {
                ClarirsError::ConversionError("BitVec conversion error".to_string())
            }
            BitVecError::MismatchedLengths { left, right } => {
                ClarirsError::MismatchedLengths { left, right }
            }
        }
    }
}
