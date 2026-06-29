use crate::StridedInterval;
use crate::strided_interval::ComparisonResult;
use clarirs_core::prelude::*;

use super::ReduceResult;

fn child(children: &[ReduceResult], index: usize) -> Result<ComparisonResult, ClarirsError> {
    if let Some(ReduceResult::Bool(result)) = children.get(index) {
        Ok(result.clone())
    } else {
        Err(ClarirsError::InvalidArguments(format!(
            "Expected Bool at index {}, found {:?}",
            index,
            children.get(index)
        )))
    }
}

fn child_si(children: &[ReduceResult], index: usize) -> Result<StridedInterval, ClarirsError> {
    if let Some(ReduceResult::BitVec(result)) = children.get(index) {
        Ok(result.clone())
    } else {
        Err(ClarirsError::InvalidArguments(format!(
            "Expected BitVec at index {}, found {:?}",
            index,
            children.get(index)
        )))
    }
}

pub(crate) fn reduce_bool(
    ast: &AstRef<'_>,
    children: &[ReduceResult],
) -> Result<ComparisonResult, ClarirsError> {
    Ok(match ast.op() {
        AstOp::BoolS(..) => ComparisonResult::Maybe,
        AstOp::BoolV(v) => {
            if *v {
                ComparisonResult::True
            } else {
                ComparisonResult::False
            }
        }
        AstOp::Not(..) => !child(children, 0)?,
        AstOp::And(..) => {
            let mut result = ComparisonResult::True;
            for c in children {
                if let ReduceResult::Bool(b) = c {
                    result = result & b.clone();
                } else {
                    return Err(ClarirsError::InvalidArguments("Expected Bool".to_string()));
                }
            }
            result
        }
        AstOp::Or(..) => {
            let mut result = ComparisonResult::False;
            for c in children {
                if let ReduceResult::Bool(b) = c {
                    result = result | b.clone();
                } else {
                    return Err(ClarirsError::InvalidArguments("Expected Bool".to_string()));
                }
            }
            result
        }
        AstOp::Xor(..) => {
            let mut result = ComparisonResult::False;
            for c in children {
                if let ReduceResult::Bool(b) = c {
                    result = result ^ b.clone();
                } else {
                    return Err(ClarirsError::InvalidArguments("Expected Bool".to_string()));
                }
            }
            result
        }
        AstOp::Eq(a, _) => {
            if a.ast_type().is_bool() {
                child(children, 0)?.eq_(child(children, 1)?)
            } else {
                child_si(children, 0)?.eq_(&child_si(children, 1)?)
            }
        }
        AstOp::Neq(a, _) => {
            if a.ast_type().is_bool() {
                !child(children, 0)?.eq_(child(children, 1)?)
            } else {
                child_si(children, 0)?.ne_(&child_si(children, 1)?)
            }
        }
        AstOp::ULT(..) => child_si(children, 0)?.ult(&child_si(children, 1)?),
        AstOp::ULE(..) => child_si(children, 0)?.ule(&child_si(children, 1)?),
        AstOp::UGT(..) => child_si(children, 0)?.ugt(&child_si(children, 1)?),
        AstOp::UGE(..) => child_si(children, 0)?.uge(&child_si(children, 1)?),
        AstOp::SLT(..) => child_si(children, 0)?.slt(&child_si(children, 1)?),
        AstOp::SLE(..) => child_si(children, 0)?.sle(&child_si(children, 1)?),
        AstOp::SGT(..) => child_si(children, 0)?.sgt(&child_si(children, 1)?),
        AstOp::SGE(..) => child_si(children, 0)?.sge(&child_si(children, 1)?),
        AstOp::FpLt(..)
        | AstOp::FpLeq(..)
        | AstOp::FpGt(..)
        | AstOp::FpGeq(..)
        | AstOp::FpIsNan(..)
        | AstOp::FpIsInf(..) => {
            return Err(ClarirsError::UnsupportedOperation(
                "Floating point operations are not supported".to_string(),
            ));
        }
        AstOp::StrContains(..)
        | AstOp::StrPrefixOf(..)
        | AstOp::StrSuffixOf(..)
        | AstOp::StrIsDigit(..) => {
            return Err(ClarirsError::UnsupportedOperation(
                "String operations are not supported".to_string(),
            ));
        }
        AstOp::ITE(..) => match child(children, 0)? {
            ComparisonResult::True => child(children, 1)?,
            ComparisonResult::False => child(children, 2)?,
            ComparisonResult::Maybe => child(children, 1)? | child(children, 2)?,
        },
        _ => unreachable!("non-boolean op dispatched to reduce_bool"),
    })
}
