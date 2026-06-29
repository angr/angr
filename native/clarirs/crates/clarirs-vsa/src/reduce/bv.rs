use super::ReduceResult;
use crate::strided_interval::{ComparisonResult, StridedInterval};
use clarirs_core::prelude::*;

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

/// Reduce a AstRef to a StridedInterval
pub(crate) fn reduce_bv(
    ast: &AstRef<'_>,
    children: &[ReduceResult],
) -> Result<StridedInterval, ClarirsError> {
    Ok(match ast.op() {
        AstOp::BVS(_, bits) => {
            // If there is an SI or ESI annotation, use it. Otherwise, return top.
            ast.annotations()
                .iter()
                .find_map(|ann| {
                    if let AnnotationType::StridedInterval {
                        stride,
                        lower_bound,
                        upper_bound,
                    } = ann.type_()
                    {
                        Some(StridedInterval::new(
                            *bits,
                            stride.clone(),
                            lower_bound.clone(),
                            upper_bound.clone(),
                        ))
                    } else if let AnnotationType::EmptyStridedInterval = ann.type_() {
                        Some(StridedInterval::empty(*bits))
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| StridedInterval::top(*bits))
        }
        AstOp::BVV(bv) => StridedInterval::constant(bv.len(), bv.to_biguint()),
        AstOp::Not(..) => child_si(children, 0)?.bitnot(),
        AstOp::And(..) => child_si(children, 0)?.bitand(&child_si(children, 1)?),
        AstOp::Or(..) => child_si(children, 0)?.bitor(&child_si(children, 1)?),
        AstOp::Xor(..) => child_si(children, 0)?.bitxor(&child_si(children, 1)?),
        AstOp::Neg(..) => child_si(children, 0)?.neg(),
        AstOp::Add(..) => child_si(children, 0)?.add(&child_si(children, 1)?),
        AstOp::Sub(..) => child_si(children, 0)?.sub(&child_si(children, 1)?),
        AstOp::Mul(..) => child_si(children, 0)?.mul(&child_si(children, 1)?),
        AstOp::UDiv(..) => child_si(children, 0)?.udiv(&child_si(children, 1)?)?,
        AstOp::SDiv(..) => child_si(children, 0)?.sdiv(&child_si(children, 1)?)?,
        AstOp::URem(..) => child_si(children, 0)?.urem(&child_si(children, 1)?)?,
        AstOp::SRem(..) => child_si(children, 0)?.srem(&child_si(children, 1)?)?,
        AstOp::ShL(..) => child_si(children, 0)?.shl(&child_si(children, 1)?)?,
        AstOp::LShR(..) => child_si(children, 0)?.lshr(&child_si(children, 1)?)?,
        AstOp::AShR(..) => child_si(children, 0)?.ashr(&child_si(children, 1)?)?,
        AstOp::RotateLeft(..) => child_si(children, 0)?.rotate_left(&child_si(children, 1)?)?,
        AstOp::RotateRight(..) => child_si(children, 0)?.rotate_right(&child_si(children, 1)?)?,
        AstOp::ZeroExt(_, amount) => child_si(children, 0)?.zero_extend(*amount),
        AstOp::SignExt(_, amount) => child_si(children, 0)?.sign_extend(*amount),
        AstOp::Extract(_, high, low) => child_si(children, 0)?.extract(*high, *low),
        AstOp::Concat(args) => {
            // Fold over all children with concat
            let mut result = child_si(children, 0)?;
            for i in 1..args.len() {
                result = result.concat(&child_si(children, i)?);
            }
            result
        }
        AstOp::ByteReverse(..) => child_si(children, 0)?.reverse_bytes()?,
        AstOp::FpToIEEEBV(..) | AstOp::FpToUBV(..) | AstOp::FpToSBV(..) => {
            return Err(ClarirsError::UnsupportedOperation(
                "Floating point operations are not supported".to_string(),
            ));
        }
        AstOp::StrLen(..) | AstOp::StrIndexOf(..) | AstOp::StrToBV(..) => {
            return Err(ClarirsError::UnsupportedOperation(
                "String operations are not supported".to_string(),
            ));
        }
        AstOp::ITE(..) => match child(children, 0)? {
            ComparisonResult::True => child_si(children, 1)?,
            ComparisonResult::False => child_si(children, 2)?,
            ComparisonResult::Maybe => child_si(children, 1)?.union(&child_si(children, 2)?),
        },
        AstOp::Union(..) => child_si(children, 0)?.union(&child_si(children, 1)?),
        AstOp::Intersection(..) => child_si(children, 0)?.intersection(&child_si(children, 1)?),
        AstOp::Widen(..) => child_si(children, 0)?.widen(&child_si(children, 1)?),
        _ => unreachable!("non-bitvector op dispatched to reduce_bv"),
    })
}
