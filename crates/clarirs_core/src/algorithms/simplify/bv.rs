use num_bigint::{BigInt, BigUint};
use num_traits::{Num, One, Zero};

use crate::{algorithms::simplify::SimplifyError, ast::bitvec::BitVecOpExt, prelude::*};

pub(crate) fn simplify_bv<'c>(
    state: &mut super::SimplifyState<'c>,
    error_on_dbz: bool,
) -> Result<BitVecAst<'c>, SimplifyError<'c>> {
    let ctx = state.expr.context();
    let bv_expr = state.expr.clone().into_bitvec().unwrap();

    match bv_expr.op() {
        BitVecOp::BVS(..) | BitVecOp::BVV(..) => Ok(bv_expr),
        BitVecOp::Not(..) => {
            let arc = state.get_bv_simplified(0)?;
            match arc.op() {
                BitVecOp::BVV(value) => Ok(ctx.bvv((!value.clone())?)?),
                _ => Ok(ctx.not(arc)?),
            }
        }
        BitVecOp::And(_) => {
            // Simplify all children in one batch to avoid quadratic re-runs.
            let simplified = state.get_all_bv_simplified()?;

            let size = simplified[0].size();

            // Flatten nested Ands, fold constants, remove identities, detect absorber
            let mut bvv_acc: Option<BitVec> = None;
            let mut sym_args: Vec<BitVecAst<'c>> = Vec::new();

            for arg in &simplified {
                match arg.op() {
                    BitVecOp::And(inner_args) => {
                        for inner in inner_args {
                            match inner.op() {
                                BitVecOp::BVV(v) if v.is_zero() => {
                                    return Ok(ctx.bvv(BitVec::zeros(size))?);
                                }
                                BitVecOp::BVV(v) if v.is_all_ones() => {}
                                BitVecOp::BVV(v) => {
                                    bvv_acc = Some(match bvv_acc {
                                        Some(acc) => (acc & v.clone())?,
                                        None => v.clone(),
                                    });
                                }
                                _ => sym_args.push(inner.clone()),
                            }
                        }
                    }
                    BitVecOp::BVV(v) if v.is_zero() => {
                        return Ok(ctx.bvv(BitVec::zeros(size))?);
                    }
                    BitVecOp::BVV(v) if v.is_all_ones() => {}
                    BitVecOp::BVV(v) => {
                        bvv_acc = Some(match bvv_acc {
                            Some(acc) => (acc & v.clone())?,
                            None => v.clone(),
                        });
                    }
                    _ => sym_args.push(arg.clone()),
                }
            }

            // Deduplicate (And is idempotent: x & x = x)
            {
                let mut seen = ahash::AHashSet::with_capacity(sym_args.len());
                sym_args.retain(|arg| seen.insert(arg.hash()));
            }

            // Check for x & ¬x = 0 using a hash set for O(n) lookup
            {
                let hashes: ahash::AHashSet<u64> = sym_args.iter().map(|a| a.hash()).collect();
                for arg in &sym_args {
                    if let BitVecOp::Not(inner) = arg.op()
                        && hashes.contains(&inner.hash())
                    {
                        return Ok(ctx.bvv(BitVec::zeros(size))?);
                    }
                }
            }

            // Check folded BVV for absorber/identity
            if let Some(ref bvv) = bvv_acc {
                if bvv.is_zero() {
                    return Ok(ctx.bvv(BitVec::zeros(size))?);
                }
                if !bvv.is_all_ones() {
                    sym_args.push(ctx.bvv(bvv.clone())?);
                }
            }

            // Check if anything changed
            let changed = sym_args.len() != simplified.len()
                || sym_args
                    .iter()
                    .zip(simplified.iter())
                    .any(|(a, b)| a.hash() != b.hash());

            match sym_args.len() {
                0 => Ok(ctx.bvv(BitVec::from_biguint_trunc(
                    &((BigUint::one() << size) - BigUint::one()),
                    size,
                ))?),
                1 => Ok(sym_args.into_iter().next().unwrap()),
                2 => {
                    let (a, b) = (&sym_args[0], &sym_args[1]);
                    match (a.op(), b.op()) {
                        // Distribute AND over CONCAT when one operand is constant
                        (BitVecOp::BVV(const_val), BitVecOp::Concat(concat_args))
                        | (BitVecOp::Concat(concat_args), BitVecOp::BVV(const_val)) => {
                            let mut parts = Vec::with_capacity(concat_args.len());
                            let mut offset = 0u32;
                            for arg in concat_args.iter().rev() {
                                let arg_size = arg.size();
                                let const_part =
                                    const_val.extract(offset, offset + arg_size - 1)?;
                                parts.push(ctx.bv_and(&ctx.bvv(const_part)?, arg)?);
                                offset += arg_size;
                            }
                            parts.reverse();
                            state.rerun(ctx.concat(parts)?)
                        }

                        // Distribute AND over zero-extend when one operand is constant
                        (BitVecOp::BVV(const_val), BitVecOp::ZeroExt(inner, ext_size))
                        | (BitVecOp::ZeroExt(inner, ext_size), BitVecOp::BVV(const_val)) => {
                            let inner_size = inner.size();
                            let const_inner = const_val.extract(0, inner_size - 1)?;
                            let inner_and = ctx.bv_and(&ctx.bvv(const_inner)?, inner)?;
                            let zero_extended = ctx.zero_ext(&inner_and, *ext_size)?;
                            state.rerun(zero_extended)
                        }

                        // rotate_shift_mask: ((A << a) | (A >> (N - a))) & mask
                        (BitVecOp::Or(or_args), BitVecOp::BVV(mask_val))
                        | (BitVecOp::BVV(mask_val), BitVecOp::Or(or_args))
                            if or_args.len() == 2 =>
                        {
                            let (or_lhs, or_rhs) = (&or_args[0], &or_args[1]);
                            match (or_lhs.op(), or_rhs.op()) {
                                (
                                    BitVecOp::ShL(shl_inner, shl_amt),
                                    BitVecOp::LShR(lshr_inner, lshr_amt),
                                )
                                | (
                                    BitVecOp::LShR(lshr_inner, lshr_amt),
                                    BitVecOp::ShL(shl_inner, shl_amt),
                                ) if shl_inner.hash() == lshr_inner.hash() => {
                                    if let (BitVecOp::BVV(shl_val), BitVecOp::BVV(lshr_val)) =
                                        (shl_amt.op(), lshr_amt.op())
                                    {
                                        if let (Some(lshift), Some(rshift)) =
                                            (shl_val.to_u64(), lshr_val.to_u64())
                                        {
                                            let bitwidth = a.size() as u64;
                                            if lshift + rshift == bitwidth
                                                && (bitwidth == 32 || bitwidth == 64)
                                            {
                                                let mask_big = mask_val.to_biguint();
                                                let full_mask = if bitwidth == 64 {
                                                    BigUint::from(u64::MAX)
                                                } else {
                                                    BigUint::from(u32::MAX)
                                                };
                                                let unrotated = ((&mask_big >> lshift as usize)
                                                    | ((&mask_big << rshift as usize)
                                                        & &full_mask))
                                                    & &full_mask;

                                                let unrotated_bvv =
                                                    ctx.bvv(BitVec::from_biguint_trunc(
                                                        &unrotated,
                                                        bitwidth as u32,
                                                    ))?;
                                                let masked_a =
                                                    ctx.bv_and(shl_inner.clone(), unrotated_bvv)?;
                                                let new_shl =
                                                    ctx.shl(&masked_a, shl_amt.clone())?;
                                                let new_lshr =
                                                    ctx.lshr(&masked_a, lshr_amt.clone())?;
                                                let result = ctx.bv_or(new_shl, new_lshr)?;
                                                state.rerun(result)
                                            } else if changed {
                                                state.rerun(ctx.bv_and_many(sym_args)?)
                                            } else {
                                                Ok(ctx.bv_and_many(sym_args)?)
                                            }
                                        } else if changed {
                                            state.rerun(ctx.bv_and_many(sym_args)?)
                                        } else {
                                            Ok(ctx.bv_and_many(sym_args)?)
                                        }
                                    } else if changed {
                                        state.rerun(ctx.bv_and_many(sym_args)?)
                                    } else {
                                        Ok(ctx.bv_and_many(sym_args)?)
                                    }
                                }
                                _ => {
                                    if changed {
                                        state.rerun(ctx.bv_and_many(sym_args)?)
                                    } else {
                                        Ok(ctx.bv_and_many(sym_args)?)
                                    }
                                }
                            }
                        }

                        _ => {
                            if changed {
                                state.rerun(ctx.bv_and_many(sym_args)?)
                            } else {
                                Ok(ctx.bv_and_many(sym_args)?)
                            }
                        }
                    }
                }
                _ => {
                    if changed {
                        state.rerun(ctx.bv_and_many(sym_args)?)
                    } else {
                        Ok(ctx.bv_and_many(sym_args)?)
                    }
                }
            }
        }
        BitVecOp::Or(_) => {
            // Simplify all children in one batch to avoid quadratic re-runs.
            let simplified = state.get_all_bv_simplified()?;

            let size = simplified[0].size();
            let all_ones =
                BitVec::from_biguint_trunc(&((BigUint::one() << size) - BigUint::one()), size);

            // Flatten nested Ors, fold constants, remove identities, detect absorber
            let mut bvv_acc: Option<BitVec> = None;
            let mut sym_args: Vec<BitVecAst<'c>> = Vec::new();

            for arg in &simplified {
                match arg.op() {
                    BitVecOp::Or(inner_args) => {
                        for inner in inner_args {
                            match inner.op() {
                                BitVecOp::BVV(v) if v.is_all_ones() => {
                                    return Ok(ctx.bvv(all_ones)?);
                                }
                                BitVecOp::BVV(v) if v.is_zero() => {}
                                BitVecOp::BVV(v) => {
                                    bvv_acc = Some(match bvv_acc {
                                        Some(acc) => (acc | v.clone())?,
                                        None => v.clone(),
                                    });
                                }
                                _ => sym_args.push(inner.clone()),
                            }
                        }
                    }
                    BitVecOp::BVV(v) if v.is_all_ones() => {
                        return Ok(ctx.bvv(all_ones)?);
                    }
                    BitVecOp::BVV(v) if v.is_zero() => {}
                    BitVecOp::BVV(v) => {
                        bvv_acc = Some(match bvv_acc {
                            Some(acc) => (acc | v.clone())?,
                            None => v.clone(),
                        });
                    }
                    _ => sym_args.push(arg.clone()),
                }
            }

            // Deduplicate (Or is idempotent: x | x = x)
            {
                let mut seen = ahash::AHashSet::with_capacity(sym_args.len());
                sym_args.retain(|arg| seen.insert(arg.hash()));
            }

            // Check for x | ¬x = all-ones using a hash set for O(n) lookup
            {
                let hashes: ahash::AHashSet<u64> = sym_args.iter().map(|a| a.hash()).collect();
                for arg in &sym_args {
                    if let BitVecOp::Not(inner) = arg.op()
                        && hashes.contains(&inner.hash())
                    {
                        return Ok(ctx.bvv(all_ones)?);
                    }
                }
            }

            // Check folded BVV for absorber/identity
            if let Some(ref bvv) = bvv_acc {
                if bvv.is_all_ones() {
                    return Ok(ctx.bvv(all_ones)?);
                }
                if !bvv.is_zero() {
                    sym_args.push(ctx.bvv(bvv.clone())?);
                }
            }

            let changed = sym_args.len() != simplified.len()
                || sym_args
                    .iter()
                    .zip(simplified.iter())
                    .any(|(a, b)| a.hash() != b.hash());

            match sym_args.len() {
                0 => Ok(ctx.bvv(BitVec::zeros(size))?),
                1 => Ok(sym_args.into_iter().next().unwrap()),
                2 => {
                    let (a, b) = (&sym_args[0], &sym_args[1]);
                    match (a.op(), b.op()) {
                        // Distribute OR over CONCAT when one operand is constant
                        (BitVecOp::BVV(const_val), BitVecOp::Concat(concat_args))
                        | (BitVecOp::Concat(concat_args), BitVecOp::BVV(const_val)) => {
                            let mut parts = Vec::with_capacity(concat_args.len());
                            let mut offset = 0u32;
                            for arg in concat_args.iter().rev() {
                                let arg_size = arg.size();
                                let const_part =
                                    const_val.extract(offset, offset + arg_size - 1)?;
                                parts.push(ctx.bv_or(&ctx.bvv(const_part)?, arg)?);
                                offset += arg_size;
                            }
                            parts.reverse();
                            state.rerun(ctx.concat(parts)?)
                        }
                        _ => {
                            if changed {
                                state.rerun(ctx.bv_or_many(sym_args)?)
                            } else {
                                Ok(ctx.bv_or_many(sym_args)?)
                            }
                        }
                    }
                }
                _ => {
                    if changed {
                        state.rerun(ctx.bv_or_many(sym_args)?)
                    } else {
                        Ok(ctx.bv_or_many(sym_args)?)
                    }
                }
            }
        }
        BitVecOp::Xor(_) => {
            // Simplify all children in one batch to avoid quadratic re-runs.
            let simplified = state.get_all_bv_simplified()?;

            let size = simplified[0].size();

            // Flatten nested Xors, fold constants, remove identities
            let mut bvv_acc: Option<BitVec> = None;
            let mut sym_args: Vec<BitVecAst<'c>> = Vec::new();

            for arg in &simplified {
                match arg.op() {
                    BitVecOp::Xor(inner_args) => {
                        for inner in inner_args {
                            match inner.op() {
                                BitVecOp::BVV(v) if v.is_zero() => {}
                                BitVecOp::BVV(v) => {
                                    bvv_acc = Some(match bvv_acc {
                                        Some(acc) => (acc ^ v.clone())?,
                                        None => v.clone(),
                                    });
                                }
                                _ => sym_args.push(inner.clone()),
                            }
                        }
                    }
                    BitVecOp::BVV(v) if v.is_zero() => {}
                    BitVecOp::BVV(v) => {
                        bvv_acc = Some(match bvv_acc {
                            Some(acc) => (acc ^ v.clone())?,
                            None => v.clone(),
                        });
                    }
                    _ => sym_args.push(arg.clone()),
                }
            }

            // Cancel pairs: x ^ x = 0
            // Count occurrences by hash; odd count means the term survives
            {
                let mut counts: ahash::AHashMap<u64, usize> =
                    ahash::AHashMap::with_capacity(sym_args.len());
                for arg in &sym_args {
                    *counts.entry(arg.hash()).or_insert(0) += 1;
                }
                let mut seen = ahash::AHashSet::with_capacity(sym_args.len());
                sym_args.retain(|arg| {
                    let h = arg.hash();
                    let count = counts.get(&h).copied().unwrap_or(0);
                    // Keep only one copy if odd count, none if even
                    if count % 2 == 1 {
                        seen.insert(h) // true on first insert, false on duplicates
                    } else {
                        false
                    }
                });
            }

            // Check folded BVV
            if let Some(ref bvv) = bvv_acc
                && !bvv.is_zero()
            {
                sym_args.push(ctx.bvv(bvv.clone())?);
            }

            let changed = sym_args.len() != simplified.len()
                || sym_args
                    .iter()
                    .zip(simplified.iter())
                    .any(|(a, b)| a.hash() != b.hash());

            match sym_args.len() {
                0 => Ok(ctx.bvv(BitVec::zeros(size))?),
                1 => Ok(sym_args.into_iter().next().unwrap()),
                2 => {
                    let (a, b) = (&sym_args[0], &sym_args[1]);
                    match (a.op(), b.op()) {
                        // ¬a ^ ¬b = a ^ b
                        (BitVecOp::Not(lhs), BitVecOp::Not(rhs)) => {
                            state.rerun(ctx.bv_xor(lhs, rhs)?)
                        }
                        // Distribute XOR over CONCAT when one operand is constant
                        (BitVecOp::BVV(const_val), BitVecOp::Concat(concat_args))
                        | (BitVecOp::Concat(concat_args), BitVecOp::BVV(const_val)) => {
                            let mut parts = Vec::with_capacity(concat_args.len());
                            let mut offset = 0u32;
                            for arg in concat_args.iter().rev() {
                                let arg_size = arg.size();
                                let const_part =
                                    const_val.extract(offset, offset + arg_size - 1)?;
                                parts.push(ctx.bv_xor(&ctx.bvv(const_part)?, arg)?);
                                offset += arg_size;
                            }
                            parts.reverse();
                            state.rerun(ctx.concat(parts)?)
                        }
                        // XOR with all-ones = NOT
                        (BitVecOp::BVV(v), _) if v.is_all_ones() => {
                            state.rerun(ctx.not(b.clone())?)
                        }
                        (_, BitVecOp::BVV(v)) if v.is_all_ones() => {
                            state.rerun(ctx.not(a.clone())?)
                        }
                        _ => {
                            if changed {
                                state.rerun(ctx.bv_xor_many(sym_args)?)
                            } else {
                                Ok(ctx.bv_xor_many(sym_args)?)
                            }
                        }
                    }
                }
                _ => {
                    // Check if there's an all-ones BVV among the args - if so, extract it
                    // and apply NOT to the XOR of the remaining args
                    if changed {
                        state.rerun(ctx.bv_xor_many(sym_args)?)
                    } else {
                        Ok(ctx.bv_xor_many(sym_args)?)
                    }
                }
            }
        }
        BitVecOp::Neg(..) => {
            let arc = state.get_bv_simplified(0)?;
            match arc.op() {
                BitVecOp::BVV(value) => Ok(ctx.bvv((-value.clone())?)?),
                // -(-x) = x (double negation)
                BitVecOp::Neg(inner) => Ok(inner.clone()),
                _ => Ok(ctx.neg(arc)?),
            }
        }
        BitVecOp::Add(_) => {
            // Simplify all children in one batch to avoid quadratic re-runs.
            let simplified = state.get_all_bv_simplified()?;

            let size = simplified[0].size();

            // Flatten nested Adds, fold constants, remove identities
            let mut bvv_acc: Option<BitVec> = None;
            let mut sym_args: Vec<BitVecAst<'c>> = Vec::new();

            for arg in &simplified {
                match arg.op() {
                    BitVecOp::Add(inner_args) => {
                        for inner in inner_args {
                            match inner.op() {
                                BitVecOp::BVV(v) if v.is_zero() => {}
                                BitVecOp::BVV(v) => {
                                    bvv_acc = Some(match bvv_acc {
                                        Some(acc) => (acc + v.clone())?,
                                        None => v.clone(),
                                    });
                                }
                                _ => sym_args.push(inner.clone()),
                            }
                        }
                    }
                    BitVecOp::BVV(v) if v.is_zero() => {}
                    BitVecOp::BVV(v) => {
                        bvv_acc = Some(match bvv_acc {
                            Some(acc) => (acc + v.clone())?,
                            None => v.clone(),
                        });
                    }
                    _ => sym_args.push(arg.clone()),
                }
            }

            // Check folded BVV
            if let Some(ref bvv) = bvv_acc
                && !bvv.is_zero()
            {
                sym_args.push(ctx.bvv(bvv.clone())?);
            }

            let changed = sym_args.len() != simplified.len()
                || sym_args
                    .iter()
                    .zip(simplified.iter())
                    .any(|(a, b)| a.hash() != b.hash());

            match sym_args.len() {
                0 => Ok(ctx.bvv(BitVec::zeros(size))?),
                1 => Ok(sym_args.into_iter().next().unwrap()),
                2 => {
                    let (a, b) = (&sym_args[0], &sym_args[1]);
                    match (a.op(), b.op()) {
                        // If one operand is a BVV and the other is a Sub with a BVV, combine
                        (BitVecOp::BVV(v), BitVecOp::Sub(bvv, other))
                        | (BitVecOp::Sub(bvv, other), BitVecOp::BVV(v))
                            if matches!(bvv.op(), BitVecOp::BVV(_)) =>
                        {
                            if let BitVecOp::BVV(bvv_value) = bvv.op() {
                                let combined_value = (v.clone() + bvv_value.clone())?;
                                let combined_bvv = ctx.bvv(combined_value)?;
                                state.rerun(ctx.sub(other.clone(), combined_bvv)?)
                            } else {
                                unreachable!()
                            }
                        }
                        (BitVecOp::BVV(v), BitVecOp::Sub(other, bvv))
                        | (BitVecOp::Sub(other, bvv), BitVecOp::BVV(v))
                            if matches!(bvv.op(), BitVecOp::BVV(_)) =>
                        {
                            if let BitVecOp::BVV(bvv_value) = bvv.op() {
                                let combined_value = (v.clone() - bvv_value.clone())?;
                                let combined_bvv = ctx.bvv(combined_value)?;
                                state.rerun(ctx.add(other.clone(), combined_bvv)?)
                            } else {
                                unreachable!()
                            }
                        }
                        _ => {
                            if changed {
                                state.rerun(ctx.add_many(sym_args)?)
                            } else {
                                Ok(ctx.add_many(sym_args)?)
                            }
                        }
                    }
                }
                _ => {
                    if changed {
                        state.rerun(ctx.add_many(sym_args)?)
                    } else {
                        Ok(ctx.add_many(sym_args)?)
                    }
                }
            }
        }
        BitVecOp::Sub(..) => {
            let (arc, arc1) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (arc.op(), arc1.op()) {
                (BitVecOp::BVV(value1), BitVecOp::BVV(value2)) => {
                    Ok(ctx.bvv((value1.clone() - value2.clone())?)?)
                }
                (BitVecOp::Sub(inner_lhs, inner_rhs), BitVecOp::BVV(v))
                    if matches!(inner_rhs.op(), BitVecOp::BVV(_)) =>
                {
                    // (a - b) - c  => a - (b + c)
                    if let BitVecOp::BVV(b_val) = inner_rhs.op() {
                        let combined_value = (b_val.clone() + v.clone())?;
                        let combined_bvv = ctx.bvv(combined_value)?;
                        let new_sub = ctx.sub(inner_lhs.clone(), combined_bvv)?;
                        state.rerun(new_sub)
                    } else {
                        unreachable!()
                    }
                }
                (BitVecOp::Add(add_args), BitVecOp::BVV(v)) => {
                    // Find a BVV among the Add args to combine with
                    if let Some(bvv_idx) = add_args
                        .iter()
                        .position(|a| matches!(a.op(), BitVecOp::BVV(_)))
                    {
                        if let BitVecOp::BVV(b_val) = add_args[bvv_idx].op() {
                            // (sum + b) - c => sum + (b - c)
                            let combined_value = (b_val.clone() - v.clone())?;
                            let combined_bvv = ctx.bvv(combined_value)?;
                            let mut new_args: Vec<BitVecAst<'c>> = add_args
                                .iter()
                                .enumerate()
                                .filter(|(i, _)| *i != bvv_idx)
                                .map(|(_, a)| a.clone())
                                .collect();
                            new_args.push(combined_bvv);
                            state.rerun(ctx.add_many(new_args)?)
                        } else {
                            unreachable!()
                        }
                    } else {
                        Ok(ctx.sub(arc, arc1)?)
                    }
                }
                (_, BitVecOp::BVV(v)) if v.is_zero() => Ok(arc.clone()),
                (lhs_op, rhs_op) if lhs_op == rhs_op => Ok(ctx.bvv(BitVec::zeros(arc.size()))?),
                _ => Ok(ctx.sub(arc, arc1)?),
            }
        }
        BitVecOp::Mul(_) => {
            // Simplify all children in one batch to avoid quadratic re-runs.
            let simplified = state.get_all_bv_simplified()?;

            let size = simplified[0].size();

            // Flatten nested Muls, fold constants, remove identities, detect absorber
            let mut bvv_acc: Option<BitVec> = None;
            let mut sym_args: Vec<BitVecAst<'c>> = Vec::new();

            for arg in &simplified {
                match arg.op() {
                    BitVecOp::Mul(inner_args) => {
                        for inner in inner_args {
                            match inner.op() {
                                BitVecOp::BVV(v) if v.is_zero() => {
                                    return Ok(ctx.bvv(BitVec::zeros(size))?);
                                }
                                BitVecOp::BVV(v) if v.to_u64() == Some(1) => {}
                                BitVecOp::BVV(v) => {
                                    bvv_acc = Some(match bvv_acc {
                                        Some(acc) => (acc * v.clone())?,
                                        None => v.clone(),
                                    });
                                }
                                _ => sym_args.push(inner.clone()),
                            }
                        }
                    }
                    BitVecOp::BVV(v) if v.is_zero() => {
                        return Ok(ctx.bvv(BitVec::zeros(size))?);
                    }
                    BitVecOp::BVV(v) if v.to_u64() == Some(1) => {}
                    BitVecOp::BVV(v) => {
                        bvv_acc = Some(match bvv_acc {
                            Some(acc) => (acc * v.clone())?,
                            None => v.clone(),
                        });
                    }
                    _ => sym_args.push(arg.clone()),
                }
            }

            // Check folded BVV
            if let Some(ref bvv) = bvv_acc {
                if bvv.is_zero() {
                    return Ok(ctx.bvv(BitVec::zeros(size))?);
                }
                if bvv.to_u64() != Some(1) {
                    sym_args.push(ctx.bvv(bvv.clone())?);
                }
            }

            let changed = sym_args.len() != simplified.len()
                || sym_args
                    .iter()
                    .zip(simplified.iter())
                    .any(|(a, b)| a.hash() != b.hash());

            match sym_args.len() {
                0 => Ok(ctx.bvv(BitVec::from_prim_with_size(1u64, size)?)?),
                1 => Ok(sym_args.into_iter().next().unwrap()),
                _ => {
                    if changed {
                        state.rerun(ctx.mul_many(sym_args)?)
                    } else {
                        Ok(ctx.mul_many(sym_args)?)
                    }
                }
            }
        }
        BitVecOp::UDiv(..) => {
            let (arc, arc1) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (arc.op(), arc1.op()) {
                (_, BitVecOp::BVV(v)) if error_on_dbz && v.is_zero() => {
                    Err(SimplifyError::Error(ClarirsError::DivisionByZero))
                }
                (BitVecOp::BVV(value1), BitVecOp::BVV(value2)) if !value2.is_zero() => {
                    Ok(ctx.bvv((value1.clone() / value2.clone())?)?)
                }
                (_, BitVecOp::BVV(v)) if v.to_u64() == Some(1) => Ok(arc.clone()),
                _ => Ok(ctx.udiv(arc, arc1)?),
            }
        }
        BitVecOp::SDiv(..) => {
            let (dividend_ast, divisor_ast) =
                (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (dividend_ast.op(), divisor_ast.op()) {
                (_, BitVecOp::BVV(v)) if error_on_dbz && v.is_zero() => {
                    Err(SimplifyError::Error(ClarirsError::DivisionByZero))
                }
                (BitVecOp::BVV(dividend_val), BitVecOp::BVV(divisor_val))
                    if !divisor_val.is_zero() =>
                {
                    Ok(ctx.bvv((dividend_val.sdiv(divisor_val))?)?)
                }
                (_, BitVecOp::BVV(v)) if v.to_u64() == Some(1) => Ok(dividend_ast.clone()),
                _ => Ok(ctx.sdiv(dividend_ast, divisor_ast)?),
            }
        }
        BitVecOp::URem(..) => {
            let (arc, arc1) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (arc.op(), arc1.op()) {
                (BitVecOp::BVV(value1), BitVecOp::BVV(value2)) => Ok(ctx.bvv(value1.urem(value2))?),
                _ => Ok(ctx.urem(arc, arc1)?),
            }
        }
        BitVecOp::SRem(..) => {
            let (dividend_ast, divisor_ast) =
                (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (dividend_ast.op(), divisor_ast.op()) {
                (BitVecOp::BVV(dividend_val), BitVecOp::BVV(divisor_val)) => {
                    Ok(ctx.bvv((dividend_val.srem(divisor_val))?)?)
                }
                _ => Ok(ctx.srem(dividend_ast, divisor_ast)?),
            }
        }
        BitVecOp::ShL(..) => {
            let (arc, arc1) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (arc.op(), arc1.op()) {
                // Base value is zero
                (BitVecOp::BVV(v), _) if v.is_zero() => Ok(arc),
                // Shift by zero
                (_, BitVecOp::BVV(v)) if v.is_zero() => Ok(arc.clone()),

                // Simplify shift left of zero-extended value when shift amount is >= extension size
                // (shl (zero_extend n x) m) where m >= n
                // The n zero-extended MSBs are shifted out, inner is shifted left by (m-n),
                // and m zero bits appear at the LSB side.
                // Result: concat(shl(inner, m-n), BVV(0, m)) truncated to total_size
                // Which is: concat(extract(inner_size-1-(m-n), 0, inner), BVV(0, m))
                // Simplified: concat(shl(inner, m-n), BVV(0, ext_size))
                (BitVecOp::ZeroExt(inner, ext_size), BitVecOp::BVV(shift_amt))
                    if { shift_amt.to_u64().unwrap_or(0) as u32 >= *ext_size } =>
                {
                    let shift_val = shift_amt.to_u64().unwrap_or(0) as u32;
                    let total_size = inner.size() + ext_size;

                    // The zero-extended MSB bits are shifted out entirely
                    let inner_shift = shift_val - ext_size;
                    if inner_shift >= inner.size() {
                        // Everything gets shifted out
                        Ok(ctx.bvv(BitVec::zeros(total_size))?)
                    } else {
                        // Shift the inner value left by (m - ext_size), then concatenate
                        // with ext_size zero bits at the bottom (LSB side)
                        let shifted_inner = if inner_shift == 0 {
                            inner.clone()
                        } else {
                            ctx.shl(
                                inner,
                                &ctx.bvv(BitVec::from_prim_with_size(
                                    inner_shift as u64,
                                    inner.size(),
                                )?)?,
                            )?
                        };
                        // Zeros go at the bottom (LSB), shifted_inner goes at the top (MSB)
                        let zero_bottom = ctx.bvv(BitVec::zeros(*ext_size))?;
                        state.rerun(ctx.concat(vec![shifted_inner, zero_bottom])?)
                    }
                }

                // Fully concrete case
                (BitVecOp::BVV(value), BitVecOp::BVV(shift_amount)) => {
                    let bit_width = value.len();
                    let shift_amount_u32 = shift_amount.to_u64().unwrap_or(0) as u32;

                    // If shifting >= bit_width, result is 0
                    if shift_amount_u32 >= bit_width {
                        Ok(ctx.bvv(BitVec::zeros(bit_width))?)
                    } else if shift_amount_u32 == 0 {
                        Ok(arc.clone())
                    } else {
                        let result = (value.clone() << shift_amount_u32)?;
                        Ok(ctx.bvv(result)?)
                    }
                }
                // Fallback case
                _ => Ok(ctx.shl(arc, arc1)?),
            }
        }
        BitVecOp::LShR(..) => {
            let (arc, arc1) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (arc.op(), arc1.op()) {
                // Base value is zero
                (BitVecOp::BVV(v), _) if v.is_zero() => Ok(arc),
                // Shift by zero
                (_, BitVecOp::BVV(v)) if v.is_zero() => Ok(arc.clone()),

                // Detect bit extraction pattern: (lshr (shl x n) m)
                // This extracts bits from position (m) to position (size - 1 - n) of x
                (BitVecOp::ShL(inner, shl_amt), BitVecOp::BVV(shr_amt)) => {
                    if let BitVecOp::BVV(shl_val) = shl_amt.op() {
                        let shl_u32 = shl_val.to_u64().unwrap_or(0) as u32;
                        let shr_u32 = shr_amt.to_u64().unwrap_or(0) as u32;
                        let size = arc.size();

                        if shl_u32 + shr_u32 >= size {
                            // All bits get shifted out, result is zero
                            Ok(ctx.bvv(BitVec::zeros(size))?)
                        } else {
                            // This extracts bits from the original value
                            // After left shift by n, then right shift by m:
                            // - The highest bit that remains is at position (size - 1 - shl_u32)
                            // - The lowest bit that remains is at position shr_u32
                            // - The result width is (size - shl_u32 - shr_u32)
                            let high = size - 1 - shl_u32;
                            let low = shr_u32;

                            // Special handling for zero-extended values
                            if let BitVecOp::ZeroExt(inner_val, _) = inner.op() {
                                let inner_size = inner_val.size();

                                if low >= inner_size {
                                    // All extracted bits are from the zero-extended part
                                    Ok(ctx.bvv(BitVec::zeros(size))?)
                                } else if high < inner_size {
                                    // All extracted bits are from the original value
                                    let extracted = ctx.extract(inner_val, high, low)?;
                                    // Need to zero-pad to get back to the expected size
                                    if extracted.size() < size {
                                        state.rerun(
                                            ctx.zero_ext(&extracted, size - extracted.size())?,
                                        )
                                    } else {
                                        Ok(extracted)
                                    }
                                } else {
                                    // Extraction spans both original and zero-extended parts
                                    // Extract what we can from the original value
                                    let extracted = ctx.extract(inner_val, inner_size - 1, low)?;
                                    // Zero-extend to the final size
                                    state.rerun(ctx.zero_ext(&extracted, size - extracted.size())?)
                                }
                            } else {
                                // Regular extraction from non-zero-extended value
                                let extracted = ctx.extract(inner, high, low)?;
                                // Need to zero-pad to get back to the expected size
                                if extracted.size() < size {
                                    state.rerun(ctx.zero_ext(&extracted, size - extracted.size())?)
                                } else {
                                    Ok(extracted)
                                }
                            }
                        }
                    } else {
                        Ok(ctx.lshr(arc, arc1)?)
                    }
                }

                // Fully concrete case
                (BitVecOp::BVV(value), BitVecOp::BVV(shift_amount)) => {
                    let bit_width = value.len();
                    let shift_amount_u32 = shift_amount.to_u64().unwrap_or(0) as u32;
                    if shift_amount_u32 >= bit_width {
                        Ok(ctx.bvv(BitVec::zeros(bit_width))?)
                    } else if shift_amount_u32 == 0 {
                        Ok(arc.clone())
                    } else {
                        let result = value.clone() >> shift_amount_u32;
                        Ok(ctx.bvv(result?)?)
                    }
                }
                // Fallback case
                _ => Ok(ctx.lshr(arc, arc1)?),
            }
        }
        BitVecOp::AShR(..) => {
            let (arc, arc1) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (arc.op(), arc1.op()) {
                // Base value is zero
                (BitVecOp::BVV(v), _) if v.is_zero() => Ok(arc),
                // Zero shift amount
                (_, BitVecOp::BVV(v)) if v.is_zero() => Ok(arc.clone()),
                // Fully concrete case
                (BitVecOp::BVV(value), BitVecOp::BVV(shift_amount)) => {
                    let shift_amount_u32 = shift_amount.to_u64().unwrap_or(0) as u32;
                    let bit_length = value.len();

                    // Convert value to BigUint
                    let unsigned_value = value.to_biguint();

                    // Check sign bit
                    let sign_bit_set = (unsigned_value.clone() >> (bit_length - 1))
                        & BigUint::one()
                        != BigUint::zero();

                    // If shifting >= bit_length, return all-ones (if negative) or all-zeros (if positive)
                    if shift_amount_u32 >= bit_length {
                        return if sign_bit_set {
                            Ok(ctx.bvv(BitVec::from_biguint_trunc(
                                &((BigUint::one() << bit_length) - BigUint::one()),
                                bit_length,
                            ))?)
                        } else {
                            Ok(ctx.bvv(BitVec::zeros(bit_length))?)
                        };
                    }

                    // Perform the shift
                    let unsigned_shifted = unsigned_value.clone() >> shift_amount_u32;

                    // Extend the sign bit if needed
                    let result = if sign_bit_set {
                        // Create a mask to extend the sign bit
                        let mask = ((BigUint::one() << shift_amount_u32) - BigUint::one())
                            << (bit_length - shift_amount_u32);
                        unsigned_shifted | mask
                    } else {
                        unsigned_shifted
                    };

                    Ok(ctx.bvv(BitVec::from_biguint_trunc(&result, bit_length))?)
                }
                // Fallback case
                _ => Ok(ctx.ashr(arc, arc1)?),
            }
        }
        BitVecOp::RotateLeft(..) => {
            let (arc, arc1) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (arc.op(), arc1.op()) {
                // Base value is zero
                (BitVecOp::BVV(v), _) if v.is_zero() => Ok(arc),
                // Shift by zero or multiple of size
                (_, BitVecOp::BVV(v))
                    if v.is_zero() || v.to_bigint() % arc.size() == BigInt::zero() =>
                {
                    Ok(arc.clone())
                }
                // Fully concrete case
                (BitVecOp::BVV(value_bv), BitVecOp::BVV(rotate_bv)) => {
                    let rotate_u32 = rotate_bv.to_u64().unwrap_or(0) as u32;
                    let rotated_bv = value_bv.rotate_left(rotate_u32)?;
                    Ok(ctx.bvv(rotated_bv)?)
                }
                // Nested rotation with concrete amounts - combine them
                // rotate_left(rotate_left(x, c1), c2) => rotate_left(x, (c1 + c2) % size)
                (BitVecOp::RotateLeft(inner, inner_amt), BitVecOp::BVV(outer_amt)) => {
                    if let BitVecOp::BVV(inner_amt_val) = inner_amt.op() {
                        let size = arc.size();
                        let combined_amt = (inner_amt_val.to_bigint() + outer_amt.to_bigint())
                            % BigInt::from(size);
                        let combined_amt_bv = BitVec::from_bigint(&combined_amt, arc1.size())?;
                        state.rerun(ctx.rotate_left(inner.clone(), ctx.bvv(combined_amt_bv)?)?)
                    } else {
                        // Inner rotation amount is not concrete, fall through
                        let rotate_amount_u32 = outer_amt.to_u64().unwrap_or(0) as u32;
                        let bottom = ctx.extract(&arc, rotate_amount_u32 - 1, 0)?;
                        let top = ctx.extract(&arc, arc.size() - 1, rotate_amount_u32)?;
                        state.rerun(ctx.concat2(bottom, top)?)
                    }
                }
                // Fallback case
                _ => Ok(ctx.rotate_left(arc, arc1)?),
            }
        }
        BitVecOp::RotateRight(..) => {
            let (arc, arc1) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            match (arc.op(), arc1.op()) {
                // Base value is zero
                (BitVecOp::BVV(v), _) if v.is_zero() => Ok(arc),
                // Shift by zero or multiple of size
                (_, BitVecOp::BVV(v))
                    if v.is_zero() || v.to_bigint() % arc.size() == BigInt::zero() =>
                {
                    Ok(arc.clone())
                }
                // Fully concrete case
                (BitVecOp::BVV(value_bv), BitVecOp::BVV(rotate_amount_bv)) => {
                    let rotate_u32 = rotate_amount_bv.to_u64().unwrap_or(0) as u32;
                    let rotated_bv = value_bv.rotate_right(rotate_u32)?;
                    Ok(ctx.bvv(rotated_bv)?)
                }
                // Nested rotation with concrete amounts - combine them
                // rotate_right(rotate_right(x, c1), c2) => rotate_right(x, (c1 + c2) % size)
                (BitVecOp::RotateRight(inner, inner_amt), BitVecOp::BVV(outer_amt)) => {
                    if let BitVecOp::BVV(inner_amt_val) = inner_amt.op() {
                        let size = arc.size();
                        let combined_amt = (inner_amt_val.to_bigint() + outer_amt.to_bigint())
                            % BigInt::from(size);
                        let combined_amt_bv = BitVec::from_bigint(&combined_amt, arc1.size())?;
                        state.rerun(ctx.rotate_right(inner.clone(), ctx.bvv(combined_amt_bv)?)?)
                    } else {
                        // Inner rotation amount is not concrete, fall through
                        let rotate_amount_u32 = outer_amt.to_u64().unwrap_or(0) as u32;
                        let bottom = ctx.extract(&arc, arc.size() - rotate_amount_u32, 0)?;
                        let top =
                            ctx.extract(&arc, arc.size() - 1, arc.size() - rotate_amount_u32)?;
                        state.rerun(ctx.concat2(top, bottom)?)
                    }
                }
                // Fallback case
                _ => Ok(ctx.rotate_right(arc, arc1)?),
            }
        }
        BitVecOp::ZeroExt(_, num_bits) => {
            let arc = state.get_bv_simplified(0)?;
            match (arc.op(), num_bits) {
                // Zero extension
                (_, 0) => Ok(arc.clone()),
                // Concrete BVV case
                (BitVecOp::BVV(value), _) => Ok(ctx.bvv(value.zero_extend(*num_bits)?)?),
                // Nested ZeroExt - combine extensions
                (BitVecOp::ZeroExt(inner, inner_num_bits), _) => {
                    let total_ext = inner_num_bits + num_bits;
                    state.rerun(ctx.zero_ext(inner, total_ext)?)
                }
                // Propogate over ITE when the children are BVVs
                (BitVecOp::ITE(cond, then_bv, else_bv), _) => {
                    let then_ext = ctx.zero_ext(then_bv, *num_bits)?;
                    let else_ext = ctx.zero_ext(else_bv, *num_bits)?;
                    state.rerun(ctx.ite(cond, &then_ext, &else_ext)?)
                }
                // Symbolic case
                (_, _) => Ok(ctx.zero_ext(arc, *num_bits)?),
            }
        }
        BitVecOp::SignExt(_, num_bits) => {
            let arc = state.get_bv_simplified(0)?;
            match (arc.op(), num_bits) {
                // Sign extension
                (_, 0) => Ok(arc.clone()),
                // Concrete BVV case
                (BitVecOp::BVV(value), _) => Ok(ctx.bvv(value.sign_extend(*num_bits)?)?),
                // Nested SignExt - combine extensions
                (BitVecOp::SignExt(inner, inner_num_bits), _) => {
                    let total_ext = inner_num_bits + num_bits;
                    state.rerun(ctx.sign_ext(inner, total_ext)?)
                }
                // Fallback case
                (_, _) => Ok(ctx.sign_ext(arc, *num_bits)?),
            }
        }
        BitVecOp::Extract(_, high, low) => {
            let arc = state.get_bv_simplified(0)?;

            // If the extract bounds are the entire BV, return the inner value as-is
            if *high == arc.size() - 1 && *low == 0 {
                return Ok(arc);
            }

            match arc.op() {
                // Concrete BVV case
                BitVecOp::BVV(value) => Ok(ctx.bvv(value.extract(*low, *high)?)?),

                // Nested Extract - combine extracts
                BitVecOp::Extract(inner, _, inner_low) => {
                    // Calculate new high and low for the inner extract
                    let new_high = inner_low + *high;
                    let new_low = inner_low + *low;
                    state.rerun(ctx.extract(inner, new_high, new_low)?)
                }

                // Propagate extract(n, 0, ...) through add/sub
                // extract(n, 0, a + b + ...) = extract(n, 0, a) + extract(n, 0, b) + ...
                // This is valid because the low bits of add/sub only depend on the low bits of the operands
                BitVecOp::Add(add_args) if *low == 0 => {
                    let extracted: Vec<BitVecAst<'c>> = add_args
                        .iter()
                        .map(|a| ctx.extract(a, *high, 0))
                        .collect::<Result<_, _>>()?;
                    state.rerun(ctx.add_many(extracted)?)
                }
                BitVecOp::Sub(lhs, rhs) if *low == 0 => {
                    let lhs_extracted = ctx.extract(lhs, *high, 0)?;
                    let rhs_extracted = ctx.extract(rhs, *high, 0)?;
                    state.rerun(ctx.sub(&lhs_extracted, &rhs_extracted)?)
                }

                // Propagate extract through bitwise operations
                // extract(n, m, a & b & ...) = extract(n, m, a) & extract(n, m, b) & ...
                BitVecOp::And(and_args) => {
                    let extracted: Vec<BitVecAst<'c>> = and_args
                        .iter()
                        .map(|a| ctx.extract(a, *high, *low))
                        .collect::<Result<_, _>>()?;
                    state.rerun(ctx.bv_and_many(extracted)?)
                }
                // extract(n, m, a | b | ...) = extract(n, m, a) | extract(n, m, b) | ...
                BitVecOp::Or(or_args) => {
                    let extracted: Vec<BitVecAst<'c>> = or_args
                        .iter()
                        .map(|a| ctx.extract(a, *high, *low))
                        .collect::<Result<_, _>>()?;
                    state.rerun(ctx.bv_or_many(extracted)?)
                }
                // extract(n, m, a ^ b ^ ...) = extract(n, m, a) ^ extract(n, m, b) ^ ...
                BitVecOp::Xor(xor_args) => {
                    let extracted: Vec<BitVecAst<'c>> = xor_args
                        .iter()
                        .map(|a| ctx.extract(a, *high, *low))
                        .collect::<Result<_, _>>()?;
                    state.rerun(ctx.bv_xor_many(extracted)?)
                }
                // extract(n, m, ~a) = ~extract(n, m, a)
                BitVecOp::Not(inner) => {
                    let inner_extracted = ctx.extract(inner, *high, *low)?;
                    state.rerun(ctx.not(&inner_extracted)?)
                }

                // Propogate through ITE
                BitVecOp::ITE(cond, then_bv, else_bv) => {
                    let then_extracted = ctx.extract(then_bv, *high, *low)?;
                    let else_extracted = ctx.extract(else_bv, *high, *low)?;
                    state.rerun(ctx.ite(cond, &then_extracted, &else_extracted)?)
                }

                // ZeroExt cases
                // If extracting from the original bits (not the extended zero bits)
                BitVecOp::ZeroExt(inner, _) if *high < inner.size() => {
                    state.rerun(ctx.extract(inner, *high, *low)?)
                }
                // If extracting only from the extended zero bits
                BitVecOp::ZeroExt(inner, _) if *low >= inner.size() => {
                    Ok(ctx.bvv(BitVec::zeros(*high - *low + 1))?)
                }
                // If extracting bits that span original and extended parts
                BitVecOp::ZeroExt(inner, _) => {
                    let inner_size = inner.size();
                    // Extract what we can from the original bits
                    let extracted = ctx.extract(inner, inner_size - 1, *low)?;
                    // Zero-extend to the final size
                    state.rerun(ctx.zero_ext(&extracted, *high - inner_size + 1)?)
                }

                // SignExt cases
                // If extracting from the original bits (not the extended sign bits)
                BitVecOp::SignExt(inner, _) if *high < inner.size() => {
                    state.rerun(ctx.extract(inner, *high, *low)?)
                }
                // If extracting only from the extended sign bits
                BitVecOp::SignExt(inner, _) if *low >= inner.size() => {
                    let sign_bit = ctx.extract(inner, inner.size() - 1, inner.size() - 1)?;
                    // Replicate the sign bit for the extracted width
                    let width = *high - *low + 1;
                    let sign_bits: Vec<_> = (0..width).map(|_| sign_bit.clone()).collect();
                    Ok(ctx.concat(sign_bits)?)
                }

                // N-ary Concat cases
                BitVecOp::Concat(args) => {
                    // Compute cumulative sizes from the right (LSB side)
                    // For concat(a, b, c), sizes are [a.size()+b.size()+c.size(), b.size()+c.size(), c.size(), 0]
                    let mut cumulative_sizes: Vec<u32> = Vec::with_capacity(args.len() + 1);
                    let mut sum = 0u32;
                    for arg in args.iter().rev() {
                        cumulative_sizes.push(sum);
                        sum += arg.size();
                    }
                    cumulative_sizes.push(sum);
                    cumulative_sizes.reverse();
                    // Now cumulative_sizes[i] = total size of args[i..] (bits from position 0 to end of arg i)

                    // Find which args the extract spans
                    // The extract covers bits [low, high] inclusive
                    // arg[i] covers bits [cumulative_sizes[i+1], cumulative_sizes[i] - 1]
                    let mut first_idx = None;
                    let mut last_idx = None;
                    for i in 0..args.len() {
                        let arg_high = cumulative_sizes[i] - 1; // highest bit of this arg
                        let arg_low = cumulative_sizes[i + 1]; // lowest bit of this arg

                        if *high >= arg_low && *low <= arg_high {
                            if first_idx.is_none() {
                                first_idx = Some(i);
                            }
                            last_idx = Some(i);
                        }
                    }

                    match (first_idx, last_idx) {
                        (Some(first), Some(last)) if first == last => {
                            // Extract is entirely within one arg
                            let arg_low = cumulative_sizes[first + 1];
                            state.rerun(ctx.extract(
                                &args[first],
                                *high - arg_low,
                                *low - arg_low,
                            )?)
                        }
                        (Some(first), Some(last)) => {
                            // Extract spans multiple args
                            let mut parts = Vec::with_capacity(last - first + 1);
                            for i in first..=last {
                                let arg = &args[i];
                                let arg_high = cumulative_sizes[i] - 1;
                                let arg_low = cumulative_sizes[i + 1];

                                let extract_high = (*high).min(arg_high) - arg_low;
                                let extract_low = (*low).max(arg_low) - arg_low;
                                parts.push(ctx.extract(arg, extract_high, extract_low)?);
                            }
                            state.rerun(ctx.concat(parts)?)
                        }
                        _ => Ok(ctx.extract(arc, *high, *low)?),
                    }
                }
                _ => Ok(ctx.extract(arc, *high, *low)?),
            }
        }
        BitVecOp::Concat(_) => {
            // Simplify all children in one batch. Fetching them one at a
            // time would make simplify_inner re-run for every child and
            // turn wide Concats into a quadratic cost.
            let simplified_args = state.get_all_bv_simplified()?;

            // Flatten nested Concats and filter zero-size args
            let mut flattened: Vec<BitVecAst<'c>> = Vec::new();
            for arg in simplified_args {
                if arg.size() == 0 {
                    continue;
                }
                if let BitVecOp::Concat(inner_args) = arg.op() {
                    flattened.extend(inner_args.iter().cloned());
                } else {
                    flattened.push(arg);
                }
            }

            // Concat(If(c, a0, b0), If(c, a1, b1), ...)
            //   -> If(c, Concat(a0, a1, ...), Concat(b0, b1, ...))
            // when every piece is an ITE guarded by the same condition. This
            // recombines values computed lane-by-lane (e.g. a word updated
            // byte-wise in memory) back into a single conditional, which is what
            // lets the surrounding arithmetic collapse.
            if flattened.len() >= 2
                && let BitVecOp::ITE(cond0, _, _) = flattened[0].op()
            {
                let cond_hash = cond0.hash();
                let all_same_cond = flattened
                    .iter()
                    .all(|a| matches!(a.op(), BitVecOp::ITE(c, _, _) if c.hash() == cond_hash));
                if all_same_cond {
                    let cond = match flattened[0].op() {
                        BitVecOp::ITE(c, _, _) => c.clone(),
                        _ => unreachable!(),
                    };
                    let mut thens: Vec<BitVecAst<'c>> = Vec::with_capacity(flattened.len());
                    let mut elses: Vec<BitVecAst<'c>> = Vec::with_capacity(flattened.len());
                    for a in &flattened {
                        if let BitVecOp::ITE(_, t, e) = a.op() {
                            thens.push(t.clone());
                            elses.push(e.clone());
                        }
                    }
                    let then_concat = ctx.concat(thens)?;
                    let else_concat = ctx.concat(elses)?;
                    return state.rerun(ctx.ite(cond, then_concat, else_concat)?);
                }
            }

            // Merge adjacent constants and adjacent extracts of the same source.
            let mut merged: Vec<BitVecAst<'c>> = Vec::new();
            let mut merged_extracts = false;
            for arg in flattened {
                // Concat(.., BVV(a), BVV(b)) -> Concat(.., BVV(a .. b))
                if let (Some(last), BitVecOp::BVV(curr_val)) = (merged.last(), arg.op())
                    && let BitVecOp::BVV(last_val) = last.op()
                {
                    let merged_val = last_val.concat(curr_val)?;
                    merged.pop();
                    merged.push(ctx.bvv(merged_val)?);
                    continue;
                }
                // Concat(.., Extract(hi, mid + 1, x), Extract(mid, lo, x))
                //   -> Concat(.., Extract(hi, lo, x))
                // Reassembles a value that was split into adjacent pieces, e.g. a
                // word stored/loaded byte-wise in memory. Without this, such
                // split-then-recombined values survive to the solver and can make
                // otherwise-trivial queries extremely hard.
                if let Some(last) = merged.last()
                    && let BitVecOp::Extract(hi_src, hi_high, hi_low) = last.op()
                    && let BitVecOp::Extract(lo_src, lo_high, lo_low) = arg.op()
                    && *hi_low == lo_high + 1
                    && hi_src.hash() == lo_src.hash()
                {
                    let combined = ctx.extract(hi_src, *hi_high, *lo_low)?;
                    merged.pop();
                    merged.push(combined);
                    merged_extracts = true;
                    continue;
                }
                merged.push(arg);
            }

            // Concat(BVV(0, N), rest...) -> ZeroExt(N, Concat(rest...))
            if merged.len() >= 2
                && matches!(merged[0].op(), BitVecOp::BVV(high_val) if high_val.is_zero())
            {
                let ext_size = merged[0].size();
                let rest: Vec<BitVecAst<'c>> = merged[1..].to_vec();
                let inner = if rest.len() == 1 {
                    rest.into_iter().next().unwrap()
                } else {
                    ctx.concat(rest)?
                };
                return state.rerun(ctx.zero_ext(&inner, ext_size)?);
            }

            // Handle result based on merged length
            let result = match merged.len() {
                0 => {
                    return Err(SimplifyError::Error(ClarirsError::InvalidArguments(
                        "Concat resulted in zero arguments".to_string(),
                    )));
                }
                1 => merged.into_iter().next().unwrap(),
                _ => ctx.concat(merged)?,
            };
            // Re-simplify when extracts were combined so that a now-full-range
            // Extract(size - 1, 0, x) collapses back to x.
            if merged_extracts {
                state.rerun(result)
            } else {
                Ok(result)
            }
        }
        BitVecOp::ByteReverse(..) => {
            let arc = state.get_bv_simplified(0)?;
            // Reversing a single byte (or smaller) is the identity.
            if arc.size() <= 8 {
                return Ok(arc);
            }
            match arc.op() {
                BitVecOp::BVV(value) => {
                    let reversed_bits = value.reverse_bytes()?;
                    Ok(ctx.bvv(reversed_bits)?)
                }
                // Reverse(Reverse(x)) -> x
                BitVecOp::ByteReverse(inner) => Ok(inner.clone()),
                // Reverse(If(c, a, b)) -> If(c, Reverse(a), Reverse(b)). Pushing
                // the reverse into the branches lets it cancel/collapse there.
                BitVecOp::ITE(cond, then_, else_) => {
                    let new = ctx.ite(
                        cond.clone(),
                        ctx.byte_reverse(then_.clone())?,
                        ctx.byte_reverse(else_.clone())?,
                    )?;
                    state.rerun(new)
                }
                // Reverse(Concat(a, .., z)) -> Concat(Reverse(z), .., Reverse(a)).
                // Byte-order reversal commutes with Concat only when every piece
                // is byte-aligned.
                BitVecOp::Concat(args)
                    if args.len() > 1 && args.iter().all(|a| a.size() % 8 == 0) =>
                {
                    let reversed = args
                        .iter()
                        .rev()
                        .map(|a| ctx.byte_reverse(a.clone()))
                        .collect::<Result<Vec<_>, _>>()?;
                    let new = ctx.concat(reversed)?;
                    state.rerun(new)
                }
                _ => Ok(ctx.byte_reverse(arc)?),
            }
        }
        BitVecOp::FpToIEEEBV(..) => {
            let arc = state.get_fp_simplified(0)?;
            match arc.op() {
                FloatOp::FPV(float) => {
                    // Convert the floating-point value to its IEEE 754 bit representation
                    let ieee_bits = float.to_ieee_bits();
                    let bit_length = float.fsort().size();

                    // Create a BitVec with the IEEE 754 representation
                    Ok(ctx.bvv(
                        BitVec::from_biguint(&ieee_bits, bit_length)
                            .expect("Failed to create BitVec from BigUint"),
                    )?)
                }
                _ => Ok(ctx.fp_to_ieeebv(arc)?), // Fallback for non-concrete values
            }
        }
        BitVecOp::FpToUBV(_, bit_size, fprm) => {
            let arc = state.get_fp_simplified(0)?;
            match arc.op() {
                FloatOp::FPV(float) => {
                    // Convert the float to an unsigned integer representation (BigUint)
                    let unsigned_value = float.to_unsigned_biguint().unwrap_or(BigUint::zero());

                    // Truncate or extend the result to fit within the specified bit size
                    let result_bitvec = BitVec::from_biguint_trunc(&unsigned_value, *bit_size);

                    Ok(ctx.bvv(result_bitvec)?)
                }
                _ => Ok(ctx.fp_to_ubv(arc, *bit_size, *fprm)?), // Fallback for non-concrete values
            }
        }
        BitVecOp::FpToSBV(_, bit_size, fprm) => {
            let arc = state.get_fp_simplified(0)?;
            match arc.op() {
                FloatOp::FPV(float) => {
                    // Convert the float to a signed integer representation (BigInt)
                    let signed_value = float.to_signed_bigint().unwrap_or(BigInt::zero());

                    // Convert the signed value to BigUint for BitVec construction
                    let unsigned_value = signed_value.to_biguint().unwrap_or(BigUint::zero());

                    // Create a BitVec with the result, truncating or extending to fit within the specified bit size
                    let result_bitvec = BitVec::from_biguint_trunc(&unsigned_value, *bit_size);

                    Ok(ctx.bvv(result_bitvec)?)
                }
                _ => Ok(ctx.fp_to_sbv(arc, *bit_size, *fprm)?), // Fallback for non-concrete values
            }
        }
        BitVecOp::StrLen(..) => {
            let arc = state.get_string_simplified(0)?;
            match arc.op() {
                StringOp::StringV(value) => {
                    // chars().count() returns the number of Unicode scalar values
                    let length = value.chars().count() as u64;
                    Ok(ctx.bvv(BitVec::from_prim_with_size(length, 64)?)?)
                }
                _ => Ok(ctx.str_len(arc)?), // Fallback to symbolic
            }
        }
        BitVecOp::StrIndexOf(..) => {
            let (arc, arc1, arc2) = (
                state.get_string_simplified(0)?,
                state.get_string_simplified(1)?,
                state.get_bv_simplified(2)?,
            );

            match (arc.op(), arc1.op(), arc2.op()) {
                (
                    StringOp::StringV(input_string),
                    StringOp::StringV(substring),
                    BitVecOp::BVV(start_index),
                ) => {
                    let s = input_string;
                    let t = substring;
                    let i = start_index.to_usize().unwrap_or(0);

                    // Use character count for Unicode-aware indexing
                    let char_count = s.chars().count();

                    // Check if `t` exists in `s` starting from character index `i`
                    if i < char_count {
                        // Convert character index to byte index
                        let byte_index = s
                            .char_indices()
                            .nth(i)
                            .map(|(idx, _)| idx)
                            .unwrap_or(s.len());

                        match s[byte_index..].find(t) {
                            Some(pos) => {
                                // Convert byte position back to character position
                                let byte_pos = byte_index + pos;
                                let char_pos = s[..byte_pos].chars().count();
                                Ok(ctx.bvv(BitVec::from_prim_with_size(char_pos as u64, 64)?)?)
                            }
                            None => Ok(ctx.bvv(BitVec::from_prim_with_size(-1i64 as u64, 64)?)?), // -1 if not found
                        }
                    } else {
                        // If start index is out of bounds, return -1
                        Ok(ctx.bvv(BitVec::from_prim_with_size(-1i64 as u64, 64)?)?)
                    }
                }
                _ => Ok(ctx.str_index_of(arc, arc1, arc2)?), // Fallback to symbolic
            }
        }
        BitVecOp::StrToBV(..) => {
            let arc = state.get_string_simplified(0)?;
            match arc.op() {
                StringOp::StringV(string) => {
                    if string.is_empty() {
                        let max_int = BigUint::from_str_radix("ffffffffffffffff", 16).unwrap();
                        return Ok(ctx.bvv(BitVec::from_biguint_trunc(&max_int, 64))?);
                    }

                    // Attempt to parse the string as a decimal integer
                    let value = BigUint::from_str_radix(string, 10)
                        .or_else(|_| BigUint::from_str_radix(string, 16)) // Try hexadecimal if decimal fails
                        .or_else(|_| BigUint::from_str_radix(string, 2)) // Try binary if hexadecimal fails
                        .unwrap_or_else(|_| {
                            BigUint::from_str_radix("ffffffffffffffff", 16).unwrap()
                        });

                    // If the parsed number is too large to fit in 64 bits, return 0.
                    if value >= BigUint::from(2u64).pow(64) {
                        return Ok(ctx.bvv(BitVec::zeros(64))?);
                    }

                    Ok(ctx.bvv(BitVec::from_biguint_trunc(&value, 64))?)
                }
                _ => Ok(ctx.str_to_bv(arc)?),
            }
        }
        BitVecOp::ITE(..) => {
            let (if_, then_, else_) = (
                state.get_bool_simplified(0)?,
                state.get_bv_simplified(1)?,
                state.get_bv_simplified(2)?,
            );

            // If both branches are identical, return either one
            if then_ == else_ {
                return Ok(then_.clone());
            }

            match if_.op() {
                // If the condition is a concrete boolean value, return the appropriate branch
                BooleanOp::BoolV(value) => {
                    if *value {
                        Ok(then_.clone())
                    } else {
                        Ok(else_.clone())
                    }
                }
                // If the condition has a Not at the top level, invert the branches
                BooleanOp::Not(inner) => state.rerun(ctx.ite(inner, else_, then_)?),
                _ => Ok(ctx.ite(if_, then_, else_)?),
            }
        }
        BitVecOp::Union(..) => {
            let (lhs, rhs) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            if lhs == rhs {
                return Ok(lhs.clone());
            }
            Ok(ctx.union(lhs, rhs)?)
        }
        BitVecOp::Intersection(..) => {
            let (lhs, rhs) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            if lhs == rhs {
                return Ok(lhs.clone());
            }
            Ok(ctx.intersection(lhs, rhs)?)
        }
        BitVecOp::Widen(..) => {
            let (lhs, rhs) = (state.get_bv_simplified(0)?, state.get_bv_simplified(1)?);
            if lhs == rhs {
                return Ok(lhs.clone());
            }
            Ok(ctx.widen(lhs, rhs)?)
        }
    }
}
