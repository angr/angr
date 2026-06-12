use std::collections::{HashMap, HashSet};

use super::SimplifyError;
use crate::prelude::*;

pub(crate) fn simplify_bool<'c>(
    state: &mut super::SimplifyState<'c>,
) -> Result<AstRef<'c>, SimplifyError<'c>> {
    let ctx = state.expr.context();
    let bool_ast = state.expr.clone();

    match bool_ast.op() {
        AstOp::BoolS(_) | AstOp::BoolV(_) => Ok(bool_ast),
        AstOp::Not(..) => {
            let arc = state.get_child_simplified(0)?;

            match arc.op() {
                AstOp::Not(arc) => Ok(arc.clone()),
                AstOp::BoolV(v) => Ok(ctx.boolv(!v)?),

                AstOp::Eq(lhs, rhs) => Ok(ctx.neq(lhs.clone(), rhs.clone())?),
                AstOp::Neq(lhs, rhs) => Ok(ctx.eq_(lhs.clone(), rhs.clone())?),

                // !(a > b)  ==>  a <= b
                AstOp::UGT(lhs, rhs) => state.rerun(ctx.ule(lhs.clone(), rhs.clone())?),
                // !(a >= b)  ==>  a < b
                AstOp::UGE(lhs, rhs) => state.rerun(ctx.ult(lhs.clone(), rhs.clone())?),
                // !(a < b)  ==>  a >= b
                AstOp::ULT(lhs, rhs) => state.rerun(ctx.uge(lhs.clone(), rhs.clone())?),
                // !(a <= b)  ==>  a > b
                AstOp::ULE(lhs, rhs) => state.rerun(ctx.ugt(lhs.clone(), rhs.clone())?),
                // !(a s> b)  ==>  a s<= b
                AstOp::SGT(lhs, rhs) => state.rerun(ctx.sle(lhs.clone(), rhs.clone())?),
                // !(a s>= b)  ==>  a s< b
                AstOp::SGE(lhs, rhs) => state.rerun(ctx.slt(lhs.clone(), rhs.clone())?),
                // !(a s< b)  ==>  a s>= b
                AstOp::SLT(lhs, rhs) => state.rerun(ctx.sge(lhs.clone(), rhs.clone())?),
                // !(a s<= b)  ==>  a s> b
                AstOp::SLE(lhs, rhs) => state.rerun(ctx.sgt(lhs.clone(), rhs.clone())?),

                _ => Ok(ctx.not(arc)?),
            }
        }
        AstOp::And(args) => {
            let available_args = (0..args.len())
                .map(|i| state.get_child_available(i))
                .collect::<Vec<_>>();

            // Absorption simplification
            let absorbed_args = available_args
                .into_iter()
                .flat_map(|arg| {
                    if let AstOp::And(nested_args) = arg.op() {
                        nested_args.clone()
                    } else {
                        vec![arg]
                    }
                })
                .filter(|arg| !matches!(arg.op(), AstOp::BoolV(true)))
                .collect::<Vec<_>>();
            // Deduplicate using == comparison
            let mut deduped = Vec::with_capacity(absorbed_args.len());
            for arg in absorbed_args {
                if !deduped.iter().any(|existing| existing == &arg) {
                    deduped.push(arg);
                }
            }
            let absorbed_args = deduped;

            if absorbed_args.is_empty() {
                return Ok(ctx.true_()?);
            }
            if absorbed_args.len() == 1 {
                return state.rerun(absorbed_args[0].clone());
            }

            // Identity simplification
            if absorbed_args
                .iter()
                .any(|arg| matches!(arg.op(), AstOp::BoolV(false)))
            {
                return Ok(ctx.false_()?);
            }

            // x & !x == false
            for i in 0..absorbed_args.len() {
                for j in (i + 1)..absorbed_args.len() {
                    if let AstOp::Not(neg) = absorbed_args[i].op()
                        && neg == &absorbed_args[j]
                    {
                        return Ok(ctx.false_()?);
                    }
                    if let AstOp::Not(neg) = absorbed_args[j].op()
                        && neg == &absorbed_args[i]
                    {
                        return Ok(ctx.false_()?);
                    }
                }
            }

            // All of the comparisons
            // ex x == K & x != K  ==>  false
            for i in 0..absorbed_args.len() {
                for j in (i + 1)..absorbed_args.len() {
                    match (absorbed_args[i].op(), absorbed_args[j].op()) {
                        (AstOp::Eq(var1, val1), AstOp::Neq(var2, val2))
                        | (AstOp::Neq(var2, val2), AstOp::Eq(var1, val1))
                        | (AstOp::ULT(var1, val1), AstOp::UGE(var2, val2))
                        | (AstOp::UGE(var2, val2), AstOp::ULT(var1, val1))
                        | (AstOp::ULE(var1, val1), AstOp::UGT(var2, val2))
                        | (AstOp::UGT(var2, val2), AstOp::ULE(var1, val1))
                        | (AstOp::SLT(var1, val1), AstOp::SGE(var2, val2))
                        | (AstOp::SGE(var2, val2), AstOp::SLT(var1, val1))
                        | (AstOp::SLE(var1, val1), AstOp::SGT(var2, val2))
                        | (AstOp::SGT(var2, val2), AstOp::SLE(var1, val1))
                            if var1 == var2 && val1 == val2 =>
                        {
                            return Ok(ctx.false_()?);
                        }
                        _ => {}
                    }
                }
            }

            if absorbed_args.len() != args.len() {
                return state.rerun(ctx.and(absorbed_args)?);
            }

            // Simplify all children in one batch to avoid quadratic re-runs
            // for wide And.
            let simplified_args = state.get_all_simplified()?;
            Ok(ctx.and(simplified_args)?)
        }
        AstOp::Or(args) => {
            let available_args = (0..args.len())
                .map(|i| state.get_child_available(i))
                .collect::<Vec<_>>();

            // Absorption simplification
            let absorbed_args = available_args
                .into_iter()
                .flat_map(|arg| {
                    if let AstOp::Or(nested_args) = arg.op() {
                        nested_args.clone()
                    } else {
                        vec![arg]
                    }
                })
                .filter(|arg| !matches!(arg.op(), AstOp::BoolV(false)))
                .collect::<Vec<_>>();
            // Deduplicate using == comparison
            let mut deduped = Vec::with_capacity(absorbed_args.len());
            for arg in absorbed_args {
                if !deduped.iter().any(|existing| existing == &arg) {
                    deduped.push(arg);
                }
            }
            let absorbed_args = deduped;

            // Identity simplification
            if absorbed_args
                .iter()
                .any(|arg| matches!(arg.op(), AstOp::BoolV(true)))
            {
                return Ok(ctx.true_()?);
            }

            if absorbed_args.is_empty() {
                return Ok(ctx.false_()?);
            }
            if absorbed_args.len() == 1 {
                return state.rerun(absorbed_args[0].clone());
            }

            // x | !x == true
            for i in 0..absorbed_args.len() {
                for j in (i + 1)..absorbed_args.len() {
                    if let AstOp::Not(neg) = absorbed_args[i].op()
                        && neg == &absorbed_args[j]
                    {
                        return Ok(ctx.true_()?);
                    }
                    if let AstOp::Not(neg) = absorbed_args[j].op()
                        && neg == &absorbed_args[i]
                    {
                        return Ok(ctx.true_()?);
                    }
                }
            }

            // All of the comparisons
            // ex x == K | x != K  ==>  true
            for i in 0..absorbed_args.len() {
                for j in (i + 1)..absorbed_args.len() {
                    match (absorbed_args[i].op(), absorbed_args[j].op()) {
                        (AstOp::Eq(var1, val1), AstOp::Neq(var2, val2))
                        | (AstOp::Neq(var2, val2), AstOp::Eq(var1, val1))
                        | (AstOp::ULT(var1, val1), AstOp::UGE(var2, val2))
                        | (AstOp::UGE(var2, val2), AstOp::ULT(var1, val1))
                        | (AstOp::ULE(var1, val1), AstOp::UGT(var2, val2))
                        | (AstOp::UGT(var2, val2), AstOp::ULE(var1, val1))
                        | (AstOp::SLT(var1, val1), AstOp::SGE(var2, val2))
                        | (AstOp::SGE(var2, val2), AstOp::SLT(var1, val1))
                        | (AstOp::SLE(var1, val1), AstOp::SGT(var2, val2))
                        | (AstOp::SGT(var2, val2), AstOp::SLE(var1, val1))
                            if var1 == var2 && val1 == val2 =>
                        {
                            return Ok(ctx.true_()?);
                        }
                        _ => {}
                    }
                }
            }

            if absorbed_args.len() != args.len() {
                return state.rerun(ctx.or(absorbed_args)?);
            }

            // Simplify all children in one batch to avoid quadratic re-runs
            // for wide Or.
            let simplified_args = state.get_all_simplified()?;
            Ok(ctx.or(simplified_args)?)
        }
        AstOp::Xor(..) => {
            // n-ary boolean xor: fold constants into a parity bit, strip
            // negations (Not(x) = x ^ true), and cancel repeated operands in
            // pairs (x ^ x = false).
            let args = state.get_all_simplified()?;
            let mut parity = false;
            let mut operands: Vec<AstRef> = Vec::with_capacity(args.len());
            for arg in args {
                match arg.op() {
                    AstOp::BoolV(b) => parity ^= b,
                    AstOp::Not(inner) => {
                        parity = !parity;
                        operands.push(inner.clone());
                    }
                    _ => operands.push(arg),
                }
            }

            // xor of k copies of x is x when k is odd, false when k is even
            let mut counts: HashMap<u64, usize> = HashMap::new();
            for o in &operands {
                *counts.entry(o.hash()).or_default() += 1;
            }
            let mut seen = HashSet::new();
            let rest: Vec<_> = operands
                .into_iter()
                .filter(|o| counts[&o.hash()] % 2 == 1 && seen.insert(o.hash()))
                .collect();

            let combined = match rest.len() {
                0 => ctx.boolv(false)?,
                1 => rest[0].clone(),
                _ => ctx.xor(rest)?,
            };
            if parity {
                match combined.op() {
                    AstOp::BoolV(b) => Ok(ctx.boolv(!b)?),
                    // Re-simplify the produced negation so Not(comparison) ->
                    // inverse-comparison rules apply, matching a directly-built Not.
                    _ => state.rerun(ctx.not(combined)?),
                }
            } else {
                Ok(combined)
            }
        }
        AstOp::Eq(..) => match state.get_child_available(0).ast_type() {
            AstType::Bool => {
                let early_lhs = state.get_child_available(0);
                let early_rhs = state.get_child_available(1);

                match (early_lhs.op(), early_rhs.op()) {
                    (AstOp::BoolV(arc), AstOp::BoolV(arc1)) => Ok(ctx.boolv(arc == arc1)?),
                    (AstOp::BoolV(true), _) => Ok(state.get_child_simplified(1)?),
                    (_, AstOp::BoolV(true)) => Ok(state.get_child_simplified(0)?),
                    // x == false -> !x; rerun so the produced Not canonicalizes.
                    (AstOp::BoolV(false), _) => state.rerun(ctx.not(&early_rhs)?),
                    (_, AstOp::BoolV(false)) => state.rerun(ctx.not(&early_lhs)?),
                    // a == a -> true. Even when floats are involved, this is a boolean
                    // identity: both sides are the same expression and evaluate to the same
                    // value (NaN only affects fp== itself, not bool== of two equal booleans).
                    _ if early_lhs == early_rhs => Ok(ctx.true_()?),
                    _ => Ok(ctx.eq_(
                        state.get_child_simplified(0)?,
                        state.get_child_simplified(1)?,
                    )?),
                }
            }
            AstType::Float(_) => {
                let early_lhs = state.get_child_available(0);
                let early_rhs = state.get_child_available(1);

                match (early_lhs.op(), early_rhs.op()) {
                    (AstOp::FPV(arc), AstOp::FPV(arc1)) => Ok(ctx.boolv(arc.compare_fp(arc1))?),
                    _ => Ok(ctx.fp_eq(
                        state.get_child_simplified(0)?,
                        state.get_child_simplified(1)?,
                    )?),
                }
            }
            AstType::String => {
                let early_lhs = state.get_child_available(0);
                let early_rhs = state.get_child_available(1);

                match (early_lhs.op(), early_rhs.op()) {
                    (AstOp::StringV(str1), AstOp::StringV(str2)) => Ok(ctx.boolv(str1 == str2)?),
                    _ => Ok(ctx.str_eq(
                        state.get_child_simplified(0)?,
                        state.get_child_simplified(1)?,
                    )?),
                }
            }
            AstType::BitVec(_) => {
                let early_lhs = state.get_child_available(0);
                let early_rhs = state.get_child_available(1);

                match (early_lhs.op(), early_rhs.op()) {
                    (lhs, rhs) if lhs == rhs => Ok(ctx.true_()?),
                    (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc == arc1)?),

                    // If on one side there is an AND where one of the operands is a mask, and on the
                    // other side, there is a BVV which matches the masked part of the AND, we can
                    // extract the AND operand directly, and extract the other side and rerun
                    (AstOp::And(and_args), AstOp::BVV(bvv))
                        if and_args
                            .iter()
                            .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                    {
                        let mask_idx = and_args
                            .iter()
                            .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                            .unwrap();
                        let mask = &and_args[mask_idx];
                        let remaining: Vec<_> = and_args
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| *i != mask_idx)
                            .map(|(_, a)| a.clone())
                            .collect();
                        let lhs_and = if remaining.len() == 1 {
                            remaining.into_iter().next().unwrap()
                        } else {
                            ctx.and(remaining)?
                        };
                        let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                            mask_val.is_mask()
                        } else {
                            None
                        }
                        .expect("Checked above, switch to if let when stabilized");
                        state.rerun(ctx.eq_(
                            ctx.extract(&lhs_and, mask_high, mask_low)?,
                            ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                        )?)
                    }

                    // If one side is a = ZeroExt and the other side is a BVV with those bits set to zero,
                    // we can extract the relevant bits and compare directly
                    (AstOp::ZeroExt(innner, ext_size), AstOp::BVV(outer))
                    | (AstOp::BVV(outer), AstOp::ZeroExt(innner, ext_size))
                        if outer.leading_zeros() as u32 >= *ext_size =>
                    {
                        state.rerun(ctx.eq_(
                            innner.clone(),
                            ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                        )?)
                    }

                    // If both sides are ZeroExt of the same size, we can compare the inner values directly
                    (AstOp::ZeroExt(inner_lhs, _), AstOp::ZeroExt(inner_rhs, _)) => {
                        state.rerun(ctx.eq_(inner_lhs.clone(), inner_rhs.clone())?)
                    }

                    // (ite cond 1 0) == 0  ==>  !cond
                    (AstOp::ITE(cond, then_val, else_val), AstOp::BVV(val))
                    | (AstOp::BVV(val), AstOp::ITE(cond, then_val, else_val))
                        if val.is_zero() =>
                    {
                        if let (AstOp::BVV(then_bvv), AstOp::BVV(else_bvv)) =
                            (then_val.op(), else_val.op())
                        {
                            if then_bvv.is_one() && else_bvv.is_zero() {
                                // (ite cond 1 0) == 0  ==>  !cond
                                return state.rerun(ctx.not(cond.clone())?);
                            } else if then_bvv.is_zero() && else_bvv.is_one() {
                                // (ite cond 0 1) == 0  ==>  cond
                                return state.rerun(cond.clone());
                            }
                        }
                        Ok(ctx.eq_(
                            state.get_child_simplified(0)?,
                            state.get_child_simplified(1)?,
                        )?)
                    }

                    // (ite cond 1 0) == 1  ==>  cond
                    (AstOp::ITE(cond, then_val, else_val), AstOp::BVV(val))
                    | (AstOp::BVV(val), AstOp::ITE(cond, then_val, else_val))
                        if val.is_one() =>
                    {
                        if let (AstOp::BVV(then_bvv), AstOp::BVV(else_bvv)) =
                            (then_val.op(), else_val.op())
                        {
                            if then_bvv.is_one() && else_bvv.is_zero() {
                                // (ite cond 1 0) == 1  ==>  cond
                                return state.rerun(cond.clone());
                            } else if then_bvv.is_zero() && else_bvv.is_one() {
                                // (ite cond 0 1) == 1  ==>  !cond
                                return state.rerun(ctx.not(cond.clone())?);
                            }
                        }
                        Ok(ctx.eq_(
                            state.get_child_simplified(0)?,
                            state.get_child_simplified(1)?,
                        )?)
                    }

                    // (x - C) == 0  ==>  x == C
                    (AstOp::Sub(lhs_sub, rhs_sub), AstOp::BVV(val))
                    | (AstOp::BVV(val), AstOp::Sub(lhs_sub, rhs_sub))
                        if val.is_zero() && matches!(rhs_sub.op(), AstOp::BVV(..)) =>
                    {
                        state.rerun(ctx.eq_(lhs_sub.clone(), rhs_sub.clone())?)
                    }

                    // (sum + C) == 0  ==>  sum == -C
                    (AstOp::Add(add_args), AstOp::BVV(val))
                    | (AstOp::BVV(val), AstOp::Add(add_args))
                        if val.is_zero()
                            && add_args.iter().any(|a| matches!(a.op(), AstOp::BVV(..))) =>
                    {
                        if let Some(bvv_idx) = add_args
                            .iter()
                            .position(|a| matches!(a.op(), AstOp::BVV(..)))
                        {
                            let neg_c = ctx.neg(&add_args[bvv_idx])?;
                            let remaining: Vec<_> = add_args
                                .iter()
                                .enumerate()
                                .filter(|(i, _)| *i != bvv_idx)
                                .map(|(_, a)| a.clone())
                                .collect();
                            let lhs = if remaining.len() == 1 {
                                remaining.into_iter().next().unwrap()
                            } else {
                                ctx.add_many(remaining)?
                            };
                            state.rerun(ctx.eq_(lhs, neg_c)?)
                        } else {
                            unreachable!()
                        }
                    }

                    _ => Ok(ctx.eq_(
                        state.get_child_simplified(0)?,
                        state.get_child_simplified(1)?,
                    )?),
                }
            }
        },
        AstOp::Neq(..) => match state.get_child_available(0).ast_type() {
            AstType::Bool => {
                let early_lhs = state.get_child_available(0);
                let early_rhs = state.get_child_available(1);

                match (early_lhs.op(), early_rhs.op()) {
                    (AstOp::BoolV(arc), AstOp::BoolV(arc1)) => Ok(ctx.boolv(arc != arc1)?),
                    // x != true -> !x; rerun so the produced Not canonicalizes.
                    (AstOp::BoolV(true), _) => state.rerun(ctx.not(&early_rhs)?),
                    (_, AstOp::BoolV(true)) => state.rerun(ctx.not(&early_lhs)?),
                    (AstOp::BoolV(false), _) => Ok(state.get_child_simplified(1)?),
                    (_, AstOp::BoolV(false)) => Ok(state.get_child_simplified(0)?),
                    // a != a -> false. Even when floats are involved, this is a boolean
                    // identity: both sides are the same expression and evaluate to the same
                    // value (NaN only affects fp!= itself, not bool!= of two equal booleans).
                    _ if early_lhs == early_rhs => Ok(ctx.false_()?),
                    _ => Ok(ctx.neq(
                        state.get_child_simplified(0)?,
                        state.get_child_simplified(1)?,
                    )?),
                }
            }
            AstType::Float(_) => {
                let early_lhs = state.get_child_available(0);
                let early_rhs = state.get_child_available(1);

                match (early_lhs.op(), early_rhs.op()) {
                    (AstOp::FPV(arc), AstOp::FPV(arc1)) => Ok(ctx.boolv(!arc.compare_fp(arc1))?),
                    _ => Ok(ctx.fp_neq(
                        state.get_child_simplified(0)?,
                        state.get_child_simplified(1)?,
                    )?),
                }
            }
            AstType::String => {
                let early_lhs = state.get_child_available(0);
                let early_rhs = state.get_child_available(1);

                match (early_lhs.op(), early_rhs.op()) {
                    (AstOp::StringV(str1), AstOp::StringV(str2)) => Ok(ctx.boolv(str1 != str2)?),
                    _ => Ok(ctx.str_neq(
                        state.get_child_simplified(0)?,
                        state.get_child_simplified(1)?,
                    )?),
                }
            }
            AstType::BitVec(_) => {
                let early_lhs = state.get_child_available(0);
                let early_rhs = state.get_child_available(1);

                match (early_lhs.op(), early_rhs.op()) {
                    (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc != arc1)?),
                    (lhs, rhs) if lhs == rhs => Ok(ctx.false_()?),

                    // If on one side there is an AND where one of the operands is a mask, and on the
                    // other side, there is a BVV which matches the masked part of the AND, we can
                    // extract the AND operand directly, and extract the other side and rerun
                    (AstOp::And(and_args), AstOp::BVV(bvv))
                        if and_args
                            .iter()
                            .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                    {
                        let mask_idx = and_args
                            .iter()
                            .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                            .unwrap();
                        let mask = &and_args[mask_idx];
                        let remaining: Vec<_> = and_args
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| *i != mask_idx)
                            .map(|(_, a)| a.clone())
                            .collect();
                        let lhs_and = if remaining.len() == 1 {
                            remaining.into_iter().next().unwrap()
                        } else {
                            ctx.and(remaining)?
                        };
                        let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                            mask_val.is_mask()
                        } else {
                            None
                        }
                        .expect("Checked above, switch to if let when stabilized");
                        state.rerun(ctx.neq(
                            ctx.extract(&lhs_and, mask_high, mask_low)?,
                            ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                        )?)
                    }

                    // If one side is a = ZeroExt and the other side is a BVV with those bits set to zero,
                    // we can extract the relevant bits and compare directly
                    (AstOp::ZeroExt(innner, ext_size), AstOp::BVV(outer))
                    | (AstOp::BVV(outer), AstOp::ZeroExt(innner, ext_size))
                        if outer.leading_zeros() as u32 >= *ext_size =>
                    {
                        state.rerun(ctx.neq(
                            innner.clone(),
                            ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                        )?)
                    }

                    // If both sides are ZeroExt of the same size, we can compare the inner values directly
                    (AstOp::ZeroExt(inner_lhs, _), AstOp::ZeroExt(inner_rhs, _)) => {
                        state.rerun(ctx.neq(inner_lhs.clone(), inner_rhs.clone())?)
                    }

                    // (ite cond 1 0) != 0  ==>  cond
                    (AstOp::ITE(cond, then_val, else_val), AstOp::BVV(val))
                    | (AstOp::BVV(val), AstOp::ITE(cond, then_val, else_val))
                        if val.is_zero() =>
                    {
                        if let (AstOp::BVV(then_bvv), AstOp::BVV(else_bvv)) =
                            (then_val.op(), else_val.op())
                        {
                            if then_bvv.is_one() && else_bvv.is_zero() {
                                // (ite cond 1 0) != 0  ==>  cond
                                return state.rerun(cond.clone());
                            } else if then_bvv.is_zero() && else_bvv.is_one() {
                                // (ite cond 0 1) != 0  ==>  !cond
                                return state.rerun(ctx.not(cond.clone())?);
                            }
                        }
                        Ok(ctx.neq(
                            state.get_child_simplified(0)?,
                            state.get_child_simplified(1)?,
                        )?)
                    }

                    // (ite cond 1 0) != 1  ==>  !cond
                    (AstOp::ITE(cond, then_val, else_val), AstOp::BVV(val))
                    | (AstOp::BVV(val), AstOp::ITE(cond, then_val, else_val))
                        if val.is_one() =>
                    {
                        if let (AstOp::BVV(then_bvv), AstOp::BVV(else_bvv)) =
                            (then_val.op(), else_val.op())
                        {
                            if then_bvv.is_one() && else_bvv.is_zero() {
                                // (ite cond 1 0) != 1  ==>  !cond
                                return state.rerun(ctx.not(cond.clone())?);
                            } else if then_bvv.is_zero() && else_bvv.is_one() {
                                // (ite cond 0 1) != 1  ==>  cond
                                return state.rerun(cond.clone());
                            }
                        }
                        Ok(ctx.neq(
                            state.get_child_simplified(0)?,
                            state.get_child_simplified(1)?,
                        )?)
                    }

                    // (x - C) != 0  ==>  x != C
                    (AstOp::Sub(lhs_sub, rhs_sub), AstOp::BVV(val))
                    | (AstOp::BVV(val), AstOp::Sub(lhs_sub, rhs_sub))
                        if val.is_zero() && matches!(rhs_sub.op(), AstOp::BVV(..)) =>
                    {
                        state.rerun(ctx.neq(lhs_sub.clone(), rhs_sub.clone())?)
                    }

                    // (sum + C) != 0  ==>  sum != -C
                    (AstOp::Add(add_args), AstOp::BVV(val))
                    | (AstOp::BVV(val), AstOp::Add(add_args))
                        if val.is_zero()
                            && add_args.iter().any(|a| matches!(a.op(), AstOp::BVV(..))) =>
                    {
                        if let Some(bvv_idx) = add_args
                            .iter()
                            .position(|a| matches!(a.op(), AstOp::BVV(..)))
                        {
                            let neg_c = ctx.neg(&add_args[bvv_idx])?;
                            let remaining: Vec<_> = add_args
                                .iter()
                                .enumerate()
                                .filter(|(i, _)| *i != bvv_idx)
                                .map(|(_, a)| a.clone())
                                .collect();
                            let lhs = if remaining.len() == 1 {
                                remaining.into_iter().next().unwrap()
                            } else {
                                ctx.add_many(remaining)?
                            };
                            state.rerun(ctx.neq(lhs, neg_c)?)
                        } else {
                            unreachable!()
                        }
                    }

                    _ => Ok(ctx.neq(
                        state.get_child_simplified(0)?,
                        state.get_child_simplified(1)?,
                    )?),
                }
            }
        },
        AstOp::ULT(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (lhs, rhs) if lhs == rhs => Ok(ctx.false_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc < arc1)?),

                // If on one side there is an AND where one of the operands is a mask, and on the
                // other side, there is a BVV which matches the masked part of the AND, we can
                // extract the AND operand directly, and extract the other side and rerun
                (AstOp::And(and_args), AstOp::BVV(bvv))
                    if and_args
                        .iter()
                        .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                {
                    let mask_idx = and_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                        .unwrap();
                    let mask = &and_args[mask_idx];
                    let remaining: Vec<_> = and_args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != mask_idx)
                        .map(|(_, a)| a.clone())
                        .collect();
                    let lhs_and = if remaining.len() == 1 {
                        remaining.into_iter().next().unwrap()
                    } else {
                        ctx.and(remaining)?
                    };
                    let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                        mask_val.is_mask()
                    } else {
                        None
                    }
                    .expect("Checked above, switch to if let when stabilized");
                    state.rerun(ctx.ult(
                        ctx.extract(&lhs_and, mask_high, mask_low)?,
                        ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                    )?)
                }
                (AstOp::BVV(bvv), AstOp::And(and_args))
                    if and_args
                        .iter()
                        .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                {
                    let mask_idx = and_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                        .unwrap();
                    let mask = &and_args[mask_idx];
                    let remaining: Vec<_> = and_args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != mask_idx)
                        .map(|(_, a)| a.clone())
                        .collect();
                    let lhs_and = if remaining.len() == 1 {
                        remaining.into_iter().next().unwrap()
                    } else {
                        ctx.and(remaining)?
                    };
                    let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                        mask_val.is_mask()
                    } else {
                        None
                    }
                    .expect("Checked above, switch to if let when stabilized");
                    state.rerun(ctx.ult(
                        ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                        ctx.extract(&lhs_and, mask_high, mask_low)?,
                    )?)
                }

                // If one side is a ZeroExt and the other side is a BVV with those bits set to zero,
                // we can extract the relevant bits and compare directly
                (AstOp::ZeroExt(innner, ext_size), AstOp::BVV(outer))
                    if outer.leading_zeros() as u32 >= *ext_size =>
                {
                    state.rerun(ctx.ult(
                        innner.clone(),
                        ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                    )?)
                }
                (AstOp::BVV(outer), AstOp::ZeroExt(innner, ext_size))
                    if outer.leading_zeros() as u32 >= *ext_size =>
                {
                    state.rerun(ctx.ult(
                        ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                        innner.clone(),
                    )?)
                }

                // If both sides are ZeroExt of the same size, we can compare the inner values directly
                (AstOp::ZeroExt(inner_lhs, _), AstOp::ZeroExt(inner_rhs, _)) => {
                    state.rerun(ctx.ult(inner_lhs.clone(), inner_rhs.clone())?)
                }

                // ULT(Concat(rest..., BVV(0, n)), BVV(c)) where c has n trailing zeros
                (AstOp::Concat(args), AstOp::BVV(c_val)) if matches!(args.last().map(|a| a.op()), Some(AstOp::BVV(v)) if v.is_zero()) =>
                {
                    let low_bits = args.last().unwrap().size();
                    if c_val
                        .extract(0, low_bits - 1)
                        .map(|v| v.is_zero())
                        .unwrap_or(false)
                    {
                        let high_parts: Vec<_> = args[..args.len() - 1].to_vec();
                        let high_part = if high_parts.len() == 1 {
                            high_parts.into_iter().next().unwrap()
                        } else {
                            ctx.concat(high_parts)?
                        };
                        state.rerun(ctx.ult(
                            high_part,
                            ctx.bvv(c_val.extract(low_bits, c_val.len() - 1)?)?,
                        )?)
                    } else {
                        Ok(ctx.ult(arc, arc1)?)
                    }
                }
                (AstOp::BVV(c_val), AstOp::Concat(args)) if matches!(args.last().map(|a| a.op()), Some(AstOp::BVV(v)) if v.is_zero()) =>
                {
                    let low_bits = args.last().unwrap().size();
                    if c_val
                        .extract(0, low_bits - 1)
                        .map(|v| v.is_zero())
                        .unwrap_or(false)
                    {
                        let high_parts: Vec<_> = args[..args.len() - 1].to_vec();
                        let high_part = if high_parts.len() == 1 {
                            high_parts.into_iter().next().unwrap()
                        } else {
                            ctx.concat(high_parts)?
                        };
                        state.rerun(ctx.ult(
                            ctx.bvv(c_val.extract(low_bits, c_val.len() - 1)?)?,
                            high_part,
                        )?)
                    } else {
                        Ok(ctx.ult(arc, arc1)?)
                    }
                }

                // ULT(BVV(b), Sub(ZeroExt(n, inner), BVV(c))) where c and b fit in inner's size
                // => ULT(extract(b), Sub(inner, extract(c)))
                (AstOp::BVV(bound), AstOp::Sub(lhs_sub, rhs_sub))
                    if matches!(lhs_sub.op(), AstOp::ZeroExt(_, ext_size)
                        if bound.leading_zeros() as u32 >= *ext_size
                        && matches!(rhs_sub.op(), AstOp::BVV(c) if c.leading_zeros() as u32 >= *ext_size)) =>
                {
                    if let AstOp::ZeroExt(inner, _) = lhs_sub.op() {
                        let inner_size = inner.size();
                        state.rerun(ctx.ult(
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                            ctx.sub(inner, &ctx.extract(rhs_sub, inner_size - 1, 0)?)?,
                        )?)
                    } else {
                        unreachable!()
                    }
                }

                // ULT(Sub(ZeroExt(n, inner), BVV(c)), BVV(b)) where c and b fit in inner's size
                // => ULT(Sub(inner, extract(c)), extract(b))
                (AstOp::Sub(lhs_sub, rhs_sub), AstOp::BVV(bound))
                    if matches!(lhs_sub.op(), AstOp::ZeroExt(_, ext_size)
                        if bound.leading_zeros() as u32 >= *ext_size
                        && matches!(rhs_sub.op(), AstOp::BVV(c) if c.leading_zeros() as u32 >= *ext_size)) =>
                {
                    if let AstOp::ZeroExt(inner, _) = lhs_sub.op() {
                        let inner_size = inner.size();
                        state.rerun(ctx.ult(
                            ctx.sub(inner, &ctx.extract(rhs_sub, inner_size - 1, 0)?)?,
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                        )?)
                    } else {
                        unreachable!()
                    }
                }

                // ULT(BVV(b), Add(ZeroExt(n, inner), BVV(c))) where c and b fit in inner's size
                (AstOp::BVV(bound), AstOp::Add(add_args)) => {
                    let ze_idx = add_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::ZeroExt(..)));
                    let bvv_idx = add_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(..)));
                    if let (Some(ze_i), Some(bvv_i)) = (ze_idx, bvv_idx)
                        && ze_i != bvv_i
                        && add_args.len() == 2
                        && let AstOp::ZeroExt(inner, ext_size) = add_args[ze_i].op()
                        && let AstOp::BVV(c) = add_args[bvv_i].op()
                        && bound.leading_zeros() as u32 >= *ext_size
                        && c.leading_zeros() as u32 >= *ext_size
                    {
                        let inner_size = inner.size();
                        return state.rerun(ctx.ult(
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                            ctx.add(inner, &ctx.extract(&add_args[bvv_i], inner_size - 1, 0)?)?,
                        )?);
                    }
                    Ok(ctx.ult(arc, arc1)?)
                }

                _ => Ok(ctx.ult(arc, arc1)?),
            }
        }
        AstOp::ULE(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (lhs, rhs) if lhs == rhs => Ok(ctx.true_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc <= arc1)?),

                // If on one side there is an AND where one of the operands is a mask, and on the
                // other side, there is a BVV which matches the masked part of the AND, we can
                // extract the AND operand directly, and extract the other side and rerun
                (AstOp::And(and_args), AstOp::BVV(bvv))
                    if and_args
                        .iter()
                        .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                {
                    let mask_idx = and_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                        .unwrap();
                    let mask = &and_args[mask_idx];
                    let remaining: Vec<_> = and_args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != mask_idx)
                        .map(|(_, a)| a.clone())
                        .collect();
                    let lhs_and = if remaining.len() == 1 {
                        remaining.into_iter().next().unwrap()
                    } else {
                        ctx.and(remaining)?
                    };
                    let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                        mask_val.is_mask()
                    } else {
                        None
                    }
                    .expect("Checked above, switch to if let when stabilized");
                    state.rerun(ctx.ule(
                        ctx.extract(&lhs_and, mask_high, mask_low)?,
                        ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                    )?)
                }
                (AstOp::BVV(bvv), AstOp::And(and_args))
                    if and_args
                        .iter()
                        .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                {
                    let mask_idx = and_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                        .unwrap();
                    let mask = &and_args[mask_idx];
                    let remaining: Vec<_> = and_args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != mask_idx)
                        .map(|(_, a)| a.clone())
                        .collect();
                    let lhs_and = if remaining.len() == 1 {
                        remaining.into_iter().next().unwrap()
                    } else {
                        ctx.and(remaining)?
                    };
                    let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                        mask_val.is_mask()
                    } else {
                        None
                    }
                    .expect("Checked above, switch to if let when stabilized");
                    state.rerun(ctx.ule(
                        ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                        ctx.extract(&lhs_and, mask_high, mask_low)?,
                    )?)
                }

                // If one side is a ZeroExt, and the other side is a BVV with a value larger than
                // what can be represented in the inner bits, we can concretize the comparison
                (AstOp::ZeroExt(inner, _), AstOp::BVV(outer))
                    if outer.bits() > inner.size() as usize =>
                {
                    Ok(ctx.true_()?)
                }
                (AstOp::BVV(outer), AstOp::ZeroExt(inner, _))
                    if outer.bits() > inner.size() as usize =>
                {
                    Ok(ctx.false_()?)
                }

                // If one side is a ZeroExt and the other side is a BVV with those bits set to zero,
                // we can extract the relevant bits and compare directly
                (AstOp::ZeroExt(innner, ext_size), AstOp::BVV(outer))
                    if outer.leading_zeros() as u32 >= *ext_size =>
                {
                    state.rerun(ctx.ule(
                        innner.clone(),
                        ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                    )?)
                }
                (AstOp::BVV(outer), AstOp::ZeroExt(innner, ext_size))
                    if outer.leading_zeros() as u32 >= *ext_size =>
                {
                    state.rerun(ctx.ule(
                        ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                        innner.clone(),
                    )?)
                }

                // If both sides are ZeroExt of the same size, we can compare the inner values directly
                (AstOp::ZeroExt(inner_lhs, _), AstOp::ZeroExt(inner_rhs, _)) => {
                    state.rerun(ctx.ule(inner_lhs.clone(), inner_rhs.clone())?)
                }

                // ULE(Sub(ZeroExt(n, inner), BVV(c)), BVV(b)) where c and b fit in inner's size
                // => ULE(Sub(inner, extract(c)), extract(b))
                (AstOp::Sub(lhs_sub, rhs_sub), AstOp::BVV(bound))
                    if matches!(lhs_sub.op(), AstOp::ZeroExt(_, ext_size)
                        if bound.leading_zeros() as u32 >= *ext_size
                        && matches!(rhs_sub.op(), AstOp::BVV(c) if c.leading_zeros() as u32 >= *ext_size)) =>
                {
                    if let AstOp::ZeroExt(inner, _) = lhs_sub.op() {
                        let inner_size = inner.size();
                        state.rerun(ctx.ule(
                            ctx.sub(inner, &ctx.extract(rhs_sub, inner_size - 1, 0)?)?,
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                        )?)
                    } else {
                        unreachable!()
                    }
                }

                // ULE(Add(ZeroExt(n, inner), BVV(c)), BVV(b)) where c and b fit in inner's size
                (AstOp::Add(add_args), AstOp::BVV(bound)) => {
                    let ze_idx = add_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::ZeroExt(..)));
                    let bvv_idx = add_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(..)));
                    if let (Some(ze_i), Some(bvv_i)) = (ze_idx, bvv_idx)
                        && ze_i != bvv_i
                        && add_args.len() == 2
                        && let AstOp::ZeroExt(inner, ext_size) = add_args[ze_i].op()
                        && let AstOp::BVV(c) = add_args[bvv_i].op()
                        && bound.leading_zeros() as u32 >= *ext_size
                        && c.leading_zeros() as u32 >= *ext_size
                    {
                        let inner_size = inner.size();
                        return state.rerun(ctx.ule(
                            ctx.add(inner, &ctx.extract(&add_args[bvv_i], inner_size - 1, 0)?)?,
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                        )?);
                    }
                    Ok(ctx.ule(arc, arc1)?)
                }

                // ULE(Concat(rest..., BVV(0, n)), BVV(c)) where c has n trailing zeros
                (AstOp::Concat(args), AstOp::BVV(c_val)) if matches!(args.last().map(|a| a.op()), Some(AstOp::BVV(v)) if v.is_zero()) =>
                {
                    let low_bits = args.last().unwrap().size();
                    if c_val
                        .extract(0, low_bits - 1)
                        .map(|v| v.is_zero())
                        .unwrap_or(false)
                    {
                        let high_parts: Vec<_> = args[..args.len() - 1].to_vec();
                        let high_part = if high_parts.len() == 1 {
                            high_parts.into_iter().next().unwrap()
                        } else {
                            ctx.concat(high_parts)?
                        };
                        state.rerun(ctx.ule(
                            high_part,
                            ctx.bvv(c_val.extract(low_bits, c_val.len() - 1)?)?,
                        )?)
                    } else {
                        Ok(ctx.ule(arc, arc1)?)
                    }
                }
                (AstOp::BVV(c_val), AstOp::Concat(args)) if matches!(args.last().map(|a| a.op()), Some(AstOp::BVV(v)) if v.is_zero()) =>
                {
                    let low_bits = args.last().unwrap().size();
                    if c_val
                        .extract(0, low_bits - 1)
                        .map(|v| v.is_zero())
                        .unwrap_or(false)
                    {
                        let high_parts: Vec<_> = args[..args.len() - 1].to_vec();
                        let high_part = if high_parts.len() == 1 {
                            high_parts.into_iter().next().unwrap()
                        } else {
                            ctx.concat(high_parts)?
                        };
                        state.rerun(ctx.ule(
                            ctx.bvv(c_val.extract(low_bits, c_val.len() - 1)?)?,
                            high_part,
                        )?)
                    } else {
                        Ok(ctx.ule(arc, arc1)?)
                    }
                }

                _ => Ok(ctx.ule(arc, arc1)?),
            }
        }
        AstOp::UGT(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (lhs, rhs) if lhs == rhs => Ok(ctx.false_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc > arc1)?),

                // If on one side there is an AND where one of the operands is a mask, and on the
                // other side, there is a BVV which matches the masked part of the AND, we can
                // extract the AND operand directly, and extract the other side and rerun
                (AstOp::And(and_args), AstOp::BVV(bvv))
                    if and_args
                        .iter()
                        .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                {
                    let mask_idx = and_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                        .unwrap();
                    let mask = &and_args[mask_idx];
                    let remaining: Vec<_> = and_args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != mask_idx)
                        .map(|(_, a)| a.clone())
                        .collect();
                    let lhs_and = if remaining.len() == 1 {
                        remaining.into_iter().next().unwrap()
                    } else {
                        ctx.and(remaining)?
                    };
                    let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                        mask_val.is_mask()
                    } else {
                        None
                    }
                    .expect("Checked above, switch to if let when stabilized");
                    state.rerun(ctx.ugt(
                        ctx.extract(&lhs_and, mask_high, mask_low)?,
                        ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                    )?)
                }
                (AstOp::BVV(bvv), AstOp::And(and_args))
                    if and_args
                        .iter()
                        .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                {
                    let mask_idx = and_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                        .unwrap();
                    let mask = &and_args[mask_idx];
                    let remaining: Vec<_> = and_args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != mask_idx)
                        .map(|(_, a)| a.clone())
                        .collect();
                    let lhs_and = if remaining.len() == 1 {
                        remaining.into_iter().next().unwrap()
                    } else {
                        ctx.and(remaining)?
                    };
                    let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                        mask_val.is_mask()
                    } else {
                        None
                    }
                    .expect("Checked above, switch to if let when stabilized");
                    state.rerun(ctx.ugt(
                        ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                        ctx.extract(&lhs_and, mask_high, mask_low)?,
                    )?)
                }

                // If one side is a ZeroExt, and the other side is a BVV with a value larger than
                // what can be represented in the inner bits, we can concretize the comparison
                (AstOp::ZeroExt(inner, _), AstOp::BVV(outer))
                    if outer.bits() > inner.size() as usize =>
                {
                    Ok(ctx.false_()?)
                }
                (AstOp::BVV(outer), AstOp::ZeroExt(inner, _))
                    if outer.bits() > inner.size() as usize =>
                {
                    Ok(ctx.true_()?)
                }

                // If one side is a ZeroExt and the other side is a BVV with those bits set to zero,
                // we can extract the relevant bits and compare directly
                (AstOp::ZeroExt(innner, ext_size), AstOp::BVV(outer))
                    if outer.leading_zeros() as u32 >= *ext_size =>
                {
                    state.rerun(ctx.ugt(
                        innner.clone(),
                        ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                    )?)
                }
                (AstOp::BVV(outer), AstOp::ZeroExt(innner, ext_size))
                    if outer.leading_zeros() as u32 >= *ext_size =>
                {
                    state.rerun(ctx.ugt(
                        ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                        innner.clone(),
                    )?)
                }

                // If both sides are ZeroExt of the same size, we can compare the inner values directly
                (AstOp::ZeroExt(inner_lhs, _), AstOp::ZeroExt(inner_rhs, _)) => {
                    state.rerun(ctx.ugt(inner_lhs.clone(), inner_rhs.clone())?)
                }

                // UGT(Sub(ZeroExt(n, inner), BVV(c)), BVV(b)) where c and b fit in inner's size
                (AstOp::Sub(lhs_sub, rhs_sub), AstOp::BVV(bound))
                    if matches!(lhs_sub.op(), AstOp::ZeroExt(_, ext_size)
                        if bound.leading_zeros() as u32 >= *ext_size
                        && matches!(rhs_sub.op(), AstOp::BVV(c) if c.leading_zeros() as u32 >= *ext_size)) =>
                {
                    if let AstOp::ZeroExt(inner, _) = lhs_sub.op() {
                        let inner_size = inner.size();
                        state.rerun(ctx.ugt(
                            ctx.sub(inner, &ctx.extract(rhs_sub, inner_size - 1, 0)?)?,
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                        )?)
                    } else {
                        unreachable!()
                    }
                }

                // UGT(Add(ZeroExt(n, inner), BVV(c)), BVV(b)) where c and b fit in inner's size
                (AstOp::Add(add_args), AstOp::BVV(bound)) => {
                    let ze_idx = add_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::ZeroExt(..)));
                    let bvv_idx = add_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(..)));
                    if let (Some(ze_i), Some(bvv_i)) = (ze_idx, bvv_idx)
                        && ze_i != bvv_i
                        && add_args.len() == 2
                        && let AstOp::ZeroExt(inner, ext_size) = add_args[ze_i].op()
                        && let AstOp::BVV(c) = add_args[bvv_i].op()
                        && bound.leading_zeros() as u32 >= *ext_size
                        && c.leading_zeros() as u32 >= *ext_size
                    {
                        let inner_size = inner.size();
                        return state.rerun(ctx.ugt(
                            ctx.add(inner, &ctx.extract(&add_args[bvv_i], inner_size - 1, 0)?)?,
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                        )?);
                    }
                    Ok(ctx.ugt(arc, arc1)?)
                }

                // UGT(Concat(rest..., BVV(0, n)), BVV(c)) where c has n trailing zeros
                (AstOp::Concat(args), AstOp::BVV(c_val)) if matches!(args.last().map(|a| a.op()), Some(AstOp::BVV(v)) if v.is_zero()) =>
                {
                    let low_bits = args.last().unwrap().size();
                    if c_val
                        .extract(0, low_bits - 1)
                        .map(|v| v.is_zero())
                        .unwrap_or(false)
                    {
                        let high_parts: Vec<_> = args[..args.len() - 1].to_vec();
                        let high_part = if high_parts.len() == 1 {
                            high_parts.into_iter().next().unwrap()
                        } else {
                            ctx.concat(high_parts)?
                        };
                        state.rerun(ctx.ugt(
                            high_part,
                            ctx.bvv(c_val.extract(low_bits, c_val.len() - 1)?)?,
                        )?)
                    } else {
                        Ok(ctx.ugt(arc, arc1)?)
                    }
                }
                (AstOp::BVV(c_val), AstOp::Concat(args)) if matches!(args.last().map(|a| a.op()), Some(AstOp::BVV(v)) if v.is_zero()) =>
                {
                    let low_bits = args.last().unwrap().size();
                    if c_val
                        .extract(0, low_bits - 1)
                        .map(|v| v.is_zero())
                        .unwrap_or(false)
                    {
                        let high_parts: Vec<_> = args[..args.len() - 1].to_vec();
                        let high_part = if high_parts.len() == 1 {
                            high_parts.into_iter().next().unwrap()
                        } else {
                            ctx.concat(high_parts)?
                        };
                        state.rerun(ctx.ugt(
                            ctx.bvv(c_val.extract(low_bits, c_val.len() - 1)?)?,
                            high_part,
                        )?)
                    } else {
                        Ok(ctx.ugt(arc, arc1)?)
                    }
                }

                _ => Ok(ctx.ugt(arc, arc1)?),
            }
        }
        AstOp::UGE(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (lhs, rhs) if lhs == rhs => Ok(ctx.true_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc >= arc1)?),

                // If on one side there is an AND where one of the operands is a mask, and on the
                // other side, there is a BVV which matches the masked part of the AND, we can
                // extract the AND operand directly, and extract the other side and rerun
                (AstOp::And(and_args), AstOp::BVV(bvv))
                    if and_args
                        .iter()
                        .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                {
                    let mask_idx = and_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                        .unwrap();
                    let mask = &and_args[mask_idx];
                    let remaining: Vec<_> = and_args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != mask_idx)
                        .map(|(_, a)| a.clone())
                        .collect();
                    let lhs_and = if remaining.len() == 1 {
                        remaining.into_iter().next().unwrap()
                    } else {
                        ctx.and(remaining)?
                    };
                    let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                        mask_val.is_mask()
                    } else {
                        None
                    }
                    .expect("Checked above, switch to if let when stabilized");
                    state.rerun(ctx.uge(
                        ctx.extract(&lhs_and, mask_high, mask_low)?,
                        ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                    )?)
                }
                (AstOp::BVV(bvv), AstOp::And(and_args))
                    if and_args
                        .iter()
                        .any(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some())) =>
                {
                    let mask_idx = and_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(v) if v.is_mask().is_some()))
                        .unwrap();
                    let mask = &and_args[mask_idx];
                    let remaining: Vec<_> = and_args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != mask_idx)
                        .map(|(_, a)| a.clone())
                        .collect();
                    let lhs_and = if remaining.len() == 1 {
                        remaining.into_iter().next().unwrap()
                    } else {
                        ctx.and(remaining)?
                    };
                    let (mask_high, mask_low) = if let AstOp::BVV(mask_val) = mask.op() {
                        mask_val.is_mask()
                    } else {
                        None
                    }
                    .expect("Checked above, switch to if let when stabilized");
                    state.rerun(ctx.uge(
                        ctx.bvv(bvv.extract(mask_low, mask_high)?)?,
                        ctx.extract(&lhs_and, mask_high, mask_low)?,
                    )?)
                }

                // If one side is a ZeroExt and the other side is a BVV with those bits set to zero,
                // we can extract the relevant bits and compare directly
                (AstOp::ZeroExt(innner, ext_size), AstOp::BVV(outer))
                    if outer.leading_zeros() as u32 >= *ext_size =>
                {
                    state.rerun(ctx.uge(
                        innner.clone(),
                        ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                    )?)
                }
                (AstOp::BVV(outer), AstOp::ZeroExt(innner, ext_size))
                    if outer.leading_zeros() as u32 >= *ext_size =>
                {
                    state.rerun(ctx.uge(
                        ctx.extract(ctx.bvv(outer.clone())?, innner.size() - 1, 0)?,
                        innner.clone(),
                    )?)
                }

                // If both sides are ZeroExt of the same size, we can compare the inner values directly
                (AstOp::ZeroExt(inner_lhs, _), AstOp::ZeroExt(inner_rhs, _)) => {
                    state.rerun(ctx.uge(inner_lhs.clone(), inner_rhs.clone())?)
                }

                // UGE(Concat(rest..., BVV(0, n)), BVV(c)) where c has n trailing zeros
                (AstOp::Concat(args), AstOp::BVV(c_val)) if matches!(args.last().map(|a| a.op()), Some(AstOp::BVV(v)) if v.is_zero()) =>
                {
                    let low_bits = args.last().unwrap().size();
                    if c_val
                        .extract(0, low_bits - 1)
                        .map(|v| v.is_zero())
                        .unwrap_or(false)
                    {
                        let high_parts: Vec<_> = args[..args.len() - 1].to_vec();
                        let high_part = if high_parts.len() == 1 {
                            high_parts.into_iter().next().unwrap()
                        } else {
                            ctx.concat(high_parts)?
                        };
                        state.rerun(ctx.uge(
                            high_part,
                            ctx.bvv(c_val.extract(low_bits, c_val.len() - 1)?)?,
                        )?)
                    } else {
                        Ok(ctx.uge(arc, arc1)?)
                    }
                }
                (AstOp::BVV(c_val), AstOp::Concat(args)) if matches!(args.last().map(|a| a.op()), Some(AstOp::BVV(v)) if v.is_zero()) =>
                {
                    let low_bits = args.last().unwrap().size();
                    if c_val
                        .extract(0, low_bits - 1)
                        .map(|v| v.is_zero())
                        .unwrap_or(false)
                    {
                        let high_parts: Vec<_> = args[..args.len() - 1].to_vec();
                        let high_part = if high_parts.len() == 1 {
                            high_parts.into_iter().next().unwrap()
                        } else {
                            ctx.concat(high_parts)?
                        };
                        state.rerun(ctx.uge(
                            ctx.bvv(c_val.extract(low_bits, c_val.len() - 1)?)?,
                            high_part,
                        )?)
                    } else {
                        Ok(ctx.uge(arc, arc1)?)
                    }
                }

                // UGE(BVV(b), Sub(ZeroExt(n, inner), BVV(c))) where c and b fit in inner's size
                // => UGE(extract(b), Sub(inner, extract(c)))
                (AstOp::BVV(bound), AstOp::Sub(lhs_sub, rhs_sub))
                    if matches!(lhs_sub.op(), AstOp::ZeroExt(_, ext_size)
                        if bound.leading_zeros() as u32 >= *ext_size
                        && matches!(rhs_sub.op(), AstOp::BVV(c) if c.leading_zeros() as u32 >= *ext_size)) =>
                {
                    if let AstOp::ZeroExt(inner, _) = lhs_sub.op() {
                        let inner_size = inner.size();
                        state.rerun(ctx.uge(
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                            ctx.sub(inner, &ctx.extract(rhs_sub, inner_size - 1, 0)?)?,
                        )?)
                    } else {
                        unreachable!()
                    }
                }

                // UGE(Sub(ZeroExt(n, inner), BVV(c)), BVV(b)) where c and b fit in inner's size
                // => UGE(Sub(inner, extract(c)), extract(b))
                (AstOp::Sub(lhs_sub, rhs_sub), AstOp::BVV(bound))
                    if matches!(lhs_sub.op(), AstOp::ZeroExt(_, ext_size)
                        if bound.leading_zeros() as u32 >= *ext_size
                        && matches!(rhs_sub.op(), AstOp::BVV(c) if c.leading_zeros() as u32 >= *ext_size)) =>
                {
                    if let AstOp::ZeroExt(inner, _) = lhs_sub.op() {
                        let inner_size = inner.size();
                        state.rerun(ctx.uge(
                            ctx.sub(inner, &ctx.extract(rhs_sub, inner_size - 1, 0)?)?,
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                        )?)
                    } else {
                        unreachable!()
                    }
                }

                // UGE(BVV(b), Add(ZeroExt(n, inner), BVV(c))) where c and b fit in inner's size
                (AstOp::BVV(bound), AstOp::Add(add_args)) => {
                    let ze_idx = add_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::ZeroExt(..)));
                    let bvv_idx = add_args
                        .iter()
                        .position(|a| matches!(a.op(), AstOp::BVV(..)));
                    if let (Some(ze_i), Some(bvv_i)) = (ze_idx, bvv_idx)
                        && ze_i != bvv_i
                        && add_args.len() == 2
                        && let AstOp::ZeroExt(inner, ext_size) = add_args[ze_i].op()
                        && let AstOp::BVV(c) = add_args[bvv_i].op()
                        && bound.leading_zeros() as u32 >= *ext_size
                        && c.leading_zeros() as u32 >= *ext_size
                    {
                        let inner_size = inner.size();
                        return state.rerun(ctx.uge(
                            ctx.bvv(bound.extract(0, inner_size - 1)?)?,
                            ctx.add(inner, &ctx.extract(&add_args[bvv_i], inner_size - 1, 0)?)?,
                        )?);
                    }
                    Ok(ctx.uge(arc, arc1)?)
                }

                _ => Ok(ctx.uge(arc, arc1)?),
            }
        }
        AstOp::SLT(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (lhs, rhs) if lhs == rhs => Ok(ctx.false_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc.signed_lt(arc1))?),
                _ => Ok(ctx.slt(arc, arc1)?),
            }
        }
        AstOp::SLE(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (lhs, rhs) if lhs == rhs => Ok(ctx.true_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc.signed_le(arc1))?),
                _ => Ok(ctx.sle(arc, arc1)?),
            }
        }
        AstOp::SGT(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (lhs, rhs) if lhs == rhs => Ok(ctx.false_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc.signed_gt(arc1))?),
                _ => Ok(ctx.sgt(arc, arc1)?),
            }
        }
        AstOp::SGE(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (lhs, rhs) if lhs == rhs => Ok(ctx.true_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc.signed_ge(arc1))?),
                _ => Ok(ctx.sge(arc, arc1)?),
            }
        }
        AstOp::FpLt(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (AstOp::FPV(arc), AstOp::FPV(arc1)) => Ok(ctx.boolv(arc.lt(arc1))?),
                _ => Ok(ctx.fp_lt(arc, arc1)?),
            }
        }
        AstOp::FpLeq(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (AstOp::FPV(arc), AstOp::FPV(arc1)) => Ok(ctx.boolv(arc.leq(arc1))?),
                _ => Ok(ctx.fp_leq(arc, arc1)?),
            }
        }
        AstOp::FpGt(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (AstOp::FPV(arc), AstOp::FPV(arc1)) => Ok(ctx.boolv(arc.gt(arc1))?),
                _ => Ok(ctx.fp_gt(arc, arc1)?),
            }
        }
        AstOp::FpGeq(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (AstOp::FPV(arc), AstOp::FPV(arc1)) => Ok(ctx.boolv(arc.geq(arc1))?),
                _ => Ok(ctx.fp_geq(arc, arc1)?),
            }
        }
        AstOp::FpIsNan(..) => {
            let arc = state.get_child_simplified(0)?;
            match arc.op() {
                AstOp::FPV(arc) => Ok(ctx.boolv(arc.is_nan())?),
                _ => Ok(ctx.fp_is_nan(arc)?),
            }
        }
        AstOp::FpIsInf(..) => {
            let arc = state.get_child_simplified(0)?;
            match arc.op() {
                AstOp::FPV(arc) => Ok(ctx.boolv(arc.is_infinity())?),
                _ => Ok(ctx.fp_is_inf(arc)?),
            }
        }
        AstOp::StrContains(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                // Check if `input_string` contains `substring`
                (AstOp::StringV(input_string), AstOp::StringV(substring)) => {
                    Ok(ctx.boolv(input_string.contains(substring))?)
                }
                _ => Ok(ctx.str_contains(arc, arc1)?),
            }
        }
        AstOp::StrPrefixOf(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                // Check if `input_string` starts with `prefix substring`
                (AstOp::StringV(prefix), AstOp::StringV(input_string)) => {
                    Ok(ctx.boolv(input_string.starts_with(prefix))?)
                }
                _ => Ok(ctx.str_prefix_of(arc, arc1)?),
            }
        }
        AstOp::StrSuffixOf(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                // Check if `input_string` ends with `suffix substring`
                (AstOp::StringV(suffix), AstOp::StringV(input_string)) => {
                    Ok(ctx.boolv(input_string.ends_with(suffix))?)
                }
                _ => Ok(ctx.str_suffix_of(arc, arc1)?),
            }
        }
        AstOp::StrIsDigit(..) => {
            let arc = state.get_child_simplified(0)?;
            match arc.op() {
                AstOp::StringV(input_string) => {
                    if input_string.is_empty() {
                        return Ok(ctx.boolv(false)?);
                    }
                    // is_numeric() is Unicode-aware and will also return true for non-ASCII numeric characters like Z3
                    Ok(ctx.boolv(input_string.chars().all(|c| c.is_numeric()))?)
                }
                _ => Ok(ctx.str_is_digit(arc)?),
            }
        }

        AstOp::ITE(..) => {
            let cond = state.get_child_simplified(0)?;
            let early_then = state.get_child_available(1);
            let early_else = state.get_child_available(2);

            match (cond.op(), early_then.op(), early_else.op()) {
                // Concrete condition cases
                (AstOp::BoolV(true), _, _) => state.get_child_simplified(1),
                (AstOp::BoolV(false), _, _) => state.get_child_simplified(2),

                // Same branch cases
                (_, _, _) if early_then == early_else => state.get_child_simplified(1),

                // Known then/else cases
                (_, AstOp::BoolV(true), AstOp::BoolV(false)) => Ok(cond.clone()),
                // ite(c, false, true) -> !c; rerun so the produced Not canonicalizes.
                (_, AstOp::BoolV(false), AstOp::BoolV(true)) => state.rerun(ctx.not(cond)?),

                // When condition equals one branch with concrete other branch
                (cond_op, AstOp::BoolV(true), else_op) if else_op == cond_op => Ok(cond.clone()),
                (cond_op, AstOp::BoolV(false), else_op) if else_op == cond_op => Ok(ctx.false_()?),
                (cond_op, then_op, AstOp::BoolV(true)) if then_op == cond_op => Ok(ctx.true_()?),
                (cond_op, then_op, AstOp::BoolV(false)) if then_op == cond_op => Ok(cond.clone()),

                // Default case
                _ => Ok(ctx.ite(
                    cond,
                    state.get_child_simplified(1)?,
                    state.get_child_simplified(2)?,
                )?),
            }
        }
        _ => unreachable!("non-boolean op dispatched to simplify_bool"),
    }
}
