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
                .iter()
                .cloned()
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

            if absorbed_args != available_args {
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
                .iter()
                .cloned()
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

            if absorbed_args != available_args {
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
                    (..) if early_lhs == early_rhs => Ok(ctx.true_()?),
                    (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc == arc1)?),

                    // Equality is commutative, so canonicalize a lone constant onto the
                    // right, the way commutative arithmetic ops already order their args.
                    // Without this, `0 == x` and `x == 0` are distinct nodes and every
                    // consumer that expects the constant on the right (angr's C codegen
                    // renders `x == 0` as `!x`, peepholes match on `operands[1]`) misses.
                    // The arm above consumed the BVV/BVV case, so this cannot loop.
                    (AstOp::BVV(_), _) => state.rerun(ctx.eq_(&early_rhs, &early_lhs)?),

                    // If on one side there is an AND where one of the operands is a mask, and on the
                    // other side, there is a BVV which matches the masked part of the AND, we can
                    // extract the AND operand directly, and extract the other side and rerun
                    (AstOp::And(and_args), AstOp::BVV(bvv)) => {
                        match split_masked_and(ctx, and_args)? {
                            Some((rest, high, low)) => state.rerun(ctx.eq_(
                                ctx.extract(rest, high, low)?,
                                ctx.bvv(bvv.extract(low, high)?)?,
                            )?),
                            None => Ok(ctx.eq_(
                                state.get_child_simplified(0)?,
                                state.get_child_simplified(1)?,
                            )?),
                        }
                    }

                    // If one side is a = ZeroExt and the other side is a BVV with those bits set to zero,
                    // we can extract the relevant bits and compare directly
                    (AstOp::ZeroExt(innner, ext_size), AstOp::BVV(outer))
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
                    (AstOp::ITE(cond, then_val, else_val), AstOp::BVV(val)) if val.is_zero() => {
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
                    (AstOp::ITE(cond, then_val, else_val), AstOp::BVV(val)) if val.is_one() => {
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
                        if val.is_zero() && matches!(rhs_sub.op(), AstOp::BVV(..)) =>
                    {
                        state.rerun(ctx.eq_(lhs_sub.clone(), rhs_sub.clone())?)
                    }

                    // (sum + C) == 0  ==>  sum == -C
                    (AstOp::Add(add_args), AstOp::BVV(val))
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
                    (..) if early_lhs == early_rhs => Ok(ctx.false_()?),

                    // Disequality is commutative, so canonicalize a lone constant onto the
                    // right, the way commutative arithmetic ops already order their args.
                    // Without this, `0 != x` and `x != 0` are distinct nodes and every
                    // consumer that expects the constant on the right (angr's C codegen
                    // renders `x != 0` as bare `x`, peepholes match on `operands[1]`) misses.
                    // The arm above consumed the BVV/BVV case, so this cannot loop.
                    (AstOp::BVV(_), _) => state.rerun(ctx.neq(&early_rhs, &early_lhs)?),

                    // If on one side there is an AND where one of the operands is a mask, and on the
                    // other side, there is a BVV which matches the masked part of the AND, we can
                    // extract the AND operand directly, and extract the other side and rerun
                    (AstOp::And(and_args), AstOp::BVV(bvv)) => {
                        match split_masked_and(ctx, and_args)? {
                            Some((rest, high, low)) => state.rerun(ctx.neq(
                                ctx.extract(rest, high, low)?,
                                ctx.bvv(bvv.extract(low, high)?)?,
                            )?),
                            None => Ok(ctx.neq(
                                state.get_child_simplified(0)?,
                                state.get_child_simplified(1)?,
                            )?),
                        }
                    }

                    // If one side is a = ZeroExt and the other side is a BVV with those bits set to zero,
                    // we can extract the relevant bits and compare directly
                    (AstOp::ZeroExt(innner, ext_size), AstOp::BVV(outer))
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
                    (AstOp::ITE(cond, then_val, else_val), AstOp::BVV(val)) if val.is_zero() => {
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
                    (AstOp::ITE(cond, then_val, else_val), AstOp::BVV(val)) if val.is_one() => {
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
                        if val.is_zero() && matches!(rhs_sub.op(), AstOp::BVV(..)) =>
                    {
                        state.rerun(ctx.neq(lhs_sub.clone(), rhs_sub.clone())?)
                    }

                    // (sum + C) != 0  ==>  sum != -C
                    (AstOp::Add(add_args), AstOp::BVV(val))
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
        AstOp::ULT(..) => simplify_unsigned_cmp(state, UCmp::Ult),
        AstOp::ULE(..) => simplify_unsigned_cmp(state, UCmp::Ule),
        AstOp::UGT(..) => simplify_unsigned_cmp(state, UCmp::Ugt),
        AstOp::UGE(..) => simplify_unsigned_cmp(state, UCmp::Uge),
        AstOp::SLT(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (..) if arc == arc1 => Ok(ctx.false_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc.signed_lt(arc1)?)?),
                _ => Ok(ctx.slt(arc, arc1)?),
            }
        }
        AstOp::SLE(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (..) if arc == arc1 => Ok(ctx.true_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc.signed_le(arc1)?)?),
                _ => Ok(ctx.sle(arc, arc1)?),
            }
        }
        AstOp::SGT(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (..) if arc == arc1 => Ok(ctx.false_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc.signed_gt(arc1)?)?),
                _ => Ok(ctx.sgt(arc, arc1)?),
            }
        }
        AstOp::SGE(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (..) if arc == arc1 => Ok(ctx.true_()?),
                (AstOp::BVV(arc), AstOp::BVV(arc1)) => Ok(ctx.boolv(arc.signed_ge(arc1)?)?),
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

/// Removes the first mask constant from an `And`'s args: (rest of the And, mask high, mask low).
fn split_masked_and<'c>(
    ctx: &'c Context<'c>,
    args: &[AstRef<'c>],
) -> Result<Option<(AstRef<'c>, u32, u32)>, ClarirsError> {
    let Some((mask_idx, (high, low))) = args.iter().enumerate().find_map(|(i, a)| match a.op() {
        AstOp::BVV(v) => v.is_mask().map(|bounds| (i, bounds)),
        _ => None,
    }) else {
        return Ok(None);
    };
    let remaining: Vec<_> = args
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != mask_idx)
        .map(|(_, a)| a.clone())
        .collect();
    let rest = match remaining.as_slice() {
        [only] => only.clone(),
        _ => ctx.and(remaining)?,
    };
    Ok(Some((rest, high, low)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UCmp {
    Ult,
    Ule,
    Ugt,
    Uge,
}

impl UCmp {
    fn build<'c>(
        self,
        ctx: &'c Context<'c>,
        lhs: AstRef<'c>,
        rhs: AstRef<'c>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        match self {
            UCmp::Ult => ctx.ult(lhs, rhs),
            UCmp::Ule => ctx.ule(lhs, rhs),
            UCmp::Ugt => ctx.ugt(lhs, rhs),
            UCmp::Uge => ctx.uge(lhs, rhs),
        }
    }

    fn fold(self, lhs: &BitVec, rhs: &BitVec) -> bool {
        match self {
            UCmp::Ult => lhs < rhs,
            UCmp::Ule => lhs <= rhs,
            UCmp::Ugt => lhs > rhs,
            UCmp::Uge => lhs >= rhs,
        }
    }

    fn on_equal(self) -> bool {
        matches!(self, UCmp::Ule | UCmp::Uge)
    }

    fn flip(self) -> Self {
        match self {
            UCmp::Ult => UCmp::Ugt,
            UCmp::Ule => UCmp::Uge,
            UCmp::Ugt => UCmp::Ult,
            UCmp::Uge => UCmp::Ule,
        }
    }
}

fn simplify_unsigned_cmp<'c>(
    state: &mut super::SimplifyState<'c>,
    kind: UCmp,
) -> Result<AstRef<'c>, SimplifyError<'c>> {
    let ctx = state.expr.context();
    let (lhs, rhs) = (
        state.get_child_simplified(0)?,
        state.get_child_simplified(1)?,
    );
    if lhs == rhs {
        return Ok(ctx.boolv(kind.on_equal())?);
    }
    // Rules below see the constant on the right; a constant on the left flips the relation.
    let (x, c, rel) = match (lhs.op(), rhs.op()) {
        (AstOp::BVV(a), AstOp::BVV(b)) => return Ok(ctx.boolv(kind.fold(a, b))?),
        // If both sides are ZeroExt of the same size, we can compare the inner values directly
        (AstOp::ZeroExt(a, _), AstOp::ZeroExt(b, _)) => {
            return state.rerun(kind.build(ctx, a.clone(), b.clone())?);
        }
        (AstOp::BVV(c), _) => (&rhs, c, kind.flip()),
        (_, AstOp::BVV(c)) => (&lhs, c, kind),
        _ => return Ok(kind.build(ctx, lhs, rhs)?),
    };
    let rewritten = match x.op() {
        // If on one side there is an AND where one of the operands is a mask, and on the
        // other side, there is a BVV which matches the masked part of the AND, we can
        // extract the AND operand directly, and extract the other side and rerun
        AstOp::And(args) => match split_masked_and(ctx, args)? {
            Some((rest, high, low)) => Some((
                ctx.extract(rest, high, low)?,
                ctx.bvv(c.extract(low, high)?)?,
            )),
            None => None,
        },
        // If one side is a ZeroExt, and the other side is a BVV with a value larger than
        // what can be represented in the inner bits, we can concretize the comparison
        AstOp::ZeroExt(inner, _) if c.bits() > inner.size() as usize => {
            return Ok(ctx.boolv(matches!(rel, UCmp::Ult | UCmp::Ule))?);
        }
        // If one side is a ZeroExt and the other side is a BVV with those bits set to zero,
        // we can extract the relevant bits and compare directly
        AstOp::ZeroExt(inner, ext_size) if c.leading_zeros() as u32 >= *ext_size => Some((
            inner.clone(),
            ctx.extract(ctx.bvv(c.clone())?, inner.size() - 1, 0)?,
        )),
        // CMP(Concat(rest..., BVV(0, n)), BVV(c)) where c has n trailing zeros
        AstOp::Concat(args) => match args.as_slice() {
            [high_parts @ .., low]
                if matches!(low.op(), AstOp::BVV(v) if v.is_zero())
                    && c.extract(0, low.size() - 1).is_ok_and(|v| v.is_zero()) =>
            {
                let high_part = match high_parts {
                    [only] => only.clone(),
                    _ => ctx.concat(high_parts.iter().cloned())?,
                };
                Some((high_part, ctx.bvv(c.extract(low.size(), c.len() - 1)?)?))
            }
            _ => None,
        },
        // CMP(Sub(ZeroExt(n, inner), BVV(k)), BVV(c)) where k and c fit in inner's size
        // => CMP(Sub(inner, extract(k)), extract(c))
        AstOp::Sub(lhs_sub, rhs_sub) => {
            if let AstOp::ZeroExt(inner, ext_size) = lhs_sub.op()
                && let AstOp::BVV(k) = rhs_sub.op()
                && c.leading_zeros() as u32 >= *ext_size
                && k.leading_zeros() as u32 >= *ext_size
            {
                let inner_size = inner.size();
                Some((
                    ctx.sub(inner, &ctx.extract(rhs_sub, inner_size - 1, 0)?)?,
                    ctx.bvv(c.extract(0, inner_size - 1)?)?,
                ))
            } else {
                None
            }
        }
        // CMP(Add(ZeroExt(n, inner), BVV(k)), BVV(c)) where k and c fit in inner's size
        AstOp::Add(add_args) => {
            let ze_idx = add_args
                .iter()
                .position(|a| matches!(a.op(), AstOp::ZeroExt(..)));
            let bvv_idx = add_args
                .iter()
                .position(|a| matches!(a.op(), AstOp::BVV(..)));
            if let (Some(ze_i), Some(bvv_i)) = (ze_idx, bvv_idx)
                && add_args.len() == 2
                && let AstOp::ZeroExt(inner, ext_size) = add_args[ze_i].op()
                && let AstOp::BVV(k) = add_args[bvv_i].op()
                && c.leading_zeros() as u32 >= *ext_size
                && k.leading_zeros() as u32 >= *ext_size
            {
                let inner_size = inner.size();
                Some((
                    ctx.add(inner, &ctx.extract(&add_args[bvv_i], inner_size - 1, 0)?)?,
                    ctx.bvv(c.extract(0, inner_size - 1)?)?,
                ))
            } else {
                None
            }
        }
        _ => None,
    };
    match rewritten {
        // Rebuild in the original operand order so the produced node keeps its shape.
        Some((x, c)) if rel == kind => state.rerun(kind.build(ctx, x, c)?),
        Some((x, c)) => state.rerun(kind.build(ctx, c, x)?),
        None => Ok(kind.build(ctx, lhs, rhs)?),
    }
}
