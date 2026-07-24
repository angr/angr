use super::SimplifyError;
use crate::prelude::*;

pub(crate) fn simplify_string<'c>(
    state: &mut super::SimplifyState<'c>,
) -> Result<AstRef<'c>, SimplifyError<'c>> {
    let ctx = state.expr.context();
    let string_expr = state.expr.clone();

    match string_expr.op() {
        AstOp::StringS(_) | AstOp::StringV(_) => Ok(string_expr),
        AstOp::StrConcat(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (AstOp::StringV(str1), AstOp::StringV(str2)) => {
                    let concatenated = format!("{str1}{str2}");
                    Ok(ctx.stringv(concatenated)?)
                }
                _ => Ok(ctx.str_concat(arc, arc1)?),
            }
        }
        AstOp::StrSubstr(..) => {
            let (arc, arc1, arc2) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
                state.get_child_simplified(2)?,
            );
            match (arc.op(), arc1.op(), arc2.op()) {
                (AstOp::StringV(s), AstOp::BVV(start_bv), AstOp::BVV(length_bv)) => {
                    // Convert the bitvectors to usize indices.
                    let start = start_bv.to_usize().unwrap_or(0);
                    let length = length_bv.to_usize().unwrap_or(s.chars().count());
                    let num_chars = s.chars().count();

                    // If the starting index is out-of-bound (e.g., negative index wrapped to 2^64-1),
                    // then return an empty string.
                    if start >= num_chars {
                        return Ok(ctx.stringv("".to_string())?);
                    }

                    // Convert character-based indices to byte-based indices.
                    let char_start = s.chars().take(start).map(|c| c.len_utf8()).sum();
                    let char_end = s.chars().take(start + length).map(|c| c.len_utf8()).sum();

                    let substring = s.get(char_start..char_end).unwrap_or("").to_string();
                    Ok(ctx.stringv(substring)?)
                }
                _ => Ok(ctx.str_substr(arc, arc1, arc2)?),
            }
        }
        AstOp::StrReplace(..) => {
            let (arc, arc1, arc2) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
                state.get_child_simplified(2)?,
            );
            match (arc.op(), arc1.op(), arc2.op()) {
                (AstOp::StringV(initial), AstOp::StringV(pattern), AstOp::StringV(replacement)) => {
                    // Case: Replace first occurrence of `pattern` with `replacement` in `initial` as per ClariPy DONE
                    let new_value = initial.replacen(pattern, replacement, 1);
                    // Case: Replace all occurrences of `pattern` with `replacement` in `initial` LEFT
                    // let new_value = initial.replace(pattern, replacement);
                    Ok(ctx.stringv(new_value)?)
                }
                _ => Ok(ctx.str_replace(arc, arc1, arc2)?), // Fallback to symbolic StrReplace
            }
        }
        AstOp::BVToStr(..) => {
            let arc = state.get_child_simplified(0)?;
            match arc.op() {
                AstOp::BVV(value) => {
                    // Convert the BitVec value to an integer, then to a string
                    let int_value = value.to_biguint();
                    let string_value = int_value.to_string();

                    Ok(ctx.stringv(string_value)?)
                }
                _ => Ok(ctx.bv_to_str(arc)?),
            }
        }
        AstOp::ITE(..) => {
            let (if_, then_, else_) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
                state.get_child_simplified(2)?,
            );

            // If both branches are identical, return either one
            if then_ == else_ {
                return Ok(then_.clone());
            }

            match if_.op() {
                // If the condition is a concrete boolean value, return the appropriate branch
                AstOp::BoolV(value) => {
                    if *value {
                        Ok(then_.clone())
                    } else {
                        Ok(else_.clone())
                    }
                }
                // If the condition has a Not at the top level, invert the branches
                AstOp::Not(inner) => Ok(ctx.ite(inner, else_, then_)?),
                _ => Ok(ctx.ite(if_, then_, else_)?),
            }
        }
        _ => unreachable!("non-string op dispatched to simplify_string"),
    }
}
