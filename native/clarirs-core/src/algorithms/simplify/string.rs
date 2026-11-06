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
            fn literal<'a>(ast: &'a AstRef<'_>) -> Option<&'a str> {
                match ast.op() {
                    AstOp::StringV(s) => Some(s.as_str()),
                    _ => None,
                }
            }

            // Simplify all children in one batch, as the bitvector Concat does,
            // then flatten nested StrConcats and drop empty literals.
            let pieces: Vec<AstRef<'c>> = state
                .get_all_simplified()?
                .into_iter()
                .flat_map(|arg| match arg.op() {
                    AstOp::StrConcat(inner) => inner.clone(),
                    _ => vec![arg],
                })
                .filter(|arg| literal(arg) != Some(""))
                .collect();

            // Merge each run of adjacent literals into one
            let merged = pieces
                .chunk_by(|a, b| literal(a).is_some() && literal(b).is_some())
                .map(|run| match run {
                    [single] => Ok(single.clone()),
                    run => ctx.stringv(run.iter().filter_map(literal).collect::<String>()),
                })
                .collect::<Result<Vec<_>, ClarirsError>>()?;

            match merged.as_slice() {
                // Every piece was the empty string
                [] => Ok(ctx.stringv("")?),
                [single] => Ok(single.clone()),
                _ => Ok(ctx.str_concat(merged)?),
            }
        }
        AstOp::StrSubstr(..) => {
            let string = state.get_child_simplified(0)?;
            let start_idx = state.get_child_simplified(1)?;
            let count = state.get_child_simplified(2)?;
            match (string.op(), start_idx.op(), count.op()) {
                (AstOp::StringV(s), AstOp::BVV(start_bv), AstOp::BVV(length_bv)) => {
                    // Convert the bitvectors to usize indices.
                    let start = start_bv.to_usize().unwrap_or(usize::MAX);
                    let length = length_bv.to_usize().unwrap_or(s.chars().count());
                    let num_chars = s.chars().count();

                    // If the starting index is out-of-bound (e.g., negative index wrapped to 2^64-1),
                    // then return an empty string.
                    if start >= num_chars {
                        return Ok(ctx.stringv("".to_string())?);
                    }

                    // Convert character-based indices to byte-based indices.
                    let char_start = s.chars().take(start).map(|c| c.len_utf8()).sum();
                    let char_end = s
                        .chars()
                        .take(start.saturating_add(length))
                        .map(|c| c.len_utf8())
                        .sum();

                    let substring = s.get(char_start..char_end).unwrap_or("").to_string();
                    Ok(ctx.stringv(substring)?)
                }
                _ => Ok(ctx.str_substr(string, start_idx, count)?),
            }
        }
        AstOp::StrReplace(..) => {
            let string = state.get_child_simplified(0)?;
            let from = state.get_child_simplified(1)?;
            let to = state.get_child_simplified(2)?;
            match (string.op(), from.op(), to.op()) {
                (AstOp::StringV(initial), AstOp::StringV(pattern), AstOp::StringV(replacement)) => {
                    // Case: Replace first occurrence of `pattern` with `replacement` in `initial` as per ClariPy DONE
                    let new_value = initial.replacen(pattern, replacement, 1);
                    // Case: Replace all occurrences of `pattern` with `replacement` in `initial` LEFT
                    // let new_value = initial.replace(pattern, replacement);
                    Ok(ctx.stringv(new_value)?)
                }
                _ => Ok(ctx.str_replace(string, from, to)?), // Fallback to symbolic StrReplace
            }
        }
        AstOp::BVToStr(..) => {
            let inner = state.get_child_simplified(0)?;
            match inner.op() {
                AstOp::BVV(value) => {
                    // Convert the BitVec value to an integer, then to a string
                    let int_value = value.to_biguint();
                    let string_value = int_value.to_string();

                    Ok(ctx.stringv(string_value)?)
                }
                _ => Ok(ctx.bv_to_str(inner)?),
            }
        }
        AstOp::ITE(..) => super::simplify_ite(state),
        _ => unreachable!("non-string op dispatched to simplify_string"),
    }
}
