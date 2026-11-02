mod bool;
mod bv;
mod float;
mod known_bits;
pub(crate) use known_bits::KnownSlot;
mod linear;
mod string;

#[cfg(test)]
mod test_bool;
#[cfg(test)]
mod test_bv;
#[cfg(test)]
mod test_float;
#[cfg(test)]
mod test_known_bits;
#[cfg(test)]
mod test_linear;

use std::collections::BTreeSet;
use std::sync::{Arc, atomic::Ordering};

use crate::{cache::Cache, prelude::*};

impl<'c> AstNode<'c> {
    pub fn simplify(self: &Arc<Self>) -> Result<AstRef<'c>, ClarirsError> {
        self.simplify_ext(true, false)
    }

    pub fn simplify_ext(
        self: &Arc<Self>,
        respect_annotations: bool,
        error_on_dbz: bool,
    ) -> Result<AstRef<'c>, ClarirsError> {
        simplify(self, respect_annotations, error_on_dbz)
    }
}

#[derive(thiserror::Error, Debug)]
enum SimplifyError<'c> {
    #[error("Missing child at index {0}")]
    MissingChild(usize),
    #[error("Missing {} children", .0.len())]
    MissingChildren(Vec<usize>),
    #[error("Re-run simplification")]
    ReRun(AstRef<'c>),
    #[error("Clarirs error: {0}")]
    Error(ClarirsError),
}

impl<T> From<T> for SimplifyError<'_>
where
    ClarirsError: From<T>,
{
    fn from(value: T) -> Self {
        SimplifyError::Error(ClarirsError::from(value))
    }
}

struct SimplifyState<'c> {
    expr: AstRef<'c>,
    children: Vec<Option<AstRef<'c>>>,
    /// Children scheduled on the work stack, collected when this state pops again.
    missed: Vec<usize>,
    /// Whether simplifying this node met a division by a zero constant (see [`dbz_node`]).
    dbz: bool,
}

impl<'c> SimplifyState<'c> {
    fn new(expr: AstRef<'c>) -> Self {
        Self {
            expr: expr.clone(),
            children: vec![None; expr.child_iter().count()],
            missed: Vec::new(),
            dbz: false,
        }
    }

    /// Get the simplified child at the given index, or return an error if it is missing.
    fn get_child_simplified(&self, index: usize) -> Result<AstRef<'c>, SimplifyError<'c>> {
        if let Some(child) = &self.children[index] {
            Ok(child.clone())
        } else {
            Err(SimplifyError::MissingChild(index))
        }
    }

    /// Return simplified versions of all children in one shot. If any are
    /// missing, returns `MissingChildren` listing every missing index so the
    /// main simplify loop can schedule them in one batch. This is crucial for
    /// n-ary ops (like Concat) with many children: fetching them one at a
    /// time causes quadratic re-runs of simplification.
    fn get_all_simplified(&self) -> Result<Vec<AstRef<'c>>, SimplifyError<'c>> {
        let missing: Vec<usize> = self
            .children
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.is_none().then_some(i))
            .collect();
        if !missing.is_empty() {
            return Err(SimplifyError::MissingChildren(missing));
        }
        Ok(self.children.iter().map(|c| c.clone().unwrap()).collect())
    }

    /// Get the best available child: if we have a simplified version, return that,
    /// otherwise return the original child.
    fn get_child_available(&self, index: usize) -> AstRef<'c> {
        if let Some(child) = &self.children[index] {
            child.clone()
        } else {
            self.expr.get_child(index).unwrap()
        }
    }

    fn rerun(&self, new_ast: AstRef<'c>) -> Result<AstRef<'c>, SimplifyError<'c>> {
        Err(SimplifyError::ReRun(new_ast))
    }
}

/// If(c, If(c, a, b), d) -> If(c, a, d) and If(c, d, If(c, a, b)) -> If(c, d, b), as claripy's
/// If() constructor does: the inner branch not selected under c is dead. None if neither applies.
fn absorb_nested_ite<'c>(
    cond: &AstRef<'c>,
    then_: &AstRef<'c>,
    else_: &AstRef<'c>,
) -> Option<(AstRef<'c>, AstRef<'c>)> {
    let new_then = match then_.op() {
        AstOp::ITE(c, a, _) if c == cond => Some(a.clone()),
        _ => None,
    };
    let new_else = match else_.op() {
        AstOp::ITE(c, _, b) if c == cond => Some(b.clone()),
        _ => None,
    };
    if new_then.is_none() && new_else.is_none() {
        return None;
    }
    Some((
        new_then.unwrap_or_else(|| then_.clone()),
        new_else.unwrap_or_else(|| else_.clone()),
    ))
}

/// Whether `state` divides by a zero constant: an error under `error_on_dbz`, kept otherwise.
fn dbz_node(state: &SimplifyState<'_>) -> bool {
    matches!(state.expr.op(), AstOp::UDiv(..) | AstOp::SDiv(..))
        && matches!(&state.children[1], Some(d) if matches!(d.op(), AstOp::BVV(v) if v.is_zero()))
}

fn simplify<'c>(
    ast: &AstRef<'c>,
    respect_annotations: bool,
    error_on_dbz: bool,
) -> Result<AstRef<'c>, ClarirsError> {
    // Keeps simplified nodes and their results interned for the whole call.
    let mut keep_alive: Vec<AstRef<'c>> = Vec::new();
    let mut work_stack: Vec<SimplifyState<'c>> = Vec::new();
    // Each state pushed onto the work stack pushes exactly one result here.
    let mut results: Vec<AstRef<'c>> = Vec::new();
    // Parallel to `results`: whether computing that result met a division by zero.
    let mut dbz_results: Vec<bool> = Vec::new();

    work_stack.push(SimplifyState::new(ast.clone()));

    while let Some(mut state) = work_stack.pop() {
        // Collect the results of the children scheduled last time.
        while let Some(idx) = state.missed.pop() {
            state.children[idx] = results.pop();
            state.dbz |= dbz_results.pop().unwrap_or(false);
        }

        let blocked = state
            .expr
            .annotations()
            .iter()
            .any(|a| !a.eliminatable() && !a.relocatable())
            || !state.expr.simplifiable();
        let should_simplify = !respect_annotations || !blocked;
        if should_simplify {
            // Reuse the inline-cached simplified form if present (`0` = none;
            // a dropped node resolves to a miss via the AST cache). A form whose computation
            // met a division by zero must raise under error_on_dbz, so that mode recomputes it.
            let cached = match state.expr.simplified.load(Ordering::Acquire) {
                0 => None,
                _ if error_on_dbz && state.expr.simplified_dbz.load(Ordering::Relaxed) => None,
                hash => state.expr.context().ast_cache.get(&hash),
            };
            if cached.is_some() {
                state.dbz |= state.expr.simplified_dbz.load(Ordering::Relaxed);
            }
            let inner_result = match cached {
                Some(cached) => Ok(cached),
                None => match state.expr.ast_type() {
                    AstType::Bool => bool::simplify_bool(&mut state).and_then(|result| {
                        // A comparison the known bits decide folds to its truth value.
                        match known_bits::decide(&result)? {
                            Some(value) => Ok(result.context().make_ast_exact(
                                AstOp::BoolV(value),
                                result.annotations().clone(),
                            )?),
                            None => Ok(result),
                        }
                    }),
                    AstType::BitVec(_) => {
                        bv::simplify_bv(&mut state, error_on_dbz).and_then(|result| {
                            // A fully known result folds to its constant, annotations kept.
                            match known_bits::fold(&result)? {
                                Some(value) => Ok(result.context().make_ast_exact(
                                    AstOp::BVV(value),
                                    result.annotations().clone(),
                                )?),
                                None => Ok(result),
                            }
                        })
                    }
                    AstType::Float(_) => float::simplify_float(&mut state),
                    AstType::String => string::simplify_string(&mut state),
                },
            };
            match inner_result {
                Ok(result) => {
                    state.dbz |= dbz_node(&state);
                    let mut new_annotations: BTreeSet<Annotation> = result
                        .annotations()
                        .iter()
                        .filter(|a| !a.relocatable())
                        .cloned()
                        .collect();
                    new_annotations.extend(
                        state
                            .expr
                            .annotations()
                            .iter()
                            .filter(|a| a.relocatable())
                            .cloned(),
                    );
                    let annotated = state
                        .expr
                        .context()
                        .make_ast_exact(result.op().clone(), new_annotations)?;

                    // Cache the simplified form for shared sub-exprs.
                    state
                        .expr
                        .simplified_dbz
                        .store(state.dbz, Ordering::Relaxed);
                    state
                        .expr
                        .simplified
                        .store(annotated.as_ref().hash(), Ordering::Release);

                    keep_alive.push(annotated.clone());
                    keep_alive.push(state.expr);
                    results.push(annotated);
                    dbz_results.push(state.dbz);
                }
                Err(SimplifyError::MissingChild(index)) => {
                    let child = state.expr.get_child(index).unwrap();
                    state.missed.push(index);
                    work_stack.push(state);
                    work_stack.push(SimplifyState::new(child));
                }
                Err(SimplifyError::MissingChildren(indices)) => {
                    // Schedule every missing child at once, so a wide n-ary op is dispatched once.
                    let children: Vec<_> = indices
                        .iter()
                        .map(|&idx| state.expr.get_child(idx).unwrap())
                        .collect();
                    state.missed = indices;
                    work_stack.push(state);
                    work_stack.extend(children.into_iter().rev().map(SimplifyState::new));
                }
                Err(SimplifyError::ReRun(new_ast)) => {
                    // Forward the rewritten node's relocatable annotations onto the
                    // rewritten expression so they are not dropped across the rerun.
                    let relocatable_annotations: Vec<Annotation> = state
                        .expr
                        .annotations()
                        .iter()
                        .filter(|a| a.relocatable())
                        .cloned()
                        .collect();
                    let new_ast = if relocatable_annotations.is_empty() {
                        new_ast
                    } else {
                        state
                            .expr
                            .context()
                            .annotate(&new_ast, relocatable_annotations)?
                    };
                    // Push a new state with the new_ast onto the stack; it inherits what this
                    // state's children met.
                    let mut rerun = SimplifyState::new(new_ast);
                    rerun.dbz = state.dbz;
                    work_stack.push(rerun);
                }
                Err(SimplifyError::Error(e)) => {
                    return Err(e);
                }
            }
        } else {
            results.push(state.expr.clone());
            dbz_results.push(state.dbz);
        }
    }

    results
        .pop()
        .ok_or_else(|| ClarirsError::InvalidArguments("No result produced".to_string()))
}
