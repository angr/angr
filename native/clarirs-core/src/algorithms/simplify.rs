mod bool;
mod bv;
mod float;
mod string;

#[cfg(test)]
mod test_bool;
#[cfg(test)]
mod test_bv;
#[cfg(test)]
mod test_float;
#[cfg(test)]
mod test_string;

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
}

impl<'c> SimplifyState<'c> {
    fn new(expr: AstRef<'c>) -> Self {
        // A child that is already its own simplified form is filled in up front.
        let children = expr
            .child_iter()
            .map(|child| {
                (!child.has_blocking_annotations
                    && child.simplified.load(Ordering::Relaxed) == child.hash())
                .then_some(child)
            })
            .collect();
        Self {
            expr,
            children,
            missed: Vec::new(),
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

    work_stack.push(SimplifyState::new(ast.clone()));

    while let Some(mut state) = work_stack.pop() {
        // Collect the results of the children scheduled last time.
        while let Some(idx) = state.missed.pop() {
            state.children[idx] = results.pop();
        }

        let blocked = !state.expr.simplifiable()
            || state
                .expr
                .annotations()
                .iter()
                .any(|a| a.blocks_simplification());
        let should_simplify = !respect_annotations || !blocked;
        if should_simplify {
            // Reuse the inline-cached simplified form if present (`0` = none;
            // a dropped node resolves to a miss via the AST cache).
            let cached = match state.expr.simplified.load(Ordering::Relaxed) {
                0 => None,
                hash if hash == state.expr.hash() => Some(state.expr.clone()),
                hash => state.expr.context().ast_cache.get(&hash),
            };
            let inner_result = match cached {
                Some(cached) => Ok(cached),
                None => match state.expr.ast_type() {
                    AstType::Bool => bool::simplify_bool(&mut state),
                    AstType::BitVec(_) => bv::simplify_bv(&mut state, error_on_dbz),
                    AstType::Float(_) => float::simplify_float(&mut state),
                    AstType::String => string::simplify_string(&mut state),
                },
            };
            match inner_result {
                Ok(result) => {
                    // The result keeps its own non-relocatable annotations and takes over
                    // the relocatable ones of the node it replaces. Only rebuild the node
                    // when that changes its annotation set.
                    let annotated = if Arc::ptr_eq(&result, &state.expr)
                        || (result.annotations().is_empty() && state.expr.annotations().is_empty())
                    {
                        result
                    } else {
                        let mut new_annotations: BTreeSet<Arc<Annotation>> = result
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
                        if new_annotations == *result.annotations() {
                            result
                        } else {
                            state
                                .expr
                                .context()
                                .make_ast_exact(result.op().clone(), new_annotations)?
                        }
                    };

                    // Cache the simplified form for shared sub-exprs.
                    state
                        .expr
                        .simplified
                        .store(annotated.as_ref().hash(), Ordering::Relaxed);
                    if !annotated.has_blocking_annotations {
                        let _ = annotated.simplified.compare_exchange(
                            0,
                            annotated.hash(),
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                    }

                    keep_alive.push(annotated.clone());
                    keep_alive.push(state.expr);
                    results.push(annotated);
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
                    let relocatable_annotations: Vec<Arc<Annotation>> = state
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
                    // Push a new state with the new_ast onto the stack
                    work_stack.push(SimplifyState::new(new_ast));
                }
                Err(SimplifyError::Error(e)) => {
                    return Err(e);
                }
            }
        } else {
            results.push(state.expr.clone());
        }
    }

    results
        .pop()
        .ok_or_else(|| ClarirsError::InvalidArguments("No result produced".to_string()))
}

/// Simplifies an ITE of any sort with the rewrites every sort shares.
fn simplify_ite<'c>(state: &SimplifyState<'c>) -> Result<AstRef<'c>, SimplifyError<'c>> {
    let ctx = state.expr.context();
    let cond = state.get_child_simplified(0)?;

    // Rewrites that need at most one branch simplified.
    match cond.op() {
        AstOp::BoolV(true) => return state.get_child_simplified(1),
        AstOp::BoolV(false) => return state.get_child_simplified(2),
        _ if state.get_child_available(1) == state.get_child_available(2) => {
            return state.get_child_simplified(1);
        }
        // If(!c, a, b) -> If(c, b, a)
        AstOp::Not(inner) => {
            return state.rerun(ctx.ite(
                inner,
                state.get_child_available(2),
                state.get_child_available(1),
            )?);
        }
        _ => {}
    }

    let then_ = state.get_child_simplified(1)?;
    let else_ = state.get_child_simplified(2)?;
    match (then_.op(), else_.op()) {
        _ if then_ == else_ => Ok(then_),
        // If(c, If(c, a, b), d) -> If(c, a, d) and If(c, d, If(c, a, b)) -> If(c, d, b), as
        // claripy's If() constructor does: the inner branch not selected under c is dead.
        (AstOp::ITE(c, a, _), _) if *c == cond => state.rerun(ctx.ite(&cond, a, &else_)?),
        (_, AstOp::ITE(c, _, b)) if *c == cond => state.rerun(ctx.ite(&cond, &then_, b)?),
        _ => Ok(ctx.ite(cond, then_, else_)?),
    }
}
