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
    last_missed_child: Option<usize>,
    /// Earlier nodes this state stands for: a rewrite (`ReRun`) replaces the
    /// node being simplified with an equivalent one, and its result is the
    /// result of every node it replaced.
    origins: Vec<AstRef<'c>>,
}

impl<'c> SimplifyState<'c> {
    fn new(expr: AstRef<'c>) -> Self {
        Self {
            expr: expr.clone(),
            children: vec![None; expr.child_iter().count()],
            last_missed_child: None,
            origins: Vec::new(),
        }
    }

    /// Get the simplified child at the given index, or return an error if it is missing.
    fn get_child_simplified(&mut self, index: usize) -> Result<AstRef<'c>, SimplifyError<'c>> {
        if let Some(child) = &self.children[index] {
            Ok(child.clone())
        } else {
            self.last_missed_child = Some(index);
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

#[cfg(test)]
thread_local! {
    /// States popped by the simplify loop on this thread, for the tests that
    /// bound how much work a simplification does.
    pub(super) static DISPATCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Results of one top-level `simplify` call, by node hash. Unlike the inline
/// `simplified` field, which names its result by hash and so loses it once
/// nothing else holds that node, this keeps every result alive until the
/// call returns. A subexpression shared by many parents is then simplified
/// once per call rather than once per path to it, which on a heavily shared
/// DAG is the difference between linear and exponential work.
///
/// The cost is that every result stays alive until the top-level call
/// returns, so peak memory grows with the number of distinct nodes visited.
type Memo<'c> = ahash::HashMap<u64, AstRef<'c>>;

fn simplify<'c>(
    ast: &AstRef<'c>,
    respect_annotations: bool,
    error_on_dbz: bool,
) -> Result<AstRef<'c>, ClarirsError> {
    simplify_with(ast, respect_annotations, error_on_dbz, &mut Memo::default())
}

fn simplify_with<'c>(
    ast: &AstRef<'c>,
    respect_annotations: bool,
    error_on_dbz: bool,
    memo: &mut Memo<'c>,
) -> Result<AstRef<'c>, ClarirsError> {
    let mut work_stack: Vec<SimplifyState<'c>> = Vec::new();
    let mut last_result: Option<AstRef<'c>> = None;

    work_stack.push(SimplifyState::new(ast.clone()));

    while let Some(mut state) = work_stack.pop() {
        #[cfg(test)]
        DISPATCHES.set(DISPATCHES.get() + 1);
        if let Some(missed_index) = state.last_missed_child {
            // We missed a child last time, so we need to get the last result and set it as the child
            state.children[missed_index] = Some(last_result.take().unwrap());
            state.last_missed_child = None;
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
            // a dropped node resolves to a miss via the AST cache).
            let cached = memo.get(&state.expr.hash()).cloned().or_else(|| {
                match state.expr.simplified.load(Ordering::Relaxed) {
                    0 => None,
                    hash => state.expr.context().ast_cache.get(&hash),
                }
            });
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

                    // Cache the simplified form inline for shared sub-exprs,
                    // on this node and on every node a rewrite replaced.
                    for node in std::iter::once(&state.expr).chain(&state.origins) {
                        node.simplified
                            .store(annotated.as_ref().hash(), Ordering::Relaxed);
                        memo.insert(node.hash(), annotated.clone());
                    }

                    last_result = Some(annotated)
                }
                Err(SimplifyError::MissingChild(index)) => {
                    let child_state = SimplifyState::new(state.expr.get_child(index).unwrap());

                    // Push the current state back onto the stack
                    work_stack.push(state);
                    // Push the missing child onto the stack
                    work_stack.push(child_state);
                }
                Err(SimplifyError::MissingChildren(indices)) => {
                    // Batch-simplify all missing children at once to avoid
                    // O(n^2) behaviour for wide n-ary ops like Concat. We use
                    // direct recursion here: the parent op is allowed to
                    // defer all its children with a single request and we
                    // simplify each child via the normal entry point. Stack
                    // depth is bounded by the nesting depth of n-ary ops,
                    // not by the number of children.
                    for idx in indices {
                        if state.children[idx].is_none() {
                            let child_expr = state.expr.get_child(idx).unwrap();
                            let simplified = simplify_with(
                                &child_expr,
                                respect_annotations,
                                error_on_dbz,
                                memo,
                            )?;
                            state.children[idx] = Some(simplified);
                        }
                    }
                    // All requested children are now cached; re-push the
                    // state so the simplification dispatch will run again with
                    // children available.
                    work_stack.push(state);
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
                    // Push a new state with the new_ast onto the stack; its
                    // result is also this node's.
                    let mut next = SimplifyState::new(new_ast);
                    next.origins = std::mem::take(&mut state.origins);
                    next.origins.push(state.expr);
                    work_stack.push(next);
                }
                Err(SimplifyError::Error(e)) => {
                    return Err(e);
                }
            }
        } else {
            // Annotations block simplifying this node, so it is its own result,
            // and so the result of any node a rewrite replaced with it.
            for node in &state.origins {
                memo.insert(node.hash(), state.expr.clone());
            }
            last_result = Some(state.expr.clone());
        }
    }

    if last_result.is_none() {
        return Err(ClarirsError::InvalidArguments(
            "No result produced".to_string(),
        ));
    }

    Ok(last_result.unwrap())
}
