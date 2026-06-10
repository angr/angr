mod bool;
mod bv;
mod float;
mod string;

#[cfg(test)]
mod test_bool;
#[cfg(test)]
mod test_bv;

use crate::{cache::Cache, prelude::*};

pub trait Simplify<'c>: Sized {
    fn simplify(&self) -> Result<Self, ClarirsError> {
        self.simplify_ext(true, false)
    }

    fn simplify_ext(
        &self,
        respect_annotations: bool,
        error_on_dbz: bool,
    ) -> Result<Self, ClarirsError>;
}

impl<'c> Simplify<'c> for BoolAst<'c> {
    fn simplify_ext(
        &self,
        respect_annotations: bool,
        error_on_dbz: bool,
    ) -> Result<Self, ClarirsError> {
        DynAst::Boolean(self.clone())
            .simplify_ext(respect_annotations, error_on_dbz)?
            .as_bool()
            .cloned()
            .ok_or(ClarirsError::TypeError("Expected BoolAst".to_string()))
    }
}

impl<'c> Simplify<'c> for BitVecAst<'c> {
    fn simplify_ext(
        &self,
        respect_annotations: bool,
        error_on_dbz: bool,
    ) -> Result<Self, ClarirsError> {
        DynAst::BitVec(self.clone())
            .simplify_ext(respect_annotations, error_on_dbz)?
            .as_bitvec()
            .cloned()
            .ok_or(ClarirsError::TypeError("Expected BvAst".to_string()))
    }
}

impl<'c> Simplify<'c> for FloatAst<'c> {
    fn simplify_ext(
        &self,
        respect_annotations: bool,
        error_on_dbz: bool,
    ) -> Result<Self, ClarirsError> {
        DynAst::Float(self.clone())
            .simplify_ext(respect_annotations, error_on_dbz)?
            .as_float()
            .cloned()
            .ok_or(ClarirsError::TypeError("Expected FloatAst".to_string()))
    }
}

impl<'c> Simplify<'c> for StringAst<'c> {
    fn simplify_ext(
        &self,
        respect_annotations: bool,
        error_on_dbz: bool,
    ) -> Result<Self, ClarirsError> {
        DynAst::String(self.clone())
            .simplify_ext(respect_annotations, error_on_dbz)?
            .as_string()
            .cloned()
            .ok_or(ClarirsError::TypeError("Expected StringAst".to_string()))
    }
}

impl<'c> Simplify<'c> for DynAst<'c> {
    fn simplify_ext(
        &self,
        respect_annotations: bool,
        error_on_dbz: bool,
    ) -> Result<Self, ClarirsError> {
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
    #[allow(dead_code)]
    ReRun(DynAst<'c>),
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
    expr: DynAst<'c>,
    children: Vec<Option<DynAst<'c>>>,
    last_missed_child: Option<usize>,
}

impl<'c> SimplifyState<'c> {
    fn new(expr: DynAst<'c>) -> Self {
        Self {
            expr: expr.clone(),
            children: vec![None; expr.child_iter().count()],
            last_missed_child: None,
        }
    }

    /// Get the simplified child at the given index, or return an error if it is missing.
    fn get_child_simplified(&mut self, index: usize) -> Result<DynAst<'c>, SimplifyError<'c>> {
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
    /// time causes quadratic re-runs of simplify_inner.
    fn get_all_simplified(&self) -> Result<Vec<DynAst<'c>>, SimplifyError<'c>> {
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

    fn get_all_bool_simplified(&self) -> Result<Vec<BoolAst<'c>>, SimplifyError<'c>> {
        self.get_all_simplified()?
            .into_iter()
            .map(|c| {
                c.into_bool()
                    .ok_or(SimplifyError::Error(ClarirsError::TypeError(
                        "Expected bool child".into(),
                    )))
            })
            .collect()
    }

    fn get_all_bv_simplified(&self) -> Result<Vec<BitVecAst<'c>>, SimplifyError<'c>> {
        self.get_all_simplified()?
            .into_iter()
            .map(|c| {
                c.into_bitvec()
                    .ok_or(SimplifyError::Error(ClarirsError::TypeError(
                        "Expected bitvector child".into(),
                    )))
            })
            .collect()
    }

    fn get_bool_simplified(&mut self, index: usize) -> Result<BoolAst<'c>, SimplifyError<'c>> {
        self.get_child_simplified(index)?
            .into_bool()
            .ok_or(SimplifyError::Error(ClarirsError::TypeError(
                "Expected bool child".into(),
            )))
    }

    fn get_bv_simplified(&mut self, index: usize) -> Result<BitVecAst<'c>, SimplifyError<'c>> {
        self.get_child_simplified(index)?
            .into_bitvec()
            .ok_or(SimplifyError::Error(ClarirsError::TypeError(
                "Expected bitvector child".into(),
            )))
    }

    fn get_fp_simplified(&mut self, index: usize) -> Result<FloatAst<'c>, SimplifyError<'c>> {
        self.get_child_simplified(index)?
            .into_float()
            .ok_or(SimplifyError::Error(ClarirsError::TypeError(
                "Expected float child".into(),
            )))
    }

    fn get_string_simplified(&mut self, index: usize) -> Result<StringAst<'c>, SimplifyError<'c>> {
        self.get_child_simplified(index)?
            .into_string()
            .ok_or(SimplifyError::Error(ClarirsError::TypeError(
                "Expected string child".into(),
            )))
    }

    /// Get the best available child: if we have a simplified version, return that,
    /// otherwise return the original child.
    fn get_child_available(&self, index: usize) -> DynAst<'c> {
        if let Some(child) = &self.children[index] {
            child.clone()
        } else {
            self.expr.get_child(index).unwrap()
        }
    }

    fn get_bool_available(&self, index: usize) -> Result<BoolAst<'c>, ClarirsError> {
        self.get_child_available(index)
            .into_bool()
            .ok_or(ClarirsError::TypeError("Expected bool child".into()))
    }

    fn get_bv_available(&self, index: usize) -> Result<BitVecAst<'c>, ClarirsError> {
        self.get_child_available(index)
            .into_bitvec()
            .ok_or(ClarirsError::TypeError("Expected bitvector child".into()))
    }

    fn get_fp_available(&self, index: usize) -> Result<FloatAst<'c>, ClarirsError> {
        self.get_child_available(index)
            .into_float()
            .ok_or(ClarirsError::TypeError("Expected float child".into()))
    }

    fn get_string_available(&self, index: usize) -> Result<StringAst<'c>, ClarirsError> {
        self.get_child_available(index)
            .into_string()
            .ok_or(ClarirsError::TypeError("Expected string child".into()))
    }

    fn rerun<T>(&self, new_ast: T) -> Result<T, SimplifyError<'c>>
    where
        DynAst<'c>: From<T>,
    {
        Err(SimplifyError::ReRun(DynAst::from(new_ast)))
    }
}

fn simplify_inner<'c>(
    state: &mut SimplifyState<'c>,
    error_on_dbz: bool,
) -> Result<DynAst<'c>, SimplifyError<'c>> {
    let expr = &state.expr.clone();
    expr.context()
        .simplification_cache
        .get_or_insert(state.expr.inner_hash(), || match expr {
            DynAst::Boolean(_) => bool::simplify_bool(state).map(DynAst::Boolean),
            DynAst::BitVec(_) => bv::simplify_bv(state, error_on_dbz).map(DynAst::BitVec),
            DynAst::Float(_) => float::simplify_float(state).map(DynAst::Float),
            DynAst::String(_) => string::simplify_string(state).map(DynAst::String),
        })
}

fn simplify<'c>(
    ast: &DynAst<'c>,
    respect_annotations: bool,
    error_on_dbz: bool,
) -> Result<DynAst<'c>, ClarirsError> {
    let mut work_stack: Vec<SimplifyState<'c>> = Vec::new();
    let mut last_result: Option<DynAst<'c>> = None;

    work_stack.push(SimplifyState::new(ast.clone()));

    while let Some(mut state) = work_stack.pop() {
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
            let inner_result = simplify_inner(&mut state, error_on_dbz);
            match inner_result {
                Ok(result) => {
                    let relocatable_annotations: Vec<Annotation> = state
                        .expr
                        .annotations()
                        .iter()
                        .filter(|a| a.relocatable())
                        .cloned()
                        .collect();
                    let annotated = state
                        .expr
                        .context()
                        .annotate_dyn(&result, relocatable_annotations)?;

                    // Cache the mapping from the original expression to the
                    // simplified result so that identical unsimplified
                    // sub-expressions elsewhere in the tree get a cache hit.
                    if state.expr.inner_hash() != annotated.inner_hash() {
                        let ctx = state.expr.context();
                        let hash = state.expr.inner_hash();
                        let annotated_ref = annotated.clone();
                        let _ = ctx
                            .simplification_cache
                            .get_or_insert::<SimplifyError<'c>>(hash, || Ok(annotated_ref.clone()));
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
                            let simplified =
                                simplify(&child_expr, respect_annotations, error_on_dbz)?;
                            state.children[idx] = Some(simplified);
                        }
                    }
                    // All requested children are now cached; re-push the
                    // state so simplify_inner will run again with children
                    // available.
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
                            .annotate_dyn(&new_ast, relocatable_annotations)?
                    };
                    // Push a new state with the new_ast onto the stack
                    work_stack.push(SimplifyState::new(new_ast));
                }
                Err(SimplifyError::Error(e)) => {
                    return Err(e);
                }
            }
        } else {
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
