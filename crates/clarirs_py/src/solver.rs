use std::collections::BTreeSet;

use crate::ast::{and, or};
use crate::{dynsolver::DynSolver, prelude::*};
use clarirs_core::solver::HybridSolver;
use clarirs_core::solver_mixins::{
    ConcreteEarlyResolutionMixin, ModelCacheMixin, SimplificationMixin,
};
use clarirs_vsa::VSASolver;
use clarirs_z3::Z3Solver;
use num_bigint::BigInt;
use pyo3::types::PyTuple;

#[pyclass(name = "Solver", module = "claripy.solver", subclass)]
#[derive(Debug)]
pub struct PySolver {
    inner: DynSolver,
    #[pyo3(get, set)]
    timeout: Option<u32>,
    #[pyo3(get, set)]
    unsat_core: bool,
}

// Helper function to wrap a solver with mixins
fn wrap_solver<'c, S: Solver<'c>>(
    solver: S,
) -> SimplificationMixin<'c, ConcreteEarlyResolutionMixin<'c, S>> {
    SimplificationMixin::new(ConcreteEarlyResolutionMixin::new(solver))
}

// Wrap a Z3 solver in the caching stack used by the default `Solver` (and the
// composite/replacement/hybrid frontends, mirroring claripy): a
// `ModelCacheMixin` just above the backend caches satisfiability and models.
// `SolverCacheless` uses `wrap_solver` directly to omit this layer.
fn wrap_z3_cached<'c>(
    solver: Z3Solver<'c>,
) -> SimplificationMixin<'c, ConcreteEarlyResolutionMixin<'c, ModelCacheMixin<'c, Z3Solver<'c>>>> {
    wrap_solver(ModelCacheMixin::new(solver))
}

impl PySolver {
    /// Extract the `exact` Python kwarg into an `Option<bool>`.
    fn extract_exact(exact: Option<Bound<PyAny>>) -> Option<bool> {
        exact.and_then(|e| e.extract::<bool>().ok())
    }

    /// Calls `f` with a mutable reference to a solver that includes the given
    /// extra constraints. When no extra constraints are provided, `f` receives
    /// `&mut self.inner` directly, avoiding a clone.
    ///
    /// When `exact` is `Some(true)` and this is a Hybrid solver, the closure
    /// receives only the exact (Z3) backend. When `Some(false)`, only the
    /// approximate (VSA) backend. Otherwise the full hybrid dispatch is used.
    fn with_extra_constraints<T>(
        &mut self,
        extra_constraints: Option<Vec<CoerceBool<'_>>>,
        exact: Option<bool>,
        f: impl FnOnce(&mut DynSolver) -> Result<T, ClaripyError>,
    ) -> Result<T, ClaripyError> {
        let has_extra = matches!(&extra_constraints, Some(ec) if !ec.is_empty());
        let needs_sub_solver = exact.is_some() && matches!(&self.inner, DynSolver::Hybrid(_));

        if has_extra || needs_sub_solver {
            let mut solver = match (exact, &self.inner) {
                (Some(true), DynSolver::Hybrid(h)) => {
                    DynSolver::Z3(h.inner().inner().exact().clone())
                }
                (Some(false), DynSolver::Hybrid(h)) => {
                    DynSolver::Vsa(h.inner().inner().approximate().clone())
                }
                _ => self.inner.clone(),
            };
            if let Some(ec) = extra_constraints {
                for constraint in ec {
                    solver.add(&constraint.0.get().inner)?;
                }
            }
            f(&mut solver)
        } else {
            f(&mut self.inner)
        }
    }
}

#[pymethods]
impl PySolver {
    #[new]
    #[pyo3(signature = (timeout = None, track = false))]
    fn new(timeout: Option<u32>, track: bool) -> Result<PyClassInitializer<Self>, ClaripyError> {
        Ok(PyClassInitializer::from(PySolver {
            inner: DynSolver::Z3(wrap_z3_cached(Z3Solver::new_with_options(
                &GLOBAL_CONTEXT,
                timeout,
                track,
            ))),
            timeout,
            unsat_core: track,
        }))
    }

    fn blank_copy(&self) -> Result<PySolver, ClaripyError> {
        Ok(PySolver {
            inner: match &self.inner {
                DynSolver::Concrete(..) => {
                    DynSolver::Concrete(ConcreteSolver::new(&GLOBAL_CONTEXT))
                }
                DynSolver::Z3(..) => DynSolver::Z3(wrap_z3_cached(Z3Solver::new_with_options(
                    &GLOBAL_CONTEXT,
                    self.timeout,
                    self.unsat_core,
                ))),
                DynSolver::Z3Cacheless(..) => DynSolver::Z3Cacheless(wrap_solver(
                    Z3Solver::new_with_options(&GLOBAL_CONTEXT, self.timeout, self.unsat_core),
                )),
                DynSolver::Vsa(..) => DynSolver::Vsa(wrap_solver(VSASolver::new(&GLOBAL_CONTEXT))),
                DynSolver::Hybrid(..) => DynSolver::Hybrid(wrap_solver(HybridSolver::new(
                    &GLOBAL_CONTEXT,
                    wrap_solver(VSASolver::new(&GLOBAL_CONTEXT)),
                    wrap_z3_cached(Z3Solver::new_with_options(
                        &GLOBAL_CONTEXT,
                        self.timeout,
                        self.unsat_core,
                    )),
                ))),
                DynSolver::Replacement(..) => {
                    DynSolver::Replacement(ReplacementSolver::new(wrap_z3_cached(
                        Z3Solver::new_with_options(&GLOBAL_CONTEXT, self.timeout, self.unsat_core),
                    )))
                }
                DynSolver::Composite(..) => DynSolver::Composite(CompositeSolver::new(
                    &GLOBAL_CONTEXT,
                    wrap_z3_cached(Z3Solver::new_with_options(
                        &GLOBAL_CONTEXT,
                        self.timeout,
                        self.unsat_core,
                    )),
                )),
            },
            timeout: self.timeout,
            unsat_core: self.unsat_core,
        })
    }

    #[getter]
    fn constraints<'py>(&self, py: Python<'py>) -> Result<Vec<Bound<'py, Bool>>, ClaripyError> {
        self.inner
            .constraints()?
            .iter()
            .map(|c| Bool::new(py, c))
            .collect::<Result<Vec<_>, _>>()
    }

    #[getter]
    fn variables(&self) -> Result<BTreeSet<String>, ClaripyError> {
        Ok(self
            .inner
            .variables()?
            .iter()
            .map(|s| s.to_string())
            .collect())
    }

    fn branch<'py>(&self, py: Python<'py>) -> Result<Bound<'py, PySolver>, ClaripyError> {
        match &self.inner {
            DynSolver::Concrete(concrete_solver) => Ok(Bound::new(
                py,
                PySolver {
                    inner: DynSolver::Concrete(concrete_solver.clone()),
                    timeout: self.timeout,
                    unsat_core: self.unsat_core,
                },
            )?),
            DynSolver::Z3(z3_solver) => Ok(Bound::new(
                py,
                PySolver {
                    inner: DynSolver::Z3(z3_solver.clone()),
                    timeout: self.timeout,
                    unsat_core: self.unsat_core,
                },
            )?),
            DynSolver::Z3Cacheless(z3_solver) => Ok(Bound::new(
                py,
                PySolver {
                    inner: DynSolver::Z3Cacheless(z3_solver.clone()),
                    timeout: self.timeout,
                    unsat_core: self.unsat_core,
                },
            )?),
            DynSolver::Vsa(vsasolver) => Ok(Bound::new(
                py,
                PySolver {
                    inner: DynSolver::Vsa(vsasolver.clone()),
                    timeout: self.timeout,
                    unsat_core: self.unsat_core,
                },
            )?),
            DynSolver::Hybrid(hybrid_solver) => Ok(Bound::new(
                py,
                PySolver {
                    inner: DynSolver::Hybrid(hybrid_solver.clone()),
                    timeout: self.timeout,
                    unsat_core: self.unsat_core,
                },
            )?),
            DynSolver::Replacement(replacement_solver) => Ok(Bound::new(
                py,
                PySolver {
                    inner: DynSolver::Replacement(replacement_solver.clone()),
                    timeout: self.timeout,
                    unsat_core: self.unsat_core,
                },
            )?),
            DynSolver::Composite(composite_solver) => Ok(Bound::new(
                py,
                PySolver {
                    inner: DynSolver::Composite(composite_solver.clone()),
                    timeout: self.timeout,
                    unsat_core: self.unsat_core,
                },
            )?),
        }
    }

    #[pyo3(signature = (others, merge_conditions, common_ancestor = None))]
    fn merge<'py>(
        &mut self,
        py: Python<'py>,
        others: Vec<Bound<'py, PySolver>>,
        merge_conditions: Vec<Bound<'py, Bool>>,
        common_ancestor: Option<Bound<'py, PySolver>>,
    ) -> Result<(bool, Bound<'py, PySolver>), ClaripyError> {
        let merged = if let Some(ancestor) = &common_ancestor {
            // Branch from common ancestor
            let merged_bound = ancestor.borrow().branch(py)?;

            // Add Or(*merge_conditions)
            let or_args: Vec<Bound<PyAny>> =
                merge_conditions.into_iter().map(|c| c.into_any()).collect();
            let or_expr = or(py, or_args)?;
            let or_expr_any = or_expr.into_any();
            merged_bound.borrow_mut().add(or_expr_any)?;

            merged_bound
        } else {
            // Create a blank copy
            let merged_solver = self.blank_copy()?;
            let merged_bound = Bound::new(py, merged_solver)?;

            // Build options: for each solver and merge condition, create And(condition, *constraints)
            let mut options = Vec::new();

            // Process self first
            let self_constraints = self.constraints(py)?;
            let mut self_and_args: Vec<Bound<PyAny>> = vec![merge_conditions[0].clone().into_any()];
            self_and_args.extend(self_constraints.into_iter().map(|c| c.into_any()));
            let self_and_expr = and(py, self_and_args)?;
            options.push(self_and_expr);

            // Process others
            for (other, condition) in others.iter().zip(merge_conditions.iter().skip(1)) {
                let other_constraints = other.borrow().constraints(py)?;
                let mut other_and_args: Vec<Bound<PyAny>> = vec![condition.clone().into_any()];
                other_and_args.extend(other_constraints.into_iter().map(|c| c.into_any()));
                let other_and_expr = and(py, other_and_args)?;
                options.push(other_and_expr);
            }

            // Add Or(*options) to the merged solver
            let or_expr = or(py, options.into_iter().map(|o| o.into_any()).collect())?;
            let or_expr_any = or_expr.into_any();
            merged_bound.borrow_mut().add(or_expr_any)?;

            merged_bound
        };

        Ok((
            matches!(
                self.inner,
                DynSolver::Z3(..)
                    | DynSolver::Z3Cacheless(..)
                    | DynSolver::Hybrid(..)
                    | DynSolver::Replacement(..)
                    | DynSolver::Composite(..)
            ),
            merged,
        ))
    }

    #[pyo3(signature = (exprs))]
    fn add<'py>(
        &mut self,
        exprs: Bound<'py, PyAny>,
    ) -> Result<Vec<Bound<'py, Bool>>, ClaripyError> {
        // First try to handle as a single Bool or BV (before trying iteration,
        // since BV supports __getitem__ which makes it iterable in Python)
        let bool_exprs = if let Ok(coerced) = exprs.extract::<CoerceBool>() {
            vec![coerced.0]
        } else if let Ok(iter) = exprs.try_iter() {
            // Convert iterable of expressions to Vec<Bound<Bool>>
            iter.map(|expr_result| {
                let expr = expr_result
                    .map_err(|e| ClaripyError::TypeError(format!("add: iteration error: {e}")))?;
                expr.extract::<CoerceBool>().map(|b| b.0).map_err(|_| {
                    ClaripyError::TypeError("add: expression must be a boolean".to_string())
                })
            })
            .collect::<Result<Vec<_>, _>>()?
        } else {
            return Err(ClaripyError::TypeError(
                "add: expression must be a boolean or iterable of booleans".to_string(),
            ));
        };

        // Return only the constraints actually added: trivially-true ones and
        // duplicates of already-present constraints are filtered out.
        let mut seen: std::collections::HashSet<u64> =
            self.inner.constraints()?.iter().map(|c| c.hash()).collect();
        let mut added = Vec::with_capacity(bool_exprs.len());
        for expr in &bool_exprs {
            let ast = expr.get().inner.clone();
            self.inner.add(&ast)?;
            if ast.simplify()?.is_true() || !seen.insert(ast.hash()) {
                continue;
            }
            added.push(expr.clone());
        }

        Ok(added)
    }

    fn simplify(&mut self) -> Result<(), ClaripyError> {
        self.inner.simplify()?;
        Ok(())
    }

    #[pyo3(signature = (extra_constraints = None, exact = None))]
    fn satisfiable<'py>(
        &mut self,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
    ) -> Result<bool, ClaripyError> {
        let exact = Self::extract_exact(exact);
        // Fast path: scoped extra-constraint checks reuse the persistent
        // incremental backend solvers instead of cloning cold copies.
        if exact.is_none() || !matches!(&self.inner, DynSolver::Hybrid(_)) {
            let asts: Vec<AstRef<'static>> = extra_constraints
                .into_iter()
                .flatten()
                .map(|c| c.0.get().inner.clone())
                .collect();
            return Ok(self.inner.satisfiable_with_extra(&asts)?);
        }
        self.with_extra_constraints(extra_constraints, exact, |solver| Ok(solver.satisfiable()?))
    }

    #[pyo3(signature = (extra_constraints = None))]
    fn unsat_core<'py>(
        &mut self,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
    ) -> Result<Vec<usize>, ClaripyError> {
        self.with_extra_constraints(extra_constraints, None, |solver| Ok(solver.unsat_core()?))
    }

    #[pyo3(signature = (expr, n, extra_constraints = None, exact = None))]
    fn eval_to_ast<'py>(
        &mut self,
        py: Python<'py>,
        expr: Bound<'py, Base>,
        n: u32,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
    ) -> Result<Vec<Bound<'py, Base>>, ClaripyError> {
        let exact = Self::extract_exact(exact);
        self.with_extra_constraints(extra_constraints, exact, |solver| {
            // Get multiple solutions based on expression type
            if let Ok(bv_value) = expr.clone().into_any().cast::<BV>() {
                let solutions = solver.eval_n(&bv_value.get().inner, n)?;
                let py_solutions = solutions
                    .into_iter()
                    .map(|sol| BV::new(py, &sol))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(py_solutions
                    .into_iter()
                    .map(|sol| sol.into_any().cast::<Base>().unwrap().clone())
                    .collect())
            } else if let Ok(bool_value) = expr.clone().into_any().cast::<Bool>() {
                let solutions = solver.eval_n(&bool_value.get().inner, n)?;
                let py_solutions = solutions
                    .into_iter()
                    .map(|sol| Bool::new(py, &sol))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(py_solutions
                    .into_iter()
                    .map(|sol| sol.into_any().cast::<Base>().unwrap().clone())
                    .collect())
            } else if let Ok(fp_value) = expr.clone().into_any().cast::<FP>() {
                let solutions = solver.eval_n(&fp_value.get().inner, n)?;
                let py_solutions = solutions
                    .into_iter()
                    .map(|sol| FP::new(py, &sol))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(py_solutions
                    .into_iter()
                    .map(|sol| sol.into_any().cast::<Base>().unwrap().clone())
                    .collect())
            } else if let Ok(string_value) = expr.clone().into_any().cast::<PyAstString>() {
                let solutions = solver.eval_n(&string_value.get().inner, n)?;
                let py_solutions = solutions
                    .into_iter()
                    .map(|sol| PyAstString::new(py, &sol))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(py_solutions
                    .into_iter()
                    .map(|sol| sol.into_any().cast::<Base>().unwrap().clone())
                    .collect())
            } else {
                Err(ClaripyError::TypeError("Unsupported type".to_string()))
            }
        })
    }

    #[pyo3(signature = (expr, n, extra_constraints = None, exact = None))]
    fn eval<'py>(
        &mut self,
        py: Python<'py>,
        expr: Bound<'py, Base>,
        n: u32,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Vec<Bound<'py, PyAny>>> {
        match self.eval_to_ast(py, expr, n, extra_constraints, exact) {
            Ok(results) => results
                .into_iter()
                .filter_map(|r| {
                    if let Ok(bv_value) = r.clone().into_any().cast::<BV>() {
                        if let AstOp::BVV(bv) = bv_value.get().inner.op() {
                            Some(bv.to_biguint().into_bound_py_any(py))
                        } else {
                            None
                        }
                    } else if let Ok(bool_value) = r.clone().into_any().cast::<Bool>() {
                        if let AstOp::BoolV(b) = bool_value.get().inner.op() {
                            Some(b.into_bound_py_any(py))
                        } else {
                            None
                        }
                    } else if let Ok(fp_value) = r.clone().into_any().cast::<FP>() {
                        if let AstOp::FPV(fp) = fp_value.get().inner.op() {
                            fp.to_f64().map(|f| f.into_bound_py_any(py))
                        } else {
                            None
                        }
                    } else if let Ok(string_value) = r.clone().into_any().cast::<PyAstString>() {
                        if let AstOp::StringV(s) = string_value.get().inner.op() {
                            Some(s.into_bound_py_any(py))
                        } else {
                            None
                        }
                    } else {
                        Some(Err(ClaripyError::UnsupportedOperation(
                            "eval: Unsupported type".to_string(),
                        )
                        .into()))
                    }
                })
                .collect::<Result<Vec<Bound<PyAny>>, pyo3::PyErr>>(),
            Err(e) => {
                if e.to_string().contains("UNSAT") {
                    Ok(vec![]) // Return empty list on UNSAT
                } else {
                    Err(e.into())
                }
            }
        }
    }

    #[pyo3(signature = (exprs, n, extra_constraints = None, exact = None))]
    fn batch_eval<'py>(
        &mut self,
        py: Python<'py>,
        exprs: Vec<Bound<'py, Base>>,
        n: u32,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Vec<Vec<Bound<'py, PyAny>>>> {
        exprs
            .into_iter()
            .map(|expr| self.eval(py, expr, n, extra_constraints.clone(), exact.clone()))
            .collect::<Result<Vec<Vec<Bound<PyAny>>>, pyo3::PyErr>>()
    }

    #[pyo3(signature = (expr, value, extra_constraints = None, exact = None))]
    fn solution(
        &mut self,
        expr: CoerceBase,
        value: Bound<PyAny>,
        extra_constraints: Option<Vec<Bound<Bool>>>,
        exact: Option<Bound<PyAny>>,
    ) -> Result<bool, ClaripyError> {
        let exact = Self::extract_exact(exact);
        let expr = expr.0;

        self.with_extra_constraints(
            extra_constraints.map(|v| v.into_iter().map(CoerceBool).collect()),
            exact,
            |solver| {
                if let Ok(bool_ast) = expr.cast::<Bool>() {
                    if let Ok(value) = value.extract::<CoerceBool>() {
                        Ok(solver.has_true(
                            &solver
                                .context()
                                .eq_(&bool_ast.get().inner, &value.0.get().inner)?,
                        )?)
                    } else {
                        let value_type = value.get_type().name()?.extract::<String>()?;
                        Err(ClaripyError::TypeError(format!(
                            "can't coerce a {value_type} to a bool ast"
                        )))
                    }
                } else if let Ok(bv_ast) = expr.cast::<BV>() {
                    if let Ok(value) = value.extract::<CoerceBV>() {
                        Ok(solver.has_true(&solver.context().eq_(
                            &bv_ast.get().inner,
                            &value.unpack_like(bv_ast.py(), bv_ast.get())?.get().inner,
                        )?)?)
                    } else {
                        let value_type = value.get_type().name()?.extract::<String>()?;
                        Err(ClaripyError::TypeError(format!(
                            "can't coerce a {value_type} to a bv ast"
                        )))
                    }
                } else if let Ok(fp_ast) = expr.cast::<FP>() {
                    if let Ok(value) = value.extract::<CoerceFP>() {
                        Ok(solver.has_true(&solver.context().eq_(
                            &fp_ast.get().inner,
                            &value.unpack_like(fp_ast.py(), fp_ast.get())?.get().inner,
                        )?)?)
                    } else {
                        let value_type = value.get_type().name()?.extract::<String>()?;
                        Err(ClaripyError::TypeError(format!(
                            "can't coerce a {value_type} to a float ast"
                        )))
                    }
                } else if let Ok(string_ast) = expr.cast::<PyAstString>() {
                    if let Ok(value) = value.extract::<CoerceString>() {
                        Ok(solver.has_true(
                            &solver
                                .context()
                                .eq_(&string_ast.get().inner, &value.0.get().inner)?,
                        )?)
                    } else {
                        let value_type = value.get_type().name()?.extract::<String>()?;
                        Err(ClaripyError::TypeError(format!(
                            "can't coerce a {value_type} to a string ast"
                        )))
                    }
                } else {
                    Err(ClaripyError::TypeError(
                        "expression must be a boolean, bitvector, float, or string".to_string(),
                    ))
                }
            },
        )
    }

    #[pyo3(signature = (expr, extra_constraints = None, exact = None))]
    fn is_true<'py>(
        &mut self,
        expr: Bound<'py, PyAny>,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
    ) -> Result<bool, ClaripyError> {
        let exact = Self::extract_exact(exact);

        // Check for Python primitive types first
        if let Ok(py_bool) = expr.extract::<bool>() {
            return Ok(py_bool);
        } else if let Ok(py_int) = expr.extract::<i64>() {
            return Ok(py_int != 0);
        }

        self.with_extra_constraints(extra_constraints, exact, |solver| {
            // Handle different expression types
            if let Ok(bool_expr) = expr.cast::<Bool>() {
                match bool_expr.get().inner.op() {
                    AstOp::BoolV(b) => Ok(*b),
                    _ => Ok(solver.is_true(&bool_expr.get().inner)?),
                }
            } else if let Ok(bv_expr) = expr.cast::<BV>() {
                // For bitvectors, check if it's concrete and non-zero
                if let AstOp::BVV(bv) = bv_expr.get().inner.op() {
                    Ok(!bv.is_zero())
                } else {
                    // For symbolic BVs, check if it can be non-zero
                    let zero = solver
                        .context()
                        .bvv(BitVec::from((0, bv_expr.get().inner.size())))?;
                    let eq_zero = solver.context().eq_(&bv_expr.get().inner, &zero)?;
                    let is_zero = solver.is_true(&eq_zero)?;
                    Ok(!is_zero)
                }
            } else {
                Err(ClaripyError::TypeError(
                    "is_true: expression must be a boolean, integer, or bitvector".to_string(),
                ))
            }
        })
    }

    #[pyo3(signature = (expr, extra_constraints = None, exact = None))]
    fn is_false<'py>(
        &mut self,
        expr: Bound<'py, PyAny>,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
    ) -> Result<bool, ClaripyError> {
        let exact = Self::extract_exact(exact);

        // Check for Python primitive types first
        if let Ok(py_bool) = expr.extract::<bool>() {
            return Ok(!py_bool);
        } else if let Ok(py_int) = expr.extract::<i64>() {
            return Ok(py_int == 0);
        }

        self.with_extra_constraints(extra_constraints, exact, |solver| {
            // Handle different expression types
            if let Ok(bool_expr) = expr.cast::<Bool>() {
                Ok(solver.is_false(&bool_expr.get().inner)?)
            } else if let Ok(bv_expr) = expr.cast::<BV>() {
                // For bitvectors, check if it's concrete and zero
                if let AstOp::BVV(bv) = bv_expr.get().inner.op() {
                    Ok(bv.is_zero())
                } else {
                    // For symbolic BVs, check if it must be zero
                    let zero = solver
                        .context()
                        .bvv(BitVec::from((0, bv_expr.get().inner.size())))?;
                    let eq_zero = solver.context().eq_(&bv_expr.get().inner, &zero)?;
                    Ok(solver.is_true(&eq_zero)?)
                }
            } else {
                Err(ClaripyError::TypeError(
                    "is_false: expression must be a boolean, integer, or bitvector".to_string(),
                ))
            }
        })
    }

    #[pyo3(signature = (expr, extra_constraints = None, exact = None))]
    fn has_true<'py>(
        &mut self,
        expr: Bound<Bool>,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
    ) -> Result<bool, ClaripyError> {
        let exact = Self::extract_exact(exact);
        self.with_extra_constraints(extra_constraints, exact, |solver| {
            Ok(solver.has_true(&expr.get().inner)?)
        })
    }

    #[pyo3(signature = (expr, extra_constraints = None, exact = None))]
    fn has_false<'py>(
        &mut self,
        expr: Bound<Bool>,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
    ) -> Result<bool, ClaripyError> {
        let exact = Self::extract_exact(exact);
        self.with_extra_constraints(extra_constraints, exact, |solver| {
            Ok(solver.has_false(&expr.get().inner)?)
        })
    }

    #[pyo3(signature = (expr, extra_constraints = None, exact = None, signed = false))]
    fn min<'py>(
        &mut self,
        expr: Bound<'py, BV>,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
        signed: bool,
    ) -> Result<BigInt, ClaripyError> {
        let exact = Self::extract_exact(exact);
        self.with_extra_constraints(extra_constraints, exact, |solver| {
            let result = if signed {
                solver.min_signed(&expr.get().inner)?
            } else {
                solver.min_unsigned(&expr.get().inner)?
            };

            if let AstOp::BVV(bv) = result.op() {
                Ok(BigInt::from(bv.to_biguint()))
            } else {
                Err(ClaripyError::TypeError(
                    "max: expression must be a bitvector".to_string(),
                ))
            }
        })
    }

    #[pyo3(signature = (expr, extra_constraints = None, exact = None, signed = false))]
    fn max<'py>(
        &mut self,
        expr: Bound<'py, BV>,
        extra_constraints: Option<Vec<CoerceBool<'py>>>,
        exact: Option<Bound<'py, PyAny>>,
        signed: bool,
    ) -> Result<BigInt, ClaripyError> {
        let exact = Self::extract_exact(exact);
        self.with_extra_constraints(extra_constraints, exact, |solver| {
            let result = if signed {
                solver.max_signed(&expr.get().inner)?
            } else {
                solver.max_unsigned(&expr.get().inner)?
            };

            if let AstOp::BVV(bv) = result.op() {
                Ok(BigInt::from(bv.to_biguint()))
            } else {
                Err(ClaripyError::TypeError(
                    "max: expression must be a bitvector".to_string(),
                ))
            }
        })
    }

    /// Add an explicit replacement mapping. The solver will replace occurrences
    /// of `old` with `new` in all future queries. Only supported for
    /// SolverReplacement.
    fn add_replacement<'py>(
        &mut self,
        old: Bound<'py, Base>,
        new: Bound<'py, Base>,
    ) -> Result<(), ClaripyError> {
        let old_dyn = Base::to_ast(old)?;
        let new_dyn = Base::to_ast(new)?;
        self.inner.add_replacement(old_dyn, new_dyn)?;
        Ok(())
    }

    /// Clear all replacements. Only supported for SolverReplacement.
    fn clear_replacements(&mut self) -> Result<(), ClaripyError> {
        self.inner.clear_replacements()?;
        Ok(())
    }

    fn __getstate__<'py>(&self, py: Python<'py>) -> Result<Bound<'py, PyTuple>, ClaripyError> {
        // Get the solver type
        let solver_type = match &self.inner {
            DynSolver::Concrete(..) => "Concrete",
            DynSolver::Z3(..) => "Z3",
            DynSolver::Z3Cacheless(..) => "Z3Cacheless",
            DynSolver::Vsa(..) => "Vsa",
            DynSolver::Hybrid(..) => "Hybrid",
            DynSolver::Replacement(..) => "Replacement",
            DynSolver::Composite(..) => "Composite",
        };

        // Get the constraints
        let constraints = self.constraints(py)?;

        // Return a tuple of (solver_type, constraints)
        Ok(PyTuple::new(
            py,
            vec![
                solver_type.into_bound_py_any(py)?,
                constraints.into_bound_py_any(py)?,
            ],
        )?)
    }

    fn __setstate__<'py>(
        &mut self,
        _py: Python<'py>,
        state: Bound<'py, PyTuple>,
    ) -> Result<(), ClaripyError> {
        // Extract solver type and constraints from the state tuple
        let solver_type: String = state.get_item(0)?.extract()?;
        let constraints: Vec<Bound<'py, Bool>> = state.get_item(1)?.extract()?;

        // Create a new solver based on the type
        self.inner = match solver_type.as_str() {
            "Concrete" => DynSolver::Concrete(ConcreteSolver::new(&GLOBAL_CONTEXT)),
            "Z3" => DynSolver::Z3(wrap_z3_cached(Z3Solver::new_with_timeout(
                &GLOBAL_CONTEXT,
                self.timeout,
            ))),
            "Z3Cacheless" => DynSolver::Z3Cacheless(wrap_solver(Z3Solver::new_with_timeout(
                &GLOBAL_CONTEXT,
                self.timeout,
            ))),
            "Vsa" => DynSolver::Vsa(wrap_solver(VSASolver::new(&GLOBAL_CONTEXT))),
            "Hybrid" => DynSolver::Hybrid(wrap_solver(HybridSolver::new(
                &GLOBAL_CONTEXT,
                wrap_solver(VSASolver::new(&GLOBAL_CONTEXT)),
                wrap_z3_cached(Z3Solver::new_with_timeout(&GLOBAL_CONTEXT, self.timeout)),
            ))),
            "Replacement" => DynSolver::Replacement(ReplacementSolver::new(wrap_z3_cached(
                Z3Solver::new_with_timeout(&GLOBAL_CONTEXT, self.timeout),
            ))),
            "Composite" => DynSolver::Composite(CompositeSolver::new(
                &GLOBAL_CONTEXT,
                wrap_z3_cached(Z3Solver::new_with_timeout(&GLOBAL_CONTEXT, self.timeout)),
            )),
            _ => {
                return Err(ClaripyError::TypeError(format!(
                    "Unknown solver type: {solver_type}"
                )));
            }
        };

        // Add the constraints to the solver
        for constraint in constraints {
            self.inner.add(&constraint.get().inner)?;
        }

        Ok(())
    }
}

#[pyclass(extends = PySolver, name = "SolverConcrete", module = "claripy.solver")]
pub struct PyConcreteSolver;

#[pymethods]
impl PyConcreteSolver {
    #[new]
    fn new() -> Result<PyClassInitializer<Self>, ClaripyError> {
        Ok(PyClassInitializer::from(PySolver {
            inner: DynSolver::Concrete(ConcreteSolver::new(&GLOBAL_CONTEXT)),
            timeout: None,
            unsat_core: false,
        })
        .add_subclass(Self {}))
    }
}

#[pyclass(extends = PySolver, name = "SolverZ3", module = "claripy.solver")]
pub struct PyZ3Solver;

#[pymethods]
impl PyZ3Solver {
    #[new]
    fn new() -> Result<PyClassInitializer<Self>, ClaripyError> {
        Ok(PyClassInitializer::from(PySolver {
            inner: DynSolver::Z3(wrap_z3_cached(Z3Solver::new_with_options(
                &GLOBAL_CONTEXT,
                None,
                false,
            ))),
            timeout: None,
            unsat_core: false,
        })
        .add_subclass(Self {}))
    }
}

#[pyclass(extends = PySolver, name = "SolverCacheless", module = "claripy.solver")]
pub struct PyCachelessSolver;

#[pymethods]
impl PyCachelessSolver {
    #[new]
    #[pyo3(signature = (timeout = None, track = false))]
    fn new(timeout: Option<u32>, track: bool) -> Result<PyClassInitializer<Self>, ClaripyError> {
        Ok(PyClassInitializer::from(PySolver {
            inner: DynSolver::Z3Cacheless(wrap_solver(Z3Solver::new_with_options(
                &GLOBAL_CONTEXT,
                timeout,
                track,
            ))),
            timeout,
            unsat_core: track,
        })
        .add_subclass(Self {}))
    }
}

#[pyclass(extends = PySolver, name = "SolverVSA", module = "claripy.solver")]
pub struct PyVSASolver;

#[pymethods]
impl PyVSASolver {
    #[new]
    fn new() -> Result<PyClassInitializer<Self>, ClaripyError> {
        Ok(PyClassInitializer::from(PySolver {
            inner: DynSolver::Vsa(wrap_solver(VSASolver::new(&GLOBAL_CONTEXT))),
            timeout: None,
            unsat_core: false,
        })
        .add_subclass(Self {}))
    }
}

#[pyclass(extends = PySolver, name = "SolverHybrid", module = "claripy.solver")]
pub struct PyHybridSolver;

#[pymethods]
impl PyHybridSolver {
    #[new]
    #[pyo3(signature = (timeout = None, track = false))]
    fn new(timeout: Option<u32>, track: bool) -> Result<PyClassInitializer<Self>, ClaripyError> {
        Ok(PyClassInitializer::from(PySolver {
            inner: DynSolver::Hybrid(wrap_solver(HybridSolver::new(
                &GLOBAL_CONTEXT,
                wrap_solver(VSASolver::new(&GLOBAL_CONTEXT)),
                wrap_z3_cached(Z3Solver::new_with_options(&GLOBAL_CONTEXT, timeout, track)),
            ))),
            timeout,
            unsat_core: track,
        })
        .add_subclass(Self {}))
    }
}

#[pyclass(extends = PySolver, name = "SolverReplacement", module = "claripy.solver")]
pub struct PyReplacementSolver;

#[pymethods]
impl PyReplacementSolver {
    #[new]
    fn new() -> Result<PyClassInitializer<Self>, ClaripyError> {
        Ok(PyClassInitializer::from(PySolver {
            inner: DynSolver::Replacement(ReplacementSolver::new(wrap_z3_cached(
                Z3Solver::new_with_options(&GLOBAL_CONTEXT, None, false),
            ))),
            timeout: None,
            unsat_core: false,
        })
        .add_subclass(Self {}))
    }
}

#[pyclass(extends = PySolver, name = "SolverComposite", module = "claripy.solver")]
pub struct PyCompositeSolver;

#[pymethods]
impl PyCompositeSolver {
    #[new]
    #[pyo3(signature = (timeout = None, track = false))]
    fn new(timeout: Option<u32>, track: bool) -> Result<PyClassInitializer<Self>, ClaripyError> {
        Ok(PyClassInitializer::from(PySolver {
            inner: DynSolver::Composite(CompositeSolver::new(
                &GLOBAL_CONTEXT,
                wrap_z3_cached(Z3Solver::new_with_options(&GLOBAL_CONTEXT, timeout, track)),
            )),
            timeout,
            unsat_core: track,
        })
        .add_subclass(Self {}))
    }
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PySolver>()?;
    m.add_class::<PyConcreteSolver>()?;
    m.add_class::<PyZ3Solver>()?;
    m.add_class::<PyCachelessSolver>()?;
    m.add_class::<PyVSASolver>()?;
    m.add_class::<PyHybridSolver>()?;
    m.add_class::<PyReplacementSolver>()?;
    m.add_class::<PyCompositeSolver>()?;

    Ok(())
}
