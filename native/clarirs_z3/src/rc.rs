use std::ffi::CStr;
use std::ops::{Deref, DerefMut};

use crate::{Z3_CONTEXT, check_z3_error, require};
use clarirs_core::error::ClarirsError;
use z3_sys::*;

#[repr(transparent)]
pub struct RcAst(Z3_ast);

impl RcAst {
    /// Returns the `DeclKind` of this AST node (assumes it is an application).
    pub fn decl_kind(&self) -> DeclKind {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let app = Z3_to_app(ctx, self.0).expect("decl_kind: not an application");
            let decl = Z3_get_app_decl(ctx, app).expect("decl_kind: no declaration");
            Z3_get_decl_kind(ctx, decl)
        })
    }

    /// Returns the number of arguments (assumes it is an application).
    pub fn num_args(&self) -> u32 {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let app = Z3_to_app(ctx, self.0).expect("num_args: not an application");
            Z3_get_app_num_args(ctx, app)
        })
    }

    /// Returns the argument at `index` as a new `RcAst`, or `None` if out of
    /// bounds or the node is not an application.
    pub fn arg(&self, index: u32) -> Option<RcAst> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let ast_kind = Z3_get_ast_kind(ctx, self.0);
            if ast_kind != AstKind::App {
                return None;
            }
            let app = Z3_to_app(ctx, self.0)?;
            let num_args = Z3_get_app_num_args(ctx, app);
            if index >= num_args {
                return None;
            }
            RcAst::try_from(Z3_get_app_arg(ctx, app, index)).ok()
        })
    }

    /// Returns the symbol name if this is an uninterpreted constant, or `None`
    /// otherwise.
    pub fn symbol_name(&self) -> Option<String> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            if Z3_get_ast_kind(ctx, self.0) != AstKind::App {
                return None;
            }
            let app = Z3_to_app(ctx, self.0)?;
            let decl = Z3_get_app_decl(ctx, app)?;
            if Z3_get_decl_kind(ctx, decl) != DeclKind::Uninterpreted {
                return None;
            }
            let sym = Z3_get_decl_name(ctx, decl)?;
            let name = Z3_get_symbol_string(ctx, sym);
            CStr::from_ptr(name).to_str().ok().map(|s| s.to_owned())
        })
    }

    /// Creates an uninterpreted constant with the given name and sort.
    #[cfg(test)]
    pub fn mk_symbol(name: &str, sort: Z3_sort) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let c_name = std::ffi::CString::new(name).unwrap();
            let sym = Z3_mk_string_symbol(ctx, c_name.as_ptr()).unwrap();
            let decl = Z3_mk_func_decl(ctx, sym, 0, std::ptr::null(), sort).unwrap();
            RcAst::try_from(Z3_mk_app(ctx, decl, 0, std::ptr::null())).unwrap()
        })
    }

    /// Creates a Z3 boolean symbol.
    #[cfg(test)]
    pub fn mk_bool(name: &str) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe { Self::mk_symbol(name, Z3_mk_bool_sort(ctx).unwrap()) })
    }

    /// Creates a Z3 bitvector symbol.
    #[cfg(test)]
    pub fn mk_bv(name: &str, width: u32) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe { Self::mk_symbol(name, Z3_mk_bv_sort(ctx, width).unwrap()) })
    }

    /// Creates a Z3 floating-point symbol. Z3's sbits includes the implicit
    /// leading bit, so `mantissa + 1` is passed to `mk_fpa_sort`.
    #[cfg(test)]
    pub fn mk_fp(name: &str, sort: clarirs_core::prelude::FSort) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe {
            Self::mk_symbol(
                name,
                Z3_mk_fpa_sort(ctx, sort.exponent, sort.mantissa + 1).unwrap(),
            )
        })
    }

    /// Creates a Z3 bitvector numeral from a decimal string value and width.
    #[cfg(test)]
    pub fn mk_bv_val(value: &str, width: u32) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let sort = Z3_mk_bv_sort(ctx, width).unwrap();
            let c_val = std::ffi::CString::new(value).unwrap();
            RcAst::try_from(Z3_mk_numeral(ctx, c_val.as_ptr(), sort)).unwrap()
        })
    }

    /// Creates a Z3 floating-point numeral from an `f32`.
    #[cfg(test)]
    pub fn mk_fp_val_f32(value: f32) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let sort = Z3_mk_fpa_sort(ctx, 8, 24).unwrap(); // f32: 8 exponent, 24 sbits (23 mantissa + 1)
            RcAst::try_from(Z3_mk_fpa_numeral_float(ctx, value, sort)).unwrap()
        })
    }

    /// Creates a Z3 floating-point numeral from an `f64`.
    #[cfg(test)]
    pub fn mk_fp_val_f64(value: f64) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let sort = Z3_mk_fpa_sort(ctx, 11, 53).unwrap(); // f64: 11 exponent, 53 sbits (52 mantissa + 1)
            RcAst::try_from(Z3_mk_fpa_numeral_double(ctx, value, sort)).unwrap()
        })
    }

    /// Creates a Z3 rounding mode AST.
    #[cfg(test)]
    pub fn mk_fprm(rm: clarirs_core::prelude::FPRM) -> RcAst {
        use clarirs_core::prelude::FPRM;
        Z3_CONTEXT.with(|&ctx| unsafe {
            RcAst::try_from(match rm {
                FPRM::NearestTiesToEven => Z3_mk_fpa_rne(ctx),
                FPRM::TowardPositive => Z3_mk_fpa_rtp(ctx),
                FPRM::TowardNegative => Z3_mk_fpa_rtn(ctx),
                FPRM::TowardZero => Z3_mk_fpa_rtz(ctx),
                FPRM::NearestTiesToAway => Z3_mk_fpa_rna(ctx),
            })
            .unwrap()
        })
    }

    /// Creates a Z3 string (sequence of chars) symbol.
    #[cfg(test)]
    pub fn mk_string(name: &str) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe {
            Self::mk_symbol(
                name,
                Z3_mk_seq_sort(ctx, Z3_mk_char_sort(ctx).unwrap()).unwrap(),
            )
        })
    }

    /// Creates a Z3 string constant (literal value).
    #[cfg(test)]
    pub fn mk_string_val(value: &str) -> RcAst {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let c_val = std::ffi::CString::new(value).unwrap();
            RcAst::try_from(Z3_mk_string(ctx, c_val.as_ptr())).unwrap()
        })
    }
}

impl Clone for RcAst {
    fn clone(&self) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_inc_ref(ctx, self.0) });
        RcAst(self.0)
    }
}

impl From<&RcAst> for RcAst {
    fn from(val: &RcAst) -> Self {
        val.clone()
    }
}

impl Drop for RcAst {
    fn drop(&mut self) {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_dec_ref(ctx, self.0) });
    }
}

impl TryFrom<Z3_ast> for RcAst {
    type Error = ClarirsError;

    fn try_from(ast: Z3_ast) -> Result<Self, Self::Error> {
        check_z3_error()?;
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_inc_ref(ctx, ast) });
        Ok(RcAst(ast))
    }
}

impl TryFrom<Option<Z3_ast>> for RcAst {
    type Error = ClarirsError;

    /// Z3 pointer constructors return `None` on failure. The error code is read
    /// first (via `check_z3_error`) so a Z3-reported reason wins over the generic
    /// null-pointer message from [`require`].
    fn try_from(ast: Option<Z3_ast>) -> Result<Self, Self::Error> {
        check_z3_error()?;
        let ast = require(ast)?;
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_inc_ref(ctx, ast) });
        Ok(RcAst(ast))
    }
}

impl From<RcAst> for Z3_ast {
    fn from(ast: RcAst) -> Self {
        ast.0
    }
}

impl Deref for RcAst {
    type Target = Z3_ast;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RcAst {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(transparent)]
pub struct RcParamSet(Z3_params);

impl RcParamSet {
    pub fn new() -> Result<Self, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let params = RcParamSet(require(Z3_mk_params(ctx))?);
            Z3_params_inc_ref(ctx, params.0);
            check_z3_error()?;
            Ok(params)
        })
    }

    pub fn set_bool(&mut self, key: &str, value: bool) -> Result<(), ClarirsError> {
        let key_cstr = std::ffi::CString::new(key).map_err(|_| {
            ClarirsError::BackendError("Z3", "Failed to convert key to CString".into())
        })?;
        Z3_CONTEXT.with(|&ctx| unsafe {
            let symbol = require(Z3_mk_string_symbol(ctx, key_cstr.as_ptr()))?;
            Z3_params_set_bool(ctx, self.0, symbol, value);
            Ok::<(), ClarirsError>(())
        })?;
        check_z3_error()
    }

    pub fn set_u32(&mut self, key: &str, value: u32) -> Result<(), ClarirsError> {
        let key_cstr = std::ffi::CString::new(key).map_err(|_| {
            ClarirsError::BackendError("Z3", "Failed to convert key to CString".into())
        })?;
        Z3_CONTEXT.with(|&ctx| unsafe {
            let symbol = require(Z3_mk_string_symbol(ctx, key_cstr.as_ptr()))?;
            Z3_params_set_uint(ctx, self.0, symbol, value);
            Ok::<(), ClarirsError>(())
        })?;
        check_z3_error()
    }
}

impl Clone for RcParamSet {
    fn clone(&self) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_params_inc_ref(ctx, self.0) });
        RcParamSet(self.0)
    }
}

impl Deref for RcParamSet {
    type Target = Z3_params;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for RcParamSet {
    fn drop(&mut self) {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_params_dec_ref(ctx, self.0) });
    }
}

#[repr(transparent)]
pub struct RcSolver(Z3_solver);

impl RcSolver {
    pub fn new() -> Result<Self, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let solver = Z3_mk_solver(ctx);
            check_z3_error()?;
            Ok(RcSolver::from(require(solver)?))
        })
    }

    pub fn set_params(&mut self, param: RcParamSet) -> Result<(), ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_solver_set_params(ctx, self.0, *param) });
        check_z3_error()
    }

    pub fn assert(&mut self, ast: &RcAst) -> Result<(), ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_solver_assert(ctx, self.0, **ast) });
        check_z3_error()
    }

    pub fn assert_and_track(&mut self, ast: &RcAst, track: &RcAst) -> Result<(), ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_solver_assert_and_track(ctx, self.0, **ast, **track) });
        check_z3_error()
    }

    pub fn check(&mut self) -> Result<Z3_lbool, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let result = Z3_solver_check(ctx, self.0);
            check_z3_error()?;
            Ok(result)
        })
    }

    pub fn check_assumptions(&mut self, assumptions: &[RcAst]) -> Result<Z3_lbool, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let ast_array: Vec<Z3_ast> = assumptions.iter().map(|a| **a).collect();
            let result = Z3_solver_check_assumptions(
                ctx,
                self.0,
                ast_array.len() as u32,
                ast_array.as_ptr(),
            );
            check_z3_error()?;
            Ok(result)
        })
    }

    pub fn get_unsat_core(&mut self) -> Result<RcAstVector, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let core = Z3_solver_get_unsat_core(ctx, self.0);
            check_z3_error()?;
            Ok(RcAstVector::from(require(core)?))
        })
    }

    pub fn model(&mut self) -> Result<RcModel, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let model = Z3_solver_get_model(ctx, self.0);
            check_z3_error()?;
            Ok(RcModel::from(require(model)?))
        })
    }
}

impl Clone for RcSolver {
    fn clone(&self) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_solver_inc_ref(ctx, self.0) });
        RcSolver(self.0)
    }
}

impl Drop for RcSolver {
    fn drop(&mut self) {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_solver_dec_ref(ctx, self.0) });
    }
}

impl From<Z3_solver> for RcSolver {
    fn from(solver: Z3_solver) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_solver_inc_ref(ctx, solver) });
        RcSolver(solver)
    }
}

impl From<RcSolver> for Z3_solver {
    fn from(solver: RcSolver) -> Self {
        solver.0
    }
}

impl Deref for RcSolver {
    type Target = Z3_solver;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RcSolver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(transparent)]
pub struct RcOptimize(Z3_optimize);

impl RcOptimize {
    pub fn new() -> Result<Self, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let optimize = Z3_mk_optimize(ctx);
            check_z3_error()?;
            Ok(RcOptimize::from(require(optimize)?))
        })
    }

    pub fn assert(&mut self, ast: &RcAst) -> Result<(), ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_optimize_assert(ctx, self.0, **ast) });
        check_z3_error()
    }

    pub fn assert_soft(&mut self, ast: &RcAst, weight: u32) -> Result<(), ClarirsError> {
        let weight_string = std::ffi::CString::new(weight.to_string()).map_err(|_| {
            ClarirsError::BackendError("Z3", "Failed to convert weight to CString".into())
        })?;
        Z3_CONTEXT.with(|&ctx| unsafe {
            Z3_optimize_assert_soft(ctx, self.0, **ast, weight_string.as_ptr(), None);
        });
        check_z3_error()
    }

    pub fn minimize(&mut self, ast: &RcAst) -> Result<(), ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_optimize_minimize(ctx, self.0, **ast) });
        check_z3_error()
    }

    pub fn maximize(&mut self, ast: &RcAst) -> Result<(), ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_optimize_maximize(ctx, self.0, **ast) });
        check_z3_error()
    }

    pub fn check(&mut self) -> Result<Z3_lbool, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let result = Z3_optimize_check(ctx, self.0, 0, std::ptr::null());
            check_z3_error()?;
            Ok(result)
        })
    }

    pub fn get_model(&mut self) -> Result<RcModel, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let model = Z3_optimize_get_model(ctx, self.0);
            check_z3_error()?;
            Ok(RcModel::from(require(model)?))
        })
    }
}

impl Clone for RcOptimize {
    fn clone(&self) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_optimize_inc_ref(ctx, self.0) });
        RcOptimize(self.0)
    }
}

impl Drop for RcOptimize {
    fn drop(&mut self) {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_optimize_dec_ref(ctx, self.0) });
    }
}

impl From<Z3_optimize> for RcOptimize {
    fn from(optimize: Z3_optimize) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_optimize_inc_ref(ctx, optimize) });
        RcOptimize(optimize)
    }
}

impl From<RcOptimize> for Z3_optimize {
    fn from(optimize: RcOptimize) -> Self {
        optimize.0
    }
}

impl Deref for RcOptimize {
    type Target = Z3_optimize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RcOptimize {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(transparent)]
pub struct RcModel(Z3_model);

impl RcModel {
    pub fn eval(&self, ast: &RcAst) -> Result<RcAst, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let mut eval_result = std::mem::MaybeUninit::<Z3_ast>::uninit();
            let eval_ret = Z3_model_eval(ctx, self.0, **ast, true, eval_result.as_mut_ptr());
            check_z3_error()?;
            if !eval_ret {
                return Err(ClarirsError::BackendError(
                    "Z3",
                    "Model evaluation failed".into(),
                ));
            }
            // `model_eval` returned true, so it wrote a valid (non-null) AST.
            RcAst::try_from(eval_result.assume_init())
        })
    }
}

impl Clone for RcModel {
    fn clone(&self) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_model_inc_ref(ctx, self.0) });
        RcModel(self.0)
    }
}

impl Drop for RcModel {
    fn drop(&mut self) {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_model_dec_ref(ctx, self.0) });
    }
}

impl From<Z3_model> for RcModel {
    fn from(model: Z3_model) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_model_inc_ref(ctx, model) });
        RcModel(model)
    }
}

impl From<RcModel> for Z3_model {
    fn from(model: RcModel) -> Self {
        model.0
    }
}

impl Deref for RcModel {
    type Target = Z3_model;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RcModel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(transparent)]
pub struct RcAstVector(Z3_ast_vector);

impl RcAstVector {
    pub fn size(&self) -> u32 {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_ast_vector_size(ctx, self.0) })
    }

    pub fn get(&self, i: u32) -> Result<RcAst, ClarirsError> {
        Z3_CONTEXT.with(|&ctx| unsafe {
            let ast = Z3_ast_vector_get(ctx, self.0, i);
            check_z3_error()?;
            RcAst::try_from(ast)
        })
    }
}

impl Clone for RcAstVector {
    fn clone(&self) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_ast_vector_inc_ref(ctx, self.0) });
        RcAstVector(self.0)
    }
}

impl Drop for RcAstVector {
    fn drop(&mut self) {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_ast_vector_dec_ref(ctx, self.0) });
    }
}

impl From<Z3_ast_vector> for RcAstVector {
    fn from(ast_vector: Z3_ast_vector) -> Self {
        Z3_CONTEXT.with(|&ctx| unsafe { Z3_ast_vector_inc_ref(ctx, ast_vector) });
        RcAstVector(ast_vector)
    }
}

impl From<RcAstVector> for Z3_ast_vector {
    fn from(ast_vector: RcAstVector) -> Self {
        ast_vector.0
    }
}

impl Deref for RcAstVector {
    type Target = Z3_ast_vector;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RcAstVector {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
