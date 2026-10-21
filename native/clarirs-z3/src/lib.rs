mod astext;
mod rc;
mod solver;

pub use solver::Z3Solver;

use std::cell::Cell;

use clarirs_core::error::ClarirsError;
use rc::WeakAstCache;
use z3_sys::*;

thread_local! {
    /// This thread's Z3 context. It has no destructor, so it stays readable
    /// while other thread-locals are torn down; [`Z3_CONTEXT_OWNER`] deletes it.
    static Z3_CONTEXT: Z3_context = unsafe {
        let cfg = Z3_mk_config().expect("Z3_mk_config returned null");
        let ctx = Z3_mk_context_rc(cfg).expect("Z3_mk_context_rc returned null");
        Z3_set_error_handler(ctx, None);
        Z3_del_config(cfg);
        Z3_CONTEXT_OWNER.with(|owner| owner.0.set(Some(ctx)));
        ctx
    };

    /// Deletes [`Z3_CONTEXT`] when the thread exits. Registered by the
    /// context's initializer, so thread-locals first touched before it
    /// (which may still hold Z3 objects) are destroyed after it.
    static Z3_CONTEXT_OWNER: ContextOwner = const { ContextOwner(Cell::new(None)) };

    /// Set once [`Z3_CONTEXT_OWNER`] has deleted the context; see [`release`].
    static Z3_CONTEXT_DELETED: Cell<bool> = const { Cell::new(false) };

    static Z3_AST_CACHE: WeakAstCache = WeakAstCache::default();
}

struct ContextOwner(Cell<Option<Z3_context>>);

impl Drop for ContextOwner {
    fn drop(&mut self) {
        if let Some(ctx) = self.0.take() {
            Z3_CONTEXT_DELETED.with(|deleted| deleted.set(true));
            // Frees every object still allocated in the context, whatever its
            // reference count.
            unsafe { Z3_del_context(ctx) };
            #[cfg(test)]
            CONTEXTS_DELETED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
static CONTEXTS_DELETED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RELEASES_SKIPPED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Drops one reference to a Z3 object through `dec_ref`, unless this thread's
/// context has already been deleted (and the object with it). Handles reach
/// here after the context during thread exit when they live in a thread-local
/// destroyed after [`Z3_CONTEXT_OWNER`], such as the solver cache.
pub(crate) fn release(dec_ref: impl FnOnce(Z3_context)) {
    if !Z3_CONTEXT_DELETED.with(Cell::get) {
        Z3_CONTEXT.with(|&ctx| dec_ref(ctx));
    } else {
        #[cfg(test)]
        RELEASES_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Convert a nullable `z3-sys` result into a [`ClarirsError`].
///
/// Pointer-returning Z3 functions yield `None` (rather than a null pointer) when
/// Z3 hits an internal error or an invalid request. Results that become an
/// [`RcAst`](rc::RcAst) are checked via `RcAst::try_from(Option<_>)`; this helper
/// covers the few intermediate handles (sorts, symbols, solvers, …) that are not. The
/// precise cause, when Z3 set one, is surfaced by [`check_z3_error`].
pub(crate) fn require<T>(value: Option<T>) -> Result<T, ClarirsError> {
    value.ok_or_else(|| ClarirsError::BackendError("Z3", "Z3 returned a null pointer".into()))
}

pub(crate) fn check_z3_error() -> Result<(), clarirs_core::error::ClarirsError> {
    Z3_CONTEXT.with(|z3_ctx| unsafe {
        let error_code = Z3_get_error_code(*z3_ctx);
        if error_code != ErrorCode::Ok {
            let err_msg = Z3_get_error_msg(*z3_ctx, error_code);
            let c_str = std::ffi::CStr::from_ptr(err_msg);
            let msg = c_str.to_string_lossy().into_owned();
            Err(clarirs_core::error::ClarirsError::BackendError("Z3", msg))
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::sync::atomic::Ordering;

    use clarirs_core::prelude::*;

    use super::{CONTEXTS_DELETED, RELEASES_SKIPPED};
    use crate::{Z3Solver, astext::AstExtZ3, rc::RcAst};

    /// Builds a term, solves with it (filling the solver cache) and returns
    /// the converted term, all on this thread's context.
    fn use_z3() -> RcAst {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32).unwrap();
        let constraint = ctx
            .ugt(&x, ctx.bvv(BitVec::from((7, 32))).unwrap())
            .unwrap();
        let mut solver = Z3Solver::new(&ctx);
        solver.add(&constraint).unwrap();
        assert!(solver.satisfiable().unwrap());
        constraint.to_z3().unwrap()
    }

    #[test]
    fn context_deleted_when_thread_exits() {
        const THREADS: usize = 16;
        let before = CONTEXTS_DELETED.load(Ordering::Relaxed);
        for _ in 0..THREADS {
            std::thread::spawn(|| drop(use_z3())).join().unwrap();
        }
        // Other tests' threads only add to the count.
        assert!(CONTEXTS_DELETED.load(Ordering::Relaxed) - before >= THREADS);
    }

    thread_local! {
        static HELD: RefCell<Option<RcAst>> = const { RefCell::new(None) };
    }

    #[test]
    fn handles_outliving_the_context_skip_release() {
        let before = RELEASES_SKIPPED.load(Ordering::Relaxed);
        std::thread::spawn(|| {
            // Registered before the context, so destroyed after it: the
            // handle's release must not touch the deleted context. This
            // relies on thread-locals being destroyed in reverse order of
            // registration, which Rust does not promise but which holds on
            // Linux, macOS and Windows.
            HELD.with(|held| held.borrow_mut().take());
            let ast = use_z3();
            HELD.with(|held| *held.borrow_mut() = Some(ast));
        })
        .join()
        .unwrap();
        assert!(RELEASES_SKIPPED.load(Ordering::Relaxed) > before);
    }
}
