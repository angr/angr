//! Indirect-jump resolvers in Rust (`angr.rustylib.ijr`).
//!
//! A [`chain::ResolverChain`] mirrors CFGBase's two resolver lists (timeless, deferred): the same Python resolver
//! instances in the same order, each mapped to an entry that is either a Rust [`Resolver`] (with the Python
//! instance as its twin) or the Python instance itself. Dispatch follows the Python loops exactly: first success
//! wins, a Rust resolver may decline any call ([`Decision::Python`]) and the twin then handles it.

pub mod chain;
pub mod cx;
pub mod effects;

use pyo3::prelude::*;

pub use cx::{IrSpec, ResolveCx};
pub use effects::Effects;

/// When a jump is being resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// At scan time (`_resolve_indirect_jump_timelessly`).
    Timeless,
    /// In `_process_one_indirect_jump`, once the job queue is empty.
    Deferred { func_graph_complete: bool },
}

/// The jump a resolver is asked about.
#[derive(Clone, Debug)]
pub struct JumpSite {
    pub addr: u64,
    pub func_addr: u64,
    /// VEX `IRJumpKind`.
    pub jumpkind: u32,
    pub phase: Phase,
    /// How to lift the block the Python resolvers receive.
    pub block: IrSpec,
}

/// A resolver answer, or a decline: run the Python twin for this call instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision<T> {
    Done(T),
    Python(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Targets in the resolver's return order.
    Resolved(Vec<u64>),
    Unresolved,
    /// Unresolved for now; revisit in the final pass (the JumpTable `deferred` flag).
    Deferred,
}

pub trait Resolver {
    /// The Python class name ("MemoryLoadResolver", ...); used for flags, stats and shadow logs.
    fn kind(&self) -> &'static str;
    fn timeless(&self) -> bool;
    /// `IndirectJumpResolver.filter`; must have no side effects.
    fn filter(&mut self, py: Python<'_>, cx: &mut ResolveCx, j: &JumpSite) -> PyResult<Decision<bool>>;
    /// `IndirectJumpResolver.resolve`. Side effects on the CFG go into `fx`; they are applied only on `Done`.
    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        j: &JumpSite,
        fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>>;
}

/// The Rust implementation of a resolver kind, if there is one. `twin` is the Python instance (its configuration
/// was already checked by `angr.analyses.cfg.indirect_jump_resolvers.rust`).
pub fn make_resolver(_kind: &str, _twin: &Bound<'_, PyAny>) -> PyResult<Option<Box<dyn Resolver>>> {
    Ok(None)
}

pub fn ijr(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<chain::ResolverChain>()?;
    Ok(())
}
