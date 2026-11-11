//! Indirect-jump resolvers in Rust (`angr.rustylib.ijr`).
//!
//! A [`chain::ResolverChain`] mirrors CFGBase's two resolver lists (timeless, deferred): the same Python resolver
//! instances in the same order, each mapped to an entry that is either a Rust [`Resolver`] (with the Python
//! instance as its twin) or the Python instance itself. Dispatch follows the Python loops exactly: first success
//! wins, a Rust resolver may decline any call ([`Decision::Python`]) and the twin then handles it.

pub mod amd64_got;
pub mod arm;
pub mod blade;
pub mod chain;
pub mod const_resolver;
pub mod cvm;
pub mod cx;
pub mod effects;
pub mod fcp;
pub mod jumptable;
pub mod memload;
pub mod mips;
pub mod si;
pub mod symex;
pub mod syscall;
pub mod u256;
pub mod x86;

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

/// A difference the shadow mode found beyond the answers: `(what, rust, python)`.
pub type ShadowDiff = (&'static str, String, String);

pub trait Resolver {
    /// The Python class name ("MemoryLoadResolver", ...); used for flags, stats and shadow logs.
    fn kind(&self) -> &'static str;
    fn timeless(&self) -> bool;
    /// `IndirectJumpResolver.filter`; must have no side effects. `cfg` is the CFGFast object.
    fn filter(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>>;
    /// `IndirectJumpResolver.resolve`. Side effects on the CFG go into `fx`; they are applied only on `Done`.
    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>>;
    /// Shadow mode, after the twin answered the same call: compare internal results (caches, slices) too.
    fn shadow_diffs(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        _j: &JumpSite,
    ) -> PyResult<Vec<ShadowDiff>> {
        Ok(Vec::new())
    }
    /// Around a call handed to the twin (a decline): sync state the twin reads or writes (caches in the KB).
    fn before_twin(
        &mut self,
        _py: Python<'_>,
        _cfg: &Bound<'_, PyAny>,
        _j: &JumpSite,
    ) -> PyResult<()> {
        Ok(())
    }
    fn after_twin(
        &mut self,
        _py: Python<'_>,
        _cfg: &Bound<'_, PyAny>,
        _j: &JumpSite,
    ) -> PyResult<()> {
        Ok(())
    }
    /// When the chain is released: publish Rust-owned state the Python resolver would have left behind.
    fn finish(&mut self, _py: Python<'_>, _cfg: &Bound<'_, PyAny>) -> PyResult<()> {
        Ok(())
    }
    /// Shadow mode: a JSON description of the last answer; when Some, every shadowed call is recorded (classified
    /// offline) instead of comparing answers.
    fn shadow_detail(&self) -> Option<String> {
        None
    }
}

/// The Rust implementation of a resolver kind, if there is one. `twin` is the Python instance (its configuration
/// was already checked by `angr.analyses.cfg.indirect_jump_resolvers.rust`); `ctx` is the chain's context dict.
pub fn make_resolver(
    kind: &str,
    twin: &Bound<'_, PyAny>,
    ctx: &Bound<'_, pyo3::types::PyDict>,
) -> PyResult<Option<Box<dyn Resolver>>> {
    let py = twin.py();
    Ok(match kind {
        "MemoryLoadResolver" => Some(Box::new(memload::MemoryLoadResolver)),
        "AMD64ElfGotResolver" => Some(Box::new(amd64_got::Amd64ElfGotResolver)),
        "MipsElfFastResolver" => Some(Box::new(mips::MipsElfFastResolver {
            is_mips: twin
                .getattr(pyo3::intern!(py, "project"))?
                .getattr(pyo3::intern!(py, "arch"))?
                .getattr(pyo3::intern!(py, "name"))?
                .extract::<String>()?
                .starts_with("MIPS"),
        })),
        "MipsElfGotResolver" => Some(Box::new(mips::MipsElfGotResolver)),
        "ArmElfFastResolver" => Some(Box::new(arm::ArmElfFastResolver {
            is_arm: twin
                .getattr(pyo3::intern!(py, "project"))?
                .getattr(pyo3::intern!(py, "arch"))?
                .getattr(pyo3::intern!(py, "name"))?
                .extract::<String>()?
                .starts_with("ARM"),
            occupy: true,
        })),
        "X86PeIatResolver" => Some(Box::new(x86::X86PeIatResolver)),
        "AMD64PeIatResolver" => Some(Box::new(x86::Amd64PeIatResolver {
            windows: ctx
                .get_item("simos_windows")?
                .is_some_and(|v| v.is_truthy().unwrap_or(false)),
        })),
        "X86ElfPicPltResolver" => Some(Box::new(x86::X86ElfPicPltResolver {
            is_x86: twin
                .getattr(pyo3::intern!(py, "project"))?
                .getattr(pyo3::intern!(py, "arch"))?
                .getattr(pyo3::intern!(py, "name"))?
                .extract::<String>()?
                == "X86",
        })),
        "SyscallResolver" => {
            let fast = twin.call_method0(pyo3::intern!(py, "rust_fast_path"))?;
            Some(Box::new(syscall::SyscallResolver {
                os_resolves_syscalls: twin
                    .getattr(pyo3::intern!(py, "_os_resolves_syscalls"))?
                    .is_truthy()?,
                fast: if fast.is_none() {
                    None
                } else {
                    Some(syscall::FastPath::from_py(&fast)?)
                },
            }))
        }
        "ConstantResolver" => {
            let max_func_nodes: usize = twin
                .getattr(pyo3::intern!(py, "max_func_nodes"))?
                .extract()?;
            let shadow_blade = ctx
                .get_item("shadow_blade")?
                .filter(|b| !b.is_none())
                .map(Bound::unbind);
            let publish = ctx
                .get_item("publish_fcp")?
                .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("publish_fcp"))?;
            Some(Box::new(const_resolver::ConstantResolver::new(
                max_func_nodes,
                shadow_blade,
                publish.unbind(),
            )))
        }
        "JumpTableResolver" => {
            let project = twin.getattr(pyo3::intern!(py, "project"))?;
            let arch = project.getattr(pyo3::intern!(py, "arch"))?;
            let arch_name: String = arch.getattr(pyo3::intern!(py, "name"))?.extract()?;
            let alignment: u64 = arch
                .getattr(pyo3::intern!(py, "instruction_alignment"))?
                .extract()
                .unwrap_or(1);
            let arches: Vec<String> = match ctx.get_item("jt_arches")? {
                Some(v) => v.extract()?,
                None => Vec::new(),
            };
            let skip = match ctx.get_item("jt_skip")? {
                Some(v) => v.is_truthy()?,
                None => false,
            };
            let skip_unbounded = match ctx.get_item("jt_skip_unbounded")? {
                Some(v) => v.is_truthy()?,
                None => false,
            };
            let target_limit: u64 = match ctx.get_item("indirect_jump_target_limit")? {
                Some(v) => v.extract()?,
                None => 100_000,
            };
            Some(Box::new(jumptable::JumpTableResolver::new(
                twin.getattr(pyo3::intern!(py, "resolve_calls"))?
                    .is_truthy()?,
                &arch_name,
                arches.contains(&arch_name),
                skip,
                skip_unbounded,
                alignment,
                target_limit,
            )))
        }
        _ => None,
    })
}

pub fn ijr(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<chain::ResolverChain>()?;
    m.add_class::<const_resolver::FcpTableView>()?;
    m.add_class::<cvm::FcpService>()?;
    m.add_class::<cvm::CvmMapping>()?;
    m.add_function(pyo3::wrap_pyfunction!(jumptable::jt_trace_addr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(jumptable::jt_trace_take, m)?)?;
    Ok(())
}
