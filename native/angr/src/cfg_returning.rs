//! The returning fixpoint of CFGFast's scan: `CFGBase._analyze_function_features` and
//! `_determine_function_returning` over the RecoveryFunctions store, statement for statement.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple, PyType};
use pyo3::{PyTraverseError, PyVisit, intern};
use rustc_hash::FxHashSet;

use crate::cfg_jobs::ScanState;
use crate::cfg_scan::LinearSweep;
use crate::function_graph::{FunctionGraph, NodeKind, SiteKind};
use crate::recovery_functions::RecoveryFunctions;

/// Which addresses `simos.syscall_from_addr` can return a procedure for.
enum SyscallCheck {
    Never,
    /// `SimUserland.is_syscall_addr`
    Userland {
        kernel_base: u64,
        align: u64,
        max_number: u64,
    },
    /// `SimWindows`: membership in the syscall handler dict.
    Dict(Py<PyDict>),
    /// `is_syscall_addr(addr)`
    Callback(Py<PyAny>),
    /// No prefilter: ask Python for every address.
    Always,
}

#[pyclass(module = "angr.rustylib.cfg_returning")]
pub struct ReturningAnalyzer {
    scan: Py<ScanState>,
    store: Py<RecoveryFunctions>,
    sweep: Py<LinearSweep>,
    sim_procedures: Py<PyDict>,
    unresolvable_jump_target: Py<PyType>,
    syscall: SyscallCheck,
    /// `syscall_returning(addr) -> bool | None`: `not NO_RET` of `syscall_from_addr(addr, allow_unsupported=False)`.
    syscall_returning: Py<PyAny>,
}

impl ReturningAnalyzer {
    fn maybe_syscall(&self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        Ok(match &self.syscall {
            SyscallCheck::Never => false,
            SyscallCheck::Userland {
                kernel_base,
                align,
                max_number,
            } => {
                addr >= *kernel_base && {
                    let off = addr - kernel_base;
                    off.is_multiple_of(*align) && off / align <= *max_number
                }
            }
            SyscallCheck::Dict(d) => d.bind(py).contains(addr)?,
            SyscallCheck::Callback(f) => f.call1(py, (addr,))?.extract(py)?,
            SyscallCheck::Always => true,
        })
    }

    /// `n.sim_procedure.__class__ == UnresolvableJumpTarget` for a HookNode successor.
    fn is_unresolvable_jump_target(
        &self,
        py: Python<'_>,
        g: &FunctionGraph,
        idx: u32,
    ) -> PyResult<bool> {
        if g.node_kind(idx)? != NodeKind::Hook {
            return Ok(false);
        }
        match self.sim_procedures.bind(py).get_item(g.node_addr(idx)?)? {
            Some(proc) => proc.get_type().eq(self.unresolvable_jump_target.bind(py)),
            None => Ok(false),
        }
    }

    /// `CFGBase._determine_function_returning`
    fn determine(&self, py: Python<'_>, addr: u64, all_completed: bool) -> PyResult<Option<bool>> {
        if !self.sweep.borrow(py).inner.inside_regions(addr) {
            return Ok(Some(true));
        }
        let graph = self.store.borrow(py).rec(addr)?.graph.clone_ref(py);
        if !graph.borrow(py).sites(SiteKind::Ret).is_empty() {
            return Ok(Some(true));
        }

        let no_ret = match self.sim_procedures.bind(py).get_item(addr)? {
            Some(proc) => match proc.getattr_opt(intern!(py, "NO_RET"))? {
                Some(v) => Some(!v.is_truthy()?),
                None => None,
            },
            None if self.maybe_syscall(py, addr)? => {
                self.syscall_returning.call1(py, (addr,))?.extract(py)?
            }
            None => None,
        };
        if no_ret.is_some() {
            return Ok(no_ret);
        }

        if !all_completed && !self.scan.borrow(py).completed.contains(&addr) {
            return Ok(None);
        }

        let g = graph.borrow(py);
        if g.local_count() == 0 {
            return Ok(Some(true));
        }

        let store = self.store.borrow(py);
        let mut bail_out = false;
        let sites = g
            .sites(SiteKind::Jumpout)
            .into_iter()
            .map(|s| (s, false))
            .chain(g.sites(SiteKind::Retout).into_iter().map(|s| (s, true)));
        for (site, retout) in sites {
            let succs = g.successors(site)?;
            let mut known = false;
            for &s in &succs {
                if !self.is_unresolvable_jump_target(py, &g, s)? {
                    known = true;
                    break;
                }
            }
            if !known {
                bail_out = true;
                continue;
            }

            let target = if retout {
                let mut callees = Vec::new();
                let mut first_other = None;
                for &s in &succs {
                    if g.node_kind(s)? == NodeKind::Func {
                        callees.push(g.node_addr(s)?);
                    } else if first_other.is_none() {
                        first_other = Some(s);
                    }
                }
                if !callees.is_empty()
                    && callees
                        .iter()
                        .all(|&a| store.is_nonreturning(a) || store.is_returning_unknown(a))
                {
                    continue;
                }
                first_other
            } else {
                succs.first().copied()
            };
            let Some(target) = target else { continue };
            let target_addr = g.node_addr(target)?;
            if !store.contains(target_addr) {
                bail_out = true;
                continue;
            }
            match store.returning(target_addr)? {
                Some(true) => return Ok(Some(true)),
                None => bail_out = true,
                Some(false) => {}
            }
        }

        Ok(if bail_out { None } else { Some(false) })
    }
}

#[pymethods]
impl ReturningAnalyzer {
    /// :param syscall: ("never",), ("userland", kernel_base, align, max_number), ("dict", handlers),
    ///                 ("callback", is_syscall_addr) or ("always",).
    #[new]
    fn new(
        scan: Py<ScanState>,
        store: Py<RecoveryFunctions>,
        sweep: Py<LinearSweep>,
        sim_procedures: Py<PyDict>,
        unresolvable_jump_target: Py<PyType>,
        syscall: &Bound<'_, PyTuple>,
        syscall_returning: Py<PyAny>,
    ) -> PyResult<Self> {
        let kind: String = syscall.get_item(0)?.extract()?;
        let syscall = match kind.as_str() {
            "never" => SyscallCheck::Never,
            "userland" => SyscallCheck::Userland {
                kernel_base: syscall.get_item(1)?.extract()?,
                align: syscall.get_item(2)?.extract()?,
                max_number: syscall.get_item(3)?.extract()?,
            },
            "dict" => SyscallCheck::Dict(syscall.get_item(1)?.cast_into::<PyDict>()?.unbind()),
            "callback" => SyscallCheck::Callback(syscall.get_item(1)?.unbind()),
            _ => SyscallCheck::Always,
        };
        Ok(ReturningAnalyzer {
            scan,
            store,
            sweep,
            sim_procedures,
            unresolvable_jump_target,
            syscall,
            syscall_returning,
        })
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.scan)?;
        visit.call(&self.store)?;
        visit.call(&self.sweep)?;
        visit.call(&self.sim_procedures)?;
        visit.call(&self.unresolvable_jump_target)?;
        visit.call(&self.syscall_returning)?;
        match &self.syscall {
            SyscallCheck::Dict(d) => visit.call(d)?,
            SyscallCheck::Callback(f) => visit.call(f)?,
            _ => {}
        }
        Ok(())
    }

    /// One `_analyze_function_features` pass seeded with `seeds` (`_updated_nonreturning_functions`). Returning
    /// statuses are written to the store as they are determined. Returns the `functions_return` and
    /// `functions_do_not_return` lists.
    fn analyze(
        &self,
        py: Python<'_>,
        seeds: Vec<u64>,
        all_completed: bool,
    ) -> PyResult<(Vec<u64>, Vec<u64>)> {
        let mut work = seeds;
        work.sort_unstable();
        let mut analyzed: FxHashSet<u64> = FxHashSet::default();
        let mut ret = Vec::new();
        let mut noret = Vec::new();
        while let Some(addr) = work.pop() {
            analyzed.insert(addr);
            if !self.store.borrow(py).is_returning_unknown(addr) {
                continue;
            }
            let Some(returning) = self.determine(py, addr, all_completed)? else {
                continue;
            };
            let mut store = self.store.borrow_mut(py);
            store.set_returning(addr, Some(returning))?;
            if returning {
                ret.push(addr);
            } else {
                noret.push(addr);
            }
            if store.cg_contains(addr) {
                for caller in store.cg_predecessors(addr)? {
                    if !analyzed.contains(&caller) && store.contains(caller) {
                        work.push(caller);
                    }
                }
            }
        }
        Ok((ret, noret))
    }
}

pub fn cfg_returning(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ReturningAnalyzer>()?;
    Ok(())
}
