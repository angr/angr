//! `ResolverChain`: the ordered resolver lists and the dispatch loops of `_resolve_indirect_jump_timelessly` and
//! `_process_one_indirect_jump`.

use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PySet, PyTuple};

use super::{
    Decision, Effects, IrSpec, JumpSite, Outcome, Phase, ResolveCx, Resolver, make_resolver,
};
use crate::cfg_jobs::{
    FuncEdge, JobRec, ScanState, SrcNode, cpython_set_order, jk_intern, py_hash_u64,
};
use crate::cfg_scan::LoaderSnapshot;
use crate::vexlift::{NextExpr, VEX_IRSB_MAX_SIZE, VexLifter, jumpkind_from_name, jumpkind_name};

enum Entry {
    Rust {
        imp: Box<dyn Resolver>,
        twin: Py<PyAny>,
    },
    Py(Py<PyAny>),
}

/// The Python `block` argument, built at most once per jump and only when a Python resolver needs it.
struct PyBlock<'py> {
    cfg: Bound<'py, PyAny>,
    addr: u64,
    given: Option<Bound<'py, PyAny>>,
    has_stmts: bool,
    value: Option<Bound<'py, PyAny>>,
}

impl<'py> PyBlock<'py> {
    fn get(&mut self) -> PyResult<Bound<'py, PyAny>> {
        if let Some(v) = &self.value {
            return Ok(v.clone());
        }
        let py = self.cfg.py();
        let v = match &self.given {
            Some(b) if self.has_stmts => b.clone(),
            // _resolve_indirect_jump_timelessly: "make sure there are statements"
            Some(b) => self
                .cfg
                .call_method1(intern!(py, "_ijr_stmt_block"), (b,))?,
            // _process_one_indirect_jump: self._lift(jump.addr)
            None => self.cfg.call_method1(intern!(py, "_lift"), (self.addr,))?,
        };
        self.value = Some(v.clone());
        Ok(v)
    }
}

/// What a Python resolver returned: `(resolved, targets)` plus the `deferred` attribute after a deferred-phase
/// failure.
struct PyAnswer<'py> {
    resolved: bool,
    targets: Bound<'py, PyAny>,
    deferred: bool,
}

#[pyclass(module = "angr.rustylib.ijr", unsendable)]
pub struct ResolverChain {
    cx: ResolveCx,
    timeless: Vec<Entry>,
    deferred: Vec<Entry>,
    rust_precheck: bool,
    shadow: bool,
    /// Rust-first runs with a Python comparison: `jt_py_shadow(cfg, twin, addr, func_addr, block, jumpkind,
    /// func_graph_complete)` runs the twin with its effects undone and returns its answer.
    py_shadow: Option<Py<PyAny>>,
    mismatches: Vec<Py<PyAny>>,
    /// `IndirectJumpType.Vtable` when resolved jumps are written back in Rust (`CFGFast._rust_ijr_write_back`).
    write_back: Option<Py<PyAny>>,
}

fn targets_vec(t: &Bound<'_, PyAny>) -> Option<Vec<u64>> {
    t.try_iter()
        .ok()?
        .map(|x| x.ok()?.extract::<u64>().ok())
        .collect()
}

fn outcome_repr(o: &Outcome) -> String {
    match o {
        Outcome::Resolved(t) => format!(
            "resolved {:?}",
            t.iter().map(|x| format!("{x:#x}")).collect::<Vec<_>>()
        ),
        Outcome::Unresolved => "unresolved".into(),
        Outcome::Deferred => "deferred".into(),
    }
}

fn answer_outcome(a: &PyAnswer<'_>) -> Option<Outcome> {
    Some(if a.resolved {
        Outcome::Resolved(targets_vec(&a.targets)?)
    } else if a.deferred {
        Outcome::Deferred
    } else {
        Outcome::Unresolved
    })
}

impl ResolverChain {
    fn build_entries(
        py: Python<'_>,
        items: Vec<(Option<String>, Py<PyAny>)>,
        ctx: &Bound<'_, PyDict>,
    ) -> PyResult<Vec<Entry>> {
        let mut out = Vec::with_capacity(items.len());
        for (kind, obj) in items {
            let imp = match &kind {
                Some(k) => make_resolver(k, obj.bind(py), ctx)?,
                None => None,
            };
            out.push(match imp {
                Some(imp) => Entry::Rust { imp, twin: obj },
                None => Entry::Py(obj),
            });
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        mismatches: &mut Vec<Py<PyAny>>,
        py: Python<'_>,
        j: &JumpSite,
        kind: &str,
        what: &str,
        rust: String,
        python: String,
    ) -> PyResult<()> {
        let d = PyDict::new(py);
        d.set_item(
            "phase",
            if j.phase == Phase::Timeless {
                "timeless"
            } else {
                "deferred"
            },
        )?;
        d.set_item("kind", kind)?;
        d.set_item("addr", j.addr)?;
        d.set_item("func_addr", j.func_addr)?;
        d.set_item("jumpkind", jumpkind_name(j.jumpkind))?;
        d.set_item("what", what)?;
        d.set_item("rust", rust)?;
        d.set_item("python", python)?;
        mismatches.push(d.into_any().unbind());
        Ok(())
    }

    /// A shadow record of a resolver whose answers may legitimately differ (JumpTableResolver): both answers and
    /// Python's table records, classified offline.
    #[allow(clippy::too_many_arguments)]
    fn record_classified(
        mismatches: &mut Vec<Py<PyAny>>,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        kind: &str,
        rust: String,
        resolved: bool,
        deferred: bool,
        targets: Option<Vec<u64>>,
        tables: Bound<'_, PyAny>,
        python_authoritative: bool,
    ) -> PyResult<()> {
        let py = cfg.py();
        let d = PyDict::new(py);
        d.set_item(
            "phase",
            if j.phase == Phase::Timeless {
                "timeless"
            } else {
                "deferred"
            },
        )?;
        d.set_item("kind", kind)?;
        d.set_item("addr", j.addr)?;
        d.set_item("func_addr", j.func_addr)?;
        d.set_item("jumpkind", jumpkind_name(j.jumpkind))?;
        d.set_item("what", "classified")?;
        d.set_item(
            "final_pass",
            cfg.getattr(intern!(py, "_unbounded_jumptable_final_pass"))?
                .is_truthy()?,
        )?;
        d.set_item("rust", rust)?;
        d.set_item("python_authoritative", python_authoritative)?;
        let p = PyDict::new(py);
        p.set_item("resolved", resolved)?;
        p.set_item("deferred", deferred)?;
        p.set_item("targets", targets)?;
        p.set_item("tables", tables)?;
        d.set_item("python", p)?;
        mismatches.push(d.into_any().unbind());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn py_filter<'py>(
        obj: &Bound<'py, PyAny>,
        cfg: &Bound<'py, PyAny>,
        j: &JumpSite,
        jumpkind: &Bound<'py, PyAny>,
        block: &mut PyBlock<'py>,
    ) -> PyResult<bool> {
        let py = cfg.py();
        if let Phase::Deferred { .. } = j.phase {
            obj.setattr(
                intern!(py, "base_state"),
                cfg.getattr(intern!(py, "_base_state"))?,
            )?;
        }
        let b = block.get()?;
        obj.call_method1(
            intern!(py, "filter"),
            (cfg, j.addr, j.func_addr, b, jumpkind),
        )?
        .is_truthy()
    }

    fn py_resolve<'py>(
        obj: &Bound<'py, PyAny>,
        cfg: &Bound<'py, PyAny>,
        j: &JumpSite,
        jumpkind: &Bound<'py, PyAny>,
        block: &mut PyBlock<'py>,
    ) -> PyResult<PyAnswer<'py>> {
        let py = cfg.py();
        let b = block.get()?;
        let r = match j.phase {
            Phase::Timeless => obj.call_method1(
                intern!(py, "resolve"),
                (cfg, j.addr, j.func_addr, b, jumpkind),
            )?,
            Phase::Deferred {
                func_graph_complete,
            } => {
                let kw = PyDict::new(py);
                kw.set_item(intern!(py, "func_graph_complete"), func_graph_complete)?;
                obj.call_method(
                    intern!(py, "resolve"),
                    (cfg, j.addr, j.func_addr, b, jumpkind),
                    Some(&kw),
                )?
            }
        };
        let (resolved, targets): (Bound<'py, PyAny>, Bound<'py, PyAny>) = r.extract()?;
        let resolved = resolved.is_truthy()?;
        let deferred = !resolved
            && matches!(j.phase, Phase::Deferred { .. })
            && match obj.getattr_opt(intern!(py, "deferred"))? {
                Some(d) => d.is_truthy()?,
                None => false,
            };
        Ok(PyAnswer {
            resolved,
            targets,
            deferred,
        })
    }

    /// One Rust entry: its own answer, or the twin's when it declines. Shadow mode runs both and keeps the twin's.
    #[allow(clippy::too_many_arguments)]
    fn run_rust<'py>(
        cx: &mut ResolveCx,
        mismatches: &mut Vec<Py<PyAny>>,
        shadow: bool,
        py_shadow: Option<&Py<PyAny>>,
        imp: &mut dyn Resolver,
        twin: &Bound<'py, PyAny>,
        cfg: &Bound<'py, PyAny>,
        j: &JumpSite,
        jumpkind: &Bound<'py, PyAny>,
        block: &mut PyBlock<'py>,
    ) -> PyResult<Option<PyAnswer<'py>>> {
        let py = cfg.py();
        let kind = imp.kind();

        if shadow {
            // Rust first, so that it sees the state the twin sees; the twin's answer is the one kept
            let rust: Result<(bool, Option<Outcome>), &'static str> =
                match imp.filter(py, cx, cfg, j)? {
                    Decision::Python(r) => Err(r),
                    Decision::Done(false) => Ok((false, None)),
                    Decision::Done(true) => {
                        let mut fx = Effects::default();
                        match imp.resolve(py, cx, cfg, j, &mut fx)? {
                            Decision::Python(r) => Err(r),
                            Decision::Done(o) => Ok((true, Some(o))),
                        }
                    }
                };
            let pf = Self::py_filter(twin, cfg, j, jumpkind, block)?;
            let pa = if pf {
                Some(Self::py_resolve(twin, cfg, j, jumpkind, block)?)
            } else {
                None
            };
            if let Some(detail) = imp.shadow_detail() {
                if let Some(a) = &pa {
                    let targets = if a.resolved {
                        targets_vec(&a.targets)
                    } else {
                        None
                    };
                    let tables = super::jumptable::py_jumptables(cfg, j.addr)?;
                    Self::record_classified(
                        mismatches, cfg, j, kind, detail, a.resolved, a.deferred, targets, tables,
                        true,
                    )?;
                }
                return Ok(pa);
            }
            match &rust {
                Err(reason) => {
                    cx.count(&format!("{kind}:shadow_decline:{reason}"));
                    imp.after_twin(py, cfg, j)?;
                }
                Ok((rf, ro)) => {
                    if *rf != pf {
                        Self::record(
                            mismatches,
                            py,
                            j,
                            kind,
                            "filter",
                            rf.to_string(),
                            pf.to_string(),
                        )?;
                    } else if let (Some(o), Some(a)) = (ro, &pa) {
                        let po = answer_outcome(a);
                        if po.as_ref() != Some(o) {
                            let prepr = match &po {
                                Some(p) => outcome_repr(p),
                                None => format!("unparsed {}", a.targets.repr()?),
                            };
                            Self::record(
                                mismatches,
                                py,
                                j,
                                kind,
                                "resolve",
                                outcome_repr(o),
                                prepr,
                            )?;
                        } else {
                            cx.count(&format!("{kind}:shadow_same"));
                        }
                    } else {
                        cx.count(&format!("{kind}:shadow_same"));
                    }
                    for (what, r, p) in imp.shadow_diffs(py, cx, cfg, j)? {
                        Self::record(mismatches, py, j, kind, what, r, p)?;
                    }
                }
            }
            return Ok(pa);
        }

        match imp.filter(py, cx, cfg, j)? {
            Decision::Done(false) => return Ok(None),
            Decision::Done(true) => {}
            Decision::Python(reason) => {
                cx.count(&format!("{kind}:decline:{reason}"));
                imp.before_twin(py, cfg, j)?;
                let a = if Self::py_filter(twin, cfg, j, jumpkind, block)? {
                    Some(Self::py_resolve(twin, cfg, j, jumpkind, block)?)
                } else {
                    None
                };
                imp.after_twin(py, cfg, j)?;
                return Ok(a);
            }
        }
        let mut fx = Effects::default();
        match imp.resolve(py, cx, cfg, j, &mut fx)? {
            Decision::Python(reason) => {
                cx.count(&format!("{kind}:decline:{reason}"));
                imp.before_twin(py, cfg, j)?;
                let a = Self::py_resolve(twin, cfg, j, jumpkind, block)?;
                imp.after_twin(py, cfg, j)?;
                if py_shadow.is_some()
                    && let Some(detail) = imp.shadow_detail()
                {
                    let targets = if a.resolved {
                        targets_vec(&a.targets)
                    } else {
                        None
                    };
                    let tables = super::jumptable::py_jumptables(cfg, j.addr)?;
                    Self::record_classified(
                        mismatches, cfg, j, kind, detail, a.resolved, a.deferred, targets, tables,
                        true,
                    )?;
                }
                Ok(Some(a))
            }
            Decision::Done(o) => {
                cx.count(&format!("{kind}:rust"));
                if let Some(f) = py_shadow
                    && let Some(detail) = imp.shadow_detail()
                {
                    // the twin's answer on the same state; its effects on the IndirectJump are undone
                    let fgc = match j.phase {
                        Phase::Deferred {
                            func_graph_complete,
                        } => func_graph_complete,
                        Phase::Timeless => true,
                    };
                    let b = block.get()?;
                    let r = f
                        .bind(py)
                        .call1((cfg, twin, j.addr, j.func_addr, b, jumpkind, fgc))?;
                    let (resolved, deferred, targets, tables): (
                        bool,
                        bool,
                        Option<Vec<u64>>,
                        Bound<'py, PyAny>,
                    ) = r.extract()?;
                    Self::record_classified(
                        mismatches, cfg, j, kind, detail, resolved, deferred, targets, tables,
                        false,
                    )?;
                }
                if let Outcome::Resolved(_) = o {
                    cx.count(&format!("{kind}:resolved"));
                }
                fx.apply(cfg)?;
                let empty = || PyList::empty(py).into_any();
                Ok(Some(match o {
                    Outcome::Resolved(t) => PyAnswer {
                        resolved: true,
                        targets: PyList::new(py, t)?.into_any(),
                        deferred: false,
                    },
                    Outcome::Unresolved => PyAnswer {
                        resolved: false,
                        targets: empty(),
                        deferred: false,
                    },
                    Outcome::Deferred => PyAnswer {
                        resolved: false,
                        targets: empty(),
                        deferred: true,
                    },
                }))
            }
        }
    }

    /// The pre-check in Rust: Some(target) resolves, None continues; Err when the Python pre-check must run.
    fn rust_precheck(
        &mut self,
        py: Python<'_>,
        block_addr: u64,
        block_size: i64,
    ) -> PyResult<Result<Option<u64>, &'static str>> {
        let s = match self.cx.lift_nostmt(py, block_addr, block_size, 1, true)? {
            Ok(s) => s,
            Err(fb) => return Ok(Err(fb.name())),
        };
        if !jumpkind_name(s.jumpkind).starts_with("Ijk_Sys")
            && let NextExpr::Const(v) = s.next
        {
            return Ok(Ok(Some(v)));
        }
        Ok(Ok(None))
    }

    /// `_resolve_indirect_jump_timelessly` for the Rust block scan, without a Python block: the jump at `addr` ends
    /// the CFG node (`addr`, `size`, `ins_addrs`) that `_create_jobs` would re-lift with statements. Escapes when the
    /// statement lift differs from the node, or when any step would need Python (a Python entry or a decline).
    #[allow(clippy::too_many_arguments)]
    pub fn scan_timeless(
        &mut self,
        py: Python<'_>,
        cfg: &Bound<'_, PyAny>,
        addr: u64,
        func_addr: u64,
        jumpkind: u32,
        size: u32,
        ins_addrs: &[u64],
    ) -> PyResult<TimelessScan> {
        if self.shadow {
            return Ok(TimelessScan::Escape("shadow"));
        }
        if !self.rust_precheck || self.timeless.iter().any(|e| matches!(e, Entry::Py(_))) {
            return Ok(TimelessScan::Escape("python_entry"));
        }
        let spec = IrSpec {
            addr,
            max_size: size as i64,
            opt_level: 1,
            cross_insn_opt: false,
            extra_stops: true,
        };
        let ir = match self.cx.ir(py, &spec)? {
            Ok(ir) => ir,
            Err(_) => return Ok(TimelessScan::Escape("lift")),
        };
        if ir.size != size || ir.jumpkind != jumpkind || ir.instruction_addresses != ins_addrs {
            return Ok(TimelessScan::Escape("ir_differs"));
        }
        match self.rust_precheck(py, ir.addr, ir.size as i64)? {
            Ok(Some(t)) => {
                self.cx.count("precheck:rust");
                return Ok(TimelessScan::Resolved(vec![t]));
            }
            Ok(None) => self.cx.count("precheck:rust"),
            Err(_) => return Ok(TimelessScan::Escape("precheck")),
        }
        let site = JumpSite {
            addr,
            func_addr,
            jumpkind,
            phase: Phase::Timeless,
            block: spec,
        };
        let ResolverChain { cx, timeless, .. } = self;
        for e in timeless.iter_mut() {
            let Entry::Rust { imp, .. } = e else {
                unreachable!()
            };
            match imp.filter(py, cx, cfg, &site)? {
                Decision::Done(false) => continue,
                Decision::Done(true) => {}
                Decision::Python(_) => return Ok(TimelessScan::Escape("decline")),
            }
            let mut fx = Effects::default();
            match imp.resolve(py, cx, cfg, &site, &mut fx)? {
                Decision::Python(_) => return Ok(TimelessScan::Escape("decline")),
                Decision::Done(o) => {
                    let kind = imp.kind();
                    cx.count(&format!("{kind}:rust"));
                    if let Outcome::Resolved(t) = o {
                        cx.count(&format!("{kind}:resolved"));
                        fx.apply(cfg)?;
                        return Ok(TimelessScan::Resolved(t));
                    }
                    fx.apply(cfg)?;
                }
            }
        }
        Ok(TimelessScan::Unresolved)
    }
}

/// The outcome of [`ResolverChain::scan_timeless`].
pub enum TimelessScan {
    /// Hand the jump to Python (`_create_jobs`).
    Escape(&'static str),
    /// Targets in the resolver's return order.
    Resolved(Vec<u64>),
    Unresolved,
}

#[pymethods]
impl ResolverChain {
    /// :param ctx:        The run's context (see ``angr.analyses.cfg.indirect_jump_resolvers.rust.build_chain``).
    /// :param timeless:   ``(kind or None, resolver)`` per entry of ``cfg.timeless_indirect_jump_resolvers``.
    /// :param deferred:   The same for ``cfg.indirect_jump_resolvers``.
    #[new]
    #[pyo3(signature = (lifter, snapshot, ctx, rust_precheck, timeless, deferred, shadow))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        lifter: Py<VexLifter>,
        snapshot: &LoaderSnapshot,
        ctx: &Bound<'_, PyDict>,
        rust_precheck: bool,
        timeless: Vec<(Option<String>, Py<PyAny>)>,
        deferred: Vec<(Option<String>, Py<PyAny>)>,
        shadow: bool,
    ) -> PyResult<Self> {
        let cx = ResolveCx::new(snapshot.inner.clone(), lifter, ctx)?;
        let py_shadow = ctx
            .get_item("jt_py_shadow")?
            .filter(|f| !f.is_none())
            .map(Bound::unbind);
        let write_back = match ctx.get_item("write_back")? {
            Some(wb) if !wb.is_none() => Some(wb.get_item("vtable")?.unbind()),
            _ => None,
        };
        Ok(ResolverChain {
            py_shadow,
            write_back,
            cx,
            timeless: Self::build_entries(py, timeless, ctx)?,
            deferred: Self::build_entries(py, deferred, ctx)?,
            rust_precheck,
            shadow,
            mismatches: Vec::new(),
        })
    }

    /// The kinds that run in Rust, timeless then deferred.
    fn rust_kinds(&self) -> (Vec<&'static str>, Vec<&'static str>) {
        let f = |l: &Vec<Entry>| {
            l.iter()
                .filter_map(|e| match e {
                    Entry::Rust { imp, .. } => Some(imp.kind()),
                    Entry::Py(_) => None,
                })
                .collect()
        };
        (f(&self.timeless), f(&self.deferred))
    }

    /// `_resolve_indirect_jump_timelessly`. `block_nstmts` is ``len(block.statements)``, or -1 without statements.
    #[allow(clippy::too_many_arguments)]
    fn resolve_timeless<'py>(
        &mut self,
        cfg: &Bound<'py, PyAny>,
        addr: u64,
        func_addr: u64,
        block: Bound<'py, PyAny>,
        jumpkind: Bound<'py, PyAny>,
        block_addr: u64,
        block_size: i64,
        block_nstmts: i64,
    ) -> PyResult<(bool, Bound<'py, PyAny>)> {
        let py = cfg.py();
        // the pre-check: a cross-instruction-optimized re-lift with a constant next resolves the jump
        let python_precheck =
            |block: &Bound<'py, PyAny>| -> PyResult<Option<(bool, Bound<'py, PyAny>)>> {
                let r = cfg.call_method1(intern!(py, "_timeless_precheck"), (block,))?;
                if r.is_none() {
                    return Ok(None);
                }
                let (a, b): (Bound<'py, PyAny>, Bound<'py, PyAny>) = r.extract()?;
                Ok(Some((a.is_truthy()?, b)))
            };
        let decided = if self.rust_precheck {
            let rust = self.rust_precheck(py, block_addr, block_size)?;
            if self.shadow {
                let p = python_precheck(&block)?;
                match &rust {
                    Err(reason) => self.cx.count(&format!("precheck:shadow_decline:{reason}")),
                    Ok(r) => {
                        let pr: Option<Option<u64>> = match &p {
                            None => Some(None),
                            Some((true, t)) => {
                                targets_vec(t).and_then(|v| (v.len() == 1).then(|| Some(v[0])))
                            }
                            Some((false, _)) => None,
                        };
                        if pr.as_ref() != Some(r) {
                            let site = JumpSite {
                                addr,
                                func_addr,
                                jumpkind: jumpkind_from_name(&jumpkind.extract::<String>()?)
                                    .unwrap_or(u32::MAX),
                                phase: Phase::Timeless,
                                block: IrSpec {
                                    addr: block_addr,
                                    max_size: block_size,
                                    opt_level: 1,
                                    cross_insn_opt: true,
                                    extra_stops: false,
                                },
                            };
                            let prepr = match &p {
                                None => "continue".to_string(),
                                Some((b, t)) => format!("{b} {}", t.repr()?),
                            };
                            Self::record(
                                &mut self.mismatches,
                                py,
                                &site,
                                "precheck",
                                "precheck",
                                format!("{r:?}"),
                                prepr,
                            )?;
                        } else {
                            self.cx.count("precheck:shadow_same");
                        }
                    }
                }
                p
            } else {
                match rust {
                    Ok(Some(t)) => {
                        self.cx.count("precheck:rust");
                        Some((true, PyList::new(py, [t])?.into_any()))
                    }
                    Ok(None) => {
                        self.cx.count("precheck:rust");
                        None
                    }
                    Err(reason) => {
                        self.cx.count(&format!("precheck:decline:{reason}"));
                        python_precheck(&block)?
                    }
                }
            }
        } else {
            python_precheck(&block)?
        };
        if let Some(d) = decided {
            return Ok(d);
        }

        let jk_str: String = jumpkind.extract()?;
        let jk = jumpkind_from_name(&jk_str);
        let has_stmts = block_nstmts >= 0;
        let spec = if has_stmts {
            // the _create_jobs re-lift: self._lift(cfg_node.addr, size=cfg_node.size).vex
            IrSpec {
                addr: block_addr,
                max_size: block_size,
                opt_level: 1,
                cross_insn_opt: false,
                extra_stops: true,
            }
        } else {
            // project.factory.block(block.addr, size=block.size).vex
            IrSpec {
                addr: block_addr,
                max_size: block_size,
                opt_level: self.cx.default_opt_level,
                cross_insn_opt: true,
                extra_stops: false,
            }
        };
        let site = JumpSite {
            addr,
            func_addr,
            jumpkind: jk.unwrap_or(u32::MAX),
            phase: Phase::Timeless,
            block: spec,
        };
        let mut pyblock = PyBlock {
            cfg: cfg.clone(),
            addr,
            given: Some(block),
            has_stmts,
            value: None,
        };
        for idx in 0..self.timeless.len() {
            let (obj, is_rust) = match &self.timeless[idx] {
                Entry::Py(obj) => (obj.bind(py).clone(), false),
                Entry::Rust { twin, .. } => (twin.bind(py).clone(), true),
            };
            let answer = if !is_rust || jk.is_none() || !self.ir_matches(py, &site, block_nstmts)? {
                if !Self::py_filter(&obj, cfg, &site, &jumpkind, &mut pyblock)? {
                    continue;
                }
                Some(Self::py_resolve(&obj, cfg, &site, &jumpkind, &mut pyblock)?)
            } else {
                let ResolverChain {
                    cx,
                    timeless,
                    mismatches,
                    shadow,
                    py_shadow,
                    ..
                } = self;
                let Entry::Rust { imp, .. } = &mut timeless[idx] else {
                    unreachable!()
                };
                Self::run_rust(
                    cx,
                    mismatches,
                    *shadow,
                    py_shadow.as_ref(),
                    imp.as_mut(),
                    &obj,
                    cfg,
                    &site,
                    &jumpkind,
                    &mut pyblock,
                )?
            };
            if let Some(a) = answer
                && a.resolved
            {
                return Ok((true, a.targets));
            }
        }
        Ok((false, PyList::empty(py).into_any()))
    }

    /// `_process_one_indirect_jump`'s resolver loop: ``(resolved, resolved_by, targets, deferred)``.
    #[pyo3(signature = (cfg, jump, func_graph_complete=true))]
    fn resolve_deferred<'py>(
        &mut self,
        cfg: &Bound<'py, PyAny>,
        jump: &Bound<'py, PyAny>,
        func_graph_complete: bool,
    ) -> PyResult<(bool, Bound<'py, PyAny>, Bound<'py, PyAny>, bool)> {
        let py = cfg.py();
        let addr: u64 = jump.getattr(intern!(py, "addr"))?.extract()?;
        let func_addr: u64 = jump.getattr(intern!(py, "func_addr"))?.extract()?;
        let jumpkind = jump.getattr(intern!(py, "jumpkind"))?;
        let jk = jumpkind_from_name(&jumpkind.extract::<String>()?);
        let site = JumpSite {
            addr,
            func_addr,
            jumpkind: jk.unwrap_or(u32::MAX),
            phase: Phase::Deferred {
                func_graph_complete,
            },
            // self._lift(jump.addr)
            block: IrSpec {
                addr,
                max_size: VEX_IRSB_MAX_SIZE as i64,
                opt_level: 1,
                cross_insn_opt: false,
                extra_stops: true,
            },
        };
        let mut pyblock = PyBlock {
            cfg: cfg.clone(),
            addr,
            given: None,
            has_stmts: true,
            value: None,
        };
        let mut deferred = false;
        for idx in 0..self.deferred.len() {
            let (obj, is_rust) = match &self.deferred[idx] {
                Entry::Py(obj) => (obj.bind(py).clone(), false),
                Entry::Rust { twin, .. } => (twin.bind(py).clone(), true),
            };
            let answer = if !is_rust || jk.is_none() {
                if !Self::py_filter(&obj, cfg, &site, &jumpkind, &mut pyblock)? {
                    continue;
                }
                Some(Self::py_resolve(&obj, cfg, &site, &jumpkind, &mut pyblock)?)
            } else {
                let ResolverChain {
                    cx,
                    deferred: entries,
                    mismatches,
                    shadow,
                    py_shadow,
                    ..
                } = self;
                let Entry::Rust { imp, .. } = &mut entries[idx] else {
                    unreachable!()
                };
                Self::run_rust(
                    cx,
                    mismatches,
                    *shadow,
                    py_shadow.as_ref(),
                    imp.as_mut(),
                    &obj,
                    cfg,
                    &site,
                    &jumpkind,
                    &mut pyblock,
                )?
            };
            let Some(a) = answer else { continue };
            if a.resolved {
                return Ok((true, obj, a.targets, deferred));
            }
            if a.deferred {
                deferred = true;
            }
        }
        Ok((
            false,
            py.None().into_bound(py),
            py.None().into_bound(py),
            deferred,
        ))
    }

    /// `_process_unresolved_indirect_jumps`: every pending jump in address order, each resolved and written back
    /// (`_indirect_jump_resolved`, the deferred set, or `_indirect_jump_unresolved`) before the next one, until
    /// `should_abort`. Returns the targets. `release_gil(idx, 50, 1e-6)` is called before each jump when given, as
    /// the Python loop does under `low_priority`.
    #[pyo3(signature = (cfg, release_gil=None))]
    fn resolve_pending<'py>(
        &mut self,
        cfg: &Bound<'py, PyAny>,
        release_gil: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PySet>> {
        let py = cfg.py();
        let pending = cfg.getattr(intern!(py, "_indirect_jumps_to_resolve"))?;
        let mut jumps: Vec<(u64, Bound<'py, PyAny>)> = Vec::new();
        for j in pending.try_iter()? {
            let j = j?;
            jumps.push((j.getattr(intern!(py, "addr"))?.extract()?, j));
        }
        // sorted(..., key=lambda j: j.addr) is stable
        jumps.sort_by_key(|(a, _)| *a);
        let all = PySet::empty(py)?;
        for (idx, (addr, jump)) in jumps.into_iter().enumerate() {
            if cfg.getattr(intern!(py, "should_abort"))?.is_truthy()? {
                break;
            }
            if let Some(f) = &release_gil {
                f.call1((idx, 50, 0.000001))?;
            }
            let (resolved, by, targets, deferred) = self.resolve_deferred(cfg, &jump, true)?;
            if resolved {
                if !self.write_back_resolved(cfg, &jump, &by, &targets)? {
                    cfg.call_method1(
                        intern!(py, "_indirect_jump_resolved"),
                        (&jump, addr, by, &targets),
                    )?;
                }
            } else if deferred {
                cfg.getattr(intern!(py, "_deferred_indirect_jumps"))?
                    .call_method1(intern!(py, "add"), (&jump,))?;
            } else {
                cfg.call_method1(intern!(py, "_indirect_jump_unresolved"), (&jump,))?;
            }
            if !targets.is_none() {
                for t in targets.try_iter()? {
                    all.add(t?)?;
                }
            }
        }
        pending.call_method0(intern!(py, "clear"))?;
        Ok(all)
    }

    /// `CFGFast._indirect_jump_resolved` with the per-target jobs built and queued in Rust. False when this run
    /// cannot (no write-back context, no Rust scan state, or targets that are not addresses); nothing happened then.
    fn write_back_resolved(
        &mut self,
        cfg: &Bound<'_, PyAny>,
        jump: &Bound<'_, PyAny>,
        by: &Bound<'_, PyAny>,
        targets: &Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        let py = cfg.py();
        let Some(vtable) = &self.write_back else {
            return Ok(false);
        };
        let scan = cfg.getattr(intern!(py, "_scan"))?;
        let Ok(scan) = scan.cast::<ScanState>() else {
            return Ok(false);
        };
        let Some(target_list) = targets_vec(targets) else {
            return Ok(false);
        };
        if jump.getattr(intern!(py, "jumptable"))?.is_truthy()? {
            cfg.call_method1(intern!(py, "_record_jump_tables"), (jump,))?;
        }
        jump.setattr(intern!(py, "resolved_targets"), targets)?;
        let source_addr: u64 = jump.getattr(intern!(py, "addr"))?.extract()?;
        let func_addr: u64 = jump.getattr(intern!(py, "func_addr"))?.extract()?;
        let jumpkind: String = jump.getattr(intern!(py, "jumpkind"))?.extract()?;
        let is_call = jumpkind == "Ijk_Call";
        let is_vtable = jump.getattr(intern!(py, "type"))?.eq(vtable.bind(py))?;
        let ins_addr: Option<u64> = jump.getattr(intern!(py, "ins_addr"))?.extract()?;
        let stmt_idx: Option<i64> = jump.getattr(intern!(py, "stmt_idx"))?.extract()?;
        let store = self.cx.functions(py, cfg)?;
        let functions = cfg
            .getattr(intern!(py, "kb"))?
            .getattr(intern!(py, "functions"))?;
        // for addr in set(targets)
        let mut uniq: Vec<u64> = Vec::with_capacity(target_list.len());
        for t in target_list {
            if !uniq.contains(&t) {
                uniq.push(t);
            }
        }
        let hashes: Vec<i64> = uniq.iter().map(|&t| py_hash_u64(t)).collect();
        let mut src: Option<(SrcNode, u64)> = None;
        for idx in cpython_set_order(&hashes) {
            let t = uniq[idx];
            let in_functions = match &store {
                Some(s) => s.bind(py).borrow().contains(t),
                None => functions.contains(t)?,
            };
            let to_outside = is_call
                || is_vtable
                || in_functions
                || !self.cx.snap.addrs_belong_to_same_section(source_addr, t);
            let target_func_addr = if is_vtable {
                let kwargs = PyDict::new(py);
                kwargs.set_item(intern!(py, "create"), true)?;
                functions.call_method(intern!(py, "function"), (t,), Some(&kwargs))?;
                t
            } else if to_outside {
                t
            } else {
                func_addr
            };
            let (s, src_end) = match src {
                Some(v) => v,
                None => {
                    let node = cfg
                        .getattr(intern!(py, "model"))?
                        .call_method1(intern!(py, "nodes_by_addr"), (source_addr,))?
                        .try_iter()?
                        .next()
                        .ok_or_else(|| pyo3::exceptions::PyStopIteration::new_err(()))??;
                    let end = source_addr + node.getattr(intern!(py, "size"))?.extract::<u64>()?;
                    let v = (scan.borrow_mut().src_node(py, &node)?, end);
                    src = Some(v);
                    v
                }
            };
            let edge = if is_call {
                FuncEdge::Call {
                    src: Some(s),
                    dst_addr: t,
                    ret_addr: Some(src_end),
                    src_func_addr: func_addr,
                    syscall: false,
                    stmt_idx,
                    ins_addr,
                }
            } else {
                FuncEdge::Transition {
                    src: Some(s),
                    dst_addr: t,
                    src_func_addr: func_addr,
                    to_outside,
                    dst_func_addr: Some(target_func_addr),
                    stmt_idx: None,
                    ins_addr: None,
                    is_exception: false,
                }
            };
            let mut job = JobRec::new(t, target_func_addr, jk_intern(&jumpkind));
            job.last_addr = Some(source_addr);
            job.src = Some(s);
            job.src_ins_addr = ins_addr;
            job.src_stmt_idx = stmt_idx;
            job.func_edges = vec![edge];
            let mut st = scan.borrow_mut();
            st.register_job(target_func_addr, &job);
            st.push_job(job);
        }
        scan.borrow_mut().deregister_object(func_addr, jump)?;
        cfg.call_method1(
            intern!(py, "_indirect_jump_resolved_done"),
            (jump, by, targets),
        )?;
        self.cx.count("write_back:rust");
        Ok(true)
    }

    /// Publish Rust-owned resolver state (``kb.propagations`` FCP models); call once when the run ends.
    fn finish(&mut self, cfg: &Bound<'_, PyAny>) -> PyResult<()> {
        let py = cfg.py();
        for e in self.timeless.iter_mut().chain(self.deferred.iter_mut()) {
            if let Entry::Rust { imp, .. } = e {
                imp.finish(py, cfg)?;
            }
        }
        Ok(())
    }

    /// FastConstantPropagation over a whole function (ConstantResolver's configuration) or over `blocks`, as table
    /// rows (see `const_resolver::table_rows`), or the decline reason. For tests.
    #[pyo3(signature = (cfg, func_addr, blocks=None, cross_insn_opt=false))]
    fn debug_fcp<'py>(
        &mut self,
        cfg: &Bound<'py, PyAny>,
        func_addr: u64,
        blocks: Option<Vec<u64>>,
        cross_insn_opt: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let py = cfg.py();
        let Some(store) = self.cx.functions(py, cfg)? else {
            return Ok("no_store".into_pyobject(py)?.into_any());
        };
        let blocks: Option<rustc_hash::FxHashSet<u64>> = blocks.map(|b| b.into_iter().collect());
        let req = super::fcp::FcpRequest {
            func_addr,
            blocks: blocks.as_ref(),
            cross_insn_opt,
            load: super::fcp::LoadPolicy::Propagator,
        };
        Ok(match super::fcp::run_fcp(py, &mut self.cx, &store, &req)? {
            Ok(t) => super::fcp::table_rows(py, &t)?.into_any(),
            Err(d) => d.into_pyobject(py)?.into_any(),
        })
    }

    /// The Blade slice from `addr` with Blade's parameters (defaults: ConstantResolver's): `(nodes, edges)`, or the
    /// decline reason. For tests.
    #[pyo3(signature = (addr, dst_stmt_idx=-1, max_level=3, stop_at_calls=true, cross_insn_opt=true, control_dependence=false, ignore_sp=false, ignore_bp=false, ignored_regs=Vec::new(), include_imarks=true, max_predecessors=10))]
    #[allow(clippy::too_many_arguments)]
    fn debug_blade<'py>(
        &mut self,
        py: Python<'py>,
        addr: u64,
        dst_stmt_idx: i64,
        max_level: i32,
        stop_at_calls: bool,
        cross_insn_opt: bool,
        control_dependence: bool,
        ignore_sp: bool,
        ignore_bp: bool,
        ignored_regs: Vec<i32>,
        include_imarks: bool,
        max_predecessors: usize,
    ) -> PyResult<Bound<'py, PyAny>> {
        let p = super::blade::BladeParams {
            ignore_sp,
            ignore_bp,
            ignored_regs,
            max_level,
            stop_at_calls,
            cross_insn_opt,
            max_predecessors,
            include_imarks,
            control_dependence,
        };
        Ok(
            match super::blade::blade(py, &mut self.cx, addr, dst_stmt_idx, &p)? {
                Ok(s) => {
                    let nodes: Vec<super::blade::SliceLoc> = s.nodes.keys().copied().collect();
                    (nodes, s.edges()).into_pyobject(py)?.into_any()
                }
                Err(d) => d.into_pyobject(py)?.into_any(),
            },
        )
    }

    /// Run the Rust JumpTableResolver on one jump (deferred phase) with a trace: ``(verdict json, trace lines)``.
    /// Its effects are dropped. For debugging.
    #[pyo3(signature = (cfg, addr, func_addr, jumpkind="Ijk_Boring"))]
    fn debug_jumptable(
        &mut self,
        cfg: &Bound<'_, PyAny>,
        addr: u64,
        func_addr: u64,
        jumpkind: &str,
    ) -> PyResult<Option<(String, Vec<String>)>> {
        let py = cfg.py();
        let site = JumpSite {
            addr,
            func_addr,
            jumpkind: jumpkind_from_name(jumpkind).unwrap_or(u32::MAX),
            phase: Phase::Deferred {
                func_graph_complete: true,
            },
            block: IrSpec {
                addr,
                max_size: VEX_IRSB_MAX_SIZE as i64,
                opt_level: 1,
                cross_insn_opt: false,
                extra_stops: true,
            },
        };
        let ResolverChain { cx, deferred, .. } = self;
        for e in deferred.iter_mut() {
            if let Entry::Rust { imp, .. } = e
                && imp.kind() == "JumpTableResolver"
            {
                super::jumptable::set_trace(true);
                let mut fx = Effects::default();
                let r = imp.resolve(py, cx, cfg, &site, &mut fx);
                let lines = super::jumptable::set_trace(false);
                r?;
                return Ok(Some((imp.shadow_detail().unwrap_or_default(), lines)));
            }
        }
        Ok(None)
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in &self.cx.stats {
            d.set_item(k, *v)?;
        }
        let (h, m) = self.cx.ir_cache_stats();
        d.set_item("ir_cache:hit", h)?;
        d.set_item("ir_cache:miss", m)?;
        Ok(d)
    }

    /// Shadow-mode mismatches, one dict each.
    fn mismatches<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, self.mismatches.iter().map(|m| m.bind(py)))
    }
}

impl ResolverChain {
    /// The timeless phase hands Python resolvers an existing IRSB; a Rust resolver only runs when its own lift has
    /// the same statement count (the default engine's block cache can return a different block than a fresh lift).
    fn ir_matches(&mut self, py: Python<'_>, site: &JumpSite, block_nstmts: i64) -> PyResult<bool> {
        if block_nstmts < 0 {
            return Ok(true);
        }
        Ok(match self.cx.ir(py, &site.block)? {
            Ok(ir) => {
                let same = ir.stmts.len() as i64 == block_nstmts;
                if !same {
                    self.cx.count("ir_mismatch");
                }
                same
            }
            Err(_) => true,
        })
    }
}
