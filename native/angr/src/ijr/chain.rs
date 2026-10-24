//! `ResolverChain`: the ordered resolver lists and the dispatch loops of `_resolve_indirect_jump_timelessly` and
//! `_process_one_indirect_jump`.

use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};

use super::{Decision, Effects, IrSpec, JumpSite, Outcome, Phase, ResolveCx, Resolver, make_resolver};
use crate::cfg_scan::LoaderSnapshot;
use crate::vexlift::{NextExpr, VEX_IRSB_MAX_SIZE, VexLifter, jumpkind_from_name, jumpkind_name};

enum Entry {
    Rust { imp: Box<dyn Resolver>, twin: Py<PyAny> },
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
            Some(b) => self.cfg.call_method1(intern!(py, "_ijr_stmt_block"), (b,))?,
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
    mismatches: Vec<Py<PyAny>>,
}

fn targets_vec(t: &Bound<'_, PyAny>) -> Option<Vec<u64>> {
    t.try_iter().ok()?.map(|x| x.ok()?.extract::<u64>().ok()).collect()
}

fn outcome_repr(o: &Outcome) -> String {
    match o {
        Outcome::Resolved(t) => format!("resolved {:?}", t.iter().map(|x| format!("{x:#x}")).collect::<Vec<_>>()),
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
    fn build_entries(py: Python<'_>, items: Vec<(Option<String>, Py<PyAny>)>) -> PyResult<Vec<Entry>> {
        let mut out = Vec::with_capacity(items.len());
        for (kind, obj) in items {
            let imp = match &kind {
                Some(k) => make_resolver(k, obj.bind(py))?,
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
            obj.setattr(intern!(py, "base_state"), cfg.getattr(intern!(py, "_base_state"))?)?;
        }
        let b = block.get()?;
        obj.call_method1(intern!(py, "filter"), (cfg, j.addr, j.func_addr, b, jumpkind))?
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
            Phase::Timeless => obj.call_method1(intern!(py, "resolve"), (cfg, j.addr, j.func_addr, b, jumpkind))?,
            Phase::Deferred { func_graph_complete } => {
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
            let rust: Result<(bool, Option<Outcome>), &'static str> = match imp.filter(py, cx, j)? {
                Decision::Python(r) => Err(r),
                Decision::Done(false) => Ok((false, None)),
                Decision::Done(true) => {
                    let mut fx = Effects::default();
                    match imp.resolve(py, cx, j, &mut fx)? {
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
            match &rust {
                Err(reason) => cx.count(&format!("{kind}:shadow_decline:{reason}")),
                Ok((rf, ro)) => {
                    if *rf != pf {
                        Self::record(mismatches, py, j, kind, "filter", rf.to_string(), pf.to_string())?;
                    } else if let (Some(o), Some(a)) = (ro, &pa) {
                        let po = answer_outcome(a);
                        if po.as_ref() != Some(o) {
                            let prepr = match &po {
                                Some(p) => outcome_repr(p),
                                None => format!("unparsed {}", a.targets.repr()?),
                            };
                            Self::record(mismatches, py, j, kind, "resolve", outcome_repr(o), prepr)?;
                        } else {
                            cx.count(&format!("{kind}:shadow_same"));
                        }
                    } else {
                        cx.count(&format!("{kind}:shadow_same"));
                    }
                }
            }
            return Ok(pa);
        }

        match imp.filter(py, cx, j)? {
            Decision::Done(false) => return Ok(None),
            Decision::Done(true) => {}
            Decision::Python(reason) => {
                cx.count(&format!("{kind}:decline:{reason}"));
                if !Self::py_filter(twin, cfg, j, jumpkind, block)? {
                    return Ok(None);
                }
                return Ok(Some(Self::py_resolve(twin, cfg, j, jumpkind, block)?));
            }
        }
        let mut fx = Effects::default();
        match imp.resolve(py, cx, j, &mut fx)? {
            Decision::Python(reason) => {
                cx.count(&format!("{kind}:decline:{reason}"));
                Ok(Some(Self::py_resolve(twin, cfg, j, jumpkind, block)?))
            }
            Decision::Done(o) => {
                cx.count(&format!("{kind}:rust"));
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
}

#[pymethods]
impl ResolverChain {
    /// :param timeless:   ``(kind or None, resolver)`` per entry of ``cfg.timeless_indirect_jump_resolvers``.
    /// :param deferred:   The same for ``cfg.indirect_jump_resolvers``.
    #[new]
    #[pyo3(signature = (lifter, snapshot, sim_procedures, extra_stop_points, exec_regions, arch_bits, arch_bytes, strict_block_end, default_opt_level, rust_precheck, timeless, deferred, shadow))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        lifter: Py<VexLifter>,
        snapshot: &LoaderSnapshot,
        sim_procedures: Py<PyDict>,
        extra_stop_points: Py<PyAny>,
        exec_regions: Vec<(u64, u64)>,
        arch_bits: u32,
        arch_bytes: u32,
        strict_block_end: bool,
        default_opt_level: i32,
        rust_precheck: bool,
        timeless: Vec<(Option<String>, Py<PyAny>)>,
        deferred: Vec<(Option<String>, Py<PyAny>)>,
        shadow: bool,
    ) -> PyResult<Self> {
        let cx = ResolveCx::new(
            snapshot.inner.clone(),
            lifter,
            sim_procedures,
            extra_stop_points,
            exec_regions,
            arch_bits,
            arch_bytes,
            strict_block_end,
            default_opt_level,
        );
        Ok(ResolverChain {
            cx,
            timeless: Self::build_entries(py, timeless)?,
            deferred: Self::build_entries(py, deferred)?,
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
        let python_precheck = |block: &Bound<'py, PyAny>| -> PyResult<Option<(bool, Bound<'py, PyAny>)>> {
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
                            Some((true, t)) => targets_vec(t).and_then(|v| (v.len() == 1).then(|| Some(v[0]))),
                            Some((false, _)) => None,
                        };
                        if pr.as_ref() != Some(r) {
                            let site = JumpSite {
                                addr,
                                func_addr,
                                jumpkind: jumpkind_from_name(&jumpkind.extract::<String>()?).unwrap_or(u32::MAX),
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
                    ..
                } = self;
                let Entry::Rust { imp, .. } = &mut timeless[idx] else {
                    unreachable!()
                };
                Self::run_rust(
                    cx,
                    mismatches,
                    *shadow,
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
            phase: Phase::Deferred { func_graph_complete },
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
                    ..
                } = self;
                let Entry::Rust { imp, .. } = &mut entries[idx] else {
                    unreachable!()
                };
                Self::run_rust(
                    cx,
                    mismatches,
                    *shadow,
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
        Ok((false, py.None().into_bound(py), py.None().into_bound(py), deferred))
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
