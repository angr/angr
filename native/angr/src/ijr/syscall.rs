//! `SyscallResolver`: the filter in Rust. A syscall whose number is a block-local constant is resolved here; any
//! other needs symbolic execution, so it declines to the twin.

use std::collections::HashMap;
use std::sync::OnceLock;

use pyo3::prelude::*;

use super::{Decision, Effects, IrSpec, JumpSite, Outcome, ResolveCx, Resolver};
use crate::ailment::vexop_names::IROP_NAMES;
use crate::vexir::{Expr, ExprId, Stmt, VexIrsb};
use crate::vexlift::{VEX_IRSB_MAX_SIZE, jumpkind_from_name, jumpkind_name};

/// What `SyscallResolver.rust_fast_path` returns: how `SimUserland.syscall` reads the number and maps it to a stub.
pub struct FastPath {
    /// The register `cc.syscall_num(state)` reads: (offset, size).
    pub num_reg: (i32, u32),
    /// `syscall_abi(state)` by VEX jumpkind; None when it is None for every jumpkind.
    pub abis: Option<HashMap<u32, String>>,
    /// The VEX optimization level the fastpath engine lifts with.
    pub opt_level: i32,
    /// `stub_addr(number, abi)`: `simos.syscall_from_number(number, abi=abi).addr`.
    pub stub_addr: Py<PyAny>,
    stubs: HashMap<(u64, Option<String>), u64>,
}

/// `((offset, size) of the syscall number register, jumpkind -> ABI, opt_level, stub_addr)`
type FastPathArgs = ((i32, u32), Option<HashMap<String, String>>, i32, Py<PyAny>);

impl FastPath {
    pub fn from_py(t: &Bound<'_, PyAny>) -> PyResult<Self> {
        let (num_reg, abis, opt_level, stub_addr): FastPathArgs = t.extract()?;
        let abis = match abis {
            None => None,
            Some(m) => {
                let mut out = HashMap::new();
                for (jk, abi) in m {
                    let code = jumpkind_from_name(&jk).ok_or_else(|| {
                        pyo3::exceptions::PyValueError::new_err(format!("unknown jumpkind {jk}"))
                    })?;
                    out.insert(code, abi);
                }
                Some(out)
            }
        };
        Ok(FastPath {
            num_reg,
            abis,
            opt_level,
            stub_addr,
            stubs: HashMap::new(),
        })
    }
}

pub struct SyscallResolver {
    /// `SyscallResolver._os_resolves_syscalls`
    pub os_resolves_syscalls: bool,
    pub fast: Option<FastPath>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpClass {
    /// Not known to evaluate without raising in the fastpath engine.
    Unsafe,
    /// Safe; the value is not tracked.
    Opaque,
    Add(u32),
    Sub(u32),
    And(u32),
    Or(u32),
    Xor(u32),
    /// `Iop_NUtoM`
    ZeroExt,
    /// `Iop_NtoM`
    Truncate(u32),
}

fn classify(name: &str) -> OpClass {
    let Some(n) = name.strip_prefix("Iop_") else {
        return OpClass::Unsafe;
    };
    let width = |s: &str| -> Option<u32> {
        match s {
            "8" => Some(8),
            "16" => Some(16),
            "32" => Some(32),
            "64" => Some(64),
            _ => None,
        }
    };
    for (prefix, f) in [
        ("Add", OpClass::Add as fn(u32) -> OpClass),
        ("Sub", OpClass::Sub),
        ("And", OpClass::And),
        ("Or", OpClass::Or),
        ("Xor", OpClass::Xor),
    ] {
        if let Some(w) = n.strip_prefix(prefix).and_then(width) {
            return f(w);
        }
    }
    for prefix in ["Mul", "Shl", "Shr", "Sar", "Not", "CmpEQ", "CmpNE"] {
        if n.strip_prefix(prefix).and_then(width).is_some() {
            return OpClass::Opaque;
        }
    }
    for prefix in ["CmpLT", "CmpLE"] {
        if let Some(rest) = n.strip_prefix(prefix)
            && let Some(w) = rest.strip_suffix('S').or_else(|| rest.strip_suffix('U'))
            && width(w).is_some()
        {
            return OpClass::Opaque;
        }
    }
    // integer conversions: NUtoM, NStoM, NtoM, NHLtoM, NHItoM
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if let Some((from, to)) = n.split_once("to")
        && digits(to)
    {
        if let Some(f) = from.strip_suffix('U')
            && digits(f)
        {
            return OpClass::ZeroExt;
        }
        if digits(from) {
            return OpClass::Truncate(to.parse().unwrap_or(0));
        }
        let f = from
            .strip_suffix('S')
            .or_else(|| from.strip_suffix("HL"))
            .or_else(|| from.strip_suffix("HI"));
        if f.is_some_and(digits) {
            return OpClass::Opaque;
        }
    }
    OpClass::Unsafe
}

fn op_class(op: u32) -> OpClass {
    static TABLE: OnceLock<Vec<OpClass>> = OnceLock::new();
    let t = TABLE.get_or_init(|| IROP_NAMES.iter().map(|n| classify(n)).collect());
    op.checked_sub(crate::ailment::vexop_names::IOP_BASE)
        .and_then(|i| t.get(i as usize).copied())
        .unwrap_or(OpClass::Unsafe)
}

fn mask(v: u64, bits: u32) -> u64 {
    if bits >= 64 {
        v
    } else {
        v & ((1u64 << bits) - 1)
    }
}

/// Ok(value) when the fastpath engine evaluates `e` without raising (None: not a known constant), Err(()) otherwise.
fn eval(ir: &VexIrsb, tmps: &[Option<u64>], e: ExprId) -> Result<Option<u64>, ()> {
    match ir.expr(e).ok_or(())? {
        Expr::Const(c) => c.int_value().map(Some).ok_or(()),
        Expr::RdTmp(t) => Ok(tmps.get(*t as usize).copied().flatten()),
        Expr::Get { .. } => Ok(None),
        Expr::Load { addr, .. } => eval(ir, tmps, *addr).map(|_| None),
        Expr::Unop { op, arg } => {
            let class = op_class(*op);
            if class == OpClass::Unsafe {
                return Err(());
            }
            let Some(v) = eval(ir, tmps, *arg)? else {
                return Ok(None);
            };
            Ok(match class {
                OpClass::ZeroExt => Some(v),
                OpClass::Truncate(bits) => Some(mask(v, bits)),
                _ => None,
            })
        }
        Expr::Binop { op, args } => {
            let class = op_class(*op);
            if class == OpClass::Unsafe {
                return Err(());
            }
            let a = eval(ir, tmps, args[0])?;
            let b = eval(ir, tmps, args[1])?;
            let (Some(a), Some(b)) = (a, b) else {
                return Ok(None);
            };
            Ok(match class {
                OpClass::Add(w) => Some(mask(a.wrapping_add(b), w)),
                OpClass::Sub(w) => Some(mask(a.wrapping_sub(b), w)),
                OpClass::And(w) => Some(mask(a & b, w)),
                OpClass::Or(w) => Some(mask(a | b, w)),
                OpClass::Xor(w) => Some(mask(a ^ b, w)),
                _ => None,
            })
        }
        Expr::Ite {
            cond,
            iftrue,
            iffalse,
        } => {
            for x in [*cond, *iftrue, *iffalse] {
                eval(ir, tmps, x)?;
            }
            Ok(None)
        }
        // without DO_CCALLS the engine returns a fresh symbol
        Expr::CCall { args, .. } => {
            for &x in ir.arg_ids(*args) {
                eval(ir, tmps, x)?;
            }
            Ok(None)
        }
        _ => Err(()),
    }
}

/// The value of `reg` after the block when every statement is one the fastpath engine runs without raising (so no
/// statement is skipped) and the block has no conditional exit. None when only symbolic execution can tell.
fn block_local_reg(ir: &VexIrsb, reg: (i32, u32)) -> Option<u64> {
    let (off, size) = (reg.0 as i64, reg.1 as i64);
    let mut tmps: Vec<Option<u64>> = vec![None; ir.tyenv.len()];
    let mut val = None;
    for s in &ir.stmts {
        match s {
            Stmt::IMark { .. } | Stmt::NoOp | Stmt::AbiHint { .. } => {}
            Stmt::WrTmp { tmp, data } => {
                let v = eval(ir, &tmps, *data).ok()?;
                if let Some(slot) = tmps.get_mut(*tmp as usize) {
                    *slot = v;
                }
            }
            Stmt::Put { offset, data } => {
                let v = eval(ir, &tmps, *data).ok()?;
                let (o, n) = (*offset as i64, (ir.result_bits(*data) / 8) as i64);
                if o == off && n == size {
                    val = v;
                } else if o < off + size && off < o + n {
                    val = None;
                }
            }
            Stmt::Store { addr, data, .. } => {
                eval(ir, &tmps, *addr).ok()?;
                eval(ir, &tmps, *data).ok()?;
            }
            _ => return None,
        }
    }
    val
}

impl Resolver for SyscallResolver {
    fn kind(&self) -> &'static str {
        "SyscallResolver"
    }

    fn timeless(&self) -> bool {
        true
    }

    fn filter(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        Ok(Decision::Done(
            self.os_resolves_syscalls && jumpkind_name(j.jumpkind).starts_with("Ijk_Sys"),
        ))
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        let Some(fast) = &mut self.fast else {
            return Ok(Decision::Python("symbolic"));
        };
        // _resolve_syscall_to_stub: cfg.functions.contains_addr(func_addr)
        let Some(store) = cx.functions(py, cfg)? else {
            return Ok(Decision::Python("no_store"));
        };
        if !store.bind(py).borrow().contains(j.func_addr) {
            return Ok(Decision::Python("no_function"));
        }
        let abi = match &fast.abis {
            None => None,
            Some(m) => match m.get(&j.jumpkind) {
                Some(a) => Some(a.clone()),
                None => return Ok(Decision::Python("abi")),
            },
        };
        let addr = j.block.addr;
        if cx.is_hooked(py, addr)? {
            return Ok(Decision::Python("hooked"));
        }
        // the block factory.successors(blank_state(addr=block.addr, mode="fastpath")) lifts
        let spec = IrSpec {
            addr,
            max_size: VEX_IRSB_MAX_SIZE as i64,
            opt_level: fast.opt_level,
            cross_insn_opt: true,
            extra_stops: false,
        };
        let Ok(ir) = cx.ir(py, &spec)? else {
            return Ok(Decision::Python("lift"));
        };
        if ir.jumpkind != j.jumpkind {
            return Ok(Decision::Python("jumpkind"));
        }
        let Some(num) = block_local_reg(&ir, fast.num_reg) else {
            return Ok(Decision::Python("symbolic"));
        };
        let key = (num, abi);
        let stub = match fast.stubs.get(&key) {
            Some(&s) => s,
            None => {
                let s: u64 = fast
                    .stub_addr
                    .bind(py)
                    .call1((num, key.1.as_deref()))?
                    .extract()?;
                fast.stubs.insert(key, s);
                s
            }
        };
        Ok(Decision::Done(Outcome::Resolved(vec![stub])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_classes() {
        assert!(classify("Iop_Add32") == OpClass::Add(32));
        assert!(classify("Iop_32Uto64") == OpClass::ZeroExt);
        assert!(classify("Iop_64to32") == OpClass::Truncate(32));
        assert!(classify("Iop_32HLto64") == OpClass::Opaque);
        assert!(classify("Iop_8Sto32") == OpClass::Opaque);
        assert!(classify("Iop_CmpLT32S") == OpClass::Opaque);
        assert!(classify("Iop_DivU32") == OpClass::Unsafe);
        assert!(classify("Iop_64UtoV128") == OpClass::Unsafe);
        assert!(classify("Iop_F32toF64") == OpClass::Unsafe);
        assert!(classify("Iop_MullS32") == OpClass::Unsafe);
    }
}
