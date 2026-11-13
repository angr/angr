//! Direct libVEX lifting for CFGFast (`angr.rustylib.vexlift`).
//!
//! [`VexLifter::lift`] calls libpyvex's `vex_lift` on the loader's own backer buffers and reads the
//! full `VEXLiftResult` into a compact, Rust-owned [`LiftSummary`]: everything CFGFast's main scan
//! reads from a statement-less pyvex IRSB (size, jumpkind, next, instruction addresses, exits, data
//! refs, const vals), without constructing pyvex IRSB / angr Block objects. The lifting policy
//! mirrors `VEXLifter.lift_vex` + `pyvex.lift` + `LibVEXLifter._lift`; anything those would handle
//! with Python lifters, statement re-lifts or block merging is reported as a [`Fallback`] so the
//! caller takes the Python path. The symbols are resolved at runtime against the loaded libpyvex
//! (see `ailment::vex_ffi`), so there is no link-time dependency.

use std::ffi::c_int;
use std::sync::Mutex;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyDict, PyTuple};

use crate::ailment::vex_ffi::{
    self, ICO_U1, ICO_U8, ICO_U16, ICO_U32, ICO_U64, IEX_CONST, IEX_RDTMP, IRConst, IRSB, IST_EXIT,
    VexArchInfo, VexCacheInfo,
};

pub const MAX_EXITS: usize = 400;
pub const MAX_DATA_REFS: usize = 2000;
pub const MAX_CONST_VALS: usize = 1000;
pub const MAX_INST_ADDRS: usize = 200;
/// `angr.engines.vex.lifter.VEX_IRSB_MAX_SIZE`.
pub const VEX_IRSB_MAX_SIZE: u32 = 400;
/// `pyvex.lifting.libvex.VEX_MAX_INSTRUCTIONS` / `VEX_MAX_BYTES`.
pub const VEX_MAX_INSTRUCTIONS: u32 = 99;
pub const VEX_MAX_BYTES: u32 = 5000;

pub const IJK_INVALID: u32 = 0x1A00;
pub const IJK_BORING: u32 = 0x1A01;
pub const IJK_NODECODE: u32 = 0x1A08;

/// `VexRegisterUpdates` values (pyvex.lifting.libvex.VexRegisterUpdates).
pub const PX_UNWINDREGS_AT_MEM_ACCESS: u32 = 0x702;
pub const PX_LD_ALLREGS_AT_EACH_INSN: u32 = 0x705;

// ---------------------------------------------------------------------------
// Full `VEXLiftResult` layout (pyvex_c/pyvex.h). 91264 bytes, checked against cffi.
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct CExitInfo {
    pub stmt_idx: c_int,
    pub ins_addr: u64,
    pub stmt: *mut vex_ffi::IRStmt,
}

#[repr(C)]
pub struct CDataRef {
    pub data_addr: u64,
    pub size: c_int,
    pub data_type: u32,
    pub stmt_idx: c_int,
    pub ins_addr: u64,
}

#[repr(C)]
pub struct CConstVal {
    pub tmp: c_int,
    pub stmt_idx: c_int,
    pub value: u64,
}

#[repr(C)]
pub struct VEXLiftResult {
    pub irsb: *mut IRSB,
    pub size: c_int,
    pub is_noop_block: u8,
    pub exit_count: c_int,
    pub exits: [CExitInfo; MAX_EXITS],
    pub is_default_exit_constant: c_int,
    pub default_exit: u64,
    pub insts: c_int,
    pub inst_addrs: [u64; MAX_INST_ADDRS],
    pub data_ref_count: c_int,
    pub data_refs: [CDataRef; MAX_DATA_REFS],
    pub const_val_count: c_int,
    pub const_vals: [CConstVal; MAX_CONST_VALS],
}

const _: () = assert!(std::mem::size_of::<VEXLiftResult>() == 91264);
const _: () = assert!(std::mem::offset_of!(VEXLiftResult, exits) == 24);
const _: () = assert!(std::mem::offset_of!(VEXLiftResult, inst_addrs) == 9648);
const _: () = assert!(std::mem::offset_of!(VEXLiftResult, data_refs) == 11256);
const _: () = assert!(std::mem::offset_of!(VEXLiftResult, const_vals) == 75264);

// ---------------------------------------------------------------------------
// Enum tables
// ---------------------------------------------------------------------------

pub const JUMPKIND_NAMES: [&str; 31] = [
    "Ijk_INVALID",
    "Ijk_Boring",
    "Ijk_Call",
    "Ijk_Ret",
    "Ijk_ClientReq",
    "Ijk_Yield",
    "Ijk_EmWarn",
    "Ijk_EmFail",
    "Ijk_NoDecode",
    "Ijk_MapFail",
    "Ijk_InvalICache",
    "Ijk_FlushDCache",
    "Ijk_NoRedir",
    "Ijk_SigILL",
    "Ijk_SigTRAP",
    "Ijk_SigSEGV",
    "Ijk_SigBUS",
    "Ijk_SigFPE",
    "Ijk_SigFPE_IntDiv",
    "Ijk_SigFPE_IntOvf",
    "Ijk_Privileged",
    "Ijk_Sys_syscall",
    "Ijk_Sys_int",
    "Ijk_Sys_int32",
    "Ijk_Sys_int128",
    "Ijk_Sys_int129",
    "Ijk_Sys_int130",
    "Ijk_Sys_int145",
    "Ijk_Sys_int210",
    "Ijk_Sys_sysenter",
    "Ijk_Extension",
];

/// `IRJumpKind` int -> the pyvex enum string ("Ijk_INVALID" for unknown values).
pub fn jumpkind_name(jk: u32) -> &'static str {
    match jk.checked_sub(IJK_INVALID) {
        Some(i) if (i as usize) < JUMPKIND_NAMES.len() => JUMPKIND_NAMES[i as usize],
        _ => "Ijk_INVALID",
    }
}

/// The pyvex enum string -> `IRJumpKind` int.
pub fn jumpkind_from_name(name: &str) -> Option<u32> {
    JUMPKIND_NAMES
        .iter()
        .position(|&n| n == name)
        .map(|i| IJK_INVALID + i as u32)
}

/// `pyvex.data_ref.data_ref_type_str`.
pub fn data_ref_type_str(dt: u32) -> &'static str {
    match dt {
        0x9000 => "unknown",
        0x9001 => "integer",
        0x9002 => "fp",
        0x9003 => "integer(store)",
        _ => "INVALID",
    }
}

/// Value of an integer `IRConst` as pyvex's `IRConst.value` exposes it; None for non-integer tags.
///
/// # Safety
/// `c` must point to a live libVEX `IRConst`.
unsafe fn const_int_value(c: *const IRConst) -> Option<u64> {
    if c.is_null() {
        return None;
    }
    let c = unsafe { &*c };
    unsafe {
        Some(match c.tag {
            ICO_U1 => c.ico.u1 as u64,
            ICO_U8 => c.ico.u8_ as u64,
            ICO_U16 => c.ico.u16_ as u64,
            ICO_U32 => c.ico.u32_ as u64,
            ICO_U64 => c.ico.u64_,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Summary types
// ---------------------------------------------------------------------------

/// The block's default-exit expression, reduced to what CFGFast consumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextExpr {
    Const(u64),
    Tmp(u32),
    Other,
}

/// A conditional exit (`Ist_Exit`) of the block.
#[pyclass(
    name = "Exit",
    module = "angr.rustylib.vexlift",
    frozen,
    from_py_object
)]
#[derive(Clone, Debug)]
pub struct Exit {
    #[pyo3(get)]
    pub stmt_idx: i32,
    #[pyo3(get)]
    pub ins_addr: u64,
    #[pyo3(get)]
    pub dst: u64,
    pub jumpkind: u32,
}

#[pymethods]
impl Exit {
    #[getter]
    fn jumpkind(&self) -> &'static str {
        jumpkind_name(self.jumpkind)
    }

    fn __repr__(&self) -> String {
        format!(
            "<Exit stmt {} at {:#x} -> {:#x} {}>",
            self.stmt_idx,
            self.ins_addr,
            self.dst,
            jumpkind_name(self.jumpkind)
        )
    }
}

/// A data reference collected by libpyvex (`pyvex.data_ref.DataRef`).
#[pyclass(
    name = "DataRef",
    module = "angr.rustylib.vexlift",
    frozen,
    from_py_object
)]
#[derive(Clone, Debug)]
pub struct DataRef {
    #[pyo3(get)]
    pub data_addr: u64,
    #[pyo3(get)]
    pub data_size: i32,
    #[pyo3(get)]
    pub data_type: u32,
    #[pyo3(get)]
    pub stmt_idx: i32,
    #[pyo3(get)]
    pub ins_addr: u64,
}

#[pymethods]
impl DataRef {
    #[getter]
    fn data_type_str(&self) -> &'static str {
        data_ref_type_str(self.data_type)
    }

    fn __repr__(&self) -> String {
        format!(
            "<DataRef accessing {:#x} {}:{} at {:#x}:{}>",
            self.data_addr,
            data_ref_type_str(self.data_type),
            self.data_size,
            self.ins_addr,
            self.stmt_idx
        )
    }
}

/// A constant tmp value from lift-time constant propagation (`pyvex.const_val.ConstVal`).
#[pyclass(
    name = "ConstVal",
    module = "angr.rustylib.vexlift",
    frozen,
    from_py_object
)]
#[derive(Clone, Debug)]
pub struct ConstVal {
    #[pyo3(get)]
    pub tmp: i32,
    #[pyo3(get)]
    pub stmt_idx: i32,
    #[pyo3(get)]
    pub value: u64,
}

#[pymethods]
impl ConstVal {
    fn __repr__(&self) -> String {
        format!(
            "<ConstVal t{} = {:#x} at stmt {}>",
            self.tmp, self.value, self.stmt_idx
        )
    }
}

/// A conditional successor as `CFGFast._scan_irsb` enumerates it: (stmt_idx, branch ins addr, target, jumpkind).
#[derive(Clone, Copy, Debug)]
pub struct Successor {
    pub stmt_idx: i32,
    pub ins_addr: u64,
    pub dst: u64,
    pub jumpkind: u32,
}

/// Statement-less summary of one lifted block. Fields are settable because `_generate_cfgnode` shrinks a block
/// that runs into a prologue-derived function start, and ARM heuristics rewrite the jumpkind.
#[pyclass(name = "LiftSummary", module = "angr.rustylib.vexlift")]
#[derive(Clone, Debug)]
pub struct LiftSummary {
    /// Lift address, with the THUMB bit (pyvex `IRSB.addr`).
    #[pyo3(get)]
    pub addr: u64,
    #[pyo3(get, set)]
    pub size: u32,
    pub jumpkind: u32,
    pub next: NextExpr,
    #[pyo3(get)]
    pub is_noop_block: bool,
    #[pyo3(get)]
    pub instructions: u32,
    pub instruction_addresses: Vec<u64>,
    #[pyo3(get, set)]
    pub exits: Vec<Exit>,
    #[pyo3(get)]
    pub default_exit_target: Option<u64>,
    #[pyo3(get, set)]
    pub data_refs: Vec<DataRef>,
    #[pyo3(get)]
    pub const_vals: Vec<ConstVal>,
    /// The MIPS32 $gp prologue scan, when the lift asked for it.
    pub mips_gp: Option<MipsGpScan>,
}

/// What `CFGFast._mips_determine_function_gp` reads from a MIPS32 block's statements.
#[derive(Clone, Debug)]
pub struct MipsGpScan {
    /// The $t9 value the scan assumed.
    pub func_addr: u64,
    /// Number of IMarks.
    pub insns: usize,
    /// (1-based instruction index, instruction address) of the last instruction that writes $gp.
    pub last_gp: Option<(usize, u64)>,
    /// `CFGFast._mips_gp_from_statements`: Some(gp) when decided, None when only symbolic stepping can decide.
    pub value: Option<Option<u64>>,
}

impl LiftSummary {
    /// `CFGFast._is_branch_vex_artifact_only`: a non-final Boring exit back to its own instruction (CAS retry).
    pub fn is_branch_vex_artifact_only(
        &self,
        branch_delay_slot: bool,
        branch_ins_addr: u64,
        exit: &Exit,
    ) -> bool {
        !branch_delay_slot
            && self
                .instruction_addresses
                .last()
                .is_some_and(|&last| branch_ins_addr != last)
            && exit.dst == branch_ins_addr
            && exit.jumpkind == IJK_BORING
    }

    /// The conditional successors of the block, exactly as the statement-less branch of `CFGFast._scan_irsb`
    /// derives them: delay-slot attribution of the branch instruction and VEX-artifact exits dropped.
    pub fn conditional_successors(&self, branch_delay_slot: bool) -> Vec<Successor> {
        let ia = &self.instruction_addresses;
        let mut out = Vec::with_capacity(self.exits.len());
        for e in &self.exits {
            let mut branch_ins_addr = e.ins_addr;
            let pos = if branch_delay_slot {
                ia.iter().position(|&a| a == e.ins_addr)
            } else {
                None
            };
            if let Some(idx) = pos {
                if idx > 0 {
                    let next_ins_addr = if idx + 1 < ia.len() {
                        ia[idx + 1]
                    } else {
                        self.addr.wrapping_add(self.size as u64)
                    };
                    if (next_ins_addr as i128 - e.ins_addr as i128)
                        <= (e.ins_addr as i128 - ia[idx - 1] as i128)
                    {
                        branch_ins_addr = ia[idx - 1];
                    }
                }
            } else if self.is_branch_vex_artifact_only(branch_delay_slot, branch_ins_addr, e) {
                continue;
            }
            out.push(Successor {
                stmt_idx: e.stmt_idx,
                ins_addr: branch_ins_addr,
                dst: e.dst,
                jumpkind: e.jumpkind,
            });
        }
        out
    }
}

#[pymethods]
impl LiftSummary {
    #[getter]
    fn jumpkind(&self) -> &'static str {
        jumpkind_name(self.jumpkind)
    }

    #[setter]
    fn set_jumpkind(&mut self, name: &str) -> PyResult<()> {
        self.jumpkind = jumpkind_from_name(name)
            .ok_or_else(|| PyValueError::new_err(format!("unknown jumpkind {name}")))?;
        Ok(())
    }

    /// The default exit target when it is a constant, else None.
    #[getter]
    fn next(&self) -> Option<u64> {
        match self.next {
            NextExpr::Const(v) => Some(v),
            _ => None,
        }
    }

    #[setter]
    fn set_next(&mut self, value: u64) {
        self.next = NextExpr::Const(value);
    }

    /// The tmp the default exit reads (`IRExpr.RdTmp`), else None.
    #[getter]
    fn next_tmp(&self) -> Option<u32> {
        match self.next {
            NextExpr::Tmp(t) => Some(t),
            _ => None,
        }
    }

    #[getter]
    fn instruction_addresses<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, self.instruction_addresses.iter().copied())
    }

    #[setter]
    fn set_instruction_addresses(&mut self, addrs: Vec<u64>) {
        self.instruction_addresses = addrs;
    }

    /// pyvex `IRSB.exit_statements` shape: (ins_addr, stmt_idx, Exit) per conditional exit.
    #[getter]
    fn exit_statements<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        let items: Vec<(u64, i32, Exit)> = self
            .exits
            .iter()
            .map(|e| (e.ins_addr, e.stmt_idx, e.clone()))
            .collect();
        PyTuple::new(py, items)
    }

    /// Always None: the summary carries no statements.
    #[getter]
    fn statements(&self, py: Python<'_>) -> Py<PyAny> {
        py.None()
    }

    #[getter]
    fn has_statements(&self) -> bool {
        false
    }

    /// (stmt_idx, branch_ins_addr, target, jumpkind) per conditional exit; see [`LiftSummary::conditional_successors`].
    #[pyo3(name = "conditional_successors")]
    fn py_conditional_successors(
        &self,
        branch_delay_slot: bool,
    ) -> Vec<(i32, u64, u64, &'static str)> {
        self.conditional_successors(branch_delay_slot)
            .into_iter()
            .map(|s| (s.stmt_idx, s.ins_addr, s.dst, jumpkind_name(s.jumpkind)))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "<LiftSummary {:#x} size {} {} insts {} exits {} data refs {}>",
            self.addr,
            self.size,
            jumpkind_name(self.jumpkind),
            self.instructions,
            self.exits.len(),
            self.data_refs.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Lifting
// ---------------------------------------------------------------------------

/// Why a block could not be summarized directly and must take the Python lifting path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// No loader backer contains the address (`_load_bytes` yields no bytes).
    NoBacker,
    /// The backer is not bytes/bytearray (`VEXLifter._load_bytes` raises).
    UnsupportedBacker,
    /// The byte window is empty (`pyvex.lift` raises on `max_bytes <= 0`).
    EmptyWindow,
    /// The backer offset does not fit libVEX's 32-bit lookback argument.
    OffsetOverflow,
    /// `vex_lift` returned NULL (libVEX failed; pyvex would try the gym spotters).
    LiftFailed,
    /// libVEX decoded nothing (`LibVEXLifter` raises; pyvex would try the gym spotters).
    NoInstructions,
    /// More than `MAX_EXITS` exits: pyvex re-lifts with statements (`SkipStatementsError`).
    TooManyExits,
    /// Partial `Ijk_NoDecode`: pyvex re-lifts with statements and merges the continuation.
    PartialNoDecode,
    /// A `next` / exit constant of a non-integer type.
    UnsupportedConst,
    /// The libpyvex symbols are unavailable.
    NoSymbols,
}

impl Fallback {
    pub fn name(self) -> &'static str {
        match self {
            Fallback::NoBacker => "no_backer",
            Fallback::UnsupportedBacker => "unsupported_backer",
            Fallback::EmptyWindow => "empty_window",
            Fallback::OffsetOverflow => "offset_overflow",
            Fallback::LiftFailed => "lift_failed",
            Fallback::NoInstructions => "no_instructions",
            Fallback::TooManyExits => "too_many_exits",
            Fallback::PartialNoDecode => "partial_nodecode",
            Fallback::UnsupportedConst => "unsupported_const",
            Fallback::NoSymbols => "no_symbols",
        }
    }
}

/// `vex_lift` knobs (pyvex.lift / LibVEXLifter arguments).
#[derive(Clone, Copy, Debug)]
pub struct LiftOptions {
    pub opt_level: i32,
    pub traceflags: i32,
    pub strict_block_end: bool,
    pub collect_data_refs: bool,
    pub load_from_ro_regions: bool,
    pub const_prop: bool,
    pub cross_insn_opt: bool,
    pub max_inst: u32,
}

impl LiftOptions {
    /// What `CFGFast._generate_cfgnode` passes through `CFGFast._lift`.
    pub fn cfgfast_main(const_prop: bool) -> Self {
        LiftOptions {
            opt_level: 1,
            traceflags: 0,
            strict_block_end: true,
            collect_data_refs: true,
            load_from_ro_regions: true,
            const_prop,
            cross_insn_opt: false,
            max_inst: VEX_MAX_INSTRUCTIONS,
        }
    }
}

/// `VexArchInfo` minus the cache pointer, so the lifter stays `Send`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArchInfo {
    pub hwcaps: u32,
    pub endness: i32,
    pub hwcache_num_levels: u32,
    pub hwcache_num_caches: u32,
    pub icaches_maintain_coherence: u8,
    pub ppc_icache_line_sz_b: i32,
    pub ppc_dcbz_sz_b: u32,
    pub ppc_scv_supported: u8,
    pub ppc_dcbzl_sz_b: u32,
    pub arm64_d_min_line_lg2_sz_b: u32,
    pub arm64_i_min_line_lg2_sz_b: u32,
    pub arm64_cache_block_size: u8,
    pub arm64_requires_fallback_llsc: u8,
    pub x86_cr0: u32,
}

impl ArchInfo {
    /// Marshal `arch.vex_archinfo` the way cffi does for `LibVEXLifter._lift`: missing keys are zero, the cache
    /// pointer is NULL.
    pub fn from_py_dict(vai: &Bound<'_, PyDict>) -> PyResult<Self> {
        fn geti(d: &Bound<'_, PyDict>, k: &str) -> PyResult<i64> {
            match d.get_item(k)? {
                Some(v) if !v.is_none() => {
                    if let Ok(b) = v.extract::<bool>() {
                        return Ok(b as i64);
                    }
                    v.extract::<i64>()
                }
                _ => Ok(0),
            }
        }
        let (num_levels, num_caches, coherence) = match vai.get_item("hwcache_info")? {
            Some(h) if !h.is_none() => {
                let h = h.cast_into::<PyDict>()?;
                (
                    geti(&h, "num_levels")? as u32,
                    geti(&h, "num_caches")? as u32,
                    geti(&h, "icaches_maintain_coherence")? as u8,
                )
            }
            _ => (0, 0, 0),
        };
        Ok(ArchInfo {
            hwcaps: geti(vai, "hwcaps")? as u32,
            endness: geti(vai, "endness")? as i32,
            hwcache_num_levels: num_levels,
            hwcache_num_caches: num_caches,
            icaches_maintain_coherence: coherence,
            ppc_icache_line_sz_b: geti(vai, "ppc_icache_line_szB")? as i32,
            ppc_dcbz_sz_b: geti(vai, "ppc_dcbz_szB")? as u32,
            ppc_scv_supported: geti(vai, "ppc_scv_supported")? as u8,
            ppc_dcbzl_sz_b: geti(vai, "ppc_dcbzl_szB")? as u32,
            arm64_d_min_line_lg2_sz_b: geti(vai, "arm64_dMinLine_lg2_szB")? as u32,
            arm64_i_min_line_lg2_sz_b: geti(vai, "arm64_iMinLine_lg2_szB")? as u32,
            arm64_cache_block_size: geti(vai, "arm64_cache_block_size")? as u8,
            arm64_requires_fallback_llsc: geti(vai, "arm64_requires_fallback_LLSC")? as u8,
            x86_cr0: geti(vai, "x86_cr0")? as u32,
        })
    }

    fn to_ffi(self) -> VexArchInfo {
        VexArchInfo {
            hwcaps: self.hwcaps,
            endness: self.endness,
            hwcache_info: VexCacheInfo {
                num_levels: self.hwcache_num_levels,
                num_caches: self.hwcache_num_caches,
                caches: std::ptr::null_mut(),
                icaches_maintain_coherence: self.icaches_maintain_coherence,
            },
            ppc_icache_line_sz_b: self.ppc_icache_line_sz_b,
            ppc_dcbz_sz_b: self.ppc_dcbz_sz_b,
            ppc_scv_supported: self.ppc_scv_supported,
            ppc_dcbzl_sz_b: self.ppc_dcbzl_sz_b,
            arm64_d_min_line_lg2_sz_b: self.arm64_d_min_line_lg2_sz_b,
            arm64_i_min_line_lg2_sz_b: self.arm64_i_min_line_lg2_sz_b,
            arm64_cache_block_size: self.arm64_cache_block_size,
            arm64_requires_fallback_llsc: self.arm64_requires_fallback_llsc,
            x86_cr0: self.x86_cr0,
        }
    }
}

/// One loader backer: the same buffer `VEXLifter._load_bytes` hands to libVEX, unpadded and uncopied.
pub struct Backer {
    pub start: u64,
    pub len: usize,
    /// None for backers without the buffer protocol (e.g. odd-byte-width `list[int]`); lifts there fall back.
    buf: Option<PyBuffer<u8>>,
}

impl Backer {
    fn ptr(&self) -> Option<*const u8> {
        self.buf.as_ref().map(|b| b.buf_ptr() as *const u8)
    }
}

/// The lifter core: the arch, the backer table and the `vex_lift` call. Usable from Rust directly.
pub struct LifterCore {
    pub guest: u32,
    pub archinfo: ArchInfo,
    /// ARM (THUMB bit in addresses); not AArch64.
    pub is_arm: bool,
    /// Sorted by start, as `ClemoryReadOnlyView._flattened_backers`.
    pub backers: Vec<Backer>,
}

/// The lifted bytes of a block, when they lie within one backer.
pub struct BlockBytes<'a>(pub &'a [u8]);

impl LifterCore {
    /// `ClemoryReadOnlyView.backers(addr)`: the backer with the greatest start <= addr, if it contains addr.
    pub fn find_backer(&self, addr: u64) -> Option<&Backer> {
        let idx = self.backers.partition_point(|b| b.start <= addr);
        if idx == 0 {
            return None;
        }
        let b = &self.backers[idx - 1];
        if addr - b.start < b.len as u64 {
            Some(b)
        } else {
            None
        }
    }

    /// `ClemoryReadOnlyView.load(addr, n)` for the single-backer case; None when it would read across backers.
    pub fn load(&self, addr: u64, n: usize) -> Option<&[u8]> {
        let b = self.find_backer(addr)?;
        let offset = (addr - b.start) as usize;
        if offset + n > b.len {
            return None;
        }
        let ptr = b.ptr()?;
        Some(unsafe { std::slice::from_raw_parts(ptr.add(offset), n) })
    }

    /// Lift the block at `addr` (THUMB bit allowed on ARM) with at most `max_size` bytes, the way
    /// `CFGFast._lift` -> `Block.vex_nostmt` would, and summarize it.
    ///
    /// `initial_regs` are registered before and always reset after the lift. The caller holds the GIL and pyvex's
    /// `_libvex_lock` (the result is read before any other lift can run).
    pub fn lift_block(
        &self,
        addr: u64,
        max_size: i64,
        initial_regs: &[(u32, u32, u64)],
        opts: &LiftOptions,
    ) -> Result<LiftSummary, Fallback> {
        let (r, insn_addr) = self.raw_lift(addr, max_size, initial_regs, opts)?;
        unsafe { summarize(r, insn_addr) }
    }

    /// [`Self::lift_block`] plus [`mips32_gp_scan`] with `mips_gp` = ($gp offset, $t9 offset, function address).
    pub fn lift_block_mips_gp(
        &self,
        addr: u64,
        max_size: i64,
        initial_regs: &[(u32, u32, u64)],
        opts: &LiftOptions,
        mips_gp: (i32, i32, u64),
    ) -> Result<LiftSummary, Fallback> {
        let (r, insn_addr) = self.raw_lift(addr, max_size, initial_regs, opts)?;
        let mut summary = unsafe { summarize(r, insn_addr) }?;
        summary.mips_gp = Some(unsafe { mips32_gp_scan(r, mips_gp.0, mips_gp.1, mips_gp.2) });
        Ok(summary)
    }

    /// The `vex_lift` call shared by every lift kind. Returns the live `_lift_r` (valid until the next lift) and the
    /// lifted address (THUMB bit included). Same caller contract as [`LifterCore::lift_block`].
    pub(crate) fn raw_lift(
        &self,
        addr: u64,
        max_size: i64,
        initial_regs: &[(u32, u32, u64)],
        opts: &LiftOptions,
    ) -> Result<(*const VEXLiftResult, u64), Fallback> {
        let lift = vex_ffi::vex_lift_fn().ok_or(Fallback::NoSymbols)?;
        let thumb: u64 = if self.is_arm { addr & 1 } else { 0 };
        let real_addr = if self.is_arm { addr & !1 } else { addr };

        // VEXLifter._load_bytes: the first backer containing the address, offset into it, unpadded.
        let backer = self.find_backer(real_addr).ok_or(Fallback::NoBacker)?;
        let base = backer.ptr().ok_or(Fallback::UnsupportedBacker)?;
        let offset = real_addr - backer.start;
        let available = backer.len as u64 - offset;
        let size = max_size.min(VEX_IRSB_MAX_SIZE as i64).min(available as i64);
        if size <= 0 {
            return Err(Fallback::EmptyWindow);
        }
        let bytes_offset = u32::try_from(offset + thumb).map_err(|_| Fallback::OffsetOverflow)?;
        let max_bytes = (size as u32).min(VEX_MAX_BYTES);
        let insn_addr = real_addr + thumb;
        let insn_start = unsafe { base.add(bytes_offset as usize) };
        let px_control = if opts.cross_insn_opt {
            PX_UNWINDREGS_AT_MEM_ACCESS
        } else {
            PX_LD_ALLREGS_AT_EACH_INSN
        };

        if !initial_regs.is_empty() {
            let reg = vex_ffi::register_initial_register_value_fn().ok_or(Fallback::NoSymbols)?;
            for &(off, sz, val) in initial_regs {
                unsafe { reg(off, sz, val) };
            }
        }
        let lift_r = unsafe {
            lift(
                self.guest,
                self.archinfo.to_ffi(),
                insn_start,
                insn_addr,
                opts.max_inst.min(VEX_MAX_INSTRUCTIONS),
                max_bytes,
                opts.opt_level,
                opts.traceflags,
                1,
                opts.strict_block_end as c_int,
                opts.collect_data_refs as c_int,
                opts.load_from_ro_regions as c_int,
                opts.const_prop as c_int,
                px_control,
                bytes_offset,
            )
        };
        if !initial_regs.is_empty()
            && let Some(reset) = vex_ffi::reset_initial_register_values_fn()
        {
            unsafe { reset() };
        }
        if lift_r.is_null() {
            return Err(Fallback::LiftFailed);
        }
        Ok((lift_r as *const VEXLiftResult, insn_addr))
    }
}

/// Read the C result into an owned summary. Must run before the next `vex_lift`.
///
/// # Safety
/// `r` must be the live `_lift_r` of a successful lift.
pub(crate) unsafe fn summarize(
    r: *const VEXLiftResult,
    addr: u64,
) -> Result<LiftSummary, Fallback> {
    let r = unsafe { &*r };
    let size = r.size;
    if r.irsb.is_null() || size <= 0 {
        return Err(Fallback::NoInstructions);
    }
    if r.exit_count as usize > MAX_EXITS {
        return Err(Fallback::TooManyExits);
    }
    let irsb = unsafe { &*r.irsb };
    let jumpkind = irsb.jumpkind;
    let next = if irsb.next.is_null() {
        NextExpr::Other
    } else {
        let n = unsafe { &*irsb.next };
        match n.tag {
            IEX_CONST => {
                let con = unsafe { n.iex.con.con };
                match unsafe { const_int_value(con) } {
                    Some(v) => NextExpr::Const(v),
                    None => return Err(Fallback::UnsupportedConst),
                }
            }
            IEX_RDTMP => NextExpr::Tmp(unsafe { n.iex.rdtmp.tmp }),
            _ => NextExpr::Other,
        }
    };
    if jumpkind == IJK_NODECODE {
        // pyvex.lift: only a NoDecode whose next is a constant other than the fall-through address is returned
        // as-is (an intentional NoDecode such as ud2); otherwise it re-lifts with statements and merges blocks.
        match next {
            NextExpr::Const(v) if v != addr.wrapping_add(size as u64) => {}
            _ => return Err(Fallback::PartialNoDecode),
        }
    }

    let insts = r.insts.max(0) as usize;
    let instruction_addresses: Vec<u64> = r.inst_addrs[..insts.min(MAX_INST_ADDRS)].to_vec();

    let mut exits = Vec::with_capacity(r.exit_count.max(0) as usize);
    for ex in &r.exits[..r.exit_count.max(0) as usize] {
        let stmt = unsafe { &*ex.stmt };
        if stmt.tag != IST_EXIT {
            return Err(Fallback::UnsupportedConst);
        }
        let e = unsafe { stmt.ist.exit };
        // CFGFast._create_jobs only takes U8..U64 exit targets as concrete
        if e.dst.is_null() || unsafe { (*e.dst).tag } == ICO_U1 {
            return Err(Fallback::UnsupportedConst);
        }
        let dst = unsafe { const_int_value(e.dst) }.ok_or(Fallback::UnsupportedConst)?;
        exits.push(Exit {
            stmt_idx: ex.stmt_idx,
            ins_addr: ex.ins_addr,
            dst,
            jumpkind: e.jk,
        });
    }

    let data_refs: Vec<DataRef> = r.data_refs
        [..(r.data_ref_count.max(0) as usize).min(MAX_DATA_REFS)]
        .iter()
        .map(|d| DataRef {
            data_addr: d.data_addr,
            data_size: d.size,
            data_type: d.data_type,
            stmt_idx: d.stmt_idx,
            ins_addr: d.ins_addr,
        })
        .collect();
    let const_vals: Vec<ConstVal> = r.const_vals
        [..(r.const_val_count.max(0) as usize).min(MAX_CONST_VALS)]
        .iter()
        .map(|c| ConstVal {
            tmp: c.tmp,
            stmt_idx: c.stmt_idx,
            value: c.value,
        })
        .collect();

    Ok(LiftSummary {
        addr,
        size: size as u32,
        jumpkind,
        next,
        is_noop_block: r.is_noop_block != 0,
        instructions: r.insts.max(0) as u32,
        instruction_addresses,
        exits,
        default_exit_target: (r.is_default_exit_constant == 1).then_some(r.default_exit),
        data_refs,
        const_vals,
        mips_gp: None,
    })
}

const IOP_ADD32: u32 = crate::ailment::vexop_names::IOP_BASE + 3;

/// `CFGFast._mips_determine_function_gp` up to the symbolic stepping: the last $gp write, then
/// `_mips_gp_from_statements` over $gp = 0xffffffff and $t9 = `func_addr`.
///
/// # Safety
/// `r` must be the live `_lift_r` of a successful lift.
pub(crate) unsafe fn mips32_gp_scan(
    r: *const VEXLiftResult,
    gp_off: i32,
    t9_off: i32,
    func_addr: u64,
) -> MipsGpScan {
    use vex_ffi::{
        IEX_BINOP, IEX_GET, IRExpr, IST_ABIHINT, IST_IMARK, IST_NOOP, IST_PUT, IST_WRTMP, ITY_I32,
    };
    debug_assert_eq!(crate::ailment::vexop_names::IROP_NAMES[3], "Iop_Add32");
    let irsb = unsafe { &*(*r).irsb };
    let n = irsb.stmts_used.max(0) as usize;
    let stmt = |i: usize| unsafe { &**irsb.stmts.add(i) };

    let mut insns = 0usize;
    let mut insn_addr = 0u64;
    let mut last_gp = None;
    for i in 0..n {
        let st = stmt(i);
        match st.tag {
            IST_IMARK => {
                insns += 1;
                insn_addr = unsafe { st.ist.imark.addr };
            }
            IST_PUT if unsafe { st.ist.put.offset } == gp_off => last_gp = Some((insns, insn_addr)),
            _ => {}
        }
    }
    let mut scan = MipsGpScan {
        func_addr,
        insns,
        last_gp,
        value: None,
    };
    let Some((last, _)) = last_gp else {
        return scan;
    };
    // instruction last+1 must exist and must not be a branch whose delay slot would run with it
    if insns < last + 3 {
        return scan;
    }

    let mut gp = Some(0xFFFF_FFFFu64);
    let mut t9 = Some(func_addr);
    let n_tmps = unsafe { (*irsb.tyenv).types_used.max(0) as usize };
    let mut tmps: Vec<Option<u64>> = vec![None; n_tmps];
    fn ev(
        e: *const IRExpr,
        tmps: &[Option<u64>],
        regs: (i32, Option<u64>, i32, Option<u64>),
    ) -> Option<u64> {
        let e = unsafe { &*e };
        match e.tag {
            IEX_CONST => unsafe { const_int_value(e.iex.con.con) },
            IEX_RDTMP => tmps
                .get(unsafe { e.iex.rdtmp.tmp } as usize)
                .copied()
                .flatten(),
            IEX_GET => {
                let g = unsafe { e.iex.get };
                if g.ty != ITY_I32 {
                    None
                } else if g.offset == regs.0 {
                    regs.1
                } else if g.offset == regs.2 {
                    regs.3
                } else {
                    None
                }
            }
            IEX_BINOP if unsafe { e.iex.binop.op } == IOP_ADD32 => {
                let b = unsafe { e.iex.binop };
                let x = ev(b.arg1, tmps, regs)?;
                let y = ev(b.arg2, tmps, regs)?;
                Some(x.wrapping_add(y) & 0xFFFF_FFFF)
            }
            _ => None,
        }
    }
    let mut ctr = 0usize;
    for i in 0..n {
        let st = stmt(i);
        match st.tag {
            IST_IMARK => {
                ctr += 1;
                if ctr > last + 1 {
                    break;
                }
            }
            IST_WRTMP => {
                let w = unsafe { st.ist.wrtmp };
                let v = ev(w.data, &tmps, (gp_off, gp, t9_off, t9));
                if let Some(slot) = tmps.get_mut(w.tmp as usize) {
                    *slot = v;
                }
            }
            IST_PUT => {
                let p = unsafe { st.ist.put };
                if p.offset == gp_off {
                    gp = ev(p.data, &tmps, (gp_off, gp, t9_off, t9));
                } else if p.offset == t9_off {
                    t9 = ev(p.data, &tmps, (gp_off, gp, t9_off, t9));
                }
            }
            IST_NOOP | IST_ABIHINT => {}
            _ => return scan,
        }
    }
    scan.value = gp.map(|v| (v != 0xFFFF_FFFF).then_some(v));
    scan
}

// ---------------------------------------------------------------------------
// Python API
// ---------------------------------------------------------------------------

/// Lifts CFGFast's main-scan blocks straight from the loader backers into [`LiftSummary`] objects.
#[pyclass(name = "VexLifter", module = "angr.rustylib.vexlift")]
pub struct VexLifter {
    pub core: LifterCore,
    /// pyvex's `_libvex_lock`, held around every `vex_lift`.
    pub(crate) lock: Py<PyAny>,
    last_fallback: Option<Fallback>,
}

#[pymethods]
impl VexLifter {
    /// :param vex_arch:        `arch.vex_arch` ("VexArchAMD64", ...).
    /// :param vex_archinfo:    `arch.vex_archinfo`.
    /// :param is_arm:          Whether addresses carry a THUMB bit (`archinfo.ArchARM`).
    /// :param backers:         `(start, buffer)` pairs sorted by start: `loader.memory_ro_view._flattened_backers`.
    /// :param lock:            `pyvex.lifting.libvex._libvex_lock`.
    #[new]
    fn new(
        py: Python<'_>,
        vex_arch: &str,
        vex_archinfo: Bound<'_, PyDict>,
        is_arm: bool,
        backers: Vec<(u64, Bound<'_, PyAny>)>,
        lock: Py<PyAny>,
    ) -> PyResult<Self> {
        vex_ffi::init_symbols(py);
        if vex_ffi::vex_lift_fn().is_none() || vex_ffi::reset_initial_register_values_fn().is_none()
        {
            return Err(PyRuntimeError::new_err(
                "libpyvex symbols not found (is pyvex imported?)",
            ));
        }
        let guest = crate::ailment::convert_vex::vex_arch_int(vex_arch)
            .ok_or_else(|| PyValueError::new_err(format!("unsupported VexArch {vex_arch}")))?;
        let archinfo = ArchInfo::from_py_dict(&vex_archinfo)?;
        let mut table = Vec::with_capacity(backers.len());
        for (start, obj) in backers {
            // VEXLifter._load_bytes only lifts from bytes/bytearray backers
            let bytes_like = obj.is_instance_of::<PyBytes>() || obj.is_instance_of::<PyByteArray>();
            let (len, buf) = match PyBuffer::<u8>::get(&obj) {
                Ok(b) if bytes_like && b.is_c_contiguous() => (b.item_count(), Some(b)),
                _ => (obj.len()?, None),
            };
            table.push(Backer { start, len, buf });
        }
        if table.windows(2).any(|w| w[0].start > w[1].start) {
            return Err(PyValueError::new_err(
                "backers must be sorted by start address",
            ));
        }
        Ok(VexLifter {
            core: LifterCore {
                guest,
                archinfo,
                is_arm,
                backers: table,
            },
            lock,
            last_fallback: None,
        })
    }

    /// Lift and summarize the block at `addr`, or None when the Python path must be taken (see `last_fallback`).
    /// Returns the summary and the block's bytes when they lie within one backer (else the caller loads them).
    #[pyo3(signature = (addr, max_size, initial_regs=None, const_prop=false))]
    fn lift<'py>(
        &mut self,
        py: Python<'py>,
        addr: u64,
        max_size: i64,
        initial_regs: Option<Vec<(u32, u32, u64)>>,
        const_prop: bool,
    ) -> PyResult<Option<(LiftSummary, Option<Bound<'py, PyBytes>>)>> {
        let opts = LiftOptions::cfgfast_main(const_prop);
        let regs = initial_regs.unwrap_or_default();
        let lock = self.lock.bind(py);
        lock.call_method0("acquire")?;
        let result = self.core.lift_block(addr, max_size, &regs, &opts);
        lock.call_method0("release")?;
        match result {
            Ok(summary) => {
                self.last_fallback = None;
                let real_addr = if self.core.is_arm { addr & !1 } else { addr };
                let bytes = self
                    .core
                    .load(real_addr, summary.size as usize)
                    .map(|b| PyBytes::new(py, b));
                Ok(Some((summary, bytes)))
            }
            Err(fb) => {
                self.last_fallback = Some(fb);
                Ok(None)
            }
        }
    }

    /// The jumpkind of `CFGBase._lift(addr).vex` (factory.block defaults: no strict block end, no data refs, no
    /// read-only loads), or None when the Python path must be taken.
    fn lift_jumpkind(&mut self, py: Python<'_>, addr: u64) -> PyResult<Option<&'static str>> {
        let opts = LiftOptions {
            opt_level: 1,
            traceflags: 0,
            strict_block_end: false,
            collect_data_refs: false,
            load_from_ro_regions: false,
            const_prop: false,
            cross_insn_opt: false,
            max_inst: VEX_MAX_INSTRUCTIONS,
        };
        let lock = self.lock.bind(py);
        lock.call_method0("acquire")?;
        let result = self
            .core
            .lift_block(addr, VEX_IRSB_MAX_SIZE as i64, &[], &opts);
        lock.call_method0("release")?;
        match result {
            Ok(summary) => {
                self.last_fallback = None;
                Ok(Some(jumpkind_name(summary.jumpkind)))
            }
            Err(fb) => {
                self.last_fallback = Some(fb);
                Ok(None)
            }
        }
    }

    /// `factory.block(addr, size=max_size, opt_level=..., cross_insn_opt=..., extra_stop_points=...).vex` as a
    /// statement-level [`crate::vexir::PyIrBlock`], or None when the Python path must be taken. `hooks` and
    /// `stop_points` are containers tested with `in` (`project._sim_procedures` and the extra stop points).
    #[pyo3(signature = (addr, max_size, opt_level=1, cross_insn_opt=false, strict_block_end=false, hooks=None, stop_points=None))]
    #[allow(clippy::too_many_arguments)]
    fn lift_ir(
        &mut self,
        py: Python<'_>,
        addr: u64,
        max_size: i64,
        opt_level: i32,
        cross_insn_opt: bool,
        strict_block_end: bool,
        hooks: Option<Bound<'_, PyAny>>,
        stop_points: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Option<crate::vexir::PyIrBlock>> {
        let opts = LiftOptions {
            opt_level,
            traceflags: 0,
            strict_block_end,
            collect_data_refs: false,
            load_from_ro_regions: false,
            const_prop: false,
            cross_insn_opt,
            max_inst: VEX_MAX_INSTRUCTIONS,
        };
        let mut is_stop = |a: u64| {
            hooks
                .as_ref()
                .is_some_and(|h| h.contains(a).unwrap_or(false))
                || stop_points
                    .as_ref()
                    .is_some_and(|s| s.contains(a).unwrap_or(false))
        };
        let lock = self.lock.bind(py);
        lock.call_method0("acquire")?;
        let result = self.core.lift_ir(addr, max_size, &[], &opts, &mut is_stop);
        lock.call_method0("release")?;
        match result {
            Ok(ir) => {
                self.last_fallback = None;
                Ok(Some(crate::vexir::PyIrBlock { inner: ir }))
            }
            Err(fb) => {
                self.last_fallback = Some(fb);
                Ok(None)
            }
        }
    }

    /// Why the last `lift` returned None.
    #[getter]
    fn last_fallback(&self) -> Option<&'static str> {
        self.last_fallback.map(Fallback::name)
    }

    /// `memory_ro_view.load(addr, n)` when the range lies within one backer, else None.
    fn load<'py>(&self, py: Python<'py>, addr: u64, n: usize) -> Option<Bound<'py, PyBytes>> {
        self.core.load(addr, n).map(|b| PyBytes::new(py, b))
    }

    #[getter]
    fn backer_count(&self) -> usize {
        self.core.backers.len()
    }
}

/// Buffers registered as read-only regions, kept alive until deregistration (pyvex's `_ro_region_cdata_cache`).
static RO_REGION_BUFFERS: Mutex<Vec<PyBuffer<u8>>> = Mutex::new(Vec::new());

/// libpyvex `register_readonly_region(start, size, content)`: `content` must support the buffer protocol and is
/// kept alive until `deregister_all_readonly_regions`.
#[pyfunction]
fn register_readonly_region(
    py: Python<'_>,
    start: u64,
    size: u64,
    content: Bound<'_, PyAny>,
) -> PyResult<bool> {
    vex_ffi::init_symbols(py);
    let f = vex_ffi::register_readonly_region_fn()
        .ok_or_else(|| PyRuntimeError::new_err("libpyvex register_readonly_region not found"))?;
    let buf = PyBuffer::<u8>::get(&content)?;
    if !buf.is_c_contiguous() {
        return Err(PyValueError::new_err(
            "content must be a contiguous bytes-like buffer",
        ));
    }
    let ok = unsafe { f(start, size, buf.buf_ptr() as *const u8) } != 0;
    RO_REGION_BUFFERS.lock().unwrap().push(buf);
    Ok(ok)
}

/// libpyvex `deregister_all_readonly_regions()`; releases the buffers held by `register_readonly_region`.
#[pyfunction]
fn deregister_all_readonly_regions(py: Python<'_>) -> PyResult<()> {
    vex_ffi::init_symbols(py);
    let f = vex_ffi::deregister_all_readonly_regions_fn().ok_or_else(|| {
        PyRuntimeError::new_err("libpyvex deregister_all_readonly_regions not found")
    })?;
    unsafe { f() };
    RO_REGION_BUFFERS.lock().unwrap().clear();
    Ok(())
}

/// libpyvex `register_initial_register_value(offset, size, value)`.
#[pyfunction]
fn register_initial_register_value(
    py: Python<'_>,
    offset: u32,
    size: u32,
    value: u64,
) -> PyResult<bool> {
    vex_ffi::init_symbols(py);
    let f = vex_ffi::register_initial_register_value_fn().ok_or_else(|| {
        PyRuntimeError::new_err("libpyvex register_initial_register_value not found")
    })?;
    Ok(unsafe { f(offset, size, value) } != 0)
}

/// libpyvex `reset_initial_register_values()`.
#[pyfunction]
fn reset_initial_register_values(py: Python<'_>) -> PyResult<bool> {
    vex_ffi::init_symbols(py);
    let f = vex_ffi::reset_initial_register_values_fn().ok_or_else(|| {
        PyRuntimeError::new_err("libpyvex reset_initial_register_values not found")
    })?;
    Ok(unsafe { f() } != 0)
}

#[pyfunction]
#[pyo3(name = "jumpkind_name")]
fn py_jumpkind_name(jk: u32) -> &'static str {
    jumpkind_name(jk)
}

pub fn vexlift(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LiftSummary>()?;
    m.add_class::<Exit>()?;
    m.add_class::<DataRef>()?;
    m.add_class::<ConstVal>()?;
    m.add_class::<VexLifter>()?;
    m.add_function(wrap_pyfunction!(register_readonly_region, m)?)?;
    m.add_function(wrap_pyfunction!(deregister_all_readonly_regions, m)?)?;
    m.add_function(wrap_pyfunction!(register_initial_register_value, m)?)?;
    m.add_function(wrap_pyfunction!(reset_initial_register_values, m)?)?;
    m.add_function(wrap_pyfunction!(py_jumpkind_name, m)?)?;
    m.add("VEX_IRSB_MAX_SIZE", VEX_IRSB_MAX_SIZE)?;
    m.add("MAX_EXITS", MAX_EXITS)?;
    Ok(())
}
