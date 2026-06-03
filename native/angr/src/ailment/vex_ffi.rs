//! Raw FFI mirrors of the libVEX C structures, plus runtime resolution of
//! the two libpyvex symbols the converter needs (`vex_lift`, `typeOfPrimop`).
//!
//! The layouts mirror `pyvex/pyvex/vex_ffi.py` exactly. We never own this
//! memory: `vex_lift` returns a pointer into libVEX's global `_lift_r` /
//! arena, valid only until the next lift. The converter therefore reads it
//! synchronously, before any other lift, while holding the GIL (and pyvex's
//! `_libvex_lock`).
//!
//! Symbols are resolved with `dlsym(RTLD_DEFAULT, ...)`: pyvex `dlopen`s
//! `libpyvex.so` with `RTLD_GLOBAL`, so once pyvex is imported (always true on
//! this code path) the symbols are in the global namespace and we need no
//! link-time dependency on the shared object.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::OnceLock;

use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// Enum tag constants (values from pyvex/pyvex/vex_ffi.py)
// ---------------------------------------------------------------------------

// IRConstTag
pub const ICO_U1: u32 = 0x1300;
pub const ICO_U8: u32 = 0x1301;
pub const ICO_U16: u32 = 0x1302;
pub const ICO_U32: u32 = 0x1303;
pub const ICO_U64: u32 = 0x1304;
pub const ICO_F32: u32 = 0x1305;
pub const ICO_F32I: u32 = 0x1306;
pub const ICO_F64: u32 = 0x1307;
pub const ICO_F64I: u32 = 0x1308;
pub const ICO_V128: u32 = 0x1309;
pub const ICO_V256: u32 = 0x130A;

// IRExprTag
pub const IEX_BINDER: u32 = 0x1900;
pub const IEX_GET: u32 = 0x1901;
pub const IEX_GETI: u32 = 0x1902;
pub const IEX_RDTMP: u32 = 0x1903;
pub const IEX_QOP: u32 = 0x1904;
pub const IEX_TRIOP: u32 = 0x1905;
pub const IEX_BINOP: u32 = 0x1906;
pub const IEX_UNOP: u32 = 0x1907;
pub const IEX_LOAD: u32 = 0x1908;
pub const IEX_CONST: u32 = 0x1909;
pub const IEX_ITE: u32 = 0x190A;
pub const IEX_CCALL: u32 = 0x190B;
pub const IEX_VECRET: u32 = 0x190C;
pub const IEX_GSPTR: u32 = 0x190D;

// IRStmtTag
pub const IST_NOOP: u32 = 0x1E00;
pub const IST_IMARK: u32 = 0x1E01;
pub const IST_ABIHINT: u32 = 0x1E02;
pub const IST_PUT: u32 = 0x1E03;
pub const IST_PUTI: u32 = 0x1E04;
pub const IST_WRTMP: u32 = 0x1E05;
pub const IST_STORE: u32 = 0x1E06;
pub const IST_LOADG: u32 = 0x1E07;
pub const IST_STOREG: u32 = 0x1E08;
pub const IST_CAS: u32 = 0x1E09;
pub const IST_LLSC: u32 = 0x1E0A;
pub const IST_DIRTY: u32 = 0x1E0B;
pub const IST_MBE: u32 = 0x1E0C;
pub const IST_EXIT: u32 = 0x1E0D;

// IRType
pub const ITY_INVALID: u32 = 0x1100;
pub const ITY_I1: u32 = 0x1101;
pub const ITY_I8: u32 = 0x1102;
pub const ITY_I16: u32 = 0x1103;
pub const ITY_I32: u32 = 0x1104;
pub const ITY_I64: u32 = 0x1105;
pub const ITY_I128: u32 = 0x1106;
pub const ITY_F16: u32 = 0x1107;
pub const ITY_F32: u32 = 0x1108;
pub const ITY_F64: u32 = 0x1109;
pub const ITY_D32: u32 = 0x110A;
pub const ITY_D64: u32 = 0x110B;
pub const ITY_D128: u32 = 0x110C;
pub const ITY_F128: u32 = 0x110D;
pub const ITY_V128: u32 = 0x110E;
pub const ITY_V256: u32 = 0x110F;

// IREndness
pub const IEND_LE: u32 = 0x1200;
pub const IEND_BE: u32 = 0x1201;

/// Bits for an `IRType`, mirroring `pyvex.const.get_type_size`.
/// Returns 0 for `Ity_INVALID` (which has no defined size).
pub fn type_size_bits(ty: u32) -> u32 {
    match ty {
        ITY_I1 => 1,
        ITY_I8 => 8,
        ITY_I16 | ITY_F16 => 16,
        ITY_I32 | ITY_F32 | ITY_D32 => 32,
        ITY_I64 | ITY_F64 | ITY_D64 => 64,
        ITY_I128 | ITY_F128 | ITY_D128 | ITY_V128 => 128,
        ITY_V256 => 256,
        _ => 0,
    }
}

/// Endness enum -> the string the AIL classes store ("Iend_LE"/"Iend_BE").
pub fn endness_str(end: u32) -> &'static str {
    match end {
        IEND_BE => "Iend_BE",
        _ => "Iend_LE",
    }
}

// ---------------------------------------------------------------------------
// Struct layouts (see pyvex/pyvex/vex_ffi.py). All `#[repr(C)]`.
// ---------------------------------------------------------------------------

#[repr(C)]
pub union IcoUnion {
    pub u1: u8,
    pub u8_: u8,
    pub u16_: u16,
    pub u32_: u32,
    pub u64_: u64,
    pub f32_: f32,
    pub f32i: u32,
    pub f64_: f64,
    pub f64i: u64,
    pub v128: u16,
    pub v256: u32,
}

#[repr(C)]
pub struct IRConst {
    pub tag: u32,
    pub ico: IcoUnion,
}

#[repr(C)]
pub struct IRCallee {
    pub regparms: c_int,
    pub name: *const c_char,
    pub addr: *mut c_void,
    pub mcx_mask: u32,
}

#[repr(C)]
pub struct IRRegArray {
    pub base: c_int,
    pub elem_ty: u32,
    pub n_elems: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprGet {
    pub offset: c_int,
    pub ty: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprGetI {
    pub descr: *mut IRRegArray,
    pub ix: *mut IRExpr,
    pub bias: c_int,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprRdTmp {
    pub tmp: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprBinder {
    pub binder: c_int,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprQop {
    pub details: *mut IRQop,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprTriop {
    pub details: *mut IRTriop,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprBinop {
    pub op: u32,
    pub arg1: *mut IRExpr,
    pub arg2: *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprUnop {
    pub op: u32,
    pub arg: *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprLoad {
    pub end: u32,
    pub ty: u32,
    pub addr: *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprConst {
    pub con: *mut IRConst,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprCCall {
    pub cee: *mut IRCallee,
    pub retty: u32,
    pub args: *mut *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExprITE {
    pub cond: *mut IRExpr,
    pub iftrue: *mut IRExpr,
    pub iffalse: *mut IRExpr,
}

#[repr(C)]
pub union IexUnion {
    pub binder: ExprBinder,
    pub get: ExprGet,
    pub geti: ExprGetI,
    pub rdtmp: ExprRdTmp,
    pub qop: ExprQop,
    pub triop: ExprTriop,
    pub binop: ExprBinop,
    pub unop: ExprUnop,
    pub load: ExprLoad,
    pub con: ExprConst,
    pub ccall: ExprCCall,
    pub ite: ExprITE,
}

#[repr(C)]
pub struct IRExpr {
    pub tag: u32,
    pub iex: IexUnion,
}

#[repr(C)]
pub struct IRTriop {
    pub op: u32,
    pub arg1: *mut IRExpr,
    pub arg2: *mut IRExpr,
    pub arg3: *mut IRExpr,
}
#[repr(C)]
pub struct IRQop {
    pub op: u32,
    pub arg1: *mut IRExpr,
    pub arg2: *mut IRExpr,
    pub arg3: *mut IRExpr,
    pub arg4: *mut IRExpr,
}

#[repr(C)]
pub struct IRCAS {
    pub old_hi: u32,
    pub old_lo: u32,
    pub end: u32,
    pub addr: *mut IRExpr,
    pub expd_hi: *mut IRExpr,
    pub expd_lo: *mut IRExpr,
    pub data_hi: *mut IRExpr,
    pub data_lo: *mut IRExpr,
}

#[repr(C)]
pub struct IRPutI {
    pub descr: *mut IRRegArray,
    pub ix: *mut IRExpr,
    pub bias: c_int,
    pub data: *mut IRExpr,
}

#[repr(C)]
pub struct IRStoreG {
    pub end: u32,
    pub addr: *mut IRExpr,
    pub data: *mut IRExpr,
    pub guard: *mut IRExpr,
}

#[repr(C)]
pub struct IRLoadG {
    pub end: u32,
    pub cvt: u32,
    pub dst: u32,
    pub addr: *mut IRExpr,
    pub alt: *mut IRExpr,
    pub guard: *mut IRExpr,
}

#[repr(C)]
pub struct IRDirtyFxState {
    pub fx: u16,
    pub offset: u16,
    pub size: u16,
    pub n_repeats: u8,
    pub repeat_len: u8,
}

#[repr(C)]
pub struct IRDirty {
    pub cee: *mut IRCallee,
    pub guard: *mut IRExpr,
    pub args: *mut *mut IRExpr,
    pub tmp: u32,
    pub m_fx: u32,
    pub m_addr: *mut IRExpr,
    pub m_size: c_int,
    pub n_fx_state: c_int,
    pub fx_state: [IRDirtyFxState; 7],
}

// IRStmt union variants
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtNoOp {
    pub dummy: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtIMark {
    pub addr: u64,
    pub len: u32,
    pub delta: u8,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtAbiHint {
    pub base: *mut IRExpr,
    pub len: c_int,
    pub nia: *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtPut {
    pub offset: c_int,
    pub data: *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtPutI {
    pub details: *mut IRPutI,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtWrTmp {
    pub tmp: u32,
    pub data: *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtStore {
    pub end: u32,
    pub addr: *mut IRExpr,
    pub data: *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtStoreG {
    pub details: *mut IRStoreG,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtLoadG {
    pub details: *mut IRLoadG,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtCAS {
    pub details: *mut IRCAS,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtLLSC {
    pub end: u32,
    pub result: u32,
    pub addr: *mut IRExpr,
    pub storedata: *mut IRExpr,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtDirty {
    pub details: *mut IRDirty,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtMBE {
    pub event: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StmtExit {
    pub guard: *mut IRExpr,
    pub dst: *mut IRConst,
    pub jk: u32,
    pub offs_ip: c_int,
}

#[repr(C)]
pub union IstUnion {
    pub no_op: StmtNoOp,
    pub imark: StmtIMark,
    pub abi_hint: StmtAbiHint,
    pub put: StmtPut,
    pub puti: StmtPutI,
    pub wrtmp: StmtWrTmp,
    pub store: StmtStore,
    pub storeg: StmtStoreG,
    pub loadg: StmtLoadG,
    pub cas: StmtCAS,
    pub llsc: StmtLLSC,
    pub dirty: StmtDirty,
    pub mbe: StmtMBE,
    pub exit: StmtExit,
}

#[repr(C)]
pub struct IRStmt {
    pub tag: u32,
    pub ist: IstUnion,
}

#[repr(C)]
pub struct IRTypeEnv {
    pub types: *mut u32,
    pub types_size: c_int,
    pub types_used: c_int,
}

#[repr(C)]
pub struct IRSB {
    pub tyenv: *mut IRTypeEnv,
    pub stmts: *mut *mut IRStmt,
    pub stmts_size: c_int,
    pub stmts_used: c_int,
    pub next: *mut IRExpr,
    pub jumpkind: u32,
    pub offs_ip: c_int,
}

#[repr(C)]
pub struct VexCacheInfo {
    pub num_levels: u32,
    pub num_caches: u32,
    pub caches: *mut c_void,
    pub icaches_maintain_coherence: u8,
}

#[repr(C)]
pub struct VexArchInfo {
    pub hwcaps: u32,
    pub endness: c_int,
    pub hwcache_info: VexCacheInfo,
    pub ppc_icache_line_sz_b: c_int,
    pub ppc_dcbz_sz_b: u32,
    pub ppc_dcbzl_sz_b: u32,
    pub arm64_d_min_line_lg2_sz_b: u32,
    pub arm64_i_min_line_lg2_sz_b: u32,
    pub x86_cr0: u32,
}

/// The tail of `VEXLiftResult` (exits/data refs/etc.) is large and unused by
/// the converter; we only declare the prefix we read. Because `vex_lift`
/// returns a pointer to the full static struct, reading only the prefix is
/// sound.
#[repr(C)]
pub struct VEXLiftResultHead {
    pub irsb: *mut IRSB,
    pub size: c_int,
    pub is_noop_block: u8,
    // ... (exits, default_exit, insts, data_refs, const_vals) omitted
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

impl IRTypeEnv {
    /// Type of temp `t`, or `Ity_INVALID` if out of range.
    ///
    /// # Safety
    ///
    /// `self.types` must point to a live libVEX type array of
    /// `self.types_used` entries (i.e. the enclosing `IRSB` arena must not
    /// have been freed or reused by another lift).
    pub unsafe fn lookup(&self, t: u32) -> u32 {
        if (t as c_int) < 0 || (t as c_int) >= self.types_used {
            return ITY_INVALID;
        }
        unsafe { *self.types.add(t as usize) }
    }
}

/// Read a NUL-terminated C string into an owned `String` (lossy).
///
/// # Safety
///
/// `p` must be null or point to a valid NUL-terminated C string that stays
/// alive for the duration of the call.
pub unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// libpyvex symbol resolution (dlsym against the already-loaded library)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlopen(file: *const c_char, flag: c_int) -> *mut c_void;
}

// RTLD_NOW | RTLD_GLOBAL (Linux). cffi loads libpyvex RTLD_LOCAL, so its
// symbols aren't in the default scope; we re-open it by path (the library is
// already mapped, so this just returns a usable handle) and promote it global.
const RTLD_NOW: c_int = 0x0002;
const RTLD_GLOBAL: c_int = 0x0100;

/// `VexArchInfo` is passed to `vex_lift` *by value*.
pub type VexLiftFn = unsafe extern "C" fn(
    guest: u32,
    archinfo: VexArchInfo,
    insn_start: *const u8,
    insn_addr: u64,
    max_insns: u32,
    max_bytes: u32,
    opt_level: c_int,
    traceflags: c_int,
    allow_arch_optimizations: c_int,
    strict_block_end: c_int,
    collect_data_refs: c_int,
    load_from_ro_regions: c_int,
    const_prop: c_int,
    px_control: u32,
    lookback_amount: u32,
) -> *mut VEXLiftResultHead;

pub type TypeOfPrimopFn = unsafe extern "C" fn(
    op: u32,
    t_dst: *mut u32,
    t_arg1: *mut u32,
    t_arg2: *mut u32,
    t_arg3: *mut u32,
    t_arg4: *mut u32,
);

struct Symbols {
    vex_lift: Option<VexLiftFn>,
    type_of_primop: Option<TypeOfPrimopFn>,
}

// SAFETY: function pointers into a permanently-loaded shared library.
unsafe impl Send for Symbols {}
unsafe impl Sync for Symbols {}

static SYMBOLS: OnceLock<Symbols> = OnceLock::new();

fn dlsym_as<T: Copy>(handle: *mut c_void, name: &str) -> Option<T> {
    let cname = std::ffi::CString::new(name).ok()?;
    let ptr = unsafe { dlsym(handle, cname.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    debug_assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut c_void>());
    Some(unsafe { *(&ptr as *const *mut c_void as *const T) })
}

fn pyvex_lib_path(py: pyo3::Python<'_>) -> Option<String> {
    let libname = if cfg!(target_os = "macos") {
        "libpyvex.dylib"
    } else if cfg!(target_os = "windows") {
        "pyvex.dll"
    } else {
        "libpyvex.so"
    };
    let ir = py.import("importlib.resources").ok()?;
    let files = ir.getattr("files").ok()?.call1(("pyvex",)).ok()?;
    let p = files
        .call_method1("__truediv__", ("lib",))
        .ok()?
        .call_method1("__truediv__", (libname,))
        .ok()?;
    p.str().ok()?.extract::<String>().ok()
}

fn resolve_all(py: pyo3::Python<'_>) -> Symbols {
    let handle = match pyvex_lib_path(py).and_then(|p| std::ffi::CString::new(p).ok()) {
        Some(cpath) => unsafe { dlopen(cpath.as_ptr(), RTLD_NOW | RTLD_GLOBAL) },
        None => std::ptr::null_mut(),
    };
    Symbols {
        vex_lift: dlsym_as::<VexLiftFn>(handle, "vex_lift"),
        type_of_primop: dlsym_as::<TypeOfPrimopFn>(handle, "typeOfPrimop"),
    }
}

/// Resolve the libpyvex symbols (idempotent). Must be called with the GIL held
/// before [`vex_lift_fn`] / [`op_result_type`] are used.
pub fn init_symbols(py: pyo3::Python<'_>) {
    SYMBOLS.get_or_init(|| resolve_all(py));
}

pub fn vex_lift_fn() -> Option<VexLiftFn> {
    SYMBOLS.get().and_then(|s| s.vex_lift)
}

pub fn type_of_primop_fn() -> Option<TypeOfPrimopFn> {
    SYMBOLS.get().and_then(|s| s.type_of_primop)
}

/// Return type (`IRType`) of a primop, via libVEX `typeOfPrimop`.
/// Returns `Ity_INVALID` if the symbol is unavailable.
pub fn op_result_type(op_int: u32) -> u32 {
    let Some(f) = type_of_primop_fn() else {
        return ITY_INVALID;
    };
    let mut dst: u32 = ITY_INVALID;
    let mut a1: u32 = ITY_INVALID;
    let mut a2: u32 = ITY_INVALID;
    let mut a3: u32 = ITY_INVALID;
    let mut a4: u32 = ITY_INVALID;
    unsafe { f(op_int, &mut dst, &mut a1, &mut a2, &mut a3, &mut a4) };
    dst
}
