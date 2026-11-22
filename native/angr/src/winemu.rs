//! A user-mode x86/x64 Windows guest on Icicle, driven by the unpacker's Python environment.
//!
//! The run loop stays in Rust and only returns at API trap slots (breakpoints), faults, traps and budget ends.
//! Self-modifying code is handled here: the written page's lifted code is dropped and the write is retried.

use std::{collections::HashMap, path::PathBuf};

use icicle_vm::cpu::{
    BlockKey, Cpu, Exception, ExceptionCode, Regs, ValueSource,
    mem::{Mapping, perm},
};
use pyo3::{
    buffer::PyBuffer,
    exceptions::{PyKeyError, PyRuntimeError, PyValueError},
    prelude::*,
    types::PyBytes,
};

const PAGE: u64 = 0x1000;

/// `Exception::value`s of `ExceptionCode::Environment` raised by the injected code.
const ENV_TRAP_FLAG: u64 = 1;
const ENV_PRIVILEGED: u64 = 2;

/// Exit kinds returned by `WinVm.run`.
pub const EXIT_LIMIT: u8 = 0;
pub const EXIT_BREAKPOINT: u8 = 1;
pub const EXIT_TRAP_FLAG: u8 = 2;
pub const EXIT_EXCEPTION: u8 = 3;
pub const EXIT_PRIVILEGED: u8 = 4;
pub const EXIT_HALT: u8 = 5;
pub const EXIT_OTHER: u8 = 6;

/// Fault categories in the `code` of an EXIT_EXCEPTION.
pub const FAULT_READ: u32 = 1;
pub const FAULT_WRITE: u32 = 2;
pub const FAULT_EXEC: u32 = 3;
pub const FAULT_DIVIDE: u32 = 4;
pub const FAULT_INVALID: u32 = 5;
pub const FAULT_SYSCALL: u32 = 6;
pub const FAULT_OTHER: u32 = 7;

fn fault(code: ExceptionCode, value: u64) -> (u8, u32, u64) {
    use ExceptionCode::*;
    let category = match code {
        ReadUnmapped | ReadPerm | ReadUnaligned | ReadWatch | ReadUninitialized => FAULT_READ,
        WriteUnmapped | WritePerm | WriteWatch | WriteUnaligned => FAULT_WRITE,
        ExecViolation | ExecUnaligned => FAULT_EXEC,
        DivisionException => FAULT_DIVIDE,
        InvalidInstruction => FAULT_INVALID,
        Syscall => FAULT_SYSCALL,
        _ => return (EXIT_EXCEPTION, FAULT_OTHER | ((code as u32) << 8), value),
    };
    (EXIT_EXCEPTION, category, value)
}

fn rdtsc(cpu: &mut Cpu, dst: pcode::VarNode, _: [pcode::Value; 2]) {
    // the host's counter, as QEMU (the Unicorn path) passes it through; protectors seed and time with it
    #[cfg(target_arch = "x86_64")]
    let value = unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(not(target_arch = "x86_64"))]
    let value = 0x2_0000_0000 + cpu.icount.wrapping_mul(3);
    cpu.write_var(dst, value);
}

fn is_x64(cpu: &Cpu) -> bool {
    matches!(
        cpu.arch.triple.architecture,
        target_lexicon::Architecture::X86_64
    )
}

fn write_trunc(cpu: &mut Cpu, dst: pcode::VarNode, value: u128) {
    let bytes = value.to_le_bytes();
    for i in 0..dst.size.min(16) {
        cpu.write_var::<u8>(dst.slice(i, 1), bytes[i as usize]);
    }
}

// descriptor-table registers of a Windows 7 machine (not a VM's)
fn gdtr(cpu: &mut Cpu, dst: pcode::VarNode, _: [pcode::Value; 2]) {
    let base: u128 = if is_x64(cpu) {
        0xFFFF_F800_00B9_5000
    } else {
        0x80B9_5000
    };
    write_trunc(cpu, dst, 0x3FF | (base << 16));
}

fn idtr(cpu: &mut Cpu, dst: pcode::VarNode, _: [pcode::Value; 2]) {
    let base: u128 = if is_x64(cpu) {
        0xFFFF_F800_00B9_6080
    } else {
        0x80B9_5400
    };
    write_trunc(cpu, dst, 0x7FF | (base << 16));
}

fn ldtr(cpu: &mut Cpu, dst: pcode::VarNode, _: [pcode::Value; 2]) {
    write_trunc(cpu, dst, 0);
}

fn task_register(cpu: &mut Cpu, dst: pcode::VarNode, _: [pcode::Value; 2]) {
    let tr = if is_x64(cpu) { 0x40 } else { 0x28 };
    write_trunc(cpu, dst, tr);
}

/// segment(seg, offset), the address of a 16-bit-addressed operand (0x67 prefix): flat segments, FS and GS at their
/// bases.
fn segment(cpu: &mut Cpu, dst: pcode::VarNode, args: [pcode::Value; 2]) {
    let base = match args[0] {
        pcode::Value::Var(var) => {
            let sleigh = &cpu.arch.sleigh;
            let lookup = |name: &str| sleigh.get_reg(name).and_then(|reg| reg.get_var());
            let base = if lookup("FS").is_some_and(|fs| fs.id == var.id) {
                lookup("FS_OFFSET")
            } else if lookup("GS").is_some_and(|gs| gs.id == var.id) {
                lookup("GS_OFFSET")
            } else {
                None
            };
            base.map_or(0, |base| cpu.read_reg(base))
        }
        pcode::Value::Const(..) => 0,
    };
    let offset: u64 = cpu.read_dynamic(args[1]).zxt();
    write_trunc(cpu, dst, base.wrapping_add(offset) as u128);
}

/// (limit, access rights as lar reports them) of the descriptors a user-mode thread can see in a Windows 7 GDT;
/// None for the null, kernel (DPL 0) and LDT selectors, which lsl, lar, verr and verw reject.
fn user_descriptor(x64: bool, selector: u64) -> Option<(u32, u32)> {
    if selector & 4 != 0 {
        return None;
    }
    match (x64, selector & 0xFFF8) {
        // user code and data; the TEB
        (false, 0x18) => Some((u32::MAX, 0x00CF_FB00)),
        (false, 0x20) => Some((u32::MAX, 0x00CF_F300)),
        (false, 0x38) => Some((0xFFF, 0x0040_F300)),
        // 32-bit code, data, 64-bit code; the WOW64 TEB (limit 0x3C00, processor 0 in bits 14+)
        (true, 0x20) => Some((u32::MAX, 0x00CF_FB00)),
        (true, 0x28) => Some((u32::MAX, 0x00CF_F300)),
        (true, 0x30) => Some((0, 0x0020_FB00)),
        (true, 0x50) => Some((0x3C00, 0x0040_F300)),
        _ => None,
    }
}

fn read_selector(cpu: &mut Cpu, arg: pcode::Value) -> Option<(u32, u32)> {
    let selector: u64 = cpu.read_dynamic(arg).zxt();
    user_descriptor(is_x64(cpu), selector & 0xFFFF)
}

/// SegmentLimit(selector), as patched in the SLEIGH spec: the limit in bits 0-31, bit 32 set when lsl succeeds.
fn segment_limit(cpu: &mut Cpu, dst: pcode::VarNode, args: [pcode::Value; 2]) {
    let value = read_selector(cpu, args[0]).map_or(0, |(limit, _)| limit as u128 | (1 << 32));
    write_trunc(cpu, dst, value);
}

/// SegmentRights(selector), added to the SLEIGH spec for lar: like SegmentLimit with the access rights.
fn segment_rights(cpu: &mut Cpu, dst: pcode::VarNode, args: [pcode::Value; 2]) {
    let value = read_selector(cpu, args[0]).map_or(0, |(_, rights)| rights as u128 | (1 << 32));
    write_trunc(cpu, dst, value);
}

/// verr(selector): readable code (type bit 1) or any data segment.
fn verr(cpu: &mut Cpu, dst: pcode::VarNode, args: [pcode::Value; 2]) {
    let ok = read_selector(cpu, args[0])
        .is_some_and(|(_, rights)| rights & 0x800 == 0 || rights & 0x200 != 0);
    write_trunc(cpu, dst, ok as u128);
}

/// verw(selector): writable data segments only.
fn verw(cpu: &mut Cpu, dst: pcode::VarNode, args: [pcode::Value; 2]) {
    let ok = read_selector(cpu, args[0])
        .is_some_and(|(_, rights)| rights & 0x800 == 0 && rights & 0x200 != 0);
    write_trunc(cpu, dst, ok as u128);
}

/// xinuse: XGETBV masks XCR0 with it; every enabled state counts as in use.
fn xinuse(cpu: &mut Cpu, dst: pcode::VarNode, _: [pcode::Value; 2]) {
    write_trunc(cpu, dst, u128::MAX);
}

fn privileged_op(cpu: &mut Cpu, _: pcode::VarNode, _: [pcode::Value; 2]) {
    cpu.exception = Exception::new(ExceptionCode::Environment, ENV_PRIVILEGED);
}

/// User ops implemented here, on top of Icicle's own tables.
const HELPERS: &[(&str, icicle_vm::cpu::exec::helpers::PcodeOpHelper)] = &[
    ("rdtsc", rdtsc),
    ("segment", segment),
    ("SegmentLimit", segment_limit),
    ("SegmentRights", segment_rights),
    ("verr", verr),
    ("verw", verw),
    ("xinuse", xinuse),
    ("GlobalDescriptorTableRegister", gdtr),
    ("InterruptDescriptorTableRegister", idtr),
    ("LocalDescriptorTableRegister", ldtr),
    ("TaskRegister", task_register),
    ("rdmsr", privileged_op),
    ("rdpmc", privileged_op),
];

fn helpers() -> impl Iterator<Item = &'static (&'static str, icicle_vm::cpu::exec::helpers::PcodeOpHelper)> {
    HELPERS
        .iter()
}

struct FlagsHandler {
    eflags: pcode::VarNode,
}

impl icicle_vm::cpu::RegHandler for FlagsHandler {
    fn read(&mut self, cpu: &mut Cpu) {
        let eflags = icicle_vm::x86::eflags(cpu);
        cpu.write_var::<u32>(self.eflags, eflags);
    }

    fn write(&mut self, cpu: &mut Cpu) {
        let eflags = cpu.read_var::<u32>(self.eflags);
        icicle_vm::x86::set_eflags(cpu, eflags);
    }
}

#[derive(Clone, Copy)]
enum Patch {
    Cpuid,
    Privileged,
    Sysenter,
    TrapFlag,
}

/// Rewrites, per lifted instruction, what the SLEIGH spec gets wrong for a user-mode Windows guest.
struct WinPatcher {
    cpuid_ops: Vec<u16>,
    sysenter_op: Option<u16>,
    cpuid_hook: pcode::HookId,
    tf_hook: pcode::HookId,
    div_hook: pcode::HookId,
    precise_faults: bool,
    tf: pcode::VarNode,
    af: pcode::VarNode,
    of: pcode::VarNode,
    sf: pcode::VarNode,
    next_pc: pcode::VarNode,
}

impl WinPatcher {
    fn classify(&self, inst: &pcode::Block, addr: u64) -> Option<Patch> {
        let ops = &inst.instructions;
        let mut writes_tf = false;
        for stmt in ops {
            if let pcode::Op::PcodeOp(id) = stmt.op {
                if self.cpuid_ops.contains(&id) {
                    return Some(Patch::Cpuid);
                }
                if Some(id) == self.sysenter_op {
                    return Some(Patch::Sysenter);
                }
            }
            writes_tf |= stmt.output.id == self.tf.id;
        }
        if writes_tf {
            return Some(Patch::TrapFlag);
        }
        // hlt is a jump to itself and nothing else
        if ops.len() == 2
            && let pcode::Op::Branch(_) = ops[1].op
        {
            let [cond, target] = ops[1].inputs.get();
            if cond.const_eq(1) && target.is_const() && target.as_u64() == addr {
                return Some(Patch::Privileged);
            }
        }
        None
    }

    /// SLEIGH leaves AF alone ("AF not implemented"); protectors fold pushfd results into their state. Add
    /// AF = bit 4 of (op1 ^ op2 ^ result) to the instructions that compute OF with a signed carry or borrow.
    fn add_aux_carry(&self, inst: &mut pcode::Block) {
        let ops = &inst.instructions;
        let Some(of_at) = ops.iter().position(|stmt| {
            stmt.output.id == self.of.id
                && matches!(
                    stmt.op,
                    pcode::Op::IntSignedCarry | pcode::Op::IntSignedBorrow
                )
        }) else {
            // logical ops and shifts: AF is undefined, the CPU (and QEMU) clear it
            if ops.iter().any(|stmt| stmt.output.id == self.sf.id)
                && !ops.iter().any(|stmt| stmt.output.id == self.af.id)
            {
                inst.push((self.af, pcode::Op::Copy, pcode::Value::Const(0, 1)));
            }
            return;
        };
        let Some(sf_at) = ops.iter().rposition(|stmt| {
            stmt.output.id == self.sf.id && matches!(stmt.op, pcode::Op::IntSignedLess)
        }) else {
            return;
        };
        if sf_at < of_at {
            return;
        }
        let [x, y] = ops[of_at].inputs.get();
        let result = ops[sf_at].inputs.get()[0];
        if x.size() != y.size() || x.size() != result.size() {
            return;
        }
        inst.recompute_next_tmp();
        let size = x.size();
        let t1 = inst.alloc_tmp(size);
        let t2 = inst.alloc_tmp(size);
        let t3 = inst.alloc_tmp(size);
        let t4 = inst.alloc_tmp(size);
        let tail: Vec<pcode::Instruction> = inst.instructions.drain(sf_at + 1..).collect();
        inst.instructions
            .insert(of_at, (t1, pcode::Op::IntXor, (x, y)).into());
        inst.push((t2, pcode::Op::IntXor, (pcode::Value::from(t1), result)));
        inst.push((
            t3,
            pcode::Op::IntRight,
            (pcode::Value::from(t2), pcode::Value::Const(4, size)),
        ));
        inst.push((
            t4,
            pcode::Op::IntAnd,
            (pcode::Value::from(t3), pcode::Value::Const(1, size)),
        ));
        inst.push((self.af, pcode::Op::Copy, pcode::Value::from(t4.slice(0, 1))));
        inst.instructions.extend(tail);
    }

    /// SLEIGH's div/idiv truncate a quotient that does not fit; the CPU raises a divide error instead.
    fn add_divide_overflow(&self, inst: &mut pcode::Block) {
        let Some(at) = inst
            .instructions
            .iter()
            .position(|stmt| matches!(stmt.op, pcode::Op::IntDiv | pcode::Op::IntSignedDiv))
        else {
            return;
        };
        let div = inst.instructions[at];
        let q = div.output;
        if q.is_invalid() || !matches!(q.size, 2 | 4 | 8 | 16) {
            return;
        }
        let half = q.size / 2;
        inst.recompute_next_tmp();
        let ovf = inst.alloc_tmp(1);
        let mut check: Vec<pcode::Instruction> = Vec::new();
        if let pcode::Op::IntDiv = div.op {
            let hi = inst.alloc_tmp(q.size);
            check.push(
                (
                    hi,
                    pcode::Op::IntRight,
                    (
                        pcode::Value::from(q),
                        pcode::Value::Const(8 * half as u64, q.size),
                    ),
                )
                    .into(),
            );
            check.push(
                (
                    ovf,
                    pcode::Op::IntNotEqual,
                    (pcode::Value::from(hi), pcode::Value::Const(0, q.size)),
                )
                    .into(),
            );
        } else {
            let ext = inst.alloc_tmp(q.size);
            check.push(
                (
                    ext,
                    pcode::Op::SignExtend,
                    pcode::Value::from(q.slice(0, half)),
                )
                    .into(),
            );
            check.push(
                (
                    ovf,
                    pcode::Op::IntNotEqual,
                    (pcode::Value::from(ext), pcode::Value::from(q)),
                )
                    .into(),
            );
        }
        check.push((pcode::Op::HookIf(self.div_hook), pcode::Value::from(ovf)).into());
        let tail: Vec<pcode::Instruction> = inst.instructions.drain(at + 1..).collect();
        inst.instructions.extend(check);
        inst.instructions.extend(tail);
    }

    /// Icicle faults on a memory access after the instruction may already have updated registers (push moves
    /// esp, stosd advances edi), which a fault handler would see. Keep register results in temporaries until the
    /// instruction's last memory access has succeeded.
    fn defer_register_writes(&self, inst: &mut pcode::Block) {
        let ops = &inst.instructions;
        let is_mem = |op: pcode::Op| matches!(op, pcode::Op::Load(_) | pcode::Op::Store(_));
        let Some(last_mem) = ops.iter().rposition(|stmt| is_mem(stmt.op)) else {
            return;
        };
        let is_reg = |var: pcode::VarNode| var.id > 0 && !var.is_invalid();
        let Some(first) = ops[..last_mem].iter().position(|stmt| {
            is_reg(stmt.output) && !matches!(stmt.op, pcode::Op::InstructionMarker)
        }) else {
            return;
        };
        // straight-line code only, and each deferred register only ever accessed whole
        let mut written: Vec<pcode::VarNode> = Vec::new();
        for stmt in &ops[first..=last_mem] {
            if matches!(
                stmt.op,
                pcode::Op::Branch(_)
                    | pcode::Op::PcodeBranch(_)
                    | pcode::Op::PcodeLabel(_)
                    | pcode::Op::Hook(_)
                    | pcode::Op::HookIf(_)
                    | pcode::Op::PcodeOp(_)
                    | pcode::Op::Exception
            ) {
                return;
            }
            if is_reg(stmt.output) && !is_mem(stmt.op) && !written.contains(&stmt.output) {
                written.push(stmt.output);
            }
        }
        for stmt in &ops[first..=last_mem] {
            let [a, b] = stmt.inputs.get();
            for var in [a, b]
                .into_iter()
                .filter_map(|v| match v {
                    pcode::Value::Var(var) => Some(var),
                    pcode::Value::Const(..) => None,
                })
                .chain(std::iter::once(stmt.output))
            {
                if written.iter().any(|w| w.id == var.id && *w != var) {
                    return;
                }
            }
        }
        inst.recompute_next_tmp();
        let temps: Vec<pcode::VarNode> = written.iter().map(|w| inst.alloc_tmp(w.size)).collect();
        let mut live = vec![false; written.len()];
        for stmt in &mut inst.instructions[first..=last_mem] {
            let [a, b] = stmt.inputs.get();
            let remap = |v: pcode::Value, live: &[bool]| match v {
                pcode::Value::Var(var) => match written.iter().position(|w| *w == var) {
                    Some(i) if live[i] => pcode::Value::Var(temps[i]),
                    _ => v,
                },
                c => c,
            };
            stmt.inputs = pcode::Inputs::new(remap(a, &live), remap(b, &live));
            if !is_mem(stmt.op) {
                if let Some(i) = written.iter().position(|w| *w == stmt.output) {
                    stmt.output = temps[i];
                    live[i] = true;
                }
            }
        }
        let copies: Vec<pcode::Instruction> = written
            .iter()
            .zip(&temps)
            .map(|(w, t)| (*w, pcode::Op::Copy, pcode::Value::Var(*t)).into())
            .collect();
        let tail: Vec<pcode::Instruction> = inst.instructions.drain(last_mem + 1..).collect();
        inst.instructions.extend(copies);
        inst.instructions.extend(tail);
    }

    fn patch(&self, inst: &mut pcode::Block) {
        self.add_aux_carry(inst);
        self.add_divide_overflow(inst);
        let Some(&marker) = inst.instructions.first() else {
            return;
        };
        if !matches!(marker.op, pcode::Op::InstructionMarker) {
            return;
        }
        let [addr, len] = marker.inputs.get();
        let (addr, len) = (addr.as_u64(), len.as_u64());
        if self.precise_faults {
            self.defer_register_writes(inst);
        }
        match self.classify(inst, addr) {
            None => {}
            Some(Patch::TrapFlag) => {
                // before the branch of iret, at the end of popf
                let check: pcode::Instruction =
                    (pcode::Op::HookIf(self.tf_hook), pcode::Value::from(self.tf)).into();
                match inst.instructions.last().map(|stmt| stmt.op) {
                    Some(pcode::Op::Branch(_)) => {
                        let at = inst.instructions.len() - 1;
                        inst.instructions.insert(at, check);
                    }
                    _ => inst.push(check),
                }
            }
            Some(Patch::Cpuid) => {
                inst.instructions.truncate(1);
                inst.push(pcode::Op::Hook(self.cpuid_hook));
            }
            Some(Patch::Privileged) => {
                inst.instructions.truncate(1);
                inst.push((
                    pcode::Op::Exception,
                    (ExceptionCode::Environment as u32, ENV_PRIVILEGED),
                ));
            }
            Some(Patch::Sysenter) => {
                inst.instructions.truncate(1);
                inst.push((
                    self.next_pc,
                    pcode::Op::Copy,
                    pcode::Value::Const(addr + len, self.next_pc.size),
                ));
                inst.push((pcode::Op::Exception, (ExceptionCode::Syscall as u32, 0u64)));
            }
        }
    }
}

fn cpuid_values(leaf: u32, sub: u32) -> [u32; 4] {
    let s = |b: &[u8; 4]| u32::from_le_bytes(*b);
    match leaf {
        0 => [0xD, s(b"Genu"), s(b"ntel"), s(b"ineI")],
        // family 6 model 0x9e; no hypervisor bit
        1 => [0x000906EA, 0x00100800, 0x7FFAFBBF & !(1 << 31), 0xBFEBFBFF],
        7 if sub == 0 => [0, 0x029C67AF, 0, 0],
        0x8000_0000 => [0x8000_0008, 0, 0, 0],
        0x8000_0001 => [0, 0, 0x121, 0x2C10_0800],
        0x8000_0002 => [s(b"Inte"), s(b"l(R)"), s(b" Cor"), s(b"e(TM")],
        0x8000_0003 => [s(b") i7"), s(b"-870"), s(b"0K C"), s(b"PU @")],
        0x8000_0004 => [s(b" 3.6"), s(b"0GHz"), 0, 0],
        _ => [0, 0, 0, 0],
    }
}

struct CpuidRegs {
    eax: pcode::VarNode,
    ebx: pcode::VarNode,
    ecx: pcode::VarNode,
    edx: pcode::VarNode,
}

#[pyclass(unsendable, module = "angr.rustylib.winemu")]
pub struct WinVm {
    vm: icicle_vm::Vm,
    is_64bit: bool,
    regs: HashMap<String, pcode::VarNode>,
    eflags: pcode::VarNode,
    tf: pcode::VarNode,
    threads: HashMap<u64, Regs>,
    snapshot: Option<icicle_vm::Snapshot>,
    #[pyo3(get)]
    smc_count: u64,
    #[pyo3(get)]
    runs: u64,
    #[pyo3(get)]
    fixups: u64,
    code_pages: std::collections::HashSet<u64>,
    scanned_blocks: usize,
}

fn reg_var(vm: &icicle_vm::Vm, name: &str) -> Option<pcode::VarNode> {
    let sleigh = &vm.cpu.arch.sleigh;
    sleigh
        .get_reg(name)
        .or_else(|| sleigh.get_reg(&name.to_uppercase()))?
        .get_var()
}

impl WinVm {
    fn var(&self, name: &str) -> PyResult<pcode::VarNode> {
        if let Some(var) = self.regs.get(name) {
            return Ok(*var);
        }
        reg_var(&self.vm, name)
            .ok_or_else(|| PyKeyError::new_err(format!("unknown register {name}")))
    }

    /// Drop all lifted code overlapping [addr, addr + size).
    fn invalidate_code(&mut self, addr: u64, size: u64, keep_current: bool) {
        let end = addr.saturating_add(size);
        let mut keys = Vec::new();
        let mut blocks = Vec::new();
        for (key, group) in &self.vm.code.map {
            if group.start < end && group.end >= addr {
                keys.push(*key);
                blocks.extend(group.range());
            }
        }
        if keys.is_empty() {
            return;
        }
        for key in keys {
            self.vm.code.map.remove(&key);
        }
        let current = self.vm.cpu.block_id;
        for id in blocks {
            self.vm.jit.invalidate(id);
            self.vm.code.blocks[id].entry = None;
            if id as u64 == current && !keep_current {
                let pc = self.vm.cpu.read_pc();
                self.vm.cpu.write_pc(pc);
            }
        }
        self.vm
            .code
            .disasm
            .retain(|&vaddr, _| vaddr < addr || vaddr >= end);
    }

    /// Whether code was ever lifted from the page at addr. Icicle's per-page `executed` mark is lost when a page
    /// is copied on write after a snapshot, so the lifted blocks themselves are the record.
    fn page_executed(&mut self, addr: u64) -> bool {
        let blocks = &self.vm.code.blocks;
        for block in &blocks[self.scanned_blocks.min(blocks.len())..] {
            let mut page = block.start & !(PAGE - 1);
            while page < block.end.max(block.start + 1) {
                self.code_pages.insert(page);
                page += PAGE;
            }
        }
        self.scanned_blocks = blocks.len();
        self.code_pages.contains(&(addr & !(PAGE - 1)))
    }

    /// Drop the code of the pages in [addr, addr + size) that ran, and clear their code-cache marks.
    fn forget_code_pages(&mut self, addr: u64, size: u64, keep_current: bool) {
        let start = addr & !(PAGE - 1);
        let end = addr.saturating_add(size).saturating_add(PAGE - 1) & !(PAGE - 1);
        let mut page = start;
        while page < end {
            if self.page_executed(page) {
                self.invalidate_code(page, PAGE, keep_current);
                let p = self.vm.cpu.mem.get_perm(page) & (perm::READ | perm::WRITE | perm::EXEC);
                let _ = self.vm.cpu.mem.update_perm(page, PAGE, p);
            }
            page += PAGE;
        }
    }

    /// A guest write hit lifted code. Icicle raises this after the instruction may already have updated
    /// registers (stosd advances edi first), so the instruction is finished from where it stopped instead of
    /// being restarted; then the code is lifted again.
    fn on_smc(&mut self, addr: u64, limit: u64) -> Option<icicle_vm::VmExit> {
        self.smc_count += 1;
        let page = addr & !(PAGE - 1);
        // a write may straddle two pages
        let size = if (addr & (PAGE - 1)) > PAGE - 16 {
            2 * PAGE
        } else {
            PAGE
        };
        self.forget_code_pages(page, size, true);
        self.vm.cpu.exception.clear();
        // resuming mid-instruction counts that instruction, so this runs exactly its rest
        self.vm.icount_limit = self.vm.cpu.icount + 1;
        let exit = self.vm.run();
        self.vm.icount_limit = limit;
        match exit {
            icicle_vm::VmExit::InstructionLimit => {
                let pc = self.vm.cpu.read_pc();
                self.vm.cpu.write_pc(pc);
                None
            }
            other => Some(other),
        }
    }

    /// SLEIGH rejects prefixes the CPU ignores (a REX that does not directly precede the opcode). Lift the code
    /// at addr as if each such byte were a DS prefix, without the guest seeing the change. Returns whether a block
    /// now exists at addr.
    fn lift_redundant_prefixes(&mut self, addr: u64) -> bool {
        let key = BlockKey {
            vaddr: addr,
            isa_mode: self.vm.cpu.isa_mode() as u64,
        };
        if self.vm.code.map.contains_key(&key) {
            return true;
        }
        if !self.is_64bit {
            return false;
        }
        let mut orig = [0u8; 15];
        if self
            .vm
            .cpu
            .mem
            .read_bytes(addr, &mut orig, perm::NONE)
            .is_err()
        {
            return false;
        }
        let mut canon = orig;
        let mut i = 0;
        while i < 14 {
            match orig[i] {
                0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {}
                0x40..=0x4F => {
                    let next = orig[i + 1];
                    let is_prefix = matches!(
                        next,
                        0x40..=0x4F
                            | 0x26
                            | 0x2E
                            | 0x36
                            | 0x3E
                            | 0x64
                            | 0x65
                            | 0x66
                            | 0x67
                            | 0xF0
                            | 0xF2
                            | 0xF3
                    );
                    if is_prefix {
                        canon[i] = 0x3E;
                    }
                }
                _ => break,
            }
            i += 1;
        }
        if canon == orig {
            return false;
        }
        self.fixups += 1;
        let smc = self.vm.cpu.mem.detect_self_modifying_code;
        self.vm.cpu.mem.detect_self_modifying_code = false;
        let _ = self.vm.cpu.mem.write_bytes(addr, &canon, perm::NONE);
        let lifted = self.vm.lift(addr).is_ok();
        let _ = self.vm.cpu.mem.write_bytes(addr, &orig, perm::NONE);
        self.vm.cpu.mem.detect_self_modifying_code = smc;
        lifted
    }

    fn step_over_breakpoint(&mut self) -> icicle_vm::VmExit {
        let pc = self.vm.cpu.read_pc();
        let had = self.vm.remove_breakpoint(pc);
        let exit = self.vm.step(1);
        if had {
            self.vm.add_breakpoint(pc);
        }
        exit
    }
}

#[pymethods]
impl WinVm {
    #[new]
    #[pyo3(signature = (is_64bit, processors_path, enable_jit=true))]
    pub fn new(is_64bit: bool, processors_path: String, enable_jit: bool) -> PyResult<Self> {
        let triple = if is_64bit { "x86_64-none" } else { "i686-none" };
        let mut config = icicle_vm::cpu::Config::from_target_triple(triple);
        config.enable_shadow_stack = false;
        config.enable_jit = enable_jit;
        // the lifter's optimizers cost more than they save on code that runs a few times (4x on Themida);
        // ANGR_WINEMU_LIFT_OPT=1 turns them back on
        let optimize = std::env::var_os("ANGR_WINEMU_LIFT_OPT").is_some();
        config.optimize_block = optimize;
        config.optimize_instructions = optimize;
        let mut vm = icicle_vm::build_with_path(&config, &PathBuf::from(processors_path))
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to build VM: {e}")))?;

        // whole-cache recompilation (every 60 s) builds functions too large for cranelift on protector code
        vm.enable_recompilation = false;
        // icicle's default of 50k pages (200 MB) is less than some protected processes touch
        vm.cpu.mem.set_capacity(1 << 20);
        let mut regs = HashMap::new();
        {
            let sleigh = &vm.cpu.arch.sleigh;
            for reg in &sleigh.named_registers {
                regs.insert(
                    sleigh.get_str(reg.name).to_lowercase(),
                    reg.get_var().unwrap_or(pcode::VarNode::NONE),
                );
            }
        }
        regs.retain(|_, v| !v.is_invalid());
        fn get(vm: &icicle_vm::Vm, name: &str) -> PyResult<pcode::VarNode> {
            reg_var(vm, name).ok_or_else(|| PyKeyError::new_err(name.to_string()))
        }
        let eflags = get(&vm, "eflags")?;
        let tf = get(&vm, "TF")?;
        let next_pc = vm.cpu.arch.reg_next_pc;
        vm.cpu
            .add_reg_handler(eflags.id, Box::new(FlagsHandler { eflags }));
        regs.insert("rflags".into(), eflags);
        regs.insert("flags".into(), eflags);
        if is_64bit {
            regs.insert("gs_base".into(), get(&vm, "GS_OFFSET")?);
        } else {
            regs.insert("fs_base".into(), get(&vm, "FS_OFFSET")?);
        }

        let names: [&str; 4] = if is_64bit {
            ["RAX", "RBX", "RCX", "RDX"]
        } else {
            ["EAX", "EBX", "ECX", "EDX"]
        };
        let cr = CpuidRegs {
            eax: get(&vm, names[0])?,
            ebx: get(&vm, names[1])?,
            ecx: get(&vm, names[2])?,
            edx: get(&vm, names[3])?,
        };
        let cpuid_hook = vm.cpu.add_hook(move |cpu: &mut Cpu, _addr: u64| {
            let leaf = cpu.read_reg(cr.eax) as u32;
            let sub = cpu.read_reg(cr.ecx) as u32;
            let [a, b, c, d] = cpuid_values(leaf, sub);
            cpu.write_reg(cr.eax, a as u64);
            cpu.write_reg(cr.ebx, b as u64);
            cpu.write_reg(cr.ecx, c as u64);
            cpu.write_reg(cr.edx, d as u64);
        });
        let div_hook = vm.cpu.add_hook(move |cpu: &mut Cpu, _addr: u64| {
            cpu.exception = Exception::new(ExceptionCode::DivisionException, 0);
        });
        let tf_hook = vm.cpu.add_hook(move |cpu: &mut Cpu, _addr: u64| {
            cpu.write_var::<u8>(tf, 0);
            cpu.exception = Exception::new(ExceptionCode::Environment, ENV_TRAP_FLAG);
        });
        let mut cpuid_ops = Vec::new();
        let mut sysenter_op = None;
        {
            let sleigh = &vm.cpu.arch.sleigh;
            for (id, op) in sleigh.user_ops.iter().enumerate() {
                let name = sleigh.get_str(*op);
                if name.starts_with("cpuid") {
                    cpuid_ops.push(id as u16);
                } else if name == "sysenter" {
                    sysenter_op = Some(id as u16);
                }
            }
        }
        let patcher = WinPatcher {
            cpuid_ops,
            sysenter_op,
            cpuid_hook,
            tf_hook,
            div_hook,
            precise_faults: std::env::var_os("ANGR_WINEMU_IMPRECISE").is_none(),
            tf,
            af: get(&vm, "AF")?,
            of: get(&vm, "OF")?,
            sf: get(&vm, "SF")?,
            next_pc,
        };
        vm.lifter
            .patchers
            .push(Box::new(move |inst: &mut pcode::Block| patcher.patch(inst)));
        for &(name, helper) in helpers() {
            if let Some(id) = vm.cpu.arch.sleigh.get_userop(name) {
                vm.cpu.set_helper(id, helper);
            }
        }
        // what smsw shows on Windows 7: PE, MP, ET, NE, WP, PG
        let cr0 = get(&vm, "CR0")?;
        vm.cpu.write_reg(cr0, 0x8001_003B);
        // x87, SSE and AVX state enabled, matching the OSXSAVE and AVX bits cpuid reports
        let xcr0 = get(&vm, "XCR0")?;
        vm.cpu.write_reg(xcr0, 7);

        Ok(Self {
            vm,
            is_64bit,
            regs,
            eflags,
            tf,
            threads: HashMap::new(),
            snapshot: None,
            smc_count: 0,
            runs: 0,
            fixups: 0,
            code_pages: std::collections::HashSet::new(),
            scanned_blocks: 0,
        })
    }

    #[getter]
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    // Registers

    pub fn reg_read(&mut self, name: &str) -> PyResult<u64> {
        let var = self.var(name)?;
        Ok(self.vm.cpu.read_reg(var))
    }

    pub fn reg_write(&mut self, name: &str, value: u64) -> PyResult<()> {
        let var = self.var(name)?;
        let value = if var == self.eflags {
            value & !0x100
        } else {
            value
        };
        self.vm.cpu.write_reg(var, value);
        // the current block may have folded in the old value
        let pc = self.vm.cpu.read_pc();
        self.vm.cpu.write_pc(pc);
        Ok(())
    }

    /// The raw little-endian bytes of a register of any width (XMM, x87).
    pub fn reg_read_bytes<'py>(&mut self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyBytes>> {
        let var = self.var(name)?;
        let bytes: Vec<u8> = (0..var.size)
            .map(|i| self.vm.cpu.read_var::<u8>(var.slice(i, 1)))
            .collect();
        Ok(PyBytes::new(py, &bytes))
    }

    pub fn reg_write_bytes(&mut self, name: &str, data: Vec<u8>) -> PyResult<()> {
        let var = self.var(name)?;
        if data.len() != var.size as usize {
            return Err(PyValueError::new_err(format!(
                "{name} is {} bytes wide",
                var.size
            )));
        }
        for (i, byte) in data.into_iter().enumerate() {
            self.vm.cpu.write_var::<u8>(var.slice(i as u8, 1), byte);
        }
        Ok(())
    }

    #[getter]
    pub fn get_pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    #[setter]
    pub fn set_pc(&mut self, pc: u64) {
        self.vm.cpu.write_pc(pc);
    }

    /// How many times a block is interpreted before it is compiled.
    #[getter]
    pub fn get_jit_threshold(&self) -> u32 {
        self.vm.jit_threshold
    }

    #[setter]
    pub fn set_jit_threshold(&mut self, threshold: u32) {
        self.vm.jit_threshold = threshold;
    }

    #[getter]
    pub fn get_jit(&self) -> bool {
        self.vm.enable_jit
    }

    #[setter]
    pub fn set_jit(&mut self, enable: bool) {
        self.vm.enable_jit = enable;
    }

    #[getter]
    pub fn get_icount(&self) -> u64 {
        self.vm.cpu.icount
    }

    #[getter]
    pub fn get_trap_flag(&mut self) -> bool {
        self.vm.cpu.read_var::<u8>(self.tf) != 0
    }

    /// Save the register file of the running thread under `tid`.
    pub fn save_thread(&mut self, tid: u64) {
        self.threads.insert(tid, self.vm.cpu.regs.clone());
    }

    pub fn load_thread(&mut self, tid: u64) -> PyResult<()> {
        let regs = self
            .threads
            .get(&tid)
            .ok_or_else(|| PyKeyError::new_err(format!("no saved thread {tid}")))?;
        let valid = self.vm.cpu.arch.sleigh.num_registers();
        self.vm.cpu.regs.restore_from(regs, valid);
        let pc = self.vm.cpu.read_pc();
        self.vm.cpu.write_pc(pc);
        Ok(())
    }

    // Memory

    pub fn mem_map(&mut self, addr: u64, size: u64, perms: u8) -> PyResult<()> {
        let mapping = Mapping {
            perm: perms_to_icicle(perms),
            value: 0,
        };
        // lifted code from whatever was mapped here before is stale
        let mut page = addr & !(PAGE - 1);
        while page < addr.saturating_add(size) {
            if self.page_executed(page) {
                self.invalidate_code(page, PAGE, false);
            }
            page += PAGE;
        }
        if !self.vm.cpu.mem.map_memory_len(addr, size, mapping) {
            return Err(PyRuntimeError::new_err(format!(
                "Failed to map {size:#x} bytes at {addr:#x}"
            )));
        }
        Ok(())
    }

    pub fn mem_unmap(&mut self, addr: u64, size: u64) -> PyResult<()> {
        self.invalidate_code(addr, size, false);
        if !self.vm.cpu.mem.unmap_memory_len(addr, size) {
            return Err(PyRuntimeError::new_err(format!(
                "Failed to unmap {size:#x} bytes at {addr:#x}"
            )));
        }
        Ok(())
    }

    /// Change the permissions of whole pages. Code lifted from them is dropped.
    pub fn mem_protect(&mut self, addr: u64, size: u64, perms: u8) -> PyResult<()> {
        let start = addr & !(PAGE - 1);
        let end = addr.saturating_add(size).saturating_add(PAGE - 1) & !(PAGE - 1);
        let mut page = start;
        while page < end {
            if self.page_executed(page) {
                self.invalidate_code(page, PAGE, false);
            }
            page += PAGE;
        }
        self.vm
            .cpu
            .mem
            .update_perm(start, end - start, perms_to_icicle(perms))
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to protect {addr:#x}: {e}")))?;
        let pc = self.vm.cpu.read_pc();
        self.vm.cpu.write_pc(pc);
        Ok(())
    }

    /// Permission bits (1 r, 2 w, 4 x) of the page at addr, or None if it is not mapped.
    pub fn mem_perm(&self, addr: u64) -> Option<u8> {
        let p = self.vm.cpu.mem.get_perm(addr);
        if p & perm::MAP == 0 {
            return None;
        }
        Some(
            (if p & perm::READ != 0 { 1 } else { 0 })
                | (if p & perm::WRITE != 0 { 2 } else { 0 })
                | (if p & perm::EXEC != 0 { 4 } else { 0 }),
        )
    }

    /// Read guest memory; unmapped bytes read as zero.
    pub fn mem_read<'py>(
        &mut self,
        py: Python<'py>,
        addr: u64,
        size: usize,
    ) -> Bound<'py, PyBytes> {
        let mut out = vec![0u8; size];
        let mut pos = 0usize;
        while pos < size {
            let a = addr.wrapping_add(pos as u64);
            let chunk = ((PAGE - (a & (PAGE - 1))) as usize).min(size - pos);
            if self
                .vm
                .cpu
                .mem
                .read_bytes(a, &mut out[pos..pos + chunk], perm::NONE)
                .is_err()
            {
                out[pos..pos + chunk].fill(0);
            }
            pos += chunk;
        }
        PyBytes::new(py, &out)
    }

    /// Write guest memory, dropping any code lifted from the bytes written.
    pub fn mem_write(&mut self, py: Python<'_>, addr: u64, data: PyBuffer<u8>) -> PyResult<()> {
        let data = data.to_vec(py)?;
        if data.is_empty() {
            return Ok(());
        }
        let len = data.len() as u64;
        let mut page = addr & !(PAGE - 1);
        let mut touched_code = false;
        while page < addr + len {
            if self.page_executed(page) {
                touched_code = true;
                break;
            }
            page += PAGE;
        }
        if touched_code {
            self.forget_code_pages(addr, len, false);
        }
        self.vm
            .cpu
            .mem
            .write_bytes(addr, &data, perm::NONE)
            .map_err(|e| {
                PyRuntimeError::new_err(format!("Failed to write {len:#x} bytes at {addr:#x}: {e}"))
            })
    }

    // Execution

    pub fn add_breakpoint(&mut self, addr: u64) -> bool {
        self.vm.add_breakpoint(addr)
    }

    pub fn remove_breakpoint(&mut self, addr: u64) -> bool {
        self.vm.remove_breakpoint(addr)
    }

    /// Run at most `budget` instructions. Returns (kind, code, value): see the EXIT_* constants; for
    /// EXIT_EXCEPTION `code` is the Icicle exception code and `value` its address operand.
    pub fn run(&mut self, py: Python<'_>, budget: u64) -> (u8, u32, u64) {
        let _ = py;
        let limit = self.vm.cpu.icount.saturating_add(budget);
        if self.vm.code.breakpoints.contains(&self.vm.cpu.read_pc()) {
            // resuming on a stop point that has nothing to do there
            self.step_over_breakpoint();
        }
        let mut pending = None;
        loop {
            let exit = match pending.take() {
                Some(exit) => exit,
                None => {
                    self.vm.icount_limit = limit;
                    self.runs += 1;
                    let exit = self.vm.run();
                    self.vm.icount_limit = u64::MAX;
                    exit
                }
            };
            match exit {
                icicle_vm::VmExit::InstructionLimit => return (EXIT_LIMIT, 0, 0),
                icicle_vm::VmExit::Breakpoint => return (EXIT_BREAKPOINT, 0, 0),
                icicle_vm::VmExit::Halt => return (EXIT_HALT, 0, 0),
                icicle_vm::VmExit::UnhandledException((code, value)) => match code {
                    ExceptionCode::SelfModifyingCode => {
                        pending = self.on_smc(value, limit);
                        self.vm.icount_limit = u64::MAX;
                        continue;
                    }
                    ExceptionCode::Environment if value == ENV_TRAP_FLAG => {
                        // the instruction after the one that set the flag runs, then the trap fires
                        self.vm.cpu.exception.clear();
                        // stopped inside the flag-setting instruction: the first step only finishes it
                        let setter = self.vm.cpu.read_pc();
                        let mut exit = self.vm.step(1);
                        if matches!(exit, icicle_vm::VmExit::InstructionLimit)
                            && self.vm.cpu.read_pc() != setter
                            && self.vm.cpu.block_offset != 0
                        {
                            exit = self.vm.step(1);
                        }
                        return match exit {
                            icicle_vm::VmExit::InstructionLimit | icicle_vm::VmExit::Breakpoint => {
                                (EXIT_TRAP_FLAG, 0, 0)
                            }
                            icicle_vm::VmExit::UnhandledException((code, value)) => {
                                fault(code, value)
                            }
                            other => (EXIT_OTHER, other_code(other), 0),
                        };
                    }
                    ExceptionCode::Environment if value == ENV_PRIVILEGED => {
                        return (EXIT_PRIVILEGED, 0, 0);
                    }
                    ExceptionCode::InvalidInstruction if self.lift_redundant_prefixes(value) => {
                        self.vm.cpu.write_pc(value);
                        continue;
                    }
                    code => return fault(code, value),
                },
                other => return (EXIT_OTHER, other_code(other), 0),
            }
        }
    }

    /// Execute one instruction. Returns like `run`.
    pub fn step(&mut self) -> (u8, u32, u64) {
        match self.step_over_breakpoint() {
            icicle_vm::VmExit::InstructionLimit | icicle_vm::VmExit::Breakpoint => {
                (EXIT_LIMIT, 0, 0)
            }
            icicle_vm::VmExit::UnhandledException((code, value)) => match code {
                ExceptionCode::Environment if value == ENV_PRIVILEGED => (EXIT_PRIVILEGED, 0, 0),
                ExceptionCode::Environment if value == ENV_TRAP_FLAG => (EXIT_LIMIT, 0, 0),
                code => fault(code, value),
            },
            other => (EXIT_OTHER, other_code(other), 0),
        }
    }

    /// Execution-local snapshot (memory and registers) for throw-away runs.
    pub fn save_snapshot(&mut self) {
        // track the pages the throw-away run writes
        let pages: Vec<u64> = self.vm.cpu.mem.modified.iter().copied().collect();
        for addr in pages {
            if let Some(index) = self.vm.cpu.mem.get_physical_index(addr) {
                self.vm.cpu.mem.get_physical_mut(index).modified = false;
            }
        }
        self.vm.cpu.mem.clear_page_modification_log();
        self.snapshot = Some(self.vm.snapshot());
    }

    pub fn restore_snapshot(&mut self) -> PyResult<()> {
        let snapshot = self
            .snapshot
            .take()
            .ok_or_else(|| PyValueError::new_err("no snapshot"))?;
        let written: Vec<u64> = self.vm.cpu.mem.modified.iter().copied().collect();
        self.vm.restore(&snapshot);
        self.vm.cpu.mem.clear_page_modification_log();
        // code lifted from bytes the run wrote is stale now
        for page in written {
            self.invalidate_code(page, PAGE, false);
        }
        let pc = self.vm.cpu.read_pc();
        self.vm.cpu.write_pc(pc);
        Ok(())
    }

    /// (address, length) of every instruction lifted so far.
    pub fn lifted_instructions(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for block in &self.vm.code.blocks {
            for stmt in &block.pcode.instructions {
                if let pcode::Op::InstructionMarker = stmt.op {
                    let [addr, len] = stmt.inputs.get();
                    out.push((addr.as_u64(), len.as_u64()));
                }
            }
        }
        out
    }

    /// (name, handling) of every SLEIGH user op: "helper", "lifter" (rewritten when lifted) or "" (unimplemented).
    pub fn user_ops(&self) -> Vec<(String, &'static str)> {
        use icicle_vm::cpu::exec::helpers as icicle_helpers;
        let sleigh = &self.vm.cpu.arch.sleigh;
        let mut out = Vec::new();
        for (id, op) in sleigh.user_ops.iter().enumerate() {
            let name = sleigh.get_str(*op);
            let has_helper = icicle_helpers::HELPERS
                .iter()
                .chain(icicle_helpers::x86::HELPERS)
                .chain(helpers())
                .any(|(helper, _)| *helper == name);
            let handling = if self.vm.lifter.op_injectors.contains_key(&(id as u16))
                || name.starts_with("cpuid")
                || name == "sysenter"
            {
                "lifter"
            } else if has_helper {
                "helper"
            } else {
                ""
            };
            out.push((name.to_string(), handling));
        }
        out
    }

    #[getter]
    pub fn get_code_blocks(&self) -> usize {
        self.vm.code.blocks.len()
    }
}

fn other_code(exit: icicle_vm::VmExit) -> u32 {
    match exit {
        icicle_vm::VmExit::Running => 0,
        icicle_vm::VmExit::InstructionLimit => 1,
        icicle_vm::VmExit::Breakpoint => 2,
        icicle_vm::VmExit::Interrupted => 3,
        icicle_vm::VmExit::Halt => 4,
        icicle_vm::VmExit::Killed => 5,
        icicle_vm::VmExit::Deadlock => 6,
        icicle_vm::VmExit::OutOfMemory => 7,
        icicle_vm::VmExit::Unimplemented => 8,
        icicle_vm::VmExit::UnhandledException(_) => 9,
    }
}

fn perms_to_icicle(p: u8) -> u8 {
    let mut out = perm::INIT;
    if p & 1 != 0 {
        out |= perm::READ;
    }
    if p & 2 != 0 {
        out |= perm::WRITE;
    }
    if p & 4 != 0 {
        out |= perm::EXEC;
    }
    out
}

#[pymodule]
pub fn winemu(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<WinVm>()?;
    m.add("EXIT_LIMIT", EXIT_LIMIT)?;
    m.add("EXIT_BREAKPOINT", EXIT_BREAKPOINT)?;
    m.add("EXIT_TRAP_FLAG", EXIT_TRAP_FLAG)?;
    m.add("EXIT_EXCEPTION", EXIT_EXCEPTION)?;
    m.add("EXIT_PRIVILEGED", EXIT_PRIVILEGED)?;
    m.add("EXIT_HALT", EXIT_HALT)?;
    m.add("EXIT_OTHER", EXIT_OTHER)?;
    m.add("FAULT_READ", FAULT_READ)?;
    m.add("FAULT_WRITE", FAULT_WRITE)?;
    m.add("FAULT_EXEC", FAULT_EXEC)?;
    m.add("FAULT_DIVIDE", FAULT_DIVIDE)?;
    m.add("FAULT_INVALID", FAULT_INVALID)?;
    m.add("FAULT_SYSCALL", FAULT_SYSCALL)?;
    m.add("FAULT_OTHER", FAULT_OTHER)?;
    Ok(())
}
