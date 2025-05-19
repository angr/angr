/// Icicle bindings
///
/// This module provides Python bindings for the Icicle emulator, allowing
/// interaction with the emulator's CPU, memory, and execution state.
///
/// This module is adapted from the `icicle-python` project, which can be found at:
/// https://github.com/icicle-emu/icicle-python
use std::{collections::HashMap, path::PathBuf};

use icicle_vm::cpu::{
    Cpu, ValueSource,
    mem::{Mapping, perm},
};

use pyo3::{
    exceptions::{PyKeyError, PyRuntimeError},
    prelude::*,
};
use target_lexicon::Architecture;

struct X86FlagsRegHandler {
    pub eflags: pcode::VarNode,
}

impl icicle_vm::cpu::RegHandler for X86FlagsRegHandler {
    fn read(&mut self, cpu: &mut Cpu) {
        let eflags = icicle_vm::x86::eflags(cpu);
        cpu.write_var::<u32>(self.eflags, eflags);
    }

    fn write(&mut self, cpu: &mut Cpu) {
        let eflags = cpu.read_var::<u32>(self.eflags);
        icicle_vm::x86::set_eflags(cpu, eflags);
    }
}

/// VmExit is the result of a VM execution. Borrowed directly from icicle.
#[pyclass(module = "angr.rustylib.icicle")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExit {
    /// The VM is still running.
    Running,
    /// The VM exited because it reached instruction count limit.
    InstructionLimit,
    /// The VM exited because it reached a breakpoint.
    Breakpoint,
    /// The VM exited because the interrupt flag was set.
    Interrupted,
    /// The VM has halted.
    Halt,
    /// Killed by an environment specific mechanism.
    Killed,
    /// A deadlock was detected.
    Deadlock,
    /// MMU was unable to allocate memory for an operation.
    OutOfMemory,
    /// Internal error where the emulator reached unimplemented code.
    Unimplemented,
    /// The VM exited due to a unhandled exception.
    UnhandledException,
}

#[pymethods]
impl VmExit {
    pub fn __eq__(&self, other: &Self) -> bool {
        *self == *other
    }
}

impl From<icicle_vm::VmExit> for VmExit {
    fn from(exit: icicle_vm::VmExit) -> Self {
        match exit {
            icicle_vm::VmExit::Running => VmExit::Running,
            icicle_vm::VmExit::InstructionLimit => VmExit::InstructionLimit,
            icicle_vm::VmExit::Breakpoint => VmExit::Breakpoint,
            icicle_vm::VmExit::Interrupted => VmExit::Interrupted,
            icicle_vm::VmExit::Halt => VmExit::Halt,
            icicle_vm::VmExit::Killed => VmExit::Killed,
            icicle_vm::VmExit::Deadlock => VmExit::Deadlock,
            icicle_vm::VmExit::OutOfMemory => VmExit::OutOfMemory,
            icicle_vm::VmExit::Unimplemented => VmExit::Unimplemented,
            icicle_vm::VmExit::UnhandledException(..) => VmExit::UnhandledException,
        }
    }
}

#[pyclass(module = "angr.rustylib.icicle")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ExceptionCode {
    #[pyo3(name = "NoException")]
    None,
    InstructionLimit,
    Halt,
    Sleep,
    SoftwareBreakpoint,
    Syscall,
    CpuStateChanged,
    DivisionException,
    ReadUnmapped,
    ReadPerm,
    ReadUnaligned,
    ReadWatch,
    ReadUninitialized,
    WriteUnmapped,
    WritePerm,
    WriteWatch,
    WriteUnaligned,
    ExecViolation,
    SelfModifyingCode,
    ExecUnaligned,
    OutOfMemory,
    AddressOverflow,
    InvalidInstruction,
    UnknownInterrupt,
    UnknownCpuID,
    InvalidOpSize,
    InvalidFloatSize,
    CodeNotTranslated,
    ShadowStackOverflow,
    ShadowStackInvalid,
    InvalidTarget,
    UnimplementedOp,
    ExternalAddr,
    Environment,
    JitError,
    InternalError,
    UnmappedRegister,
    UnknownError,
}

impl ExceptionCode {
    pub fn from_code(code: u32) -> Self {
        icicle_vm::cpu::ExceptionCode::from_u32(code).into()
    }
}

#[pymethods]
impl ExceptionCode {
    pub fn __eq__(&self, other: &Self) -> bool {
        *self == *other
    }
}

impl From<icicle_vm::cpu::ExceptionCode> for ExceptionCode {
    fn from(value: icicle_vm::cpu::ExceptionCode) -> Self {
        use icicle_vm::cpu::ExceptionCode::*;
        match value {
            None => ExceptionCode::None,
            InstructionLimit => ExceptionCode::InstructionLimit,
            Halt => ExceptionCode::Halt,
            Sleep => ExceptionCode::Sleep,
            SoftwareBreakpoint => ExceptionCode::SoftwareBreakpoint,
            Syscall => ExceptionCode::Syscall,
            CpuStateChanged => ExceptionCode::CpuStateChanged,
            DivisionException => ExceptionCode::DivisionException,
            ReadUnmapped => ExceptionCode::ReadUnmapped,
            ReadPerm => ExceptionCode::ReadPerm,
            ReadUnaligned => ExceptionCode::ReadUnaligned,
            ReadWatch => ExceptionCode::ReadWatch,
            ReadUninitialized => ExceptionCode::ReadUninitialized,
            WriteUnmapped => ExceptionCode::WriteUnmapped,
            WritePerm => ExceptionCode::WritePerm,
            WriteWatch => ExceptionCode::WriteWatch,
            WriteUnaligned => ExceptionCode::WriteUnaligned,
            ExecViolation => ExceptionCode::ExecViolation,
            SelfModifyingCode => ExceptionCode::SelfModifyingCode,
            ExecUnaligned => ExceptionCode::ExecUnaligned,
            OutOfMemory => ExceptionCode::OutOfMemory,
            AddressOverflow => ExceptionCode::AddressOverflow,
            InvalidInstruction => ExceptionCode::InvalidInstruction,
            UnknownInterrupt => ExceptionCode::UnknownInterrupt,
            UnknownCpuID => ExceptionCode::UnknownCpuID,
            InvalidOpSize => ExceptionCode::InvalidOpSize,
            InvalidFloatSize => ExceptionCode::InvalidFloatSize,
            CodeNotTranslated => ExceptionCode::CodeNotTranslated,
            ShadowStackOverflow => ExceptionCode::ShadowStackOverflow,
            ShadowStackInvalid => ExceptionCode::ShadowStackInvalid,
            InvalidTarget => ExceptionCode::InvalidTarget,
            UnimplementedOp => ExceptionCode::UnimplementedOp,
            ExternalAddr => ExceptionCode::ExternalAddr,
            Environment => ExceptionCode::Environment,
            JitError => ExceptionCode::JitError,
            InternalError => ExceptionCode::InternalError,
            UnmappedRegister => ExceptionCode::UnmappedRegister,
            UnknownError => ExceptionCode::UnknownError,
        }
    }
}

#[pyclass(unsendable, module = "angr.rustylib.icicle")]
struct Icicle {
    #[pyo3(get)]
    architecture: String,
    vm: icicle_vm::Vm,
    // regs: HashMap<String, NamedRegister>,
}

#[pymethods]
impl Icicle {
    #[new]
    pub fn new(architecture: String, processors_path: String) -> PyResult<Self> {
        let mut config =
            icicle_vm::cpu::Config::from_target_triple(format!("{}-none", architecture).as_str());
        config.enable_shadow_stack = false;
        let mut vm = icicle_vm::build_with_path(&config, &PathBuf::from(processors_path))
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to build VM: {}", e)))?;

        // Populate the lowercase register map
        let mut regs = HashMap::new();
        let sleigh = &vm.cpu.arch.sleigh;
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            regs.insert(name.to_lowercase(), reg.clone());
        }

        // Special handling for x86 flags
        match config.triple.architecture {
            Architecture::X86_32(_) | Architecture::X86_64 | Architecture::X86_64h => {
                let eflags = sleigh
                    .get_reg("eflags")
                    .ok_or(PyKeyError::new_err(
                        "Could not find eflags register in the architecture",
                    ))?
                    .get_var()
                    .ok_or(PyKeyError::new_err(
                        "Eflags register does not have a variable node",
                    ))?;
                let reg_handler = X86FlagsRegHandler { eflags };
                vm.cpu.add_reg_handler(eflags.id, Box::new(reg_handler));
            }
            _ => {}
        }

        Ok(Self { architecture, vm })
    }

    // Basic state accessors

    pub fn reg_read(&mut self, name: String) -> PyResult<u64> {
        Ok(self.vm.cpu.read_reg(get_reg_varnode(&self.vm, &name)?))
    }

    pub fn reg_write(&mut self, reg: String, value: u64) -> PyResult<()> {
        self.vm
            .cpu
            .write_reg(get_reg_varnode(&self.vm, &reg)?, value);
        Ok(())
    }

    pub fn mem_map(&mut self, addr: u64, size: u64, perm: u8) -> PyResult<()> {
        if !self.vm.cpu.mem.map_memory_len(
            addr,
            size,
            Mapping {
                perm: perms_to_icicle(perm),
                value: 0,
            },
        ) {
            return Err(PyRuntimeError::new_err(format!(
                "Failed to map memory at {:#x} with size {}",
                addr, size
            )));
        }
        Ok(())
    }

    pub fn mem_unmap(&mut self, addr: u64, size: u64) -> PyResult<()> {
        if !self.vm.cpu.mem.unmap_memory_len(addr, size) {
            return Err(PyRuntimeError::new_err(format!(
                "Failed to unmap memory at {:#x} with size {}",
                addr, size
            )));
        }
        Ok(())
    }

    pub fn mem_protect(&mut self, addr: u64, size: u64, perms: u8) -> PyResult<()> {
        self.vm
            .cpu
            .mem
            .update_perm(addr, size, perms_to_icicle(perms))
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "Failed to protect memory at {:#x} with size {}: {}",
                    addr, size, e
                ))
            })?;
        Ok(())
    }

    pub fn mem_read(&mut self, addr: u64, size: u64) -> PyResult<Vec<u8>> {
        let mut buf = vec![0; size as usize];
        self.vm
            .cpu
            .mem
            .read_bytes(addr, &mut buf, perm::NONE)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to read memory: {}", e)))?;
        Ok(buf)
    }

    pub fn mem_write(&mut self, addr: u64, data: Vec<u8>) -> PyResult<()> {
        self.vm
            .cpu
            .mem
            .write_bytes(addr, &data, perm::NONE)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to write memory: {}", e)))?;
        Ok(())
    }

    // Specialized state accessors

    #[getter]
    pub fn get_pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    #[setter]
    pub fn set_pc(&mut self, pc: u64) -> PyResult<()> {
        self.vm.cpu.write_pc(pc);
        Ok(())
    }

    #[getter]
    pub fn get_isa_mode(&self) -> u8 {
        self.vm.cpu.isa_mode()
    }

    #[setter]
    pub fn set_isa_mode(&mut self, mode: u8) {
        // https://github.com/icicle-emu/icicle-emu/issues/70#issuecomment-2857265222
        self.vm.cpu.set_isa_mode(mode);
        self.set_pc(self.get_pc()).unwrap();
    }

    // Execution

    pub fn add_breakpoint(&mut self, addr: u64) -> PyResult<()> {
        if !self.vm.add_breakpoint(addr) {
            return Err(PyRuntimeError::new_err(format!(
                "Failed to add breakpoint at {:#x}",
                addr
            )));
        }
        Ok(())
    }

    pub fn remove_breakpoint(&mut self, addr: u64) -> PyResult<()> {
        if !self.vm.remove_breakpoint(addr) {
            return Err(PyRuntimeError::new_err(format!(
                "Failed to remove breakpoint at {:#x}",
                addr
            )));
        }
        Ok(())
    }

    #[setter]
    pub fn set_icount_limit(&mut self, limit: u64) {
        self.vm.icount_limit = limit;
    }

    #[getter]
    pub fn get_icount_limit(&self) -> u64 {
        self.vm.icount_limit
    }

    pub fn run(&mut self) -> VmExit {
        self.vm.run().into()
    }

    #[getter]
    pub fn get_exception_code(&self) -> ExceptionCode {
        ExceptionCode::from_code(self.vm.cpu.exception.code)
    }

    #[getter]
    pub fn get_exception_value(&self) -> u64 {
        self.vm.cpu.exception.value
    }
}

fn get_reg_varnode(vm: &icicle_vm::Vm, name: &str) -> PyResult<pcode::VarNode> {
    // Try original name first, then uppercase for case-insensitive matching
    let lookup = vm
        .cpu
        .arch
        .sleigh
        .get_reg(name)
        .or_else(|| vm.cpu.arch.sleigh.get_reg(&name.to_uppercase()));
    let reg =
        lookup.ok_or_else(|| PyKeyError::new_err(format!("Could not find register {}", name)))?;
    reg.get_var().ok_or(PyKeyError::new_err(format!(
        "Register {} does not have a variable node",
        name
    )))
}

/// Converts a permission byte to an icicle permission byte.
fn perms_to_icicle(perm: u8) -> u8 {
    let mut icicle_perm = perm::INIT; // Always mark as initialized
    if perm & 0b1 != 0 {
        icicle_perm |= perm::READ;
    }
    if perm & 0b010 != 0 {
        icicle_perm |= perm::WRITE;
    }
    if perm & 0b100 != 0 {
        icicle_perm |= perm::EXEC;
    }
    icicle_perm
}

#[pymodule]
pub fn icicle(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VmExit>()?;
    m.add_class::<ExceptionCode>()?;
    m.add_class::<Icicle>()?;
    Ok(())
}
