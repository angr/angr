# stub file for angr.rustylib.icicle

from typing_extensions import override

class VmExit:
    """
    The result of a VM execution.
    """

    Running: VmExit
    InstructionLimit: VmExit
    Breakpoint: VmExit
    Interrupted: VmExit
    Halt: VmExit
    Killed: VmExit
    Deadlock: VmExit
    OutOfMemory: VmExit
    Unimplemented: VmExit
    UnhandledException: VmExit

    @override
    def __eq__(self, other: object) -> bool: ...

class ExceptionCode:
    """
    Exception codes produced by the VM.
    """

    NoException: ExceptionCode
    InstructionLimit: ExceptionCode
    Halt: ExceptionCode
    Sleep: ExceptionCode
    SoftwareBreakpoint: ExceptionCode
    Syscall: ExceptionCode
    CpuStateChanged: ExceptionCode
    DivisionException: ExceptionCode
    ReadUnmapped: ExceptionCode
    ReadPerm: ExceptionCode
    ReadUnaligned: ExceptionCode
    ReadWatch: ExceptionCode
    ReadUninitialized: ExceptionCode
    WriteUnmapped: ExceptionCode
    WritePerm: ExceptionCode
    WriteWatch: ExceptionCode
    WriteUnaligned: ExceptionCode
    ExecViolation: ExceptionCode
    SelfModifyingCode: ExceptionCode
    ExecUnaligned: ExceptionCode
    OutOfMemory: ExceptionCode
    AddressOverflow: ExceptionCode
    InvalidInstruction: ExceptionCode
    UnknownInterrupt: ExceptionCode
    UnknownCpuID: ExceptionCode
    InvalidOpSize: ExceptionCode
    InvalidFloatSize: ExceptionCode
    CodeNotTranslated: ExceptionCode
    ShadowStackOverflow: ExceptionCode
    ShadowStackInvalid: ExceptionCode
    InvalidTarget: ExceptionCode
    UnimplementedOp: ExceptionCode
    ExternalAddr: ExceptionCode
    Environment: ExceptionCode
    JitError: ExceptionCode
    InternalError: ExceptionCode
    UnmappedRegister: ExceptionCode
    UnknownError: ExceptionCode

    @override
    def __eq__(self, other: object) -> bool: ...

class Icicle:
    """
    The Icicle VM interface for concrete execution.
    """

    # Arch-independent program counter
    pc: int
    # ISA mode (e.g., ARM Thumb mode)
    isa_mode: int
    # Instruction count limit for the next run
    icount_limit: int
    # Number of instructions executed on the cpu
    cpu_icount: int

    def __init__(
        self, architecture: str, processors_path: str, enable_tracing: bool, enable_edge_hitmap: bool
    ) -> None: ...
    @property
    def architecture(self) -> str:
        """The architecture of the VM, e.g., 'x86_64', 'armv7', etc."""

    def reg_read(self, name: str) -> int:
        """Read a register value.

        :arg name: The name of the register to read.
        :returns: The value of the register.
        """

    def reg_write(self, reg: str, value: int) -> None:
        """Write a value to a register.

        :arg reg: The name of the register to write.
        :arg value: The value to write to the register.
        """

    def mem_map(self, addr: int, size: int, perm: int) -> None:
        """Map a memory region.

        :arg addr: The starting address of the memory region.
        :arg size: The size of the memory region.
        :arg perm: The permissions for the memory region.
        """

    def mem_unmap(self, addr: int, size: int) -> None:
        """Unmap a memory region.

        :arg addr: The starting address of the memory region.
        :arg size: The size of the memory region to unmap.
        """

    def mem_protect(self, addr: int, size: int, perms: int) -> None:
        """Change the permissions of a mapped memory region.

        :arg addr: The starting address of the memory region.
        :arg size: The size of the memory region.
        :arg perms: The new permissions for the memory region.
        """

    def mem_read(self, addr: int, size: int) -> bytes:
        """Read data from memory.

        :arg addr: The starting address to read from.
        :arg size: The number of bytes to read.
        :returns: The data read from memory as bytes.
        """

    def mem_write(self, addr: int, data: bytes) -> None:
        """Write data to memory.

        :arg addr: The starting address to write to.
        :arg data: The data to write to memory as bytes.
        """

    def add_breakpoint(self, addr: int) -> None:
        """Add a breakpoint at a specific address.

        :arg addr: The address where the breakpoint should be set.
        """

    def remove_breakpoint(self, addr: int) -> None:
        """Remove a breakpoint at a specific address.

        :arg addr: The address where the breakpoint should be removed.
        """

    def run(self) -> VmExit:
        """Run the VM until it exits or hits a breakpoint.

        :returns: A VmExit object indicating the result of the run.
        """

    @property
    def exception_code(self) -> ExceptionCode:
        """The exception code from the last run, if any."""

    @property
    def exception_value(self) -> int:
        """The exception code from the last run, if any."""

    @property
    def recent_blocks(self) -> list[tuple[int, int]]:
        """The addresses of recently executed basic blocks, if available."""

    @property
    def edge_hitmap(self) -> bytes | None:
        """The edge hitmap from the most recent run, if edge hitmap is enabled."""

    @edge_hitmap.setter
    def edge_hitmap(self, value: bytes | None) -> None:
        """Set the edge hitmap for the current run."""
