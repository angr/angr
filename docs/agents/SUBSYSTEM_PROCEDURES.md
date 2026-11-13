# Procedures Subsystem

SimProcedures are Python replacements for library functions. Calling conventions map args/returns to registers/stack.

## Core Classes
- sim_procedure.py — `SimProcedure`: base class; override `run()`, return value or mutate state
- calling_conventions.py — `SimCC` base + `SimRegArg`, `SimStackArg`, `SimComboArg`, `SimCCUsercall`
- procedures/procedure_dict.py — `SIM_PROCEDURES`: global dict, auto-imports all procedures
- procedures/definitions/__init__.py — `SIM_LIBRARIES`, `SimLibrary`: symbol→procedure+prototype mappings

## SimProcedure Lifecycle
1. Engine hits hooked address → looks up SimProcedure in `project._sim_procedures`
2. `execute(state)` copies procedure, extracts args via `cc.next_arg()`, calls `run(*args)`
3. `run()` returns value; `ret(expr)` writes return and jumps to return addr
4. `self.call(addr, args, continue_at=name)` chains to another function

Key class vars: `NO_RET`, `ADDS_EXITS`, `IS_FUNCTION`, `ARGS_MISMATCH`, `ALT_NAMES`, `local_vars`

## Calling Conventions
DEFAULT_CC maps `arch_name → platform → SimCC subclass`:
- AMD64: SimCCSystemVAMD64 (Linux), SimCCMicrosoftAMD64 (Win)
- X86: SimCCCdecl / SimCCMicrosoftCdecl
- AARCH64: SimCCAArch64; ARM: SimCCARM / SimCCARMHF
- MIPS32: SimCCO32; MIPS64: SimCCN64
- PPC32: SimCCPowerPC; PPC64: SimCCPowerPC64
- RISCV64: SimCCRISCV64; S390X: SimCCS390X

Syscall CCs: SimCCX86LinuxSyscall, SimCCAMD64LinuxSyscall, SimCCARMLinuxSyscall, etc.

## Procedure Libraries (`procedures/`)
- libc/ — C stdlib: malloc, free, printf, scanf, strlen, strcmp, strcpy, memcpy, memset, fopen, fread, atoi, strtol, rand, exit
- posix/ — POSIX: read, write, open, close, socket, recv, send, fork, getenv
- glibc/ — glibc: `__libc_start_main`, scanf, sscanf, dlopen/dlsym, errno
- linux_kernel/ — syscalls: mmap, brk, stat, fstat, getpid, sigaction
- linux_loader/ — dynamic linker: sim_loader, TLS setup
- cgc/ — CGC: transmit, receive, allocate, deallocate, random, fdwait
- win32/ — Windows API: VirtualAlloc, heap, GetModuleHandle, file handles, TLS, mutex
- win32_kernel/ — ExAllocatePool, ExFreePoolWithTag
- win_user32/ — MessageBox, keyboard, chars
- ntdll/ — exception handling
- msvcr/ — `__getmainargs`, `_initterm`
- java*/ — java_lang, java_io, java_jni, java_util
- libstdcpp/ — terminate, throw helpers
- stubs/ — ReturnUnconstrained, Nop, PathTerminator, UserHook, format_parser
- definitions/ — library def files mapping symbols → procedures + types

## Key Patterns
- `SIM_PROCEDURES["libc"]["malloc"]` — access procedure class
- `SIM_LIBRARIES["libc.so.6"]` — get SimLibrary with symbol mappings
- `project.hook(addr, MyProcedure())` / `project.hook_symbol("malloc", MyMalloc())`
- `__provides__` class attr — override library/name registration
- `self.inline_call(proc, *args)` — call another SimProcedure inline
