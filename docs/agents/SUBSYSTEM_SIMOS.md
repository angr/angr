# SimOS Subsystem

All under `simos/`. OS-level modeling: state init, syscall dispatch, calling conventions, environment setup.

## Class Hierarchy
- SimOS (simos.py) — abstract base, no syscall support
  - SimUserland (userland.py) — adds syscall library mapping + dispatch
    - SimLinux (linux.py) — ELF/Linux process model
    - SimCGC (cgc.py) — DECREE/CGC platform
  - SimWindows (windows.py) — PE/Win32 (extends SimOS directly; limited syscall support)
  - SimJavaVM (javavm.py) — JVM environment for Soot engine
  - SimSnimmucNxp (snimmuc_nxp.py) — bare-metal NXP MCU
  - SimXbox (xbox.py) — Xbox environment

## OS Selection
- `__init__.py` has `os_mapping`: name → SimOS class (from CLE EI_OSABI + registrations)
- `register_simos(name, cls)` adds entries; `Project` looks up via loader's detected OS

## SimOS Base Key Methods
- `configure_project()` — hooks CallReturn, UnresolvableJumpTarget/CallTarget; resolves IRELATIVE relocs
- `state_blank()` — creates SimState with stack, brk, POSIX, permissions, register defaults
- `state_entry()` — state_blank() + entry point setup (args, env)
- `state_full_init()` — state_entry() + runs initializers (_start → main)
- `state_call(addr, *args)` — state for calling a specific function
- `prepare_call_state()` — saves/restores caller regs, sets up call frame
- `syscall()` / `syscall_from_addr()` / `syscall_from_number()` — syscall resolution
- `setup_gdt()` / `generate_gdt()` — x86 GDT/segment setup

## SimUserland — Syscall Dispatch
- Takes `SimSyscallLibrary` at construction (e.g. `SIM_LIBRARIES["linux"]`)
- Maps syscall numbers to addresses in CLE's `kernel_object`
- `syscall_cc(state)` → looks up `SYSCALL_CC[arch][os]`

## OS-Specific
- **SimLinux** — syscall lib: `linux`; hooks LinuxLoader; sets up vsyscall, TLS, auxv, brk; handles ELF cores
- **SimWindows** — loads win32api defs; sets up TEB/PEB, GDT, security cookies; `__fastfail` via ntoskrnl
- **SimCGC** — syscall lib: `cgcabi`; fixed stack at 0xBAAAB000; flag page; DECREE format
- **SimJavaVM** — no syscalls; Soot/Java class hierarchy, native JNI SimProcedures
