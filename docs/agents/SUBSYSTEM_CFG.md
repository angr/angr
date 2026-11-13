# CFG Recovery Subsystem

All under `analyses/cfg/`.

## Core Files
- cfg.py — `CFG`: compatibility alias for CFGFast
- cfg_base.py — `CFGBase(Analysis)`: shared base; manages CFGModel
- cfg_fast.py — `CFGFast(ForwardAnalysis, CFGBase)`: static recursive disassembly + heuristic function detection
- cfg_emulated.py — `CFGEmulated(ForwardAnalysis, CFGBase)`: symbolic execution-based CFG (precise, slow)
- cfg_fast_soot.py — `CFGFastSoot(CFGFast)`: Java/Soot variant
- cfg_job_base.py — `CFGJobBase`: work item base; `BlockID` for block identity
- cfg_arch_options.py — `CFGArchOptions`: arch-specific tuning knobs
- cfb.py — `CFBlanket(Analysis)`: full binary coverage filling gaps

## Indirect Jump Resolvers (`indirect_jump_resolvers/`)
- resolver.py — `IndirectJumpResolver` base: `filter()` + `resolve()`
- default_resolvers.py — builds resolver chain per arch/format
- jumptable.py — `JumpTableResolver`: switch statement tables
- const_resolver.py — constant-value indirect jumps
- memload_resolver.py — memory-load-based targets
- propagator_utils.py — propagator integration
- constant_value_manager.py — constant value tracking
- syscall_resolver.py — syscall indirect jumps

Arch-specific: amd64_elf_got, amd64_pe_iat, x86_elf_pic_plt, x86_pe_iat, arm_elf_fast, mips_elf_fast, mips_elf_got, aarch64_macho_got

Resolver chain: arch-specific first, then ALL-arch (MemoryLoad, JumpTable, Constant, Syscall).

## CFG Slice to Sink (`analyses/cfg_slice_to_sink/`)
- cfg_slice_to_sink.py — slice CFG from source to sink
- graph.py — graph ops; transitions.py — transition handling

## Key Design
- `CFGBase.model` returns CFGModel (from knowledge_plugins.cfg); stored in `project.kb.cfgs`
- CFGFast uses ForwardAnalysis worklist with CFGJob items
- CFGEmulated also uses ForwardAnalysis but drives symbolic execution per block
- Indirect jump resolution is pluggable: each resolver's `filter()` checked, then `resolve()` called
- CFBlanket registered as both "CFB" and "CFBlanket"
