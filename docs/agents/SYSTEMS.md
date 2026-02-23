# angr Subsystems

Entry: `angr.Project(path)` → CLE loader → engines/analyses/SimOS

- **Core** — Project, Factory, SimState, SimManager, KB, Block, errors; [detail](SUBSYSTEM_CORE.md)
- **Engines** — VEX, Unicorn, PCode, Soot, AIL, hooks; `engines/`; [detail](SUBSYSTEM_ENGINES.md)
- **State & Memory** — State plugins, memory mixins, concretization; `state_plugins/`, `storage/`; [detail](SUBSYSTEM_STATE_AND_MEMORY.md)
- **SimOS** — OS models: Linux, Windows, CGC, Java; `simos/`; [detail](SUBSYSTEM_SIMOS.md)
- **Procedures** — SimProcedure hooks + calling conventions; `procedures/`, `calling_conventions.py`; [detail](SUBSYSTEM_PROCEDURES.md)
- **Exploration** — Exploration techniques; `exploration_techniques/`; [detail](SUBSYSTEM_EXPLORATION.md)
- **Knowledge** — KB plugin system (functions, CFG, vars, xrefs, types); `knowledge_plugins/`; [detail](SUBSYSTEM_KNOWLEDGE.md)
- **AIL** — Angr Intermediate Language; `ailment/`; [detail](SUBSYSTEM_AIL.md)
- **CFG** — CFG recovery (CFGFast, CFGEmulated); `analyses/cfg/`; [detail](SUBSYSTEM_CFG.md)
- **Decompiler** — Full decompilation pipeline; `analyses/decompiler/`; [detail](SUBSYSTEM_DECOMPILER.md)
- **Data Flow** — RDA, propagator, DDG, VFG; `analyses/reaching_definitions/`, `analyses/propagator/`; [detail](SUBSYSTEM_DATA_FLOW.md)
- **Recovery** — Variable recovery, Typehoon, CC recovery; `analyses/variable_recovery/`, `analyses/typehoon/`; [detail](SUBSYSTEM_RECOVERY.md)
- **Identification** — FLIRT, identifier, boyscout, bindiff; `analyses/flirt/`, `analyses/identifier/`; [detail](SUBSYSTEM_IDENTIFICATION.md)
- **Analysis Misc** — Loops, slicing, code tagging, vtable, deobfuscator; `analyses/`; [detail](SUBSYSTEM_ANALYSIS_MISC.md)
- **Utilities** — utils, misc, angrdb, protos, distributed; [detail](SUBSYSTEM_UTILITIES.md)

## Patterns
- **Mixin composition**: memory system uses deep mixin chains (`storage/memory_mixins/`)
- **Plugin system**: state + KB plugins use `misc/plugins.py` PluginHub
- **Forward analysis**: `analyses/forward_analysis/` — RDA, propagator, variable recovery
- **Engine dispatch**: `engines/engine.py` UberEngine dispatches via MRO
- **Analysis registration**: `analyses/analysis.py` → `project.analyses.Name()`

## External Deps
CLE (loader), claripy (solver/Z3), pyvex (VEX lifter), archinfo (arch defs), pypcode (P-Code/Sleigh)
