# Knowledge Subsystem

Plugin-based storage for all analysis results, accessed via `project.kb`.

## Architecture
- `KnowledgeBase` (knowledge_base.py) — dict-like; plugins lazy-created on first access
- `KnowledgeBasePlugin` (knowledge_plugins/plugin.py) — base class; `register_default(name, cls)`
- Lookup: `kb.foo` → `get_plugin("foo")` → instantiate from `default_plugins[name]`
- Management: `has_plugin()`, `register_plugin()`, `release_plugin()`, `get_knowledge(cls)` / `request_knowledge(cls)` (type-safe access)

## Plugin Registry
- `functions` → FunctionManager (functions/function_manager.py)
- `variables` → VariableManager (variables/variable_manager.py)
- `cfgs` → CFGManager (cfg/cfg_manager.py)
- `xrefs` → XRefManager (xrefs/xref_manager.py)
- `defs` → KeyDefinitionManager (key_definitions/key_definition_manager.py)
- `propagations` → PropagationManager (propagations/propagation_manager.py)
- `types` → TypesStore (types.py)
- `decompilations` → StructuredCodeManager (structured_code.py)
- `comments` → Comments (comments.py)
- `labels` → Labels (labels.py)
- `patches` → PatchManager (patches.py)
- `data` → Data (data.py)
- `indirect_jumps` → IndirectJumps (indirect_jumps.py)
- `obfuscations` → Obfuscations (obfuscations.py)
- `custom_strings` → CustomStrings (custom_strings.py)
- `dvars` → DebugVariableManager (debug_variables.py)
- `callsite_prototypes` → CallsitePrototypes (callsite_prototypes.py)
- `rtdb` → RuntimeDb (rtdb/rtdb.py)

## Functions (`functions/`)
- `FunctionManager` — dict-like (`kb.functions[addr]`); SortedDict or LMDB-spilling
- `Function` (function.py) — `.name`, `.addr`, `.graph`, `.blocks`, `.calling_convention`, `.prototype`, `.is_simprocedure`
- function_parser.py — builds Function objects from CFG edges/nodes
- soot_function.py — Java/Soot variant

## CFG (`cfg/`)
- `CFGManager` — named CFGModel instances (`kb.cfgs["CFGFast"]`)
- `CFGModel` — `.graph` (networkx DiGraph of CFGNode), `.get_any_node(addr)`
- `CFGNode` — `.addr`, `.size`, `.block`, `.successors`, `.predecessors`, `.function_address`
- MemoryData — data references (strings, pointers) from CFG recovery
- IndirectJump — unresolved/resolved indirect jump targets

## Variables (`variables/`)
- `VariableManager` — `kb.variables[func_addr]` → per-function `VariableManagerInternal`
- `VariableAccess` — records where a SimVariable is read/written

## Cross-References (`xrefs/`)
- `XRefManager` — `.get_xrefs_by_dst(addr)`, `.get_xrefs_by_src(addr)`
- `XRef` — `.ins_addr`, `.dst`, `.xref_type`
- `XRefType` — enum: Offset, Read, Write, CodeReference

## Reaching Definitions (`key_definitions/`)
- KeyDefinitionManager — stores ReachingDefinitionsModel per function
- Definition — value at CodeLocation for an Atom
- Atom — Register, MemoryLocation, Tmp, ConstantSrc, HeapAddress, GuardUse, VirtualVariable
- LiveDefinitions — snapshot of def-use state at program point
- ReachingDefinitionsModel — per-node LiveDefinitions mapping
- Uses — tracks which Definitions used at which CodeLocations

## Propagation (`propagations/`)
- PropagationManager — stores PropagationModel per function
- PropagationModel — per-CodeLocation replacement maps
- PropValue — propagated value wrapper

## Other Plugins
- TypesStore — recovered type info; KnowledgeBasePlugin + UserDict[str, TypeRef]
- StructuredCodeManager — caches decompiled StructuredCode per function
- Comments — dict[int, str] mapping address → comment
- Labels — dict[int, str] mapping address → label
- PatchManager — binary patches with `.apply_patches_to_binary()`
- RuntimeDb — runtime database for dynamic analysis
