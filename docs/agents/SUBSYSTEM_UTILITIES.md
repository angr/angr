# Utilities, Misc, AngrDB, Protos, Distributed

## Utils (`utils/`)
- graph.py — graph ops: shallow_reverse, inverted_idoms, loop detection, acyclic conversion
- ail.py — AIL expression/statement helpers
- algo.py — algorithm utilities
- balancer.py — constraint balancer for condition simplification
- bits.py — sign-extension, truncation, mask generation
- constants.py — default timeouts, sizes
- cowdict.py — ChainMapCOW / DefaultChainMapCOW: copy-on-write dict
- cpp.py — C++ name demangling
- doms.py — dominator tree utilities
- dynamic_dictlist.py — hybrid dict-list
- endness.py — endianness conversion
- enums_conv.py — enum conversion
- env.py — environment variable helpers
- formatting.py — output formatting
- funcid.py — function identification helpers
- lazy_import.py — lazy module importing
- library.py — library/symbol lookup
- loader.py — loader utilities
- mp.py — multiprocessing helpers
- orderedset.py — OrderedSet
- smart_cache.py — smart caching
- strings.py — string manipulation
- tagged_interval_map.py — tagged interval map
- timing.py — timing/profiling
- types.py — type utilities
- vex.py — VEX IR helpers
- ssa/ — tmp_uses_collector.py, vvar_uses_collector.py, vvar_extra_defs_collector.py

## Misc (`misc/`)
- plugins.py — PluginHub/PluginPreset: generic plugin system used by SimState, analyses, engines, KB
- hookset.py — HookSet/HookedMethod: nested method hooking for exploration techniques
- autoimport.py — auto-import submodules
- loggers.py — logging config
- ansi.py — ANSI color codes
- bug_report.py — bug report generation
- picklable_lock.py — threading.Lock that survives pickling
- testing.py — test helpers
- telemetry.py — telemetry
- ux.py — deprecation warnings, user-facing messages

## AngrDB (`angrdb/`)
SQLAlchemy-based persistent storage for projects and knowledge bases.
- db.py — `AngrDB`: `save(db_path, project, kb)` / `load(db_path)`. SQLite backend.
- models.py — ORM models (DbInformation, DbObject)
- serializers/ — kb.py (KnowledgeBase), cfg_model.py (CFG), funcs.py (functions), variables.py, xrefs.py, comments.py, labels.py, loader.py, structured_code.py

## Protos (`protos/`)
Protobuf definitions + generated _pb2.py: cfg, function, primitives, variables, xrefs

## Distributed (`distributed/`)
Multi-process symbolic execution with state spilling.
- server.py — `Server`: spawns workers, state spill yard (disk), coordinates via SQLite
- worker.py — `Worker`: runs SimulationManager in subprocess with max_states/staging_max
