# Exploration Techniques

All under `exploration_techniques/`. Attached via `simgr.use_technique(ExplorationTechnique())`.

## Base Class Hooks (base.py)
- `setup(simgr)` — one-time init when attached
- `step(simgr, stash, **kw)` — wrap the overall step
- `filter(simgr, state, **kw)` — route state to stash by name
- `selector(simgr, state, **kw)` — True/False whether state participates
- `step_state(simgr, state, **kw)` — categorize successors; overrides filter
- `successors(simgr, state, **kw)` — control how a state is stepped
- `complete(simgr)` — return True to halt `simgr.run()`

Hooks are nested (each wraps the next). `complete` aggregated via `simgr.completion_mode` (default: `any`).

## Standard Stashes
`active`, `deadended`, `found`, `avoid`, `errored`, `unsat`, `pruned`, `spilled`, `unconstrained`

## Techniques
- Explorer (explorer.py) — find/avoid addresses; moves to found/avoid stashes
- DFS (dfs.py) — depth-first: one active, rest stashed
- LengthLimiter (lengthlimiter.py) — deadend states exceeding max steps
- LoopSeer (loop_seer.py) — detect loops via CFG, discard past bound
- LocalLoopSeer (local_loop_seer.py) — per-function loop bounding
- Veritesting (veritesting.py) — merge paths at CFG join points
- Tracer (tracer.py) — replay concrete trace (QEMU/PIN)
- DrillerCore (driller_core.py) — hybrid fuzzing: concolic on AFL inputs
- Director (director.py) — directed exec toward goals
- Spiller (spiller.py) — serialize states to disk past threshold
- SpillerDB (spiller_db.py) — DB-backed spilling
- Threading (threading.py) — parallel stepping
- StochasticSearch (stochastic.py) — random state selection
- ManualMergepoint (manual_mergepoint.py) — user-specified merge addresses
- Oppologist (oppologist.py) — concretize for unsupported VEX ops
- Slicecutor (slicecutor.py) — execute along program slice
- Bucketizer (bucketizer.py) — group states by address
- MemoryWatcher (memory_watcher.py) — drop states on high memory
- Timeout (timeout.py) — halt after wall-clock limit
- UniqueSearch (unique.py) — avoid duplicate states
- Suggestions (suggestions.py) — user-injected hints
- StubStasher (stub_stasher.py) — stash states at unresolved stubs
- TechniqueBuilder (tech_builder.py) — build from lambdas

## Utilities
- common.py — `condition_to_lambda(condition)`: converts int/set/list/callable to lambda used by Explorer
