# State Plugins, Memory Mixins, and Concretization

## State Plugins (`state_plugins/`)

- **Base**: `plugin.py` `SimStatePlugin` — copied on branch, stores weak ref via `state._get_weakref()` (unless `STRONGREF_STATE = True`, only SimStateHistory uses that)
- Key methods: `copy(memo)` (use `@memo` decorator to avoid infinite recursion), `merge()`, `set_state()`, `init_state()`
- Registered via `SimState.register_default(name, cls)`, accessed as `state.<name>` (lazy)

### Core Plugins
- `solver` (solver.py) — constraint solving, wraps claripy
- `memory`/`registers` (storage/memory_mixins/__init__.py) — mixin-composed memory
- `inspect` (inspect.py) — breakpoints: `mem_read`, `mem_write`, `call`, etc.
- `history` (history.py) — execution history, actions, constraints
- `callstack` (callstack.py), `scratch` (scratch.py) — call frames, per-step temp data
- `posix` (posix.py), `fs` (filesystem.py) — FDs/stdin/stdout, simulated filesystem
- `libc` (libc.py) — heap metadata, locale, format state
- `globals` (globals.py) — dict-like key/value store
- `heap` (heap/heap_brk.py) — default brk heap; swappable with heap_ptmalloc.py
- `log` (log.py) — recorded actions/events
- `unicorn` (unicorn_engine.py) — concrete execution via Unicorn
- `preconstrainer` (preconstrainer.py) — constrain inputs for tracing
- `regs`/`mem` (view.py) — `state.regs.rax` / `state.mem[addr].type` convenience
- Others: symbolizer.py, cgc.py, gdb.py, debug_variables.py, light_registers.py
- JVM: javavm_classloader.py, jni_references.py

## Memory Mixin System (`storage/memory_mixins/`)

- **Base**: `MemoryMixin(SimStatePlugin)` in memory_mixin.py — has `id`, `endness`, `category`
- `category` derived from `memory_id`: "reg", "mem", "file", or custom prefix (e.g. "file_stdin")
- Built by stacking mixins via MRO; each overrides `load()`/`store()` + `super()`
- PagedMemoryMixin uses CoW pages: `acquire_shared()`/`release_shared()` for sharing, `acquire_unique()` for copy-on-write

### DefaultMemory Mixin Stack (top = called first)
HexDumperMixin, SmartFindMixin, UnwrapperMixin — output/search/unwrap
NameResolutionMixin, DataNormalizationMixin — name→addr, int/bytes→BVV
SimplificationMixin, InspectMixinHigh — simplify, breakpoints
ActionsMixinHigh, UnderconstrainedMixin — action recording
SizeConcretizationMixin, SizeNormalizationMixin — symbolic/norm size
AddressConcretizationMixin — symbolic addr → concrete
ActionsMixinLow, ConditionalMixin — low actions, cond read/write
ConvenientMappingsMixin, DirtyAddrsMixin — named regions, dirty tracking
StackAllocationMixin — auto-allocate stack pages
ConcreteBackerMixin, ClemoryBackerMixin, DictBackerMixin — backing stores
PrivilegedPagingMixin, UltraPagesMixin — permissions, page config
DefaultFillerMixin, SymbolicMergerMixin — uninit fill, merge
PagedMemoryMixin — page-based storage with CoW

### Composed Memory Classes
- `DefaultMemory` — standard symbolic execution (UltraPage)
- `DefaultListPagesMemory` — per-byte symbolic (ListPage)
- `FastMemory` — fast concrete-only (SimpleInterfaceMixin + ExplicitFillerMixin + SlottedMemory)
- `AbstractMemory` — value-set analysis (regioned)
- `LabeledMemory` — static analysis with definitions
- `MultiValuedMemory` — multi-value static analysis

### Page Types (`paged_memory/pages/`)
- `UltraPage` — fast concrete byte array, falls back for symbolic
- `ListPage` — per-byte list, full symbolic
- `MVListPage` — multi-value variant

## Concretization Strategies (`concretization_strategies/`)

- **Base**: `SimConcretizationStrategy` in base.py
- Resolves symbolic addresses → concrete value(s)
- Set on `state.memory.read_strategies` / `.write_strategies` (list, tried in order)
- Helpers: `_min()`, `_max()`, `_any()`, `_eval()`, `_range()`

### Built-in Strategies
- Single (single.py) — exactly one solution
- Any (any.py) — any satisfying value
- Eval (eval.py) — up to N solutions
- Range (range.py) — all in [min,max] if range ≤ limit
- Max (max.py) — maximum value
- Norepeats (norepeats.py) — not previously used
- Solutions (solutions.py) — fixed set
- ControlledData (controlled_data.py) — prefer controlled regions

### Default Strategy Chains
- **Reads**: Range(1024, approx?) → Range(1024) → Any()
- **Writes**: Single(approx?) or Range(128, approx?) → Range(128) or filtered → Max()
