# Rust-backed CFG graph store (`feat/rust-cfg-graph`)

## Problem

`CFGModel.graph` is a `SpillingCFG`, whose adjacency lives in `SpillingDiGraph` (a networkx `DiGraph` whose
`_adj`/`_pred` outer dicts are `SpillingAdjDict`: LRU + LMDB spilling of per-node inner dicts). On mold (923k
nodes, 603 s) the adjacency load/evict ping-pong on the Stage-1 path `add_edge_by_key -> has_edge/add_edge ->
SpillingAdjDict.__getitem__ -> _load_from_lmdb (+_evict_lru)` is 14% of py-spy samples, adjacency saves another
20 s, and the post-analysis whole-graph sweeps (`make_functions`, `_remove_redundant_overlapping_blocks`) pay for
reloading every record once. A resident Python adjacency would cost about 1.07 KB per edge; a packed store about
60 B per edge, so the whole mold adjacency fits in roughly 100 MB and never needs to spill.

## Rust data layout (`native/angr/src/cfg_graph.rs`, `angr.rustylib.cfg_graph.CfgGraph`)

```
Node   { addr: u64, size: i64, in_graph: bool, call_dst: bool }   // size == -1 encodes "no size"
Edge   { jk: u16, flags: u8, ins_addr: u64, stmt_idx: i64 }        // sentinels encode None; flags = presence bits

CfgGraph {
    nodes:     Vec<Node>,                  // node id = index; stable for the graph lifetime
    by_key:    FxHashMap<(u64, i64), u32>, // (addr, size) -> live node id
    by_addr:   FxHashMap<u64, Vec<u32>>,   // addr -> live node ids (replaces SpillingCFG._keys_by_addr)
    edges:     FxHashMap<(u32, u32), Edge>,
    out_adj:   Vec<Vec<u32>>,              // insertion order == networkx successor order
    in_adj:    Vec<Vec<u32>>,
    n_live:    usize,
    jumpkinds: Vec<String>,                // interning table; jk == u16::MAX is None
    jk_is_call: Vec<bool>,                 // "Ijk_Call" or "Ijk_Sys*"
    jk_pystr:  Vec<Py<PyString>>,          // cached Python str objects, rebuilt lazily after from_bytes
}
```

* Node ids are dense `u32` indices. `remove_node` detaches edges, clears `in_graph`, and drops the node from
  `by_key`/`by_addr`; re-adding the same key allocates a fresh id so that node iteration order matches networkx
  (removed-then-re-added nodes come last). Tombstones are cheap (17 B) and are compacted only by `to_bytes`.
* `add_edge` has networkx merge semantics: attributes that are passed overwrite, attributes that are not passed keep
  their previous value; presence bits make `edge_data()` return exactly the keys that were ever set (networkx
  returns the dict as built; the old LMDB codec always materialised all three keys, which only mattered after a
  spill round trip).
* Jumpkinds are interned strings, not a closed enum, so any jumpkind round-trips losslessly (CFGEmulated passes
  VEX jumpkinds that are not in the protobuf map).
* Call-destination tracking (`SpillingCFG.call_destination_keys`, which `make_functions` uses as function
  starts) keeps master's exact *sticky* semantics: a node is flagged when a call/syscall edge into it is added, and
  unflagged only by `remove_edge`/`remove_node` when no other call/syscall in-edge remains. A jumpkind change via
  `add_edge` merge does not clear the flag, exactly as on master.
* `out_degree`/`in_degree` are `Vec::len`; `SpillingCFG._out_degree_cache` goes away.

## Python wrapper (`angr/knowledge_plugins/cfg/spilling_cfg.py`)

`SpillingCFG` keeps its name and its entire public surface (`add_node`, `add_edge`, `add_edge_by_key`,
`remove_node`, `remove_edge(_by_key)`, `has_edge(_by_key)`, `get_edge_data`, `successors`, `predecessors`,
`nodes`, `edges`, `in_edges`, `out_edges`, `in_degree`, `out_degree`, `out_edges_by_key`, `out_degree_by_key`,
`__getitem__`/`_AdjacencyDict`, `__contains__`, `__len__`, `__iter__`, `nodes_by_addr`, `has_node_addr`,
`node_keys`, `call_destination_keys/nodes`, `copy`, `subgraph`, `to_networkx`, `from_networkx`, spilling
controls, `set_rtdb`, pickling). `self._graph` is now the `CfgGraph`.

Key mapping. Block keys stay the identity at the Python surface (`get_block_key`, `SpillingCFGNodeDict` is keyed by
them). Mapping key -> node id:

* `addr_type == "int"` (CFGFast): keys are `(addr, size)` with `size = -1` for None; the Rust `by_key` map *is* the
  key table (`find_node(addr, size)`, `node_key(id)`), and `by_addr` replaces `_keys_by_addr`. No Python-side
  key table at all.
* `addr_type in ("block_id", "soot")` (CFGEmulated, Soot): a Python interning table `_key_to_id: dict[K, int]` /
  `_id_to_key: list[K]`; Rust nodes get the opaque key `(id, 0)`. `_keys_by_addr` stays a Python
  `defaultdict(set)` for these (addresses can be Soot descriptors).

Both are behind a small `_IntKeys` / `_ObjKeys` strategy object with `id_of(key)`, `add(key, addr)`, `key_of(id)`,
`remove(key)`, `ids_at(addr)`, `has_addr(addr)`.

Extra edge attributes. CFGFast/CFGEmulated only store `jumpkind`, `ins_addr`, `stmt_idx` (CFGEmulated has one
`stmt_id=` typo site). Anything else goes into `SpillingCFG._extra_edge_attrs: dict[(src_id, dst_id), dict]`, merged
into returned edge dicts only when that dict is non-empty, so the fast path pays one truthiness check.

Node storage. `SpillingCFGNodeDict` (CFGNode objects, LMDB-spilled above `cfg_nodes` cap) is unchanged in this
branch; whether node spilling can go too is decided from the paired measurements (REPORT.md).

### Callers that change

* `CFGModel.serialize_to_cmessage` / `_parse_graph_spilled`: iterate `self.graph._graph.edges_with_data()` and map
  node ids to addresses through the Rust store (no `key_to_addr` dict; no eviction toggling).
* `CFGModel.__init__/copy`: still accept `edge_cache_limit`/`edge_db_batch_size`, stored but unused.
* `Project.get_cfg_edge_cache_limit()` and `cache_limits={"cfg_edges": ...}` remain valid and are no-ops.
* Tests that reached into `SpillingDiGraph`/`SpillingAdjDict` (`test_spilling_digraph.py`, `test_pickle.py`,
  `test_cfgmanager_addr_type.py`, `test_spilling_cfg_graph.py`) are rewritten against the new store.
* `prof_cfg.py` in this sandbox imports `SpillingAdjDict` for the E-family timers; the import is made optional.

## Serialization

* angrdb (`cfg.proto`): unchanged on disk. Nodes are still byte-copied via `export_serialized_nodes`; edges are
  written as `primitives.Edge{src_ea, dst_ea, jumpkind, ins_addr, stmt_idx}` from the Rust edge table. Loading uses
  the same two paths (materialised nodes, or the spilled fast path when the node count exceeds the node cap); both
  resolve `src_ea`/`dst_ea` to the first node at that address and call `add_edge_by_key`.
* pickle: `CfgGraph.__reduce__` -> `(CfgGraph.from_bytes, (bytes,))`, a postcard blob (format byte + nodes incl.
  tombstones so that ids stay stable for the object-key tables + edges + jumpkind table). `SpillingCFG.__getstate__`
  pickles the `CfgGraph`, the node-dict state, the key table (object keys only) and `_extra_edge_attrs`.
  `CFGModel` pickling is unchanged.
* Runtime-db edge spilling disappears: no `edges` LMDB database, no `_evict_lru`, no load-evict ping-pong.

## `to_networkx()`, CFGEmulated, Soot

`to_networkx()` builds a plain `networkx.DiGraph` of CFGNode objects (unchanged). CFGEmulated and Soot use the
object-key strategy; their graphs never spilled edges before either (the old codec supported it but the small
graphs never hit the cap). `SpillingDiGraph`/`SpillingAdjDict`/`DirtyDict` are deleted (`spilling_digraph.py`
removed) since nothing but the CFG graph used them.

## Risks

* Edge iteration order: master's `edges()` iterated `SpillingAdjDict` in *set* order (non-deterministic); the new
  store iterates nodes in insertion order and successors in insertion order. Verified by compare_cfg on the
  benchmark binaries (sorted comparison) and by CFGFast test suites.
* `remove_edge` of a missing edge raised `networkx.NetworkXError` before; the wrapper keeps raising it.
