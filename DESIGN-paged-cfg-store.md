# Paged CFG graph store (`feat/cfg-paged-store`)

Successor of the `feat/rust-cfg-graph` store (`DESIGN-rust-cfg-graph.md`). Same public surface
(`angr.rustylib.cfg_graph.CfgGraph`, `SpillingCFG`), new layout and an optional paging mode.

## Why

At mold scale (923k nodes / 1.55M edges) the first Rust store was 270 MB resident: a
`FxHashMap<(u32,u32),Edge>` plus two `Vec<Vec<u32>>` adjacency lists cost ~200 B of bookkeeping per node, and
every read built a fresh dict with a fresh jumpkind `PyString`. Binaries larger than mold would need the graph
to spill again, and the old per-record LMDB spilling was the thing the first store removed (14% of samples on
mold). Access is address-local (71% of Stage-1 edges stay inside the source function; every post-analysis pass
sweeps the graph once), so the unit of spilling has to be an address window, not a record.

## Layout (`native/angr/src/cfg_graph.rs`)

```
node id  = (segment slot: u32) << 32 | local index: u32         (Python int)
window   = addr >> shift   (shift 20 = 1 MB of address space, configurable 1..=32)
Store {
    windows: FxHashMap<window, slot>, slot_windows: Vec<window>, slots: Vec<Slot>,
    order: Vec<node id>,          // global insertion order, NIL on removal
    jumpkinds (interned), backend: Option<Box<dyn SegmentBackend>>, budget, resident_bytes, stats,
}
Slot = Resident(Segment) | Cold(blob not yet handed to a backend) | Evicted(in the backend)
Segment {
    g: petgraph::StableDiGraph<NodeRec, EdgeRec, u32>,
    by_addr: FxHashMap<addr_lo: u32, head local>,      // live nodes at an address, chained through next_at_addr
    proxy_of: FxHashMap<foreign node id, proxy local>,
    dirty, last_used, bytes,
}
NodeRec = Live { addr_lo: u32, size: i32, next_at_addr: u32, seq: u32, call_dst: bool } | Proxy { slot, local }
EdgeRec = { ins_addr: u64, stmt_idx: i32, jk: u16, present: Present(enum u8) }           // 16 B
```

* **One petgraph graph per segment.** `Option<NodeRec>` and `Option<EdgeRec>` (what `StableGraph` stores per
  slot) are niche-sized: `Present` is a fieldless enum so the edge slot is 16 B + 16 B of petgraph links = 32 B,
  the node slot 20 B + 8 B = 28 B (compile-time asserted). `size` and `stmt_idx` are `i32`; values that do not
  fit are rejected (`size`) or routed to `SpillingCFG._extra_edge_attrs` (`stmt_idx`) as before.
* **Cross-segment edges are stored in both endpoint segments.** The foreign endpoint is a *proxy* node holding
  the foreign node id; `has_edge`, `edge_data`, `out_*` need only the source segment, `in_*` only the target
  segment. Proxies are garbage-collected when their last edge goes. `add_edge` merges the same record into both
  copies; `remove_edge`/`remove_node` remove both. Removing a node touches its own segment and then each segment
  that holds a mirror.
* **Iteration order is exactly networkx's.** `nodes()` is the global `order` vector (no segment access at all).
  `node_keys()`, `edges()`, `call_destinations()` walk `order` when everything is resident, and otherwise gather
  per segment and sort by `seq` (one pass over each segment instead of random reloads). petgraph lists are
  newest-first, so successor/predecessor lists are reversed on output.
* **Serialization replays edges in an order that reproduces both out- and in-lists**: a topological merge of the
  two per-node chains (`Segment::edges_in_replay_order`). Per-address chains are serialized verbatim and the
  heads re-derived as "live node nothing points to". A reloaded segment therefore answers every ordered query the
  way the never-evicted one would, which is what makes paged runs produce the same CFG as resident runs.
* **Ids.** A removed node's local index may be reused (petgraph free list). Nothing in Python caches ids across
  a removal; `_ObjKeys` (CFGEmulated/Soot keys) keeps a dict id table instead of a dense list.
* **Read path.** Jumpkind strings are interned once as `Py<PyString>` (parallel to the Rust table); dict
  accessors reuse them. Tuple accessors (`edge_tuple`, `edges_with_tuples`, `out_edges_jumpkinds`,
  `in_edges_jumpkinds`) exist for callers that do not index by name; `CFGModel.serialize_to_cmessage`'s
  per-edge fallback uses them.

## Paging

* `SegmentBackend` trait: `get(window) -> Option<bytes>`, `put(window, bytes)`, `delete(window)`,
  `delete_all()`. Implementations: none (resident mode: `budget = usize::MAX`, nothing is ever evicted),
  `MemoryBackend` (tests), `PyBackend` (any Python object with those four methods).
* Residency: every operation `ensure`s the segments it touches (pinned), then `finish` refreshes their byte
  estimate (`Vec` capacities x slot sizes + map capacities) and evicts least-recently-used unpinned segments
  while `resident_bytes > budget`. Eviction encodes dirty segments to postcard and `put`s them. Counters:
  loads / evictions / writebacks, exposed by `stats()`.
* Blobs: `to_blobs() -> (header, [blob per segment])`; evicted segments are copied straight out of the backend,
  cold ones are passed through, resident ones encoded. `from_blobs` keeps every segment `Cold` until first
  touched, so loading never decodes more than what is used; `attach_backend` hands cold blobs to the backend
  without decoding.
* Promotion: `set_paging_policy(threshold, callback)`; once the live node count reaches the threshold the store
  calls `callback() -> (backend, budget) | None` and attaches. `copy()` is always resident (no backend).

## Python side

* `CFGSegmentStore(rtdb)` (`angr/knowledge_plugins/cfg/spilling_cfg.py`): one shared LMDB sub-database
  `cfgsegments` on the knowledge base's `RuntimeDb` (same environment, same atexit/pin lifecycle), keys =
  per-graph random prefix + window; `MapFullError` grows the map like the other spilling containers.
* `SpillingCFG(segment_budget=None, paged_node_threshold=0, estimated_nodes=0)`: with a budget and an rtdb it
  attaches up front when `max(estimated, live) >= threshold`, otherwise arms the promotion policy (the callback
  holds a weak reference, so the Rust object never keeps the wrapper alive). Re-armed by `set_rtdb`, `copy`,
  `_load_graph_blobs`. `flush()` writes dirty resident segments back; `CFGFast._post_analysis` calls it.
* `Project`: `cache_limits` keys `cfg_segment_bytes` (budget; `None` = never page) and `cfg_paged_nodes`
  (threshold; 0 = page from the first node). Defaults: threshold 1,000,000 nodes, budget
  `min(max(128 MB, 16 x executable bytes), 512 MB)`, estimate = executable bytes / 19. `cfg_edges` is accepted
  and inert.
* angrdb (`cfg.proto`): integer-keyed graphs are stored as `graph_header` + `graph_segments` instead of
  `edges`; loading rebuilds the store from the blobs and only imports the node messages (the spilled fast path
  skips edge replay entirely). Per-edge messages remain for non-int keys and for older databases. `AngrDB.VERSION`
  3 (`COMPATIBLE_VERSIONS` 1, 2, 3). Pickle: `CfgGraph.__reduce__` -> `from_blobs(header, blobs)`.

## Measurements

See REPORT.md in the sandbox for the paired runs; the numbers that drove the layout decisions:

* Resident at mold scale (923k nodes / 1.55M edges, fresh process, statm): 300 MB (previous store) -> 159 MB,
  137 MB after `compact()`; the store's own estimate is 106 MB (20 segments of 1 MB address windows).
* Paired full runs, identical CFGs: mold 456 -> 429 s, peak RSS 3570 -> 3369 MB; e346 255 -> 244 s. No store
  frame in py-spy's top-self list on either arm.
* Forced paged, full mold: 256 MB budget 478 s / 0 loads; 128 MB 487 s / 513 loads; 64 MB (below the 106 MB
  graph) 956 s / 75k loads, 50k of them in `make_functions` (insertion-order sweep). CFG identical at every budget.
* Per-op (us): out_edges_with_data 0.96 -> 0.69, edge_data 0.89 -> 0.97, has_edge 0.75 -> 0.87, out_degree
  0.25 -> 0.43 (list walk instead of Vec::len), add_edge merge 0.81 -> 0.94.
