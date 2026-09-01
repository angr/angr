# Deobfuscated-graph dump/load

Dump everything the decompiler needs about the devirtualised function, immediately before
`Decompiler` runs, in a format a **different angr version** can load and decompile. No pickle —
Python class layouts differ across versions.

## Producing a dump

Set `project.vm_deob_dump_path` before running `VMDeobfuscation`. Default behaviour is unchanged
when the attribute is unset.

```python
proj = angr.Project("./VM", auto_load_libs=False)
proj.vm_deob_dump_path = "/tmp/xmas.json.gz"
...
proj.analyses.VMDeobfuscation(...)
```

Or without editing the eval script, using the runner in `tools/`:

```sh
cd pushan-evaluation/sample_vm_x-mas-ctf
PUSHAN_OVERRIDES="vm_deob_dump_path=/tmp/xmas.json.gz" \
    <venv>/bin/python <repo>/tools/runner.py
```

## Consuming a dump

```sh
<other-venv>/bin/python <other-tree>/tools/decompile_deobf.py /tmp/xmas.json.gz ./VM -o out.c
```

The consumer needs only `deobf_schema.py` + `deobf_reader.py` (and the CLI). Neither imports
anything from pushan: by the dump point all VM-specific surgery has already been applied to the
graph, so the consumer just needs angr's `Decompiler`.

Useful flags:

* `--rewrite-tmp-sentinel` — rewrite the `"tmp removed"` tyenv sentinel to `Ity_I8`, if a stricter
  decompiler trips over it. The marked temporaries are unreferenced either way.
* `--no-vm-deobfuscation` — stop passing `vm_deobfuscation=True`. **You normally want it on**: this
  angr gates both its VM simplification passes *and* `remove_dead_memdefs` on that flag, and
  without it the same graph decompiles to roughly 3x the code. If output looks bloated, check this
  first.

## Format

Gzipped JSON, `format_version` 1. Two decisions drive the encoding:

* **Every address and constant is a decimal string.** pushan encodes a whole `BlockID` into an
  address, which historically ran to 90–160 bits. JSON numbers are doubles in most parsers, and
  this also rules out MessagePack/CBOR (64-bit integer ceiling).
* **`tyenv.types` may contain the literal string `"tmp removed"`** where a temporary was deleted.
  It is not a valid `Ity_*` and must round-trip verbatim.

Serialise intent, not internal representation: edges are recorded semantically (`transition`,
`call`, `return`) and replayed through the `Function` API so each angr version does its own
bookkeeping; prototypes become C declarations; calling conventions become class names.

The writer refuses to emit an IR construct it has no encoding for rather than dropping it
silently, and it verifies every rendered prototype by re-parsing it (arg count, variadic, per-arg
and return size). A prototype that cannot be rendered faithfully is stored as `null` and listed in
`unrendered_prototypes` — it never emits a declaration that parses back to a different call shape.

## Version adaptation lives in the reader

The format has not changed across the versions tried; the reader adapts to its host:

| difference | handling |
|---|---|
| `_register_nodes(is_local, *nodes)` → `_register_node(is_local, node)` | probes for either |
| `BlockID` moved `analyses.cfg.cfg_job_base` → `knowledge_plugins.cfg.block_id` | tries both, falls back to a tuple |
| AIL addresses became u64 | renumbers into a dense range (`0x7000_0000_0000_0000`, stride `0x1_0000`) driven by `enc_addr_map` |
| AIL block address now comes from the first IMark, not `irsb.addr` | realigns each block's first IMark |
| byte-less synthetic addresses | populates `project.synthetic_irsbs` and sets `project.vm_deobfuscation` where they exist |

The last two are decided by *probing* the running angr (convert a block whose two addresses
disagree; convert one at `1 << 100`), not by version number — so a host that does not need them is
left alone.

Functions the decompiler resolves through the knowledge base rather than a graph edge are dumped
too, with `in_graph: false`. `try_decompilation` deliberately keeps `exit` out of the transition
graph, and a graph-only walk turns `exit(0)` into a raw indirect call.

## Tools

| file | use |
|---|---|
| `tools/decompile_deobf.py` | consumer CLI |
| `tools/deobf_roundtrip.py` | dump → load → re-decompile in-tree; asserts structure and compares the `.c` |
| `tools/test_deobf_format.py` | synthetic round trip over all 14 statement kinds, callsite prototypes, `calls_as_rets`, kb-only callees and forced renumbering |
| `tools/runner.py` | run an eval `script.py` with `PUSHAN_OVERRIDES="attr=value,..."`; `PUSHAN_QUIET=1` suppresses a script's own DEBUG logging |
| `tools/cctrace.py` | trace condition-code `Put` counts through every deobfuscation pass |
| `tools/daeprobe.py`, `tools/daeprobe2.py` | instrument the whole-CFG dead-assignment pass |

Run tools from a neutral cwd — from a repo root, `import angr` picks up `./angr`.

## Known gap

A prototype with a **by-value** struct/array argument cannot be rendered as a standalone C
declaration without also emitting the struct definition; it is stored as `null` plus an
`unrendered_prototypes` entry. 165 of 166 libc prototypes render; the miss is `vsnprintf`, whose
`struct va_list[1]` is passed by value.
