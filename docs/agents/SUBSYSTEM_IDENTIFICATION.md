# Function Identification Subsystem

## FLIRT (`analyses/flirt/`)
Byte-pattern trie matching (IDA-compatible .sig files). Entry: `project.analyses.Flirt(sig=path)`

- flirt.py — `FlirtAnalysis(sig=None)`: auto-selects sig if none given
- flirt_sig.py — `FlirtSignature`/`FlirtSignatureParsed`: parsed trie from .sig file
- flirt_node.py — trie node with byte patterns + wildcards
- flirt_matcher.py — walks trie against function bytes, CRC16 verification
- flirt_module.py / flirt_function.py — matched module/function info
- angr/flirt/__init__.py — `FLIRT_SIGNATURES_BY_ARCH`, `load_signatures()`, signature registry
- angr/flirt/build_sig.py — build .sig files from static libraries
- Result: renames kb.functions in place

## Identifier (`analyses/identifier/`)
Identify library functions by symbolic execution of candidates. CGC-only.

- identify.py — `Identifier(cfg=None)`: runs CFGFast, then `find_stack_vars_x86` per function
- runner.py — `Runner`: sets up CGC state, executes candidates via `IdentifierCallable`
- func.py — known function base (`.num_args()`, `.try_match()`)
- functions/ — 23 known: malloc, free, memcpy, memset, memcmp, strlen, strcmp, strcpy, strncmp, strncpy, strcasecmp, printf, sprintf, snprintf, fdprintf, atoi, based_atoi, strtol, int2str, recv_until, skip_calloc, skip_realloc, skip_recv_n
- Bails if `len(cfg.functions) > 400`

## BoyScout (`analyses/boyscout.py`)
Heuristic arch/endianness guessing. Matches `arch.function_prologs`/`epilogs` regexes across all archinfo arches. Votes by (arch, endianness). Result: `.arch`, `.endianness`, `.votes`

## BinDiff (`analyses/bindiff.py`)
Match functions between two binaries. CFG attribute vectors + Levenshtein on basic blocks.
- `BinDiff(other_project, cfg_a=, cfg_b=)`
- `.function_matches` — set((addr_a, addr_b))
- `.identical_functions` / `.differing_functions`
- `.get_function_diff(addr_a, addr_b)` → FunctionDiff with `.differing_blocks`, `.identical_blocks`
