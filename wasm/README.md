# angr in WebAssembly

angr supports browsers and other WebAssembly hosts through Pyodide. The WebAssembly build retains the VEX execution
engine, Claripy/Z3 solving, binary loading, CFG recovery, AIL, and the portable parts of `angr.rustylib`.

WebAssembly builds do not provide LMDB-backed spilling, psutil memory monitoring, Unicorn, Icicle, subprocesses, or
multiprocessing. Browser files live in Pyodide's virtual filesystem; pass uploaded bytes to the worker rather than a
host path.

## Build and test

Run `uv sync`, check out an unmodified upstream `z3` beside `angr`, and then run:

```console
$ ./wasm/build_wheels.sh
$ ANGR_WASM_TEST_BINARY=/path/to/fauxware ./wasm/test_wheels.sh
```

The build materializes the exact dependency revisions selected by `uv sync` and `tool.uv.sources`. Existing sibling
checkouts of `archinfo`, `claripy`, `cle`, `pypcode`, or `pyvex` are used for local development instead.

The build produces PEP 783 `pyemscripten_*_wasm32` wheels and `wasm/manifest.json`. If the angr binaries repository is
available as a sibling, it also bundles its x86-64 fauxware sample; set `ANGR_WASM_SAMPLE_BINARY` to use a different
source path. Serve the repository over HTTP and open `wasm/index.html` to analyze the bundled sample or an uploaded
binary. `worker.mjs` also accepts a `run` message, so an application can execute its own Python analysis after
initialization.

## Worker protocol

Each request has an `id` that is copied to the response.

- `{ type: "init", manifestUrl?: string }` loads Pyodide and the wheel manifest.
- `{ type: "analyze", data: ArrayBuffer, cfg?: boolean }` loads a binary and returns entry-block and optional CFG data.
- `{ type: "run", code: string }` runs Python in the initialized angr runtime and returns a JavaScript-converted value.

Keep angr in a dedicated worker: symbolic execution is CPU-intensive and should not block the browser's UI thread.
