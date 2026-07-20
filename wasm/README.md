# angr in WebAssembly

angr supports browsers and other WebAssembly hosts through Pyodide. The WebAssembly build retains the VEX execution
engine, Claripy/Z3 solving, binary loading, CFG recovery, AIL, and the portable parts of `angr.rustylib`.

The host features reported as unavailable by `angr.capabilities` are LMDB-backed spilling, psutil memory monitoring,
P-code, Unicorn, Icicle, subprocesses, and multiprocessing. Browser files live in Pyodide's virtual filesystem; pass
uploaded bytes to the worker rather than a host path.

## Build and test

Check out `angr`, `archinfo`, `claripy`, `cle`, `pyvex`, and `z3` as siblings in one directory, initialize PyVEX's VEX
submodule, and run:

```console
$ ./wasm/build_wheels.sh
$ ANGR_WASM_TEST_BINARY=/path/to/fauxware ./wasm/test_wheels.sh
```

The build produces PEP 783 `pyemscripten_*_wasm32` wheels and `wasm/manifest.json`. Serve the repository over HTTP and
open `wasm/index.html` for the minimal upload-and-analyze demo. `worker.mjs` also accepts a `run` message, so an
application can execute its own Python analysis after initialization.

## Worker protocol

Each request has an `id` that is copied to the response.

- `{ type: "init", manifestUrl?: string }` loads Pyodide and the wheel manifest.
- `{ type: "analyze", data: ArrayBuffer, cfg?: boolean }` loads a binary and returns entry-block and optional CFG data.
- `{ type: "run", code: string }` runs Python in the initialized angr runtime and returns a JavaScript-converted value.

Keep angr in a dedicated worker: symbolic execution is CPU-intensive and should not block the browser's UI thread.
