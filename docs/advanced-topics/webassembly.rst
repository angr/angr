WebAssembly and browsers
========================

angr targets browsers and other WebAssembly hosts using Pyodide. WebAssembly wheels are built for angr,
PyVEX, pypcode, Capstone and pydemumble, and Z3's own Emscripten wheel is downloaded; the remaining Python
dependencies are installed as pure Python or Pyodide packages. The VEX execution engine, Z3, CLE loaders, CFG
recovery, AIL, and the portable Rust extension modules are all carried into the build.

The build does not run yet. Pyodide cannot resolve ``libz3.so`` when it loads ``angr.rustylib``, which has linked
Z3 since angr/angr#6550, so importing angr in the browser fails.

The browser host does not provide every native operating-system facility. WebAssembly builds do not provide
LMDB-backed spilling, psutil memory monitoring, Unicorn, Icicle, subprocesses, or multiprocessing. Analyses use
in-memory function and CFG storage when LMDB is unavailable.

The browser example and reproducible wheel build are in the repository's ``wasm`` directory. The example loads angr
in a dedicated module worker, copies an uploaded binary into Pyodide's virtual filesystem, and runs CFG recovery
without sending the binary to a server. Applications can use the same worker's ``run`` request to execute arbitrary
Python analysis code in the initialized runtime.
