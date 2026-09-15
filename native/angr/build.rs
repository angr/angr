fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // On Emscripten the extension is a side module whose dylink section names libz3.so by bare
    // name, and Pyodide resolves that name against LD_LIBRARY_PATH, which it seeds with its own
    // shared-library directory and site-packages itself, and then against the module's runtime
    // path. The z3-solver wheel installs libz3.so under site-packages/z3/lib, which is on neither,
    // so record where it is relative to the extension.
    // Pyodide normalizes the resolved path, so this finds the copy it already loaded when it
    // installed z3-solver rather than loading a second one. The native platforms need nothing here:
    // angr/_z3.py opens the wheel's libz3 before importing the extension, and their loaders match
    // the needed name against libraries already loaded.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("emscripten") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../z3/lib");
    }
}
