pub mod ailment;
pub mod automaton;
pub mod cfg_block;
pub mod cfg_funcs;
pub mod cfg_graph;
pub mod cfg_jobs;
pub mod cfg_normalize;
pub mod cfg_post;
pub mod cfg_returning;
pub mod cfg_scan;
pub mod claripy;
pub mod function_core;
pub mod function_graph;
pub mod fuzzer;
pub mod icicle;
pub mod ijr;
pub mod memory_data;
pub mod ordered_map;
pub mod recovery_functions;
pub mod segmentlist;
pub mod vexir;
pub mod vexlift;

use pyo3::prelude::*;

fn import_submodule<'py>(
    py: Python<'py>,
    m: &Bound<'py, PyModule>,
    package: &str,
    name: &str,
    import_func: impl FnOnce(&Bound<'py, PyModule>) -> PyResult<()>,
) -> PyResult<()> {
    let submodule = PyModule::new(py, name)?;
    import_func(&submodule)?;

    // Add the submodule to sys.modules
    let sys_modules = PyModule::import(py, "sys")?.getattr("modules")?;
    sys_modules.set_item(format!("{package}.{name}"), submodule.clone())?;

    m.add_submodule(&submodule)?;
    Ok(())
}

#[pymodule]
fn rustylib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    import_submodule(m.py(), m, "angr.rustylib", "fuzzer", fuzzer::fuzzer)?;
    import_submodule(m.py(), m, "angr.rustylib", "icicle", icicle::icicle)?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "segmentlist",
        segmentlist::segmentlist,
    )?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "automaton",
        automaton::automaton,
    )?;
    import_submodule(m.py(), m, "angr.rustylib", "ailment", ailment::ailment)?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "cfg_graph",
        cfg_graph::cfg_graph,
    )?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "function_graph",
        function_graph::function_graph,
    )?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "function_core",
        function_core::function_core,
    )?;
    import_submodule(m.py(), m, "angr.rustylib", "vexlift", vexlift::vexlift)?;
    import_submodule(m.py(), m, "angr.rustylib", "vexir", vexir::vexir)?;
    import_submodule(m.py(), m, "angr.rustylib", "ijr", ijr::ijr)?;
    import_submodule(m.py(), m, "angr.rustylib", "cfg_scan", cfg_scan::cfg_scan)?;
    import_submodule(m.py(), m, "angr.rustylib", "cfg_jobs", cfg_jobs::cfg_jobs)?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "cfg_block",
        cfg_block::cfg_block,
    )?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "recovery_functions",
        recovery_functions::recovery_functions,
    )?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "memory_data",
        memory_data::memory_data,
    )?;
    import_submodule(m.py(), m, "angr.rustylib", "cfg_post", cfg_post::cfg_post)?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "cfg_returning",
        cfg_returning::cfg_returning,
    )?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "cfg_funcs",
        cfg_funcs::cfg_funcs,
    )?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "cfg_normalize",
        cfg_normalize::cfg_normalize,
    )?;

    let py = m.py();
    let claripy_module = PyModule::new(py, "angr.rustylib.claripy")?;
    claripy::claripy(py, &claripy_module)?;
    PyModule::import(py, "sys")?
        .getattr("modules")?
        .set_item("angr.rustylib.claripy", claripy_module.clone())?;
    m.add("claripy", claripy_module)?;

    m.add_class::<segmentlist::Segment>()?;
    m.add_class::<segmentlist::SegmentList>()?;
    Ok(())
}
