pub mod icicle;
pub mod segmentlist;

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
    sys_modules.set_item(format!("{}.{}", package, name), submodule.clone())?;

    m.add_submodule(&submodule)?;
    Ok(())
}

#[pymodule]
fn rustylib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    import_submodule(m.py(), m, "angr.rustylib", "icicle", icicle::icicle)?;
    import_submodule(
        m.py(),
        m,
        "angr.rustylib",
        "segmentlist",
        segmentlist::segmentlist,
    )?;

    m.add_class::<segmentlist::Segment>()?;
    m.add_class::<segmentlist::SegmentList>()?;
    Ok(())
}
