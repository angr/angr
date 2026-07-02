use crate::prelude::*;

#[pyclass(extends=Base, subclass, frozen, weakref, module="claripy.ast.bits")]
#[derive(Default)]
pub struct Bits;

impl Bits {
    pub fn new() -> Self {
        Bits {}
    }
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Bits>()?;
    Ok(())
}
