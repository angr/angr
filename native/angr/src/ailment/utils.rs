//! Helpers shared across the ailment port.

use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;

/// Mirror of `angr.ailment.utils.is_none_or_likeable`. Falls back to `==`
/// when the operands are not Expressions.
pub fn is_none_or_likeable(
    py: Python<'_>,
    a: &Bound<'_, PyAny>,
    b: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    if a.is_none() || b.is_none() {
        return a.eq(b);
    }
    if let Ok(true) = a.hasattr("likes") {
        let r = a.call_method1("likes", (b,))?;
        return r.is_truthy();
    }
    let _ = py;
    a.eq(b)
}

pub fn is_none_or_likeable_list(
    py: Python<'_>,
    a: &Bound<'_, PyAny>,
    b: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    if a.is_none() || b.is_none() {
        return a.eq(b);
    }
    let la = a.len()?;
    let lb = b.len()?;
    if la != lb {
        return Ok(false);
    }
    let it_a = a.try_iter()?;
    let it_b = b.try_iter()?;
    for (xa, xb) in it_a.zip(it_b) {
        if !is_none_or_likeable(py, &xa?, &xb?)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn is_none_or_matchable(
    py: Python<'_>,
    a: &Bound<'_, PyAny>,
    b: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    if a.is_none() || b.is_none() {
        return a.eq(b);
    }
    if let Ok(true) = a.hasattr("matches") {
        let r = a.call_method1("matches", (b,))?;
        return r.is_truthy();
    }
    let _ = py;
    a.eq(b)
}

pub fn is_none_or_matchable_list(
    py: Python<'_>,
    a: &Bound<'_, PyAny>,
    b: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    if a.is_none() || b.is_none() {
        return a.eq(b);
    }
    let la = a.len()?;
    let lb = b.len()?;
    if la != lb {
        return Ok(false);
    }
    let it_a = a.try_iter()?;
    let it_b = b.try_iter()?;
    for (xa, xb) in it_a.zip(it_b) {
        if !is_none_or_matchable(py, &xa?, &xb?)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Replace-helper: attempt `obj.replace(old, new)`.
///
/// Only invokes ``replace`` when the target looks like an ailment object
/// (has ``_hash_core``). Builtins like ``str`` happen to expose a ``replace``
/// method with different semantics; calling it would break.
pub fn try_replace<'py>(
    obj: &Bound<'py, PyAny>,
    old: &Bound<'py, PyAny>,
    new: &Bound<'py, PyAny>,
) -> PyResult<(bool, Py<PyAny>)> {
    if obj.is_none() {
        return Ok((false, obj.clone().unbind()));
    }
    if obj.eq(old)? {
        return Ok((true, new.clone().unbind()));
    }
    if obj.hasattr("_hash_core").unwrap_or(false) {
        let res = obj.call_method1("replace", (old, new))?;
        let (r, replaced): (bool, Py<PyAny>) = res.extract()?;
        return Ok((r, replaced));
    }
    Ok((false, obj.clone().unbind()))
}

/// Call `x.deep_copy(manager)`. Used pervasively.
pub fn deep_copy_obj<'py>(
    obj: &Bound<'py, PyAny>,
    manager: &Bound<'py, PyAny>,
) -> PyResult<Py<PyAny>> {
    if obj.is_none() {
        return Ok(obj.clone().unbind());
    }
    let r = obj.call_method1("deep_copy", (manager,))?;
    Ok(r.unbind())
}

/// Hash an arbitrary Python object as `hash(obj) & 0xFFFF_FFFF_FFFF_FFFF`,
/// matching the fallback branch of `_dump_tuple` in the Python implementation.
pub fn py_object_hash_u64(obj: &Bound<'_, PyAny>) -> PyResult<u64> {
    let h = obj.hash()?;
    Ok(h as i128 as u128 as u64)
}

/// Build a Python attribute getter chain: returns whether the chain exists
/// and dereferences it. Used by helpers that want to read `.depth` /
/// `.bits` on heterogeneous operand lists.
pub fn pyobj_bits(obj: &Bound<'_, PyAny>) -> PyResult<u32> {
    if obj.is_none() {
        return Ok(0);
    }
    if let Ok(b) = obj.getattr("bits")
        && !b.is_none()
    {
        return b.extract::<u32>();
    }
    // Fall through to claripy ASTs which expose `.size()`.
    if let Ok(true) = obj.hasattr("size") {
        let s = obj.call_method0("size")?;
        if !s.is_none() {
            return s.extract::<u32>();
        }
    }
    Ok(0)
}

pub fn pyobj_depth(obj: &Bound<'_, PyAny>) -> PyResult<u32> {
    if obj.is_none() {
        return Ok(0);
    }
    if let Ok(d) = obj.getattr("depth")
        && !d.is_none()
    {
        return d.extract::<u32>().or(Ok(0));
    }
    Ok(0)
}
