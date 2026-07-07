//! Module-level ``ailment.dumps`` / ``ailment.loads`` entry points.
//!
//! There's a single ``Expression`` and a single ``Statement`` pyclass,
//! both with their own
//! ``to_bytes`` / ``from_bytes`` methods that postcard-encode the
//! inline ``AilExpression`` / ``AilStatement`` fat enums. The
//! module-level ``dumps`` / ``loads`` just wrap that payload with a
//! one-byte format version and a discriminator so callers don't have
//! to know which kind of node they're handling.

use pyo3::exceptions::{PyNotImplementedError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use serde::{Deserialize, Serialize};

use crate::ailment::ail_expr::Expression;
use crate::ailment::ail_stmt::Statement;
use crate::ailment::block::Block;

/// One-byte version header prepended to every ``dumps`` payload. Bump
/// when the AilNode shape (below) changes incompatibly.
pub const FORMAT_VERSION: u8 = 0x02;

/// Top-level node carried by ``dumps`` / ``loads``. Per-node payloads
/// are the postcard-encoded ``Wire`` / ``StmtWire`` bytes produced by
/// ``Expression::to_bytes`` / ``Statement::to_bytes``.
#[derive(Debug, Serialize, Deserialize)]
pub enum AilNode {
    /// AIL ``Expression`` -- bytes of the postcard ``Wire``.
    Expr(Vec<u8>),
    /// AIL ``Statement`` -- bytes of the postcard ``StmtWire``.
    Stmt(Vec<u8>),
    /// AIL ``Block`` -- the block header + per-statement
    /// ``to_bytes`` payloads.
    Block(BlockPayload),
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BlockPayload {
    pub addr: i64,
    pub original_size: Option<i64>,
    pub idx: Option<i64>,
    pub statements: Vec<Vec<u8>>,
}

// ===================================================================
// Public byte-level helpers
// ===================================================================

/// Serialize a Python AIL node to bytes. Output is ``[VERSION] [postcard]``.
pub fn dumps_to_bytes(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let node = pyobj_to_node(py, obj)?;
    let body = postcard::to_allocvec(&node)
        .map_err(|e| PyValueError::new_err(format!("postcard encode failed: {e}")))?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Deserialize a Python AIL node from bytes. Expects ``[VERSION] [postcard]``.
pub fn loads_from_bytes(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyAny>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("ailment.loads: empty input"));
    }
    let version = data[0];
    if version != FORMAT_VERSION {
        return Err(PyValueError::new_err(format!(
            "ailment.loads: unsupported format version {version} (expected {FORMAT_VERSION})",
        )));
    }
    let node: AilNode = postcard::from_bytes(&data[1..])
        .map_err(|e| PyValueError::new_err(format!("postcard decode failed: {e}")))?;
    node_to_pyobj(py, node)
}

fn pyobj_to_node(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<AilNode> {
    if let Ok(b) = obj.cast::<Block>() {
        let b = b.borrow();
        let stmts_list = b.statements.bind(py);
        let mut statements: Vec<Vec<u8>> = Vec::with_capacity(stmts_list.len());
        for s in stmts_list.iter() {
            // Native fast path: downcast once and serialize directly, rather
            // than a second downcast plus a Python `to_bytes` dispatch and a
            // PyBytes round-trip.
            let st = s.cast::<Statement>().map_err(|_| {
                PyNotImplementedError::new_err(format!(
                    "ailment.dumps: Block statement {} is not a Statement",
                    type_qualname(&s)
                ))
            })?;
            statements.push(st.borrow().to_wire_bytes()?);
        }
        return Ok(AilNode::Block(BlockPayload {
            addr: b.addr,
            original_size: b.original_size,
            idx: b.idx,
            statements,
        }));
    }
    if let Ok(e) = obj.cast::<Expression>() {
        return Ok(AilNode::Expr(e.borrow().to_wire_bytes()?));
    }
    if let Ok(s) = obj.cast::<Statement>() {
        return Ok(AilNode::Stmt(s.borrow().to_wire_bytes()?));
    }
    Err(PyNotImplementedError::new_err(format!(
        "ailment.dumps: {} is not a Block / Expression / Statement",
        type_qualname(obj)
    )))
}

fn node_to_pyobj(py: Python<'_>, node: AilNode) -> PyResult<Py<PyAny>> {
    match node {
        AilNode::Expr(bytes) => {
            let helper = py
                .import("angr.ailment._reconstruct")?
                .getattr("reconstruct_expression")?;
            Ok(helper.call1((PyBytes::new(py, &bytes),))?.unbind())
        }
        AilNode::Stmt(bytes) => {
            let helper = py
                .import("angr.ailment._reconstruct")?
                .getattr("reconstruct_statement")?;
            Ok(helper.call1((PyBytes::new(py, &bytes),))?.unbind())
        }
        AilNode::Block(b) => {
            let helper = py
                .import("angr.ailment._reconstruct")?
                .getattr("reconstruct_statement")?;
            let stmts = PyList::empty(py);
            for sb in b.statements {
                let s = helper.call1((PyBytes::new(py, &sb),))?;
                stmts.append(s)?;
            }
            let block_cls = py.import("angr.ailment.block")?.getattr("Block")?;
            let kwargs = PyDict::new(py);
            kwargs.set_item("statements", stmts)?;
            kwargs.set_item("original_size", b.original_size)?;
            kwargs.set_item("idx", b.idx)?;
            Ok(block_cls.call((b.addr,), Some(&kwargs))?.unbind())
        }
    }
}

fn type_qualname(obj: &Bound<'_, PyAny>) -> String {
    obj.get_type()
        .qualname()
        .map(|s| s.to_string())
        .unwrap_or_else(|_| "<unknown type>".into())
}

// ===================================================================
// Module-level Python entry points
// ===================================================================

#[pyfunction]
#[pyo3(name = "dumps")]
pub fn py_dumps<'py>(py: Python<'py>, obj: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = dumps_to_bytes(py, obj)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
#[pyo3(name = "loads")]
pub fn py_loads(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyAny>> {
    loads_from_bytes(py, data)
}
