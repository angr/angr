//! Rust port of `angr.ailment` data classes.
//!
//! Exposed Python-side as `angr.rustylib.ailment`.
//!
//! There are two Python-facing pyclasses,
//! ``Expression`` and ``Statement``, each wrapping an inline fat-enum
//! (``ExprInner`` / ``StmtInner``) carrying per-variant data. Per-class
//! marker types (``Const``, ``BinaryOp``, ``Assignment``, ...) live on
//! the Python side and dispatch via metaclass ``__instancecheck__`` on
//! the variant tag.

pub mod ail_expr;
pub mod ail_stmt;
pub mod base;
pub mod block;
pub mod const_value;
pub mod enums;
pub mod hash;
pub mod serialize;
pub mod tags;
pub mod utils;

use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::wrap_pyfunction;

pub fn ailment(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Tags
    m.add_class::<tags::TagsView>()?;
    m.add_class::<tags::TagsKeyIter>()?;

    // Enums
    m.add_class::<enums::VirtualVariableCategory>()?;
    m.add_class::<enums::ConvertType>()?;
    m.add_class::<enums::RoundingMode>()?;
    m.add_class::<enums::ExpressionKind>()?;
    m.add_class::<enums::StatementKind>()?;

    // Fat-enum pyclasses. ``Expression`` wraps the ``AilExpression``
    // sum, ``Statement`` wraps the ``AilStatement`` sum. Per-variant
    // marker classes live on the Python side; see
    // ``angr/ailment/expression.py`` and ``angr/ailment/statement.py``.
    m.add_class::<ail_expr::Expression>()?;
    m.add_class::<ail_stmt::Statement>()?;

    // Block.
    m.add_class::<block::Block>()?;

    // Module-level byte serialization helpers.
    m.add_function(wrap_pyfunction!(serialize::py_dumps, m)?)?;
    m.add_function(wrap_pyfunction!(serialize::py_loads, m)?)?;

    Ok(())
}
