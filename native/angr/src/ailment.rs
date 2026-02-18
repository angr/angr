use pyo3::prelude::*;

// AIL Expressions
pub use crate::ail_expr::*;

// AIL Statements
pub use crate::ail_stmt::*;

// AIL Block
pub use crate::ail_block::*;

#[pymodule]
pub fn ailment(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Expression classes
    m.add_class::<Const>()?;
    m.add_class::<VirtualVariable>()?;
    m.add_class::<VirtualVariableCategory>()?;
    m.add_class::<Convert>()?;
    m.add_class::<ConvertType>()?;
    m.add_class::<Reinterpret>()?;
    m.add_class::<Load>()?;
    m.add_class::<ITE>()?;
    m.add_class::<UnaryOp>()?;
    m.add_class::<BinaryOp>()?;
    m.add_class::<Phi>()?;
    m.add_class::<DirtyExpression>()?;
    m.add_class::<MultiStatementExpression>()?;
    m.add_class::<BasePointerOffset>()?;
    m.add_class::<StackBaseOffset>()?;
    m.add_class::<ConstValue>()?;
    m.add_class::<OIdentValue>()?;

    // Statement classes
    m.add_class::<Assignment>()?;
    m.add_class::<WeakAssignment>()?;
    m.add_class::<Store>()?;
    m.add_class::<Jump>()?;
    m.add_class::<ConditionalJump>()?;
    m.add_class::<Call>()?;
    m.add_class::<Return>()?;
    m.add_class::<Label>()?;
    m.add_class::<CAS>()?;
    m.add_class::<DirtyStatement>()?;

    // Block class
    m.add_class::<Block>()?;

    Ok(())
}