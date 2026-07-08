use pyo3::{create_exception, exceptions::PyException};

create_exception!(angr.rustylib.claripy.errors, ClaripyError, PyException);
create_exception!(angr.rustylib.claripy.errors, ClaripyTypeError, ClaripyError);
create_exception!(angr.rustylib.claripy.errors, UnsatError, ClaripyError);
create_exception!(
    angr.rustylib.claripy.errors,
    ClaripyFrontendError,
    ClaripyError
);
create_exception!(
    angr.rustylib.claripy.errors,
    ClaripySolverInterruptError,
    ClaripyError
);
create_exception!(
    angr.rustylib.claripy.errors,
    ClaripyOperationError,
    ClaripyError
);
create_exception!(
    angr.rustylib.claripy.errors,
    ClaripyZeroDivisionError,
    ClaripyOperationError
);
create_exception!(
    angr.rustylib.claripy.errors,
    InvalidExtractBoundsError,
    ClaripyOperationError
);
