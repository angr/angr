use pyo3::{create_exception, exceptions::PyException};

create_exception!(claripy.errors, ClaripyError, PyException);
create_exception!(claripy.errors, ClaripyTypeError, ClaripyError);
create_exception!(claripy.errors, UnsatError, ClaripyError);
create_exception!(claripy.errors, ClaripyFrontendError, ClaripyError);
create_exception!(claripy.errors, ClaripySolverInterruptError, ClaripyError);
create_exception!(claripy.errors, ClaripyOperationError, ClaripyError);
create_exception!(
    claripy.errors,
    ClaripyZeroDivisionError,
    ClaripyOperationError
);
create_exception!(
    claripy.errors,
    InvalidExtractBoundsError,
    ClaripyOperationError
);
