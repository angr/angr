#![allow(non_snake_case)]

use std::sync::{
    LazyLock,
    atomic::{AtomicUsize, Ordering},
};

use dashmap::DashMap;
use pyo3::types::PyWeakrefReference;

use crate::prelude::*;

static STRINGS_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PY_STRING_CACHE: LazyLock<DashMap<u64, Py<PyWeakrefReference>>> =
    LazyLock::new(DashMap::new);

#[pyclass(name="String", extends=Base, subclass, frozen, module="claripy.ast.strings")]
pub struct PyAstString {
    pub(crate) inner: AstRef<'static>,
}

impl PyAstString {
    pub fn new<'py>(
        py: Python<'py>,
        inner: &AstRef<'static>,
    ) -> Result<Bound<'py, PyAstString>, ClaripyError> {
        Self::new_with_name(py, inner, None)
    }

    pub fn new_with_name<'py>(
        py: Python<'py>,
        inner: &AstRef<'static>,
        name: Option<String>,
    ) -> Result<Bound<'py, PyAstString>, ClaripyError> {
        let inner = &inner.simplify()?;
        if let Some(cache_hit) = PY_STRING_CACHE.get(&inner.hash()).and_then(|cache_hit| {
            cache_hit
                .bind(py)
                .upgrade_as::<PyAstString>()
                .expect("bool cache poisoned")
        }) {
            Ok(cache_hit)
        } else {
            let this = Py::new(
                py,
                PyClassInitializer::from(Base::new_with_name(py, inner, name)).add_subclass(
                    PyAstString {
                        inner: inner.clone(),
                    },
                ),
            )?;
            let weakref = PyWeakrefReference::new(this.bind(py))?;
            PY_STRING_CACHE.insert(inner.hash(), weakref.unbind());

            Ok(this.into_bound(py))
        }
    }
}

#[pymethods]
impl PyAstString {
    #[new]
    #[pyo3(signature = (op, args, annotations=None))]
    pub fn py_new<'py>(
        py: Python<'py>,
        op: &str,
        args: Vec<Py<PyAny>>,
        annotations: Option<Vec<PyAnnotation>>,
    ) -> Result<Py<PyAstString>, ClaripyError> {
        let inner = match op {
            "StringS" => GLOBAL_CONTEXT.strings(&args[0].extract::<String>(py)?)?,
            "StringV" => GLOBAL_CONTEXT.stringv(&args[0].extract::<String>(py)?)?,
            "StrConcat" => GLOBAL_CONTEXT.str_concat(
                &args[0].cast_bound::<PyAstString>(py)?.get().inner,
                &args[1].cast_bound::<PyAstString>(py)?.get().inner,
            )?,
            "StrSubstr" => GLOBAL_CONTEXT.str_substr(
                &args[0].cast_bound::<PyAstString>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
                &args[2].cast_bound::<BV>(py)?.get().inner,
            )?,
            "StrReplace" => GLOBAL_CONTEXT.str_replace(
                &args[0].cast_bound::<PyAstString>(py)?.get().inner,
                &args[1].cast_bound::<PyAstString>(py)?.get().inner,
                &args[2].cast_bound::<PyAstString>(py)?.get().inner,
            )?,
            "IntToStr" => GLOBAL_CONTEXT.bv_to_str(&args[0].cast_bound::<BV>(py)?.get().inner)?,
            "If" => GLOBAL_CONTEXT.ite(
                &args[0].cast_bound::<Bool>(py)?.get().inner,
                &args[1].cast_bound::<PyAstString>(py)?.get().inner,
                &args[2].cast_bound::<PyAstString>(py)?.get().inner,
            )?,
            _ => return Err(ClaripyError::InvalidOperation(op.to_string())),
        };

        let inner_with_annotations = if let Some(annots) = annotations {
            GLOBAL_CONTEXT.annotate(&inner, annots.into_iter().map(|a| a.0))?
        } else {
            inner
        };

        Ok(PyAstString::new(py, &inner_with_annotations)?.unbind())
    }

    #[getter]
    pub fn concrete_value(&self) -> Result<Option<String>, ClaripyError> {
        Ok(match self.inner.simplify_ext(false, false)?.op() {
            AstOp::StringV(value) => Some(value.clone()),
            _ => None,
        })
    }

    pub fn __add__<'py>(
        &self,
        py: Python<'py>,
        other: Bound<'py, PyAstString>,
    ) -> Result<Bound<'py, PyAstString>, ClaripyError> {
        PyAstString::new(
            py,
            &GLOBAL_CONTEXT.str_concat(&self.inner, &other.get().inner)?,
        )
    }

    pub fn __eq__<'py>(
        &self,
        py: Python<'py>,
        other: Bound<'py, PyAstString>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(py, &GLOBAL_CONTEXT.str_eq(&self.inner, &other.get().inner)?)
    }

    pub fn __ne__<'py>(
        &self,
        py: Python<'py>,
        other: Bound<'py, PyAstString>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.str_neq(&self.inner, &other.get().inner)?,
        )
    }

    // `Base` defines `__hash__`, but Python makes a class unhashable if it
    // defines `__eq__` without its own `__hash__`, so it must be repeated here.
    pub fn __hash__(&self) -> usize {
        self.inner.hash() as usize
    }

    #[allow(clippy::type_complexity)]
    pub fn __reduce__<'py>(
        &self,
        py: Python<'py>,
    ) -> Result<
        (
            Bound<'py, PyAny>,
            (String, Vec<Bound<'py, PyAny>>, Vec<PyAnnotation>),
        ),
        ClaripyError,
    > {
        let class = py.get_type::<PyAstString>();
        let op = self.inner.to_opstring();
        let args = self.inner.extract_py_args(py)?;
        let annotations: Vec<PyAnnotation> = self
            .inner
            .annotations()
            .iter()
            .cloned()
            .map(PyAnnotation::from)
            .collect();
        Ok((class.into_any(), (op, args, annotations)))
    }
}

#[pyfunction(signature = (name, explicit_name = false))]
pub fn StringS<'py>(
    py: Python<'py>,
    name: &str,
    explicit_name: bool,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    let name: String = if explicit_name {
        name.to_string()
    } else {
        let counter = STRINGS_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{name}_{counter}")
    };
    PyAstString::new_with_name(py, &GLOBAL_CONTEXT.strings(&name)?, Some(name))
}

#[pyfunction]
pub fn StringV<'py>(py: Python<'py>, value: &str) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(py, &GLOBAL_CONTEXT.stringv(value)?)
}

#[pyfunction]
pub fn StrLen<'py>(
    py: Python<'py>,
    s: Bound<'py, PyAstString>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.str_len(&s.get().inner)?)
}

#[pyfunction]
pub fn StrConcat<'py>(
    py: Python<'py>,
    s1: Bound<'py, PyAstString>,
    s2: Bound<'py, PyAstString>,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(
        py,
        &GLOBAL_CONTEXT.str_concat(&s1.get().inner, &s2.get().inner)?,
    )
}

#[pyfunction]
pub fn StrSubstr<'py>(
    py: Python<'py>,
    start: CoerceBV<'py>,
    size: CoerceBV<'py>,
    base: Bound<'py, PyAstString>,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(
        py,
        &GLOBAL_CONTEXT.str_substr(
            &base.get().inner,
            &start.unpack(py, 64, false)?.get().inner,
            &size.unpack(py, 64, false)?.get().inner,
        )?,
    )
}

#[pyfunction]
pub fn StrContains<'py>(
    py: Python<'py>,
    haystack: Bound<'py, PyAstString>,
    needle: Bound<'py, PyAstString>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.str_contains(&haystack.get().inner, &needle.get().inner)?,
    )
}

#[pyfunction]
pub fn StrIndexOf<'py>(
    py: Python<'py>,
    haystack: Bound<'py, PyAstString>,
    needle: Bound<'py, PyAstString>,
    start: CoerceBV<'py>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(
        py,
        &GLOBAL_CONTEXT.str_index_of(
            &haystack.get().inner,
            &needle.get().inner,
            &start.unpack(py, 64, false)?.get().inner,
        )?,
    )
}

#[pyfunction]
pub fn StrReplace<'py>(
    py: Python<'py>,
    haystack: Bound<'py, PyAstString>,
    needle: Bound<'py, PyAstString>,
    replacement: Bound<'py, PyAstString>,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(
        py,
        &GLOBAL_CONTEXT.str_replace(
            &haystack.get().inner,
            &needle.get().inner,
            &replacement.get().inner,
        )?,
    )
}

#[pyfunction]
pub fn StrPrefixOf<'py>(
    py: Python<'py>,
    needle: Bound<'py, PyAstString>,
    haystack: Bound<'py, PyAstString>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.str_prefix_of(&needle.get().inner, &haystack.get().inner)?,
    )
}

#[pyfunction]
pub fn StrSuffixOf<'py>(
    py: Python<'py>,
    needle: Bound<'py, PyAstString>,
    haystack: Bound<'py, PyAstString>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.str_suffix_of(&needle.get().inner, &haystack.get().inner)?,
    )
}

#[pyfunction]
pub fn StrToInt<'py>(
    py: Python<'py>,
    s: Bound<'py, PyAstString>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.str_to_bv(&s.get().inner)?)
}

#[pyfunction]
pub fn IntToStr<'py>(
    py: Python<'py>,
    bv: Bound<'py, BV>,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(py, &GLOBAL_CONTEXT.bv_to_str(&bv.get().inner)?)
}

#[pyfunction]
pub fn StrIsDigit<'py>(
    py: Python<'py>,
    s: Bound<'py, PyAstString>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(py, &GLOBAL_CONTEXT.str_is_digit(&s.get().inner)?)
}

#[pyfunction]
pub fn StrEq<'py>(
    py: Python<'py>,
    s1: Bound<'py, PyAstString>,
    s2: Bound<'py, PyAstString>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.str_eq(&s1.get().inner, &s2.get().inner)?,
    )
}

#[pyfunction]
pub fn StrNeq<'py>(
    py: Python<'py>,
    s1: Bound<'py, PyAstString>,
    s2: Bound<'py, PyAstString>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.str_neq(&s1.get().inner, &s2.get().inner)?,
    )
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyAstString>()?;

    add_pyfunctions!(
        m,
        StringS,
        StringV,
        StrLen,
        StrConcat,
        StrSubstr,
        StrContains,
        StrIndexOf,
        StrReplace,
        StrPrefixOf,
        StrSuffixOf,
        StrToInt,
        IntToStr,
        StrIsDigit,
        StrEq,
        StrNeq,
    );

    Ok(())
}
