use std::collections::BTreeSet;

use clarirs_core::algorithms::{collect_vars::collect_vars, structurally_match};
use pyo3::types::{PyDict, PyFrozenSet, PySet, PyType};

use crate::prelude::*;

/// The base class for all AST wrappers. It holds the underlying [`AstRef`] and
/// implements every operation that does not depend on the concrete sort
/// (structure queries, hashing, simplification, replacement, annotation
/// management). The sort-specific subclasses (`Bool`, `BV`, `FP`, `String`)
/// inherit these and add only their own typed operations.
#[pyclass(subclass, frozen, weakref, module = "claripy.ast.base", from_py_object)]
#[derive(Clone)]
pub struct Base {
    inner: AstRef<'static>,
    errored: Py<PySet>,
    name: Option<String>,
    encoded_name: Option<Vec<u8>>,
}

impl Base {
    pub fn new(py: Python, inner: &AstRef<'static>) -> Self {
        Self::new_with_name(py, inner, None)
    }

    pub fn new_with_name(py: Python, inner: &AstRef<'static>, name: Option<String>) -> Self {
        let encoded_name = name.as_ref().map(|name| name.as_bytes().to_vec());
        Self {
            inner: inner.clone(),
            errored: PySet::empty(py).expect("Failed to create PySet").unbind(),
            name,
            encoded_name,
        }
    }

    pub fn to_ast(self_: Bound<'_, Base>) -> Result<AstRef<'static>, ClaripyError> {
        Ok(self_.get().inner.clone())
    }

    /// A clone of the wrapped [`AstRef`].
    pub fn ast(&self) -> AstRef<'static> {
        self.inner.clone()
    }

    /// Wrap an existing [`AstRef`] without simplifying it, keeping its
    /// annotation set exactly as given.
    pub fn from_ast<'py>(
        py: Python<'py>,
        ast: AstRef<'static>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        match ast.ast_type() {
            AstType::Bool => Bool::new(py, &ast).map(|b| b.into_any().cast_into::<Base>().unwrap()),
            AstType::BitVec(_) => {
                BV::new(py, &ast).map(|b| b.into_any().cast_into::<Base>().unwrap())
            }
            AstType::Float(_) => {
                FP::new(py, &ast).map(|b| b.into_any().cast_into::<Base>().unwrap())
            }
            AstType::String => {
                PyAstString::new(py, &ast).map(|b| b.into_any().cast_into::<Base>().unwrap())
            }
        }
    }
}

#[pymethods]
impl Base {
    #[getter]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[getter]
    pub fn _encoded_name(&self) -> Option<&[u8]> {
        self.encoded_name.as_deref()
    }

    #[getter]
    pub fn _errored(&self) -> Py<PySet> {
        self.errored.clone()
    }

    #[getter]
    pub fn op(&self) -> String {
        self.inner.to_opstring()
    }

    #[getter]
    pub fn args<'py>(&self, py: Python<'py>) -> Result<Vec<Bound<'py, PyAny>>, ClaripyError> {
        self.inner.extract_py_args(py)
    }

    #[getter]
    pub fn variables<'py>(&self, py: Python<'py>) -> Result<Bound<'py, PyFrozenSet>, ClaripyError> {
        Ok(PyFrozenSet::new(
            py,
            self.inner
                .variables()
                .iter()
                .map(|v| v.as_str().into_py_any(py))
                .collect::<Result<Vec<_>, _>>()?
                .iter(),
        )?)
    }

    #[getter]
    pub fn symbolic(&self) -> bool {
        self.inner.symbolic()
    }

    #[getter]
    pub fn concrete(&self) -> bool {
        !self.inner.symbolic()
    }

    #[getter]
    pub fn annotations<'py>(
        &self,
        py: Python<'py>,
    ) -> Result<Vec<Bound<'py, PyAnnotation>>, ClaripyError> {
        self.inner
            .annotations()
            .iter()
            .map(|annotation| PyAnnotation::from_annotation(py, annotation))
            .collect()
    }

    pub fn hash(&self) -> u64 {
        self.inner.hash()
    }

    pub fn __hash__(&self) -> usize {
        self.hash() as usize
    }

    pub fn __repr__(&self) -> String {
        self.inner.to_smtlib()
    }

    #[pyo3(signature = (max_depth=2))]
    pub fn shallow_repr(&self, max_depth: usize) -> String {
        self.inner.to_smtlib_shallow(max_depth)
    }

    /// Canonicalize variable names to v0, v1, ... like claripy's
    /// `canonicalize(var_map=None, counter=None)`.
    ///
    /// `var_map` (hash -> canonical variable) is mutated in place when
    /// provided, so a mapping can be shared across several expressions.
    /// `counter` may be an int (the value clarirs returns) or any iterator of
    /// ints such as `itertools.count` (which claripy returns); when an
    /// iterator is passed it is advanced in place and returned as-is.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::mutable_key_type)]
    #[pyo3(signature = (var_map = None, counter = None))]
    pub fn canonicalize<'py>(
        &self,
        py: Python<'py>,
        var_map: Option<Bound<'py, PyDict>>,
        counter: Option<Bound<'py, PyAny>>,
    ) -> Result<(Bound<'py, PyDict>, Bound<'py, PyAny>, Bound<'py, Base>), ClaripyError> {
        let dict = var_map.unwrap_or_else(|| PyDict::new(py));
        let counter_is_iter = matches!(&counter, Some(c) if c.hasattr("__next__").unwrap_or(false));
        let mut int_counter: usize = match &counter {
            Some(c) if !counter_is_iter => c.extract::<usize>()?,
            _ => 0,
        };

        let vars = collect_vars(&self.inner)?;
        let mut sorted_vars: Vec<_> = vars.into_iter().collect();
        sorted_vars.sort_by_key(|v| v.variables().iter().next().cloned());

        let ctx = self.inner.context();
        let mut replacements: Vec<(AstRef<'static>, AstRef<'static>)> = Vec::new();
        for var in sorted_vars {
            let key = var.hash();
            let canonical_ast = match dict.get_item(key)? {
                Some(existing) => Base::to_ast(existing.cast_into::<Base>()?)?,
                None => {
                    let idx = if counter_is_iter {
                        counter
                            .as_ref()
                            .expect("counter_is_iter implies counter")
                            .call_method0("__next__")?
                            .extract::<usize>()?
                    } else {
                        let idx = int_counter;
                        int_counter += 1;
                        idx
                    };
                    let name = format!("v{idx}");
                    let canonical = match var.ast_type() {
                        AstType::Bool => ctx.bools(name.as_str())?,
                        AstType::BitVec(size) => ctx.bvs(name.as_str(), size)?,
                        AstType::Float(sort) => ctx.fps(name.as_str(), sort)?,
                        AstType::String => ctx.strings(name.as_str())?,
                    };
                    dict.set_item(key, Base::from_ast(py, canonical.clone())?)?;
                    canonical
                }
            };
            replacements.push((var, canonical_ast));
        }

        let mut result = self.inner.clone();
        for (from, to) in &replacements {
            result = result.replace(from, to)?;
        }

        let counter_ret: Bound<'py, PyAny> = match counter {
            Some(c) if counter_is_iter => c,
            _ => int_counter
                .into_pyobject(py)
                .map_err(PyErr::from)?
                .into_any(),
        };

        Ok((dict, counter_ret, Base::from_ast(py, result)?))
    }

    pub fn identical(&self, other: Bound<'_, Base>) -> Result<bool, ClaripyError> {
        let other_dyn = Base::to_ast(other)?;
        Ok(structurally_match(&self.inner, &other_dyn)?)
    }

    #[getter]
    pub fn depth(&self) -> u32 {
        self.inner.depth()
    }

    pub fn is_leaf(&self) -> bool {
        self.inner.depth() == 1
    }

    #[pyo3(signature = (respect_annotations=true))]
    pub fn simplify<'py>(
        &self,
        py: Python<'py>,
        respect_annotations: bool,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        Base::from_ast(py, self.inner.simplify_ext(respect_annotations, false)?)
    }

    pub fn replace<'py>(
        &self,
        py: Python<'py>,
        from: Bound<'py, Base>,
        to: Bound<'py, Base>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let from_ast = Base::to_ast(from)?;
        let to_ast = Base::to_ast(to)?;
        // `replace` builds a new AST, so simplify the result before wrapping it.
        Base::from_ast(py, self.inner.replace(&from_ast, &to_ast)?.simplify()?)
    }

    pub fn has_annotation_type(
        &self,
        annotation_type: Bound<'_, PyType>,
    ) -> Result<bool, ClaripyError> {
        let py = annotation_type.py();
        for annotation in self.inner.annotations() {
            if PyAnnotation::from_annotation(py, annotation)?.is_instance(&annotation_type)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn get_annotations_by_type<'py>(
        &self,
        annotation_type: Bound<'py, PyType>,
    ) -> Result<Vec<Bound<'py, PyAnnotation>>, ClaripyError> {
        let py = annotation_type.py();
        let mut matching = Vec::new();
        for annotation in self.inner.annotations() {
            let annotation = PyAnnotation::from_annotation(py, annotation)?;
            if annotation.is_instance(&annotation_type)? {
                matching.push(annotation);
            }
        }
        Ok(matching)
    }

    pub fn get_annotation<'py>(
        &self,
        annotation_type: Bound<'py, PyType>,
    ) -> Result<Option<Bound<'py, PyAnnotation>>, ClaripyError> {
        let py = annotation_type.py();
        for annotation in self.inner.annotations() {
            let annotation = PyAnnotation::from_annotation(py, annotation)?;
            if annotation.is_instance(&annotation_type)? {
                return Ok(Some(annotation));
            }
        }
        Ok(None)
    }

    pub fn append_annotation<'py>(
        &self,
        annotation: Bound<'py, PyAnnotation>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let py = annotation.py();
        let annotation = PyAnnotation::to_annotation(&annotation)?;
        let new_annotations = self.inner.annotations().iter().cloned().chain([annotation]);
        Base::from_ast(py, GLOBAL_CONTEXT.annotate(&self.inner, new_annotations)?)
    }

    pub fn append_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<Bound<'py, PyAnnotation>>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let annotations = annotations
            .iter()
            .map(PyAnnotation::to_annotation)
            .collect::<Result<Vec<_>, _>>()?;
        let new_annotations = self.inner.annotations().iter().cloned().chain(annotations);
        Base::from_ast(py, GLOBAL_CONTEXT.annotate(&self.inner, new_annotations)?)
    }

    #[pyo3(signature = (*annotations, remove_annotations = None))]
    pub fn annotate<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<Bound<'py, PyAnnotation>>,
        remove_annotations: Option<Vec<Bound<'py, PyAnnotation>>>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let annotations = annotations
            .iter()
            .map(PyAnnotation::to_annotation)
            .collect::<Result<Vec<_>, _>>()?;
        let remove_annotations = remove_annotations
            .as_ref()
            .map(|annotations| {
                annotations
                    .iter()
                    .map(PyAnnotation::to_annotation)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let new_annotations = self
            .inner
            .annotations()
            .iter()
            .filter(|a| match &remove_annotations {
                Some(remove_annotations) => !remove_annotations.iter().any(|ra| ra == *a),
                None => true,
            })
            .cloned()
            .chain(annotations)
            .collect();
        let inner = self
            .inner
            .context()
            .make_ast_exact(self.inner.op().clone(), new_annotations)?;
        Base::from_ast(py, inner)
    }

    pub fn insert_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<Bound<'py, PyAnnotation>>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let annotations = annotations
            .iter()
            .map(PyAnnotation::to_annotation)
            .collect::<Result<Vec<_>, _>>()?;
        Base::from_ast(py, GLOBAL_CONTEXT.annotate(&self.inner, annotations)?)
    }

    /// This actually just removes all annotations and adds the new ones.
    pub fn replace_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<Bound<'py, PyAnnotation>>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let inner = self.inner.context().make_ast_exact(
            self.inner.op().clone(),
            annotations
                .iter()
                .map(PyAnnotation::to_annotation)
                .collect::<Result<_, _>>()?,
        )?;
        Base::from_ast(py, inner)
    }

    pub fn remove_annotation<'py>(
        &self,
        annotation: Bound<'py, PyAnnotation>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let py = annotation.py();
        let annotation = PyAnnotation::to_annotation(&annotation)?;
        let inner = self.inner.context().make_ast_exact(
            self.inner.op().clone(),
            self.inner
                .annotations()
                .iter()
                .filter(|a| **a != annotation)
                .cloned()
                .collect(),
        )?;
        Base::from_ast(py, inner)
    }

    pub fn remove_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<Bound<'py, PyAnnotation>>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let annotations_set: BTreeSet<_> = annotations
            .iter()
            .map(PyAnnotation::to_annotation)
            .collect::<Result<_, _>>()?;
        let inner = self.inner.context().make_ast_exact(
            self.inner.op().clone(),
            self.inner
                .annotations()
                .iter()
                .filter(|a| !annotations_set.contains(a))
                .cloned()
                .collect(),
        )?;
        Base::from_ast(py, inner)
    }

    pub fn clear_annotations<'py>(
        &self,
        py: Python<'py>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let inner = self
            .inner
            .context()
            .make_ast_exact(self.inner.op().clone(), Default::default())?;
        Base::from_ast(py, inner)
    }

    pub fn clear_annotation_type<'py>(
        &self,
        annotation_type: Bound<'py, PyType>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let py = annotation_type.py();
        let mut kept = BTreeSet::new();
        for annotation in self.inner.annotations() {
            if !PyAnnotation::from_annotation(py, annotation)?.is_instance(&annotation_type)? {
                kept.insert(annotation.clone());
            }
        }
        let inner = self
            .inner
            .context()
            .make_ast_exact(self.inner.op().clone(), kept)?;
        Base::from_ast(py, inner)
    }
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Base>()?;
    Ok(())
}
