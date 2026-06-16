use std::collections::{BTreeSet, HashMap};

use clarirs_core::algorithms::{canonicalize, structurally_match};
use pyo3::types::{PyFrozenSet, PySet, PyType};

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

    #[allow(clippy::type_complexity)]
    pub fn canonicalize<'py>(
        &self,
        py: Python<'py>,
    ) -> Result<(HashMap<u64, Bound<'py, PyAny>>, usize, Bound<'py, Base>), ClaripyError> {
        let (replacement_map, counter, canonical) = canonicalize(&self.inner.clone())?;
        let canonical_py = Base::from_ast(py, canonical)?;

        let mut py_map = HashMap::new();
        for (hash, ast) in replacement_map {
            let py_ast = Base::from_ast(py, ast)?;
            py_map.insert(hash, py_ast.into_any());
        }

        Ok((py_map, counter, canonical_py))
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
        Base::from_ast(py, self.inner.replace(&from_ast, &to_ast)?)
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
            .make_ast_annotated(self.inner.op().clone(), new_annotations)?;
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
        let inner = self.inner.context().make_ast_annotated(
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
        let inner = self.inner.context().make_ast_annotated(
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
        let inner = self.inner.context().make_ast_annotated(
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
            .make_ast_annotated(self.inner.op().clone(), Default::default())?;
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
            .make_ast_annotated(self.inner.op().clone(), kept)?;
        Base::from_ast(py, inner)
    }
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Base>()?;
    Ok(())
}
