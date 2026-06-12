use std::collections::{BTreeSet, HashMap};

use clarirs_core::algorithms::{canonicalize, structurally_match};
use pyo3::types::{PyFrozenSet, PySet};

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
    pub fn annotations(&self) -> PyResult<Vec<PyAnnotation>> {
        Ok(self
            .inner
            .annotations()
            .iter()
            .cloned()
            .map(PyAnnotation::from)
            .collect())
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
        annotation_type: PyAnnotationType,
    ) -> Result<bool, ClaripyError> {
        Ok(self
            .annotations()?
            .iter()
            .any(|annotation| annotation_type.matches(annotation.0.type_())))
    }

    pub fn get_annotations_by_type(
        &self,
        annotation_type: PyAnnotationType,
    ) -> Result<Vec<PyAnnotation>, ClaripyError> {
        Ok(self
            .annotations()?
            .into_iter()
            .filter(|annotation| annotation_type.matches(annotation.0.type_()))
            .collect())
    }

    pub fn get_annotation(
        &self,
        annotation_type: PyAnnotationType,
    ) -> Result<Option<PyAnnotation>, ClaripyError> {
        Ok(self
            .annotations()?
            .into_iter()
            .find(|annotation| annotation_type.matches(annotation.0.type_())))
    }

    pub fn append_annotation<'py>(
        &self,
        py: Python<'py>,
        annotation: PyAnnotation,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let new_annotations = self
            .inner
            .annotations()
            .iter()
            .cloned()
            .chain([annotation.0.clone()]);
        Base::from_ast(py, GLOBAL_CONTEXT.annotate(&self.inner, new_annotations)?)
    }

    pub fn append_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let new_annotations = self
            .inner
            .annotations()
            .iter()
            .cloned()
            .chain(annotations.into_iter().map(|a| a.0));
        Base::from_ast(py, GLOBAL_CONTEXT.annotate(&self.inner, new_annotations)?)
    }

    #[pyo3(signature = (*annotations, remove_annotations = None))]
    pub fn annotate<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
        remove_annotations: Option<Vec<PyAnnotation>>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let new_annotations = self
            .annotations()?
            .iter()
            .filter(|a| {
                if let Some(remove_annotations) = &remove_annotations {
                    !remove_annotations.iter().any(|ra| ra.0 == a.0)
                } else {
                    true
                }
            })
            .map(|a| a.0.clone())
            .chain(annotations.into_iter().map(|a| a.0))
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
        annotations: Vec<PyAnnotation>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        Base::from_ast(
            py,
            GLOBAL_CONTEXT.annotate(&self.inner, annotations.into_iter().map(|a| a.0))?,
        )
    }

    /// This actually just removes all annotations and adds the new ones.
    pub fn replace_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let inner = self.inner.context().make_ast_annotated(
            self.inner.op().clone(),
            annotations.into_iter().map(|a| a.0).collect(),
        )?;
        Base::from_ast(py, inner)
    }

    pub fn remove_annotation<'py>(
        &self,
        py: Python<'py>,
        annotation: PyAnnotation,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let inner = self.inner.context().make_ast_annotated(
            self.inner.op().clone(),
            self.inner
                .annotations()
                .iter()
                .filter(|a| **a != annotation.0)
                .cloned()
                .collect(),
        )?;
        Base::from_ast(py, inner)
    }

    pub fn remove_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let annotations_set: BTreeSet<_> = annotations.into_iter().map(|a| a.0).collect();
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
        py: Python<'py>,
        annotation_type: PyAnnotationType,
    ) -> Result<Bound<'py, Base>, ClaripyError> {
        let inner = self.inner.context().make_ast_annotated(
            self.inner.op().clone(),
            self.inner
                .annotations()
                .iter()
                .filter(|a| !annotation_type.matches(a.type_()))
                .cloned()
                .collect(),
        )?;
        Base::from_ast(py, inner)
    }
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Base>()?;
    Ok(())
}
