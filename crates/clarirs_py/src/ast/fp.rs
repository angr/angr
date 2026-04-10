#![allow(non_snake_case)]

use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use clarirs_core::algorithms::{canonicalize, structurally_match};
use clarirs_core::ast::float::{FloatExt, FloatOpExt};
use dashmap::DashMap;
use pyo3::types::{PyFrozenSet, PyTuple, PyWeakrefReference};

use crate::prelude::*;
use clarirs_core::smtlib::ToSmtLib;

static FPS_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PY_FP_CACHE: LazyLock<DashMap<u64, Py<PyWeakrefReference>>> = LazyLock::new(DashMap::new);

#[pyclass(name = "RM", module = "claripy.ast.fp", eq, from_py_object)]
#[derive(Clone, PartialEq, Eq, Default)]
#[allow(non_camel_case_types)]
pub enum PyRM {
    #[default]
    RM_NearestTiesEven,
    RM_NearestTiesAwayFromZero,
    RM_TowardsZero,
    RM_TowardsPositiveInf,
    RM_TowardsNegativeInf,
}

#[pymethods]
impl PyRM {
    #[staticmethod]
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> PyRM {
        <PyRM as Default>::default()
    }
}

impl From<PyRM> for FPRM {
    fn from(rm: PyRM) -> FPRM {
        match rm {
            PyRM::RM_NearestTiesEven => FPRM::NearestTiesToEven,
            PyRM::RM_NearestTiesAwayFromZero => FPRM::NearestTiesToAway,
            PyRM::RM_TowardsZero => FPRM::TowardZero,
            PyRM::RM_TowardsPositiveInf => FPRM::TowardPositive,
            PyRM::RM_TowardsNegativeInf => FPRM::TowardNegative,
        }
    }
}

impl From<FPRM> for PyRM {
    fn from(rm: FPRM) -> PyRM {
        match rm {
            FPRM::NearestTiesToEven => PyRM::RM_NearestTiesEven,
            FPRM::NearestTiesToAway => PyRM::RM_NearestTiesAwayFromZero,
            FPRM::TowardZero => PyRM::RM_TowardsZero,
            FPRM::TowardPositive => PyRM::RM_TowardsPositiveInf,
            FPRM::TowardNegative => PyRM::RM_TowardsNegativeInf,
        }
    }
}

impl From<&FPRM> for PyRM {
    fn from(rm: &FPRM) -> PyRM {
        match rm {
            FPRM::NearestTiesToEven => PyRM::RM_NearestTiesEven,
            FPRM::NearestTiesToAway => PyRM::RM_NearestTiesAwayFromZero,
            FPRM::TowardZero => PyRM::RM_TowardsZero,
            FPRM::TowardPositive => PyRM::RM_TowardsPositiveInf,
            FPRM::TowardNegative => PyRM::RM_TowardsNegativeInf,
        }
    }
}

#[pyclass(name = "FSort", module = "claripy.ast.fp", from_py_object)]
#[derive(Clone)]
pub struct PyFSort(FSort);

impl PyFSort {
    pub fn new(fsort: &FSort) -> Self {
        PyFSort(*fsort)
    }
}

#[pymethods]
impl PyFSort {
    #[getter]
    pub fn length(&self) -> u32 {
        self.0.size()
    }

    #[staticmethod]
    pub fn from_size(size: u32) -> Result<Self, ClaripyError> {
        Ok(PyFSort(match size {
            32 => FSort::f32(),
            64 => FSort::f64(),
            _ => {
                return Err(ClaripyError::InvalidOperation(
                    "Unsuported float size".to_string(),
                ));
            }
        }))
    }

    pub fn __reduce__<'py>(&self, py: Python<'py>) -> PyResult<(Bound<'py, PyAny>, (u32,))> {
        let class = py.get_type::<PyFSort>();
        let from_size = class.getattr("from_size")?;
        Ok((from_size.into_any(), (self.0.size(),)))
    }

    pub fn __eq__(&self, other: &PyFSort) -> bool {
        self.0 == other.0
    }

    pub fn __ne__(&self, other: &PyFSort) -> bool {
        self.0 != other.0
    }

    pub fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        self.0.size().hash(&mut h);
        h.finish()
    }

    pub fn __repr__(&self) -> String {
        format!("FSORT_{}", self.0.size())
    }
}

impl From<PyFSort> for FSort {
    fn from(val: PyFSort) -> Self {
        val.0
    }
}

impl From<FSort> for PyFSort {
    fn from(val: FSort) -> Self {
        PyFSort(val)
    }
}

impl From<&FSort> for PyFSort {
    fn from(val: &FSort) -> Self {
        PyFSort(*val)
    }
}

pub fn fsort_float() -> PyFSort {
    PyFSort(FSort::f32())
}

pub fn fsort_double() -> PyFSort {
    PyFSort(FSort::f64())
}

#[pyclass(extends=Bits, subclass, frozen, weakref, module="claripy.ast.fp")]
pub struct FP {
    pub(crate) inner: FloatAst<'static>,
}

impl FP {
    pub fn new<'py>(
        py: Python<'py>,
        inner: &FloatAst<'static>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        Self::new_with_name(py, inner, None)
    }

    pub fn new_with_name<'py>(
        py: Python<'py>,
        inner: &FloatAst<'static>,
        name: Option<String>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        let inner = &inner.simplify()?;
        if let Some(cache_hit) = PY_FP_CACHE.get(&inner.hash()).and_then(|cache_hit| {
            cache_hit
                .bind(py)
                .upgrade_as::<FP>()
                .expect("bool cache poisoned")
        }) {
            Ok(cache_hit)
        } else {
            let this = Py::new(
                py,
                PyClassInitializer::from(Base::new_with_name(py, name))
                    .add_subclass(Bits::new())
                    .add_subclass(FP {
                        inner: inner.clone(),
                    }),
            )?;
            let weakref = PyWeakrefReference::new(this.bind(py))?;
            PY_FP_CACHE.insert(inner.hash(), weakref.unbind());

            Ok(this.into_bound(py))
        }
    }
}

#[pymethods]
impl FP {
    #[new]
    #[pyo3(signature = (op, args, annotations=None))]
    pub fn py_new<'py>(
        py: Python<'py>,
        op: &str,
        args: Vec<Py<PyAny>>,
        annotations: Option<Vec<PyAnnotation>>,
    ) -> Result<Py<FP>, ClaripyError> {
        let inner = match op {
            "FPS" => {
                let name = args[0].extract::<String>(py)?;
                let sort: FSort = args[1].extract::<PyFSort>(py)?.into();
                GLOBAL_CONTEXT.fps(&name, sort)?
            }
            "FPV" => {
                let float_value = Float::from(args[0].extract::<f64>(py)?);
                GLOBAL_CONTEXT.fpv(float_value)?
            }
            "fpFP" => GLOBAL_CONTEXT.fp_fp(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
                &args[2].cast_bound::<BV>(py)?.get().inner,
            )?,
            "fpNeg" => GLOBAL_CONTEXT.fp_neg(&args[0].cast_bound::<FP>(py)?.get().inner)?,
            "fpAbs" => GLOBAL_CONTEXT.fp_abs(&args[0].cast_bound::<FP>(py)?.get().inner)?,
            "fpAdd" => {
                let rm: FPRM = args[2].extract::<PyRM>(py)?.into();
                GLOBAL_CONTEXT.fp_add(
                    &args[0].cast_bound::<FP>(py)?.get().inner,
                    &args[1].cast_bound::<FP>(py)?.get().inner,
                    rm,
                )?
            }
            "fpSub" => {
                let rm: FPRM = args[2].extract::<PyRM>(py)?.into();
                GLOBAL_CONTEXT.fp_sub(
                    &args[0].cast_bound::<FP>(py)?.get().inner,
                    &args[1].cast_bound::<FP>(py)?.get().inner,
                    rm,
                )?
            }
            "fpMul" => {
                let rm: FPRM = args[2].extract::<PyRM>(py)?.into();
                GLOBAL_CONTEXT.fp_mul(
                    &args[0].cast_bound::<FP>(py)?.get().inner,
                    &args[1].cast_bound::<FP>(py)?.get().inner,
                    rm,
                )?
            }
            "fpDiv" => {
                let rm: FPRM = args[2].extract::<PyRM>(py)?.into();
                GLOBAL_CONTEXT.fp_div(
                    &args[0].cast_bound::<FP>(py)?.get().inner,
                    &args[1].cast_bound::<FP>(py)?.get().inner,
                    rm,
                )?
            }
            "fpSqrt" => {
                let rm: FPRM = args[1].extract::<PyRM>(py)?.into();
                GLOBAL_CONTEXT.fp_sqrt(&args[0].cast_bound::<FP>(py)?.get().inner, rm)?
            }
            "fpToFP" => {
                // Polymorphic: (RM, FP, FSort) or (BV, FSort)
                if args.len() == 2 {
                    // (BV, FSort) case - BV to FP conversion
                    let sort: FSort = args[1].extract::<PyFSort>(py)?.into();
                    GLOBAL_CONTEXT.bv_to_fp(&args[0].cast_bound::<BV>(py)?.get().inner, sort)?
                } else {
                    // (RM, FP, FSort) case - FP to FP conversion
                    let rm: FPRM = args[0].extract::<PyRM>(py)?.into();
                    let sort: FSort = args[2].extract::<PyFSort>(py)?.into();
                    GLOBAL_CONTEXT.fp_to_fp(&args[1].cast_bound::<FP>(py)?.get().inner, sort, rm)?
                }
            }
            "fpToFPUnsigned" => {
                let rm: FPRM = args[0].extract::<PyRM>(py)?.into();
                let sort: FSort = args[2].extract::<PyFSort>(py)?.into();
                GLOBAL_CONTEXT.bv_to_fp_unsigned(
                    &args[1].cast_bound::<BV>(py)?.get().inner,
                    sort,
                    rm,
                )?
            }
            "If" => GLOBAL_CONTEXT.ite(
                &args[0].cast_bound::<Bool>(py)?.get().inner,
                &args[1].cast_bound::<FP>(py)?.get().inner,
                &args[2].cast_bound::<FP>(py)?.get().inner,
            )?,
            _ => return Err(ClaripyError::InvalidOperation(op.to_string())),
        };

        let inner_with_annotations = if let Some(annots) = annotations {
            GLOBAL_CONTEXT.annotate(&inner, annots.into_iter().map(|a| a.0))?
        } else {
            inner
        };

        Ok(FP::new(py, &inner_with_annotations)?.unbind())
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
    ) -> Result<(HashMap<u64, Bound<'py, PyAny>>, usize, Bound<'py, FP>), ClaripyError> {
        let (replacement_map, counter, canonical) = canonicalize(&self.inner.clone().into())?;
        let canonical_fp = FP::new(
            py,
            &canonical
                .into_float()
                .ok_or(ClaripyError::InvalidOperation(
                    "Canonicalization did not produce a Float".to_string(),
                ))?,
        )?;

        let mut py_map = HashMap::new();
        for (hash, dynast) in replacement_map {
            let py_ast = Base::from_dynast(py, dynast)?;
            py_map.insert(hash, py_ast.into_any());
        }

        Ok((py_map, counter, canonical_fp))
    }

    pub fn identical(&self, other: Bound<'_, Base>) -> Result<bool, ClaripyError> {
        let other_dyn = Base::to_dynast(other)?;
        Ok(structurally_match(
            &DynAst::Float(self.inner.clone()),
            &other_dyn,
        )?)
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
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(py, &self.inner.simplify_ext(respect_annotations, false)?)
    }

    pub fn replace<'py>(
        &self,
        py: Python<'py>,
        from: Bound<'py, Base>,
        to: Bound<'py, Base>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        use clarirs_core::algorithms::Replace;
        let from_ast = Base::to_dynast(from)?;
        let to_ast = Base::to_dynast(to)?;
        let replaced = self.inner.replace(&from_ast, &to_ast)?;
        FP::new(py, &replaced)
    }

    pub fn size(&self) -> usize {
        self.inner.size() as usize
    }

    pub fn __len__(&self) -> usize {
        self.size()
    }

    #[getter]
    pub fn concrete_value(&self) -> Result<Option<f64>, ClaripyError> {
        Ok(match self.inner.simplify_ext(false, false)?.op() {
            FloatOp::FPV(value) => value.to_f64(),
            _ => None,
        })
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
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        let new_annotations = self
            .inner
            .annotations()
            .iter()
            .cloned()
            .chain([annotation.0.clone()]);
        Self::new(py, &GLOBAL_CONTEXT.annotate(&self.inner, new_annotations)?)
    }

    pub fn append_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        let new_annotations = self
            .inner
            .annotations()
            .iter()
            .cloned()
            .chain(annotations.into_iter().map(|a| a.0));
        Self::new(py, &GLOBAL_CONTEXT.annotate(&self.inner, new_annotations)?)
    }

    #[pyo3(signature = (*annotations, remove_annotations = None))]
    pub fn annotate<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
        remove_annotations: Option<Vec<PyAnnotation>>,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
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
            .make_float_annotated(self.inner.op().clone(), new_annotations)?;
        Self::new(py, &inner)
    }

    pub fn insert_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        Self::new(
            py,
            &GLOBAL_CONTEXT.annotate(&self.inner, annotations.into_iter().map(|a| a.0))?,
        )
    }

    /// This actually just removes all annotations and adds the new ones.
    pub fn replace_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        let inner = self.inner.context().make_float_annotated(
            self.inner.op().clone(),
            annotations.into_iter().map(|a| a.0).collect(),
        )?;
        Self::new(py, &inner)
    }

    pub fn remove_annotation<'py>(
        &self,
        py: Python<'py>,
        annotation: PyAnnotation,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        let inner = self.inner.context().make_float_annotated(
            self.inner.op().clone(),
            self.inner
                .annotations()
                .iter()
                .filter(|a| **a != annotation.0)
                .cloned()
                .collect(),
        )?;
        Self::new(py, &inner)
    }

    pub fn remove_annotations<'py>(
        &self,
        py: Python<'py>,
        annotations: Vec<PyAnnotation>,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        let annotations_set: BTreeSet<_> = annotations.into_iter().map(|a| a.0).collect();
        let inner = self.inner.context().make_float_annotated(
            self.inner.op().clone(),
            self.inner
                .annotations()
                .iter()
                .filter(|a| !annotations_set.contains(a))
                .cloned()
                .collect(),
        )?;
        Self::new(py, &inner)
    }

    pub fn clear_annotations<'py>(
        &self,
        py: Python<'py>,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        let inner = self.inner.context().make_float(self.inner.op().clone())?;
        Self::new(py, &inner)
    }

    pub fn clear_annotation_type<'py>(
        &self,
        py: Python<'py>,
        annotation_type: PyAnnotationType,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        let inner = self.inner.context().make_float_annotated(
            self.inner.op().clone(),
            self.inner
                .annotations()
                .iter()
                .filter(|a| !annotation_type.matches(a.type_()))
                .cloned()
                .collect(),
        )?;
        Self::new(py, &inner)
    }

    pub fn raw_to_bv(self_: Bound<'_, FP>) -> Result<Bound<'_, BV>, ClaripyError> {
        BV::new(
            self_.py(),
            &GLOBAL_CONTEXT.fp_to_ieeebv(&self_.get().inner)?,
        )
    }

    pub fn raw_to_fp(self_: Bound<'_, FP>) -> Result<Bound<'_, FP>, ClaripyError> {
        Ok(self_)
    }

    pub fn to_bv(self_: Bound<'_, FP>) -> Result<Bound<'_, BV>, ClaripyError> {
        BV::new(
            self_.py(),
            &GLOBAL_CONTEXT.fp_to_ieeebv(&self_.get().inner)?,
        )
    }

    #[pyo3(signature = (sort, rm = None))]
    pub fn to_fp<'py>(
        self_: Bound<'py, FP>,
        sort: PyFSort,
        rm: Option<PyRM>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(
            self_.py(),
            &GLOBAL_CONTEXT.fp_to_fp(&self_.get().inner, sort, rm.unwrap_or_default())?,
        )
    }

    pub fn __eq__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.fp_eq(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __ne__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.fp_neq(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __lt__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.fp_lt(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __le__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.fp_leq(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __gt__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.fp_gt(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __ge__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.fp_geq(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __abs__<'py>(&self, py: Python<'py>) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(py, &GLOBAL_CONTEXT.fp_abs(&self.inner)?)
    }

    pub fn __neg__<'py>(&self, py: Python<'py>) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(py, &GLOBAL_CONTEXT.fp_neg(&self.inner)?)
    }

    pub fn __add__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(
            py,
            &GLOBAL_CONTEXT.fp_add(
                &self.inner,
                &other.unpack_like(py, self)?.get().inner,
                PyRM::default(),
            )?,
        )
    }

    pub fn __sub__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(
            py,
            &GLOBAL_CONTEXT.fp_sub(
                &self.inner,
                &other.unpack_like(py, self)?.get().inner,
                PyRM::default(),
            )?,
        )
    }

    pub fn __mul__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(
            py,
            &GLOBAL_CONTEXT.fp_mul(
                &self.inner,
                &other.unpack_like(py, self)?.get().inner,
                PyRM::default(),
            )?,
        )
    }

    pub fn __truediv__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceFP<'py>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(
            py,
            &GLOBAL_CONTEXT.fp_div(
                &self.inner,
                &other.unpack_like(py, self)?.get().inner,
                PyRM::default(),
            )?,
        )
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
        let class = py.get_type::<FP>();
        let op = self.op();
        let args = self.args(py)?;
        let annotations = self.annotations()?;
        Ok((class.into_any(), (op, args, annotations)))
    }

    #[getter]
    pub fn length(&self) -> usize {
        self.size()
    }

    #[getter]
    pub fn sort(&self) -> PyFSort {
        PyFSort::from(self.inner.sort())
    }

    #[pyo3(signature = (size, signed = true, rm = None))]
    pub fn val_to_bv<'py>(
        self_: Bound<'py, FP>,
        size: u32,
        signed: bool,
        rm: Option<PyRM>,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        if signed {
            BV::new(
                self_.py(),
                &GLOBAL_CONTEXT.fp_to_sbv(&self_.get().inner, size, rm.unwrap_or_default())?,
            )
        } else {
            BV::new(
                self_.py(),
                &GLOBAL_CONTEXT.fp_to_ubv(&self_.get().inner, size, rm.unwrap_or_default())?,
            )
        }
    }

    #[staticmethod]
    #[pyo3(signature = (lhs, rm = None))]
    pub fn Sqrt<'py>(
        py: Python<'py>,
        lhs: Bound<'py, FP>,
        rm: Option<PyRM>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        FP::new(
            py,
            &GLOBAL_CONTEXT.fp_sqrt(&lhs.get().inner, rm.unwrap_or_default())?,
        )
    }
}

#[pyfunction(signature = (name, sort, explicit_name = false))]
pub fn FPS<'py>(
    py: Python<'py>,
    name: &str,
    sort: PyFSort,
    explicit_name: bool,
) -> Result<Bound<'py, FP>, ClaripyError> {
    let name: String = if explicit_name {
        name.to_string()
    } else {
        let counter = FPS_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{name}_{counter}")
    };
    FP::new_with_name(py, &GLOBAL_CONTEXT.fps(&name, sort)?, Some(name))
}

#[pyfunction]
pub fn FPV(py: Python<'_>, value: f64, sort: PyFSort) -> Result<Bound<'_, FP>, ClaripyError> {
    let float_value = Float::from(value);
    FP::new(
        py,
        &GLOBAL_CONTEXT.fpv(float_value.to_fsort(sort.into(), FPRM::default())?)?,
    )
}

#[pyfunction]
pub fn fpFP<'py>(
    py: Python<'py>,
    sign: Bound<'py, BV>,
    exponent: Bound<'py, BV>,
    significand: Bound<'py, BV>,
) -> Result<Bound<'py, FP>, ClaripyError> {
    FP::new(
        py,
        &GLOBAL_CONTEXT.fp_fp(
            &sign.get().inner,
            &exponent.get().inner,
            &significand.get().inner,
        )?,
    )
}

#[pyfunction(name = "fpToFP")]
#[pyo3(signature = (*args))]
pub fn FpToFP<'py>(
    py: Python<'py>,
    args: &Bound<'py, PyTuple>,
) -> Result<Bound<'py, FP>, ClaripyError> {
    // Polymorphic: (RM, FP, FSort) or (BV, FSort)
    if args.len() == 2 {
        // (BV, FSort) case
        let bv_item = args.get_item(0)?;
        let bv = bv_item.cast::<BV>()?;
        let sort: PyFSort = args.get_item(1)?.extract()?;
        FP::new(py, &GLOBAL_CONTEXT.bv_to_fp(&bv.get().inner, sort)?)
    } else if args.len() == 3 {
        // (RM, FP, FSort) case
        let rm: PyRM = args.get_item(0)?.extract()?;
        let fp_item = args.get_item(1)?;
        let fp = fp_item.cast::<FP>()?;
        let sort: PyFSort = args.get_item(2)?.extract()?;
        FP::new(py, &GLOBAL_CONTEXT.fp_to_fp(&fp.get().inner, sort, rm)?)
    } else {
        Err(ClaripyError::InvalidOperation(
            "fpToFP requires 2 or 3 arguments".to_string(),
        ))
    }
}

#[pyfunction(name = "fpToFPUnsigned", signature = (rm, bv, sort))]
pub fn BvToFpUnsigned<'py>(
    py: Python<'py>,
    rm: PyRM,
    bv: Bound<'py, BV>,
    sort: PyFSort,
) -> Result<Bound<'py, FP>, ClaripyError> {
    FP::new(
        py,
        &GLOBAL_CONTEXT.bv_to_fp_unsigned(&bv.get().inner, sort, rm)?,
    )
}

#[pyfunction(name = "fpToIEEEBV", signature = (fp))]
pub fn fpToIEEEBV<'py>(
    py: Python<'py>,
    fp: Bound<'py, FP>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.fp_to_ieeebv(&fp.get().inner)?)
}

#[pyfunction(name = "fpToUBV", signature = (rm, fp, len))]
pub fn FpToUbv<'py>(
    py: Python<'py>,
    rm: PyRM,
    fp: Bound<'py, FP>,
    len: u32,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.fp_to_ubv(&fp.get().inner, len, rm)?)
}

#[pyfunction(name = "fpToSBV", signature = (rm, fp, len))]
pub fn FpToBv<'py>(
    py: Python<'py>,
    rm: PyRM,
    fp: Bound<'py, FP>,
    len: u32,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.fp_to_sbv(&fp.get().inner, len, rm)?)
}

#[pyfunction(name = "fpNeg", signature = (lhs))]
pub fn FpNeg<'py>(py: Python<'py>, lhs: Bound<'py, FP>) -> Result<Bound<'py, FP>, ClaripyError> {
    FP::new(py, &GLOBAL_CONTEXT.fp_neg(&lhs.get().inner)?)
}

#[pyfunction(name = "fpAbs", signature = (lhs))]
pub fn FpAbs<'py>(py: Python<'py>, lhs: Bound<'py, FP>) -> Result<Bound<'py, FP>, ClaripyError> {
    FP::new(py, &GLOBAL_CONTEXT.fp_abs(&lhs.get().inner)?)
}

#[pyfunction(name = "fpAdd", signature = (rm, lhs, rhs))]
pub fn FpAdd<'py>(
    py: Python<'py>,
    rm: PyRM,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, FP>, ClaripyError> {
    FP::new(
        py,
        &GLOBAL_CONTEXT.fp_add(&lhs.get().inner, &rhs.get().inner, rm)?,
    )
}

#[pyfunction(name = "fpSub", signature = (rm, lhs, rhs))]
pub fn FpSub<'py>(
    py: Python<'py>,
    rm: PyRM,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, FP>, ClaripyError> {
    FP::new(
        py,
        &GLOBAL_CONTEXT.fp_sub(&lhs.get().inner, &rhs.get().inner, rm)?,
    )
}

#[pyfunction(name = "fpMul", signature = (rm, lhs, rhs))]
pub fn FpMul<'py>(
    py: Python<'py>,
    rm: PyRM,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, FP>, ClaripyError> {
    FP::new(
        py,
        &GLOBAL_CONTEXT.fp_mul(&lhs.get().inner, &rhs.get().inner, rm)?,
    )
}

#[pyfunction(name = "fpDiv", signature = (rm, lhs, rhs))]
pub fn FpDiv<'py>(
    py: Python<'py>,
    rm: PyRM,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, FP>, ClaripyError> {
    FP::new(
        py,
        &GLOBAL_CONTEXT.fp_div(&lhs.get().inner, &rhs.get().inner, rm)?,
    )
}

#[pyfunction(name = "fpSqrt", signature = (*args))]
pub fn FpSqrt<'py>(
    py: Python<'py>,
    args: Vec<Bound<'py, PyAny>>,
) -> Result<Bound<'py, FP>, ClaripyError> {
    // fpSqrt can be called as:
    // - fpSqrt(fp) - uses default rounding mode
    // - fpSqrt(rm, fp) - uses specified rounding mode
    let (lhs, rm) = match args.len() {
        1 => (
            &args[0]
                .cast::<FP>()
                .map_err(|e| ClaripyError::CastingError(format!("{e}")))?,
            None,
        ),
        2 => (
            &args[1]
                .cast::<FP>()
                .map_err(|e| ClaripyError::CastingError(format!("{e}")))?,
            Some(args[0].extract::<PyRM>()?),
        ),
        _ => {
            return Err(ClaripyError::InvalidOperation(
                "fpSqrt requires 1 or 2 arguments".to_string(),
            ));
        }
    };

    FP::new(
        py,
        &GLOBAL_CONTEXT.fp_sqrt(&lhs.get().inner, rm.unwrap_or_default())?,
    )
}

#[pyfunction(name = "fpEQ", signature = (lhs, rhs))]
pub fn FpEq<'py>(
    py: Python<'py>,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.fp_eq(&lhs.get().inner, &rhs.get().inner)?,
    )
}

#[pyfunction(name = "fpNEQ", signature = (lhs, rhs))]
pub fn FpNEQ<'py>(
    py: Python<'py>,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.fp_neq(&lhs.get().inner, &rhs.get().inner)?,
    )
}

#[pyfunction(name = "fpLT", signature = (lhs, rhs))]
pub fn FpLt<'py>(
    py: Python<'py>,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.fp_lt(&lhs.get().inner, &rhs.get().inner)?,
    )
}

#[pyfunction(name = "fpLEQ", signature = (lhs, rhs))]
pub fn FpLeq<'py>(
    py: Python<'py>,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.fp_leq(&lhs.get().inner, &rhs.get().inner)?,
    )
}

#[pyfunction(name = "fpGT", signature = (lhs, rhs))]
pub fn FpGt<'py>(
    py: Python<'py>,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.fp_gt(&lhs.get().inner, &rhs.get().inner)?,
    )
}

#[pyfunction(name = "fpGEQ", signature = (lhs, rhs))]
pub fn FpGeq<'py>(
    py: Python<'py>,
    lhs: Bound<'py, FP>,
    rhs: Bound<'py, FP>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.fp_geq(&lhs.get().inner, &rhs.get().inner)?,
    )
}

#[pyfunction(name = "fpIsNaN", signature = (fp))]
pub fn FpIsNan<'py>(py: Python<'py>, fp: Bound<'py, FP>) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(py, &GLOBAL_CONTEXT.fp_is_nan(&fp.get().inner)?)
}

#[pyfunction(name = "fpIsInf", signature = (fp))]
pub fn FpIsInf<'py>(py: Python<'py>, fp: Bound<'py, FP>) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(py, &GLOBAL_CONTEXT.fp_is_inf(&fp.get().inner)?)
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyFSort>()?;
    m.add_class::<FP>()?;

    add_pyfunctions!(
        m,
        FPS,
        FPV,
        fpFP,
        FpToFP,
        BvToFpUnsigned,
        fpToIEEEBV,
        FpToUbv,
        FpToBv,
        FpNeg,
        FpAbs,
        FpAdd,
        FpSub,
        FpMul,
        FpDiv,
        FpSqrt,
        FpEq,
        FpNEQ,
        FpLt,
        FpLeq,
        FpGt,
        FpGeq,
        FpIsNan,
        FpIsInf,
    );

    m.add("FSORT_FLOAT", fsort_float())?;
    m.add("FSORT_DOUBLE", fsort_double())?;

    Ok(())
}
