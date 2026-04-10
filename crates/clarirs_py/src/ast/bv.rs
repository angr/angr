#![allow(non_snake_case)]

use std::collections::{BTreeSet, HashMap};
use std::iter::once;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use clarirs_core::algorithms::{canonicalize, structurally_match};
use clarirs_core::ast::bitvec::{BitVecAstExt, BitVecOpExt};
use clarirs_vsa::cardinality::Cardinality;
use clarirs_vsa::reduce::Reduce;
use dashmap::DashMap;
use num_bigint::{BigInt, BigUint, Sign};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::types::{PyFrozenSet, PySlice, PyWeakrefReference};

use crate::ast::fp::{PyFSort, PyRM};
use crate::ast::{and, not, or, xor};
use crate::prelude::*;
use crate::pyslicemethodsext::PySliceMethodsExt;
use clarirs_core::smtlib::ToSmtLib;

static BVS_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PY_BV_CACHE: LazyLock<DashMap<u64, Py<PyWeakrefReference>>> = LazyLock::new(DashMap::new);

#[pyclass(extends=Bits, subclass, frozen, weakref, module="claripy.ast.bv")]
pub struct BV {
    pub(crate) inner: BitVecAst<'static>,
}

impl BV {
    pub fn new<'py>(
        py: Python<'py>,
        inner: &BitVecAst<'static>,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        Self::new_with_name(py, inner, None)
    }

    pub fn new_with_name<'py>(
        py: Python<'py>,
        inner: &BitVecAst<'static>,
        name: Option<String>,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        let inner = &inner.simplify_ext(true, true)?;
        if let Some(cache_hit) = PY_BV_CACHE.get(&inner.hash()).and_then(|cache_hit| {
            cache_hit
                .bind(py)
                .upgrade_as::<BV>()
                .expect("bool cache poisoned")
        }) {
            Ok(cache_hit)
        } else {
            let this = Bound::new(
                py,
                PyClassInitializer::from(Base::new_with_name(py, name))
                    .add_subclass(Bits::new())
                    .add_subclass(BV {
                        inner: inner.clone(),
                    }),
            )?;
            let weakref = PyWeakrefReference::new(&this)?;
            PY_BV_CACHE.insert(inner.hash(), weakref.unbind());

            Ok(this)
        }
    }
}

#[pymethods]
impl BV {
    #[new]
    #[pyo3(signature = (op, args, annotations=None))]
    pub fn py_new<'py>(
        py: Python<'py>,
        op: &str,
        args: Vec<Py<PyAny>>,
        annotations: Option<Vec<PyAnnotation>>,
    ) -> Result<Py<BV>, ClaripyError> {
        let inner = match op {
            "BVS" => GLOBAL_CONTEXT.bvs(args[0].extract::<String>(py)?, args[1].extract(py)?)?,
            "BVV" => GLOBAL_CONTEXT
                .bvv_from_biguint_with_size(&args[0].extract(py)?, args[1].extract(py)?)?,
            "__and__" => GLOBAL_CONTEXT.bv_and(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__or__" => GLOBAL_CONTEXT.bv_or(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__xor__" => GLOBAL_CONTEXT.bv_xor(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__neg__" => GLOBAL_CONTEXT.neg(&args[0].cast_bound::<BV>(py)?.get().inner)?,
            "__add__" => GLOBAL_CONTEXT.add(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__sub__" => GLOBAL_CONTEXT.sub(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__mul__" => GLOBAL_CONTEXT.mul(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__floordiv__" => GLOBAL_CONTEXT.udiv(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "SDiv" => GLOBAL_CONTEXT.sdiv(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__mod__" => GLOBAL_CONTEXT.urem(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "SMod" => GLOBAL_CONTEXT.srem(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__lshift__" => GLOBAL_CONTEXT.shl(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "LShR" => GLOBAL_CONTEXT.lshr(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "__rshift__" => GLOBAL_CONTEXT.ashr(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "RotateLeft" => GLOBAL_CONTEXT.rotate_left(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "RotateRight" => GLOBAL_CONTEXT.rotate_right(
                &args[0].cast_bound::<BV>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
            )?,
            "ZeroExt" => GLOBAL_CONTEXT.zero_ext(
                &args[1].cast_bound::<BV>(py)?.get().inner,
                args[0].extract(py)?,
            )?,
            "SignExt" => GLOBAL_CONTEXT.sign_ext(
                &args[1].cast_bound::<BV>(py)?.get().inner,
                args[0].extract(py)?,
            )?,
            "Extract" => GLOBAL_CONTEXT.extract(
                &args[2].cast_bound::<BV>(py)?.get().inner,
                args[0].extract(py)?,
                args[1].extract(py)?,
            )?,
            "Concat" => {
                let concat_args: Vec<_> = args
                    .iter()
                    .map(|a| a.cast_bound::<BV>(py).map(|b| b.get().inner.clone()))
                    .collect::<Result<_, _>>()?;
                GLOBAL_CONTEXT.concat(concat_args)?
            }
            "Reverse" => GLOBAL_CONTEXT.byte_reverse(&args[0].cast_bound::<BV>(py)?.get().inner)?,
            "fpToIEEEBV" => {
                GLOBAL_CONTEXT.fp_to_ieeebv(&args[0].cast_bound::<FP>(py)?.get().inner)?
            }
            // "fpToUBV" => GLOBAL_CONTEXT.fp_to_ubv(
            //     &args[0].cast_bound::<FP>(py)?.get().inner,
            // )?,
            // "fpToSBV" => GLOBAL_CONTEXT.fp_to_sbv(
            //     &args[0].cast_bound::<FP>(py)?.get().inner,
            // )?,
            "StrLen" => {
                GLOBAL_CONTEXT.str_len(&args[0].cast_bound::<PyAstString>(py)?.get().inner)?
            }
            "StrIndexOf" => GLOBAL_CONTEXT.str_index_of(
                &args[0].cast_bound::<PyAstString>(py)?.get().inner,
                &args[1].cast_bound::<PyAstString>(py)?.get().inner,
                &args[2].cast_bound::<BV>(py)?.get().inner,
            )?,
            "StrToBV" => {
                GLOBAL_CONTEXT.str_to_bv(&args[0].cast_bound::<PyAstString>(py)?.get().inner)?
            }
            "If" => GLOBAL_CONTEXT.ite(
                &args[0].cast_bound::<Bool>(py)?.get().inner,
                &args[1].cast_bound::<BV>(py)?.get().inner,
                &args[2].cast_bound::<BV>(py)?.get().inner,
            )?,
            _ => return Err(ClaripyError::InvalidOperation(op.to_string())),
        };

        let inner_with_annotations = if let Some(annots) = annotations {
            GLOBAL_CONTEXT.annotate(&inner, annots.into_iter().map(|a| a.0))?
        } else {
            inner
        };

        Ok(BV::new(py, &inner_with_annotations)?.unbind())
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
    ) -> Result<(HashMap<u64, Bound<'py, PyAny>>, usize, Bound<'py, BV>), ClaripyError> {
        let (replacement_map, counter, canonical) = canonicalize(&self.inner.clone().into())?;
        let canonical_bv = BV::new(
            py,
            &canonical
                .into_bitvec()
                .ok_or(ClaripyError::InvalidOperation(
                    "Canonicalization did not produce a BitVec".to_string(),
                ))?,
        )?;

        let mut py_map = HashMap::new();
        for (hash, dynast) in replacement_map {
            let py_ast = Base::from_dynast(py, dynast)?;
            py_map.insert(hash, py_ast.into_any());
        }

        Ok((py_map, counter, canonical_bv))
    }

    pub fn identical(&self, other: Bound<'_, Base>) -> Result<bool, ClaripyError> {
        let structural = structurally_match(
            &DynAst::BitVec(self.inner.clone()),
            &Base::to_dynast(other.clone())?,
        )?;
        if structural {
            return Ok(true);
        }
        // Fall back to VSA reduction comparison
        if let Ok(other_bv) = other.into_any().cast::<BV>()
            && let (Ok(a_reduced), Ok(b_reduced)) =
                (self.inner.reduce(), other_bv.get().inner.reduce())
        {
            return Ok(a_reduced == b_reduced);
        }
        Ok(false)
    }

    #[getter]
    pub fn depth(&self) -> u32 {
        self.inner.depth()
    }

    pub fn is_leaf(&self) -> bool {
        self.inner.depth() == 1
    }

    pub fn is_true(&self) -> bool {
        // A BV is "true" if it's a concrete non-zero value
        if let Ok(simplified) = self.inner.simplify()
            && let BitVecOp::BVV(bv) = simplified.op()
        {
            return !bv.is_zero();
        }
        false
    }

    pub fn is_false(&self) -> bool {
        // A BV is "false" if it's a concrete zero value
        if let Ok(simplified) = self.inner.simplify()
            && let BitVecOp::BVV(bv) = simplified.op()
        {
            return bv.is_zero();
        }
        false
    }

    #[pyo3(signature = (respect_annotations=true))]
    pub fn simplify<'py>(
        &self,
        py: Python<'py>,
        respect_annotations: bool,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(py, &self.inner.simplify_ext(respect_annotations, false)?)
    }

    pub fn replace<'py>(
        &self,
        py: Python<'py>,
        from: Bound<'py, Base>,
        to: Bound<'py, Base>,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        use clarirs_core::algorithms::Replace;
        let from_ast = Base::to_dynast(from)?;
        let to_ast = Base::to_dynast(to)?;
        let replaced = self.inner.replace(&from_ast, &to_ast)?;
        BV::new(py, &replaced)
    }

    pub fn size(&self) -> usize {
        self.inner.size() as usize
    }

    pub fn __len__(&self) -> usize {
        self.size()
    }

    #[getter]
    pub fn length(&self) -> usize {
        self.size()
    }

    #[getter]
    pub fn concrete_value(&self) -> Result<Option<BigUint>, ClaripyError> {
        Ok(match self.inner.simplify_ext(false, false)?.op() {
            BitVecOp::BVV(bv) => Some(bv.to_biguint()),
            _ => None,
        })
    }

    pub fn __getitem__<'py>(
        self_: Bound<'py, BV>,
        range: Bound<'py, PyAny>,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        if let Ok(slice) = range.cast::<PySlice>() {
            if slice.step()?.is_some() {
                return Err(ClaripyError::InvalidOperation(
                    "slicing with step is not supported".to_string(),
                ));
            }

            let py = self_.py();
            let size = self_.get().size() as isize;

            // We use weird backwards SMTLIB indexing rules that are not python
            // rules. These conditions should fix it up to make the default
            // values correct
            let mut start = slice.start()?.unwrap_or(size - 1);
            let mut stop = slice.stop()?.unwrap_or(0);

            if start < 0 {
                start += size;
            }
            if stop < 0 {
                stop += size;
            }

            // Validate extract bounds
            if start < 0 || stop < 0 {
                return Err(ClaripyError::InvalidExtractBounds {
                    upper: start.max(0) as u32,
                    lower: stop.max(0) as u32,
                    length: size as u32,
                });
            }
            if stop > start {
                return Err(ClaripyError::InvalidExtractBounds {
                    upper: start as u32,
                    lower: stop as u32,
                    length: size as u32,
                });
            }
            if start >= size {
                return Err(ClaripyError::InvalidExtractBounds {
                    upper: start as u32,
                    lower: stop as u32,
                    length: size as u32,
                });
            }

            Extract(self_.py(), start as u32, stop as u32, self_)?
                .get()
                .simplify(py, true)
        } else if let Ok(int_val) = range.extract::<u32>() {
            let size = self_.get().size() as u32;
            if int_val >= size {
                return Err(ClaripyError::InvalidExtractBounds {
                    upper: int_val,
                    lower: int_val,
                    length: size,
                });
            }
            Extract(self_.py(), int_val, int_val, self_)
        } else {
            Err(ClaripyError::FailedToExtractArg(range.unbind()))
        }
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
            .make_bitvec_annotated(self.inner.op().clone(), new_annotations)?;
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
        let inner = self.inner.context().make_bitvec_annotated(
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
        let inner = self.inner.context().make_bitvec_annotated(
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
        let inner = self.inner.context().make_bitvec_annotated(
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
        let inner = self.inner.context().make_bitvec(self.inner.op().clone())?;
        Self::new(py, &inner)
    }

    pub fn clear_annotation_type<'py>(
        &self,
        py: Python<'py>,
        annotation_type: PyAnnotationType,
    ) -> Result<Bound<'py, Self>, ClaripyError> {
        let inner = self.inner.context().make_bitvec_annotated(
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

    pub fn raw_to_bv(self_: Bound<'_, BV>) -> Result<Bound<'_, BV>, ClaripyError> {
        Ok(self_)
    }

    pub fn raw_to_fp(self_: Bound<'_, BV>) -> Result<Bound<'_, FP>, ClaripyError> {
        let ctx = self_.get().inner.context();
        match self_.get().size() {
            32 => Ok(FP::new(
                self_.py(),
                &ctx.bv_to_fp(&self_.get().inner, FSort::f32())?,
            )?),
            64 => Ok(FP::new(
                self_.py(),
                &ctx.bv_to_fp(&self_.get().inner, FSort::f64())?,
            )?),
            _ => Err(ClaripyError::InvalidOperation(
                "Cannot convert BV to FP".to_string(),
            )),
        }
    }

    pub fn to_bv(self_: Bound<'_, BV>) -> Result<Bound<'_, BV>, ClaripyError> {
        Ok(self_)
    }

    #[pyo3(signature = (sort = None, signed = true, rm = None))]
    pub fn val_to_fp<'py>(
        self_: Bound<'py, BV>,
        sort: Option<PyFSort>,
        signed: bool,
        rm: Option<PyRM>,
    ) -> Result<Bound<'py, FP>, ClaripyError> {
        let sort = sort.unwrap_or_else(|| {
            PyFSort::from_size(self_.get().size() as u32)
                .expect("Failed to create FSort from BV size")
        });
        let rm = rm.unwrap_or_default();

        if signed {
            FP::new(
                self_.py(),
                &GLOBAL_CONTEXT.bv_to_fp_signed(&self_.get().inner, sort, rm)?,
            )
        } else {
            FP::new(
                self_.py(),
                &GLOBAL_CONTEXT.bv_to_fp_unsigned(&self_.get().inner, sort, rm)?,
            )
        }
    }

    pub fn __add__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.add(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __radd__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        self.__add__(py, other)
    }

    pub fn __sub__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.sub(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rsub__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.sub(&other.unpack_like(py, self)?.get().inner, &self.inner)?,
        )
    }

    pub fn __mul__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.mul(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rmul__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        self.__mul__(py, other)
    }

    pub fn __truediv__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.udiv(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rtruediv__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.udiv(&other.unpack_like(py, self)?.get().inner, &self.inner)?,
        )
    }

    pub fn __floordiv__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.udiv(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rfloordiv__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.udiv(&other.unpack_like(py, self)?.get().inner, &self.inner)?,
        )
    }

    pub fn __mod__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.urem(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rmod__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.urem(&other.unpack_like(py, self)?.get().inner, &self.inner)?,
        )
    }

    pub fn SDiv<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.sdiv(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn SMod<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.srem(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __and__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.bv_and(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rand__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        self.__and__(py, other)
    }

    pub fn __or__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.bv_or(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __ror__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        self.__or__(py, other)
    }

    pub fn __xor__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.bv_xor(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rxor__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        self.__xor__(py, other)
    }

    pub fn __lshift__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.shl(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rlshift__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.shl(&other.unpack_like(py, self)?.get().inner, &self.inner)?,
        )
    }

    pub fn __rshift__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.ashr(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __rrshift__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.ashr(&other.unpack_like(py, self)?.get().inner, &self.inner)?,
        )
    }

    pub fn LShR<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.lshr(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __neg__<'py>(&self, py: Python<'py>) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(py, &GLOBAL_CONTEXT.neg(&self.inner)?)
    }

    pub fn __invert__<'py>(&self, py: Python<'py>) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(py, &GLOBAL_CONTEXT.not(&self.inner)?)
    }

    pub fn __pos__(self_: Bound<BV>) -> Result<Bound<BV>, ClaripyError> {
        Ok(self_)
    }

    pub fn __eq__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.eq_(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __ne__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.neq(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __lt__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.ult(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __le__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.ule(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __gt__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.ugt(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn __ge__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.uge(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn ULT<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.ult(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn ULE<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.ule(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn UGT<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.ugt(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn UGE<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.uge(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn SLT<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.slt(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn SLE<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.sle(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn SGT<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.sgt(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn SGE<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(
            py,
            &GLOBAL_CONTEXT.sge(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn Extract<'py>(
        &self,
        py: Python<'py>,
        upper_bound: u32,
        lower_bound: u32,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.extract(&self.inner, upper_bound, lower_bound)?,
        )
    }

    #[pyo3(signature = (*args))]
    pub fn concat<'py>(
        self_: Bound<'py, BV>,
        py: Python<'py>,
        args: Vec<CoerceBV<'py>>,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        Concat(py, once(self_.into()).chain(args).collect())
    }

    pub fn zero_extend<'py>(
        &self,
        py: Python<'py>,
        amount: u32,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(py, &GLOBAL_CONTEXT.zero_ext(&self.inner, amount)?)
    }

    pub fn sign_extend<'py>(
        &self,
        py: Python<'py>,
        amount: u32,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(py, &GLOBAL_CONTEXT.sign_ext(&self.inner, amount)?)
    }

    #[getter]
    pub fn reversed<'py>(&self, py: Python<'py>) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(py, &GLOBAL_CONTEXT.byte_reverse(&self.inner)?)
    }

    pub fn get_bytes<'py>(
        self_: Bound<'py, BV>,
        py: Python<'py>,
        index: u32,
        size: u32,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        // Calculate pos
        let bv_size = self_.get().size() as i32;
        let pos = (bv_size + 7) / 8 - 1 - index as i32;

        // Check if pos is negative
        if pos < 0 {
            return Err(PyValueError::new_err(format!(
                "Incorrect index {}. Your index must be between 0 and {}.",
                index,
                bv_size / 8 - 1
            ))
            .into());
        }

        // Handle size = 0
        if size == 0 {
            let a = GLOBAL_CONTEXT
                .bvv_from_biguint_with_size(&BigUint::from(0u32), 0)
                .map_err(ClaripyError::from)?;
            return BV::new(py, &a);
        }

        // Check if index + size is too large (exceeds the number of bytes in the bitvector)
        let bv_bytes = (bv_size + 7) / 8;

        // Special case: if index is 0 and size is too large, we should just return the first byte
        if index == 0 && size > bv_bytes as u32 {
            // Extract the first byte - for a 32-bit value, we want to extract bits 31:24
            let upper = bv_size - 1;
            let lower = std::cmp::max(0, bv_size - 8);
            let extracted = Extract(py, upper as u32, lower as u32, self_)?;

            // If the bitvector is concrete, we can create a BVV with the actual value
            if let Some(concrete_value) = extracted.get().concrete_value()? {
                // Create a BVV with the concrete value
                let result_size = extracted.get().size() as u32;
                let a = GLOBAL_CONTEXT
                    .bvv_from_biguint_with_size(&concrete_value, result_size)
                    .map_err(ClaripyError::from)?;
                return BV::new(py, &a);
            }

            return Ok(extracted);
        }

        // For other cases where index + size is too large, raise an error
        if index + size > bv_bytes as u32 && pos - size as i32 + 1 < 0 && index > 0 {
            // This should raise a ClaripyOperationError
            return Err(ClaripyError::InvalidOperation(format!(
                "Index {index} + size {size} exceeds the number of bytes in the bitvector ({bv_bytes})"
            )));
        }

        // Calculate upper and lower bounds for extraction
        let upper = std::cmp::min(pos * 8 + 7, bv_size - 1) as u32;
        let lower = std::cmp::max(0, (pos - size as i32 + 1) * 8) as u32;

        // If size is larger than the number of bytes in the bitvector but doesn't exceed the bounds,
        // we need to handle it specially
        if size as i32 > bv_bytes && pos >= size as i32 - 1 {
            // In this case, we should just return the first byte
            let extracted = Extract(py, upper, std::cmp::max(0, bv_size - 8) as u32, self_)?;

            // If the bitvector is concrete, we can create a BVV with the actual value
            if let Some(concrete_value) = extracted.get().concrete_value()? {
                // Create a BVV with the concrete value
                let result_size = extracted.get().size() as u32;
                let a = GLOBAL_CONTEXT
                    .bvv_from_biguint_with_size(&concrete_value, result_size)
                    .map_err(ClaripyError::from)?;
                return BV::new(py, &a);
            }

            return Ok(extracted);
        }

        // Extract the bytes
        let extracted = Extract(py, upper, lower, self_)?;

        // Zero-extend if needed
        let extracted_size = extracted.get().size() as u32;
        let final_size = if !extracted_size.is_multiple_of(8) {
            let extend_amount = 8 - extracted_size % 8;
            extracted.get().zero_extend(py, extend_amount)?
        } else {
            extracted
        };

        // If the bitvector is concrete, we can create a BVV with the actual value
        if let Some(concrete_value) = final_size.get().concrete_value()? {
            // Create a BVV with the concrete value
            let result_size = final_size.get().size() as u32;
            let a = GLOBAL_CONTEXT
                .bvv_from_biguint_with_size(&concrete_value, result_size)
                .map_err(ClaripyError::from)?;
            return BV::new(py, &a);
        }

        Ok(final_size)
    }

    pub fn get_byte<'py>(
        self_: Bound<'py, BV>,
        py: Python<'py>,
        index: u32,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::get_bytes(self_, py, index, 1)
    }

    pub fn chop<'py>(
        self_: Bound<'py, BV>,
        py: Python<'py>,
        bits: u32,
    ) -> Result<Vec<Bound<'py, BV>>, ClaripyError> {
        self_.get().inner.chop(bits).map(|r| {
            r.into_iter()
                .map(|r| BV::new(py, &r))
                .collect::<Result<Vec<_>, _>>()
        })?
    }

    // VSA Ops

    pub fn union<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.union(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn intersection<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.intersection(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    pub fn widen<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBV,
    ) -> Result<Bound<'py, BV>, ClaripyError> {
        BV::new(
            py,
            &GLOBAL_CONTEXT.widen(&self.inner, &other.unpack_like(py, self)?.get().inner)?,
        )
    }

    #[getter]
    pub fn cardinality(self_: Bound<'_, BV>) -> Result<BigUint, ClaripyError> {
        Ok(self_.get().inner.cardinality()?)
    }

    #[getter]
    pub fn singlevalued(self_: Bound<'_, BV>) -> Result<bool, ClaripyError> {
        Ok(BV::cardinality(self_)? == BigUint::from(1u32))
    }

    #[getter]
    pub fn multivalued(self_: Bound<'_, BV>) -> Result<bool, ClaripyError> {
        Ok(BV::cardinality(self_)? > BigUint::from(1u32))
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
        let class = py.get_type::<BV>();
        let op = self.op();
        let args = self.args(py)?;
        let annotations = self.annotations()?;
        Ok((class.into_any(), (op, args, annotations)))
    }
}

#[pyfunction(signature = (name, size, explicit_name = false))]
pub fn BVS(
    py: Python<'_>,
    name: String,
    size: u32,
    explicit_name: bool,
) -> Result<Bound<'_, BV>, ClaripyError> {
    let name: String = if explicit_name {
        name.to_string()
    } else {
        let counter = BVS_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{name}_{counter}_{size}")
    };
    BV::new_with_name(py, &GLOBAL_CONTEXT.bvs(&name, size)?, Some(name.clone()))
}

#[allow(non_snake_case)]
#[pyfunction(signature = (value, size = None))]
pub fn BVV<'py>(
    py: Python<'py>,
    value: Bound<PyAny>,
    size: Option<u32>,
) -> Result<Bound<'py, BV>, PyErr> {
    if let Ok(int_val) = value.extract::<BigUint>() {
        if let Some(size) = size {
            let a = GLOBAL_CONTEXT
                .bvv_from_biguint_with_size(&int_val, size)
                .map_err(ClaripyError::from)?;
            return Ok(BV::new(py, &a)?);
        } else {
            return Err(PyErr::new::<PyValueError, _>("size must be specified"));
        }
    }
    if let Ok(int_val) = value.extract::<BigInt>() {
        if let Some(size) = size {
            let uint_value = int_val.to_biguint().unwrap_or(
                ((BigInt::from(1) << size) + int_val)
                    .to_biguint()
                    .expect("BigInt to BigUInt failed"),
            );
            let a = GLOBAL_CONTEXT
                .bvv_from_biguint_with_size(&uint_value, size)
                .map_err(ClaripyError::from)?;
            return Ok(BV::new(py, &a)?);
        } else {
            return Err(PyErr::new::<PyValueError, _>("size must be specified"));
        }
    }
    // TODO: deduplicate bytes/str
    if let Ok(bytes_val) = value.extract::<Vec<u8>>() {
        let int_val = BigUint::from_bytes_be(&bytes_val);
        log::warn!("bytes value passed to BVV, assuming big-endian");
        if size.is_some() {
            log::warn!("BVV size specified with bytes, value will be ignored");
        }
        return Ok(BV::new(
            py,
            &GLOBAL_CONTEXT
                .bvv_from_biguint_with_size(&int_val, bytes_val.len() as u32 * 8)
                .map_err(ClaripyError::from)?,
        )?);
    }
    if let Ok(str_val) = value.extract::<String>() {
        log::warn!("string value passed to BVV, assuming utf-8/big-endian");
        let bytes_val = str_val.as_bytes();
        let int_val = BigUint::from_bytes_be(bytes_val);
        if size.is_some() {
            log::warn!("BVV size specified with string, value will be ignored");
        }
        return Ok(BV::new(
            py,
            &GLOBAL_CONTEXT
                .bvv_from_biguint_with_size(&int_val, bytes_val.len() as u32 * 8)
                .map_err(ClaripyError::from)?,
        )?);
    }
    Err(PyErr::new::<PyTypeError, _>(
        "BVV value must be a int, bytes, or str",
    ))
}

macro_rules! binop {
    ($name:ident, $context_method:ident, $ret:ty) => {
        #[pyfunction]
        pub fn $name<'py>(
            py: Python<'py>,
            lhs: CoerceBV<'py>,
            rhs: CoerceBV<'py>,
        ) -> Result<Bound<'py, $ret>, ClaripyError> {
            let (elhs, erhs) = CoerceBV::unpack_pair(py, &lhs, &rhs)?;
            <$ret>::new(
                py,
                &GLOBAL_CONTEXT.$context_method(&elhs.get().inner, &erhs.get().inner)?,
            )
        }
    };
}

binop!(Add, add, BV);
binop!(Sub, sub, BV);
binop!(Mul, mul, BV);
binop!(UDiv, udiv, BV);
binop!(SDiv, sdiv, BV);
binop!(UMod, urem, BV);
binop!(SMod, srem, BV);
binop!(ShL, shl, BV);
binop!(LShR, lshr, BV);
binop!(AShR, ashr, BV);
binop!(RotateLeft, rotate_left, BV);
binop!(RotateRight, rotate_right, BV);

#[pyfunction(signature = (*args))]
pub fn Concat<'py>(
    py: Python<'py>,
    args: Vec<CoerceBV<'py>>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    let unpacked = CoerceBV::unpack_vec_mismatch(py, &args)?;
    if unpacked.is_empty() {
        return Err(ClaripyError::MissingArgIndex(0));
    }
    let inner_args: Vec<_> = unpacked.iter().map(|b| b.get().inner.clone()).collect();
    let result = GLOBAL_CONTEXT.concat(inner_args)?;
    BV::new(py, &result)
}

#[pyfunction]
pub fn Extract<'py>(
    py: Python<'py>,
    upper: u32,
    lower: u32,
    base: Bound<'py, BV>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    let size = base.get().size() as u32;

    // Validate extract bounds
    if lower > upper {
        return Err(ClaripyError::InvalidOperation(
            "Extract low must be <= high".to_string(),
        ));
    }
    if upper >= size {
        return Err(ClaripyError::InvalidOperation(format!(
            "Extract bound ({upper}) must be less than BV size ({size})"
        )));
    }

    BV::new(
        py,
        &GLOBAL_CONTEXT.extract(&base.get().inner, upper, lower)?,
    )
}

#[pyfunction]
pub fn ZeroExt<'py>(
    py: Python<'py>,
    amount: u32,
    base: Bound<'py, BV>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.zero_ext(&base.get().inner, amount)?)
}

#[pyfunction]
pub fn SignExt<'py>(
    py: Python<'py>,
    amount: u32,
    base: Bound<'py, BV>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.sign_ext(&base.get().inner, amount)?)
}

#[pyfunction]
pub fn Reverse<'py>(py: Python<'py>, base: Bound<'py, BV>) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.byte_reverse(&base.get().inner)?)
}

binop!(ULT, ult, Bool);
binop!(ULE, ule, Bool);
binop!(UGT, ugt, Bool);
binop!(UGE, uge, Bool);
binop!(SLT, slt, Bool);
binop!(SLE, sle, Bool);
binop!(SGT, sgt, Bool);
binop!(SGE, sge, Bool);
binop!(Eq_, eq_, Bool);
binop!(Neq, neq, Bool);

// VSA Stuff

#[pyfunction]
pub fn SI(
    py: Python<'_>,
    bits: u32,
    stride: BigUint,
    lower_bound: BigInt,
    upper_bound: BigInt,
) -> Result<Bound<'_, BV>, ClaripyError> {
    // Convert potentially negative bounds to unsigned values in the bitvector's domain
    let modulus = BigInt::from(1) << bits;
    let lower_bound = if lower_bound.sign() == Sign::Minus {
        lower_bound + modulus.clone()
    } else {
        lower_bound
    }
    .to_biguint()
    .expect("lower_bound conversion failed");

    let upper_bound = if upper_bound.sign() == Sign::Minus {
        upper_bound + modulus
    } else {
        upper_bound
    }
    .to_biguint()
    .expect("upper_bound conversion failed");

    BV::new(
        py,
        &GLOBAL_CONTEXT.si(bits, stride, lower_bound, upper_bound)?,
    )
}

#[pyfunction]
pub fn ESI(py: Python<'_>, bits: u32) -> Result<Bound<'_, BV>, ClaripyError> {
    BV::new(py, &GLOBAL_CONTEXT.esi(bits)?)
}

#[pyfunction]
pub fn VS<'py>(
    py: Python<'py>,
    bits: u32,
    region_id: String,
    region_base_addr: BigUint,
    value: CoerceBV,
) -> Result<Bound<'py, BV>, ClaripyError> {
    let value = value.unpack(py, bits, false)?;
    BV::new(
        py,
        &GLOBAL_CONTEXT.annotate(
            &value.get().inner,
            [Annotation::new(
                AnnotationType::Region {
                    region_id,
                    region_base_addr,
                },
                false,
                false,
            )],
        )?,
    )
}

#[pyfunction]
pub fn union<'py>(
    py: Python<'py>,
    lhs: CoerceBV,
    rhs: CoerceBV,
) -> Result<Bound<'py, BV>, ClaripyError> {
    let (elhs, erhs) = CoerceBV::unpack_pair(py, &lhs, &rhs)?;
    BV::new(
        py,
        &GLOBAL_CONTEXT.union(&elhs.get().inner, &erhs.get().inner)?,
    )
}

#[pyfunction]
pub fn intersection<'py>(
    py: Python<'py>,
    lhs: CoerceBV,
    rhs: CoerceBV,
) -> Result<Bound<'py, BV>, ClaripyError> {
    let (elhs, erhs) = CoerceBV::unpack_pair(py, &lhs, &rhs)?;
    BV::new(
        py,
        &GLOBAL_CONTEXT.intersection(&elhs.get().inner, &erhs.get().inner)?,
    )
}

#[pyfunction]
pub fn widen<'py>(
    py: Python<'py>,
    lhs: CoerceBV,
    rhs: CoerceBV,
) -> Result<Bound<'py, BV>, ClaripyError> {
    let (elhs, erhs) = CoerceBV::unpack_pair(py, &lhs, &rhs)?;
    BV::new(
        py,
        &GLOBAL_CONTEXT.widen(&elhs.get().inner, &erhs.get().inner)?,
    )
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<BV>()?;

    add_pyfunctions!(
        m,
        BVS,
        BVV,
        not,
        and,
        or,
        xor,
        Add,
        Sub,
        Mul,
        UDiv,
        SDiv,
        UMod,
        SMod,
        ShL,
        LShR,
        AShR,
        RotateLeft,
        RotateRight,
        Concat,
        Extract,
        ZeroExt,
        SignExt,
        Reverse,
        ULT,
        ULE,
        UGT,
        UGE,
        SLT,
        SLE,
        SGT,
        SGE,
        Eq_,
        super::r#if,
        SI,
        ESI,
        VS,
        union,
        intersection,
        widen,
    );

    Ok(())
}
