use num_bigint::BigUint;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyString, PyTuple, PyType};

use crate::prelude::*;

/// Process-global cache of the original Python objects for annotations, keyed
/// by their core [`Annotation`] value. It lets retrieval return the very object
/// that was attached — while it is still alive — instead of a freshly
/// constructed copy, so `is` and `==` hold for callers that round-trip an
/// annotation through an AST. This applies to every annotation, built-in or
/// user-defined. It is a `WeakValueDictionary`, so entries evict once the
/// original annotation is garbage-collected, at which point retrieval falls
/// back to reconstructing the annotation from the core value.
static ORIGINAL_ANNOTATIONS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

fn original_annotations(py: Python<'_>) -> Result<Bound<'_, PyAny>, ClaripyError> {
    let cache =
        ORIGINAL_ANNOTATIONS.get_or_try_init(py, || -> Result<Py<PyAny>, ClaripyError> {
            Ok(py
                .import("weakref")?
                .getattr("WeakValueDictionary")?
                .call0()?
                .unbind())
        })?;
    Ok(cache.bind(py).clone())
}

/// A process-local key identifying an annotation by its content, used to store
/// and look up the original Python object in [`ORIGINAL_ANNOTATIONS`].
///
/// The `Debug` representation is injective over distinct [`Annotation`] values,
/// and the cache it keys is never persisted (it lives only for the lifetime of
/// the process), so `Debug` is a sound key here even though it is not a stable
/// serialization format.
fn cache_key<'py>(py: Python<'py>, annotation: &Annotation) -> Bound<'py, PyString> {
    PyString::new(py, &format!("{annotation:?}"))
}

/// Remember `obj` as the original Python object for `annotation`, so a later
/// retrieval can hand it back verbatim while it is still alive. Best-effort:
/// objects that cannot be weakly referenced are simply not cached.
fn remember_original(annotation: &Annotation, obj: &Bound<'_, PyAnnotation>) {
    let py = obj.py();
    if let Ok(cache) = original_annotations(py) {
        let _ = cache.set_item(cache_key(py, annotation), obj);
    }
}

/// Return the original Python object that produced `annotation` if it is still
/// cached and alive, preserving Python identity across an attach/read
/// round-trip.
fn cached_annotation<'py>(
    py: Python<'py>,
    annotation: &Annotation,
) -> Option<Bound<'py, PyAnnotation>> {
    let cache = original_annotations(py).ok()?;
    let obj = cache
        .call_method1("get", (cache_key(py, annotation),))
        .ok()?;
    if obj.is_none() {
        return None;
    }
    obj.cast_into::<PyAnnotation>().ok()
}

/// `claripy.annotation.Annotation`
///
/// The base class for every annotation. User code can subclass it, and the
/// built-in annotations below are genuine subclasses.
#[pyclass(
    name = "Annotation",
    subclass,
    frozen,
    weakref,
    module = "claripy.annotation"
)]
pub struct PyAnnotation;

#[pymethods]
impl PyAnnotation {
    /// Accept (and ignore) arbitrary arguments so that Python subclasses with
    /// their own `__init__` signatures can be instantiated, mirroring the
    /// behaviour of `object.__new__` when `__init__` is overridden.
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(_args: &Bound<'_, PyTuple>, _kwargs: Option<&Bound<'_, PyDict>>) -> Self {
        PyAnnotation
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        true
    }
}

impl PyAnnotation {
    /// Convert a Python annotation object (an instance of this class or any of
    /// its subclasses) into the core [`Annotation`] consumed by the solver.
    pub fn to_annotation(slf: &Bound<'_, PyAnnotation>) -> Result<Annotation, ClaripyError> {
        let any = slf.as_any();
        let annotation = if any.cast::<SimplificationAvoidanceAnnotation>().is_ok() {
            Annotation::new(AnnotationType::SimplificationAvoidance, false, false)
        } else if let Ok(si) = any.cast::<StridedIntervalAnnotation>() {
            let si = si.get();
            Annotation::new(
                AnnotationType::StridedInterval {
                    stride: si.stride.clone(),
                    lower_bound: si.lower_bound.clone(),
                    upper_bound: si.upper_bound.clone(),
                },
                false,
                false,
            )
        } else if any.cast::<EmptyStridedIntervalAnnotation>().is_ok() {
            Annotation::new(AnnotationType::EmptyStridedInterval, false, false)
        } else if let Ok(region) = any.cast::<RegionAnnotation>() {
            let region = region.get();
            Annotation::new(
                AnnotationType::Region {
                    region_id: region.region_id.clone(),
                    region_base_addr: region.region_base_addr.clone(),
                },
                false,
                false,
            )
        } else if any.cast::<UninitializedAnnotation>().is_ok() {
            Annotation::new(AnnotationType::Uninitialized, false, true)
        } else {
            // Unknown, user-defined annotation: preserve it losslessly by
            // pickling the Python object so it can be reconstructed later.
            let eliminatable = slf
                .getattr("eliminatable")
                .and_then(|v| v.extract::<bool>())
                .unwrap_or(true);
            let relocatable = slf
                .getattr("relocatable")
                .and_then(|v| v.extract::<bool>())
                .unwrap_or(false);
            let module_name = slf.getattr("__module__")?.extract::<String>()?;
            let class_name = slf
                .getattr("__class__")?
                .getattr("__name__")?
                .extract::<String>()?;
            let pickle_dumps = slf.py().import("pickle")?.getattr("dumps")?;
            let pickled = pickle_dumps.call1((slf,))?.extract::<Vec<u8>>()?;
            // Identify the annotation by the object's hash; the pickled bytes
            // are kept only to reconstruct it.
            let obj_hash = slf.hash()? as i64;
            Annotation::new(
                AnnotationType::Unknown {
                    name: format!("{module_name}:{class_name}"),
                    value: pickled.into(),
                    obj_hash,
                },
                eliminatable,
                relocatable,
            )
        };

        // Remember the original object, keyed by the core annotation it
        // produced, so retrieval can return it verbatim while it is still alive,
        // preserving Python identity (`is`/`==`) across an attach/read
        // round-trip — for built-in and user-defined annotations alike.
        remember_original(&annotation, slf);

        Ok(annotation)
    }

    /// Build a Python annotation object from a core [`Annotation`].
    pub fn from_annotation<'py>(
        py: Python<'py>,
        annotation: &Annotation,
    ) -> Result<Bound<'py, PyAnnotation>, ClaripyError> {
        // Return the original Python object if it is still cached and alive,
        // preserving identity; otherwise reconstruct it from the core value
        // below. This covers every annotation type, not just user-defined ones.
        if let Some(obj) = cached_annotation(py, annotation) {
            return Ok(obj);
        }

        match annotation.type_() {
            AnnotationType::Unknown { value, .. } => {
                let pickle_loads = py.import("pickle")?.getattr("loads")?;
                Ok(pickle_loads
                    .call1((value.0.clone(),))?
                    .cast_into::<PyAnnotation>()?)
            }
            AnnotationType::SimplificationAvoidance => upcast(Bound::new(
                py,
                (SimplificationAvoidanceAnnotation, PyAnnotation),
            )?),
            AnnotationType::StridedInterval {
                stride,
                lower_bound,
                upper_bound,
            } => upcast(Bound::new(
                py,
                (
                    StridedIntervalAnnotation {
                        stride: stride.clone(),
                        lower_bound: lower_bound.clone(),
                        upper_bound: upper_bound.clone(),
                    },
                    PyAnnotation,
                ),
            )?),
            AnnotationType::EmptyStridedInterval => upcast(Bound::new(
                py,
                (EmptyStridedIntervalAnnotation, PyAnnotation),
            )?),
            AnnotationType::Region {
                region_id,
                region_base_addr,
            } => upcast(Bound::new(
                py,
                (
                    RegionAnnotation {
                        region_id: region_id.clone(),
                        region_base_addr: region_base_addr.clone(),
                    },
                    PyAnnotation,
                ),
            )?),
            AnnotationType::Uninitialized => {
                upcast(Bound::new(py, (UninitializedAnnotation, PyAnnotation))?)
            }
        }
    }
}

/// Upcast a concrete annotation subclass instance to its `PyAnnotation` base.
fn upcast<'py, T>(bound: Bound<'py, T>) -> Result<Bound<'py, PyAnnotation>, ClaripyError> {
    Ok(bound.into_any().cast_into::<PyAnnotation>()?)
}

/// `claripy.annotation.SimplificationAvoidanceAnnotation`
#[pyclass(extends = PyAnnotation, subclass, frozen, weakref, module = "claripy.annotation")]
pub struct SimplificationAvoidanceAnnotation;

#[pymethods]
impl SimplificationAvoidanceAnnotation {
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(SimplificationAvoidanceAnnotation)
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __repr__(&self) -> &'static str {
        "SimplificationAvoidanceAnnotation()"
    }
}

/// `claripy.annotation.StridedIntervalAnnotation`
#[pyclass(extends = PyAnnotation, subclass, frozen, weakref, module = "claripy.annotation")]
pub struct StridedIntervalAnnotation {
    #[pyo3(get)]
    stride: BigUint,
    #[pyo3(get)]
    lower_bound: BigUint,
    #[pyo3(get)]
    upper_bound: BigUint,
}

#[pymethods]
impl StridedIntervalAnnotation {
    #[new]
    fn py_new(
        stride: BigUint,
        lower_bound: BigUint,
        upper_bound: BigUint,
    ) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(StridedIntervalAnnotation {
            stride,
            lower_bound,
            upper_bound,
        })
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __reduce__<'py>(slf: PyRef<'py, Self>) -> (Bound<'py, PyType>, (BigUint, BigUint, BigUint)) {
        (
            slf.py().get_type::<Self>(),
            (
                slf.stride.clone(),
                slf.lower_bound.clone(),
                slf.upper_bound.clone(),
            ),
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "StridedIntervalAnnotation(stride={}, lower_bound={}, upper_bound={})",
            self.stride, self.lower_bound, self.upper_bound
        )
    }
}

/// `claripy.annotation.EmptyStridedIntervalAnnotation`
#[pyclass(extends = PyAnnotation, subclass, frozen, weakref, module = "claripy.annotation")]
pub struct EmptyStridedIntervalAnnotation;

#[pymethods]
impl EmptyStridedIntervalAnnotation {
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(EmptyStridedIntervalAnnotation)
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __repr__(&self) -> &'static str {
        "EmptyStridedIntervalAnnotation()"
    }
}

/// `claripy.annotation.RegionAnnotation`
#[pyclass(extends = PyAnnotation, subclass, frozen, weakref, module = "claripy.annotation")]
pub struct RegionAnnotation {
    #[pyo3(get)]
    region_id: String,
    #[pyo3(get)]
    region_base_addr: BigUint,
}

#[pymethods]
impl RegionAnnotation {
    #[new]
    fn py_new(region_id: String, region_base_addr: BigUint) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(RegionAnnotation {
            region_id,
            region_base_addr,
        })
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __reduce__<'py>(slf: PyRef<'py, Self>) -> (Bound<'py, PyType>, (String, BigUint)) {
        (
            slf.py().get_type::<Self>(),
            (slf.region_id.clone(), slf.region_base_addr.clone()),
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "RegionAnnotation(region_id={}, region_base_addr={})",
            self.region_id, self.region_base_addr
        )
    }
}

/// `claripy.annotation.UninitializedAnnotation`
#[pyclass(extends = PyAnnotation, subclass, frozen, weakref, module = "claripy.annotation")]
pub struct UninitializedAnnotation;

#[pymethods]
impl UninitializedAnnotation {
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(UninitializedAnnotation)
    }

    #[classattr]
    fn relocatable() -> bool {
        true
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __repr__(&self) -> &'static str {
        "UninitializedAnnotation()"
    }
}

pub(crate) fn build_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let module = PyModule::new(py, "claripy.annotation")?;
    module.add_class::<PyAnnotation>()?;
    module.add_class::<SimplificationAvoidanceAnnotation>()?;
    module.add_class::<StridedIntervalAnnotation>()?;
    module.add_class::<EmptyStridedIntervalAnnotation>()?;
    module.add_class::<RegionAnnotation>()?;
    module.add_class::<UninitializedAnnotation>()?;
    Ok(module)
}
