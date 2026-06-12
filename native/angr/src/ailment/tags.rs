//! Tags storage for AIL objects.
//!
//! In the Python implementation `TaggedObject.tags` is an open dict containing
//! a handful of well-known keys (see `TagDict` in
//! `angr/ailment/tagged_object.py`). The new Rust implementation pins that
//! schema to a fixed struct of primitives so the whole AIL tree can be
//! serialized with Serde.
//!
//! The keys `reference_variable` and `reg_vvars`, which used to point to
//! Python objects, have been refactored:
//!   * `reference_variable: SimVariable`  ->  `reference_variable_ident: str`
//!   * `reg_vvars`                          ->  dedicated field on VirtualVariable
//!   * `reference_values` / `type`          ->  dropped entirely
//!
//! For backward compatibility, `Expression.tags` and `Statement.tags` are
//! still exposed to Python as a dict-like object. Reads and writes go through
//! `TagsView`, which translates names <-> struct fields.

use std::collections::HashMap;

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyKeyError, PyStopIteration, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyMapping, PyTuple};
use pyo3::{Borrowed, Py, PyAny};
use serde::{Deserialize, Serialize};

/// Value stored in the `extras` bucket for unknown tag keys.
///
/// The primitive variants serde-round-trip cleanly; the `Opaque` variant
/// holds a Python object (e.g. a SimVariable that hasn't been refactored to
/// an ident yet) and is silently skipped during Serde serialization.
#[derive(Debug, Clone)]
pub enum TagExtra {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    IntList(Vec<i64>),
    StrList(Vec<String>),
    /// Non-primitive Python value. Serde skips it.
    Opaque(Py<PyAny>),
}

impl PartialEq for TagExtra {
    fn eq(&self, other: &Self) -> bool {
        use TagExtra::*;
        match (self, other) {
            (Bool(a), Bool(b)) => a == b,
            (Int(a), Int(b)) => a == b,
            (Float(a), Float(b)) => a == b,
            (Str(a), Str(b)) => a == b,
            (IntList(a), IntList(b)) => a == b,
            (StrList(a), StrList(b)) => a == b,
            (Opaque(a), Opaque(b)) => {
                Python::attach(|py| a.bind(py).eq(b.bind(py)).unwrap_or(false))
            }
            _ => false,
        }
    }
}

impl Eq for TagExtra {}

// Serde: encode primitives as a tagged enum; treat Opaque as if it were None
// so we don't write Python objects into the byte stream.
impl Serialize for TagExtra {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;
        match self {
            TagExtra::Bool(v) => ser.serialize_newtype_variant("TagExtra", 0, "Bool", v),
            TagExtra::Int(v) => ser.serialize_newtype_variant("TagExtra", 1, "Int", v),
            TagExtra::Float(v) => ser.serialize_newtype_variant("TagExtra", 2, "Float", v),
            TagExtra::Str(v) => ser.serialize_newtype_variant("TagExtra", 3, "Str", v),
            TagExtra::IntList(v) => ser.serialize_newtype_variant("TagExtra", 4, "IntList", v),
            TagExtra::StrList(v) => ser.serialize_newtype_variant("TagExtra", 5, "StrList", v),
            TagExtra::Opaque(_) => {
                let v = ser.serialize_struct_variant("TagExtra", 6, "Opaque", 0)?;
                v.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for TagExtra {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "kind", content = "value")]
        enum Helper {
            Bool(bool),
            Int(i64),
            Float(f64),
            Str(String),
            IntList(Vec<i64>),
            StrList(Vec<String>),
            Opaque,
        }
        let h: Helper = Deserialize::deserialize(de)?;
        Ok(match h {
            Helper::Bool(v) => TagExtra::Bool(v),
            Helper::Int(v) => TagExtra::Int(v),
            Helper::Float(v) => TagExtra::Float(v),
            Helper::Str(v) => TagExtra::Str(v),
            Helper::IntList(v) => TagExtra::IntList(v),
            Helper::StrList(v) => TagExtra::StrList(v),
            Helper::Opaque => TagExtra::Opaque(Python::attach(|py| py.None())),
        })
    }
}

/// All known tag fields. Keep this list and the macro implementations below
/// in sync.
///
/// Unknown keys end up in `extras` (also primitive-only). The full set is
/// exposed Python-side as a dict-like view via `TagsView`.
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tags {
    pub always_propagate: Option<bool>,
    pub block_idx: Option<i64>,
    pub deref_src_addr: Option<i64>,
    pub extra_def: Option<bool>,
    pub extra_defs: Option<Vec<i64>>,
    pub ins_addr: Option<i64>,
    pub is_prototype_guessed: Option<bool>,
    pub keep_in_slice: Option<bool>,
    pub orig_ins_addr: Option<i64>,
    pub reg_name: Option<String>,
    pub uninitialized: Option<bool>,
    pub vex_block_addr: Option<i64>,
    pub vex_stmt_idx: Option<i64>,
    pub write_size: Option<i64>,
    /// Anything that isn't a recognized tag goes here, as long as the value
    /// is still a primitive. Keeps Tags fully serializable while remaining
    /// compatible with code/tests that attach ad-hoc tags.
    pub extras: HashMap<String, TagExtra>,
}

/// The list of all known tag keys. Used to enumerate set keys for
/// `keys()` / `items()` / `__iter__`.
pub const TAG_KEYS: &[&str] = &[
    "always_propagate",
    "block_idx",
    "deref_src_addr",
    "extra_def",
    "extra_defs",
    "ins_addr",
    "is_prototype_guessed",
    "keep_in_slice",
    "orig_ins_addr",
    "reg_name",
    "uninitialized",
    "vex_block_addr",
    "vex_stmt_idx",
    "write_size",
];

#[derive(Debug)]
enum TagValueKind {
    Bool,
    Int,
    Str,
    IntList,
}

fn kind_of(key: &str) -> Option<TagValueKind> {
    match key {
        "always_propagate"
        | "extra_def"
        | "is_prototype_guessed"
        | "keep_in_slice"
        | "uninitialized" => Some(TagValueKind::Bool),
        "block_idx"
        | "deref_src_addr"
        | "ins_addr"
        | "orig_ins_addr"
        | "vex_block_addr"
        | "vex_stmt_idx"
        | "write_size" => Some(TagValueKind::Int),
        "reg_name" => Some(TagValueKind::Str),
        "extra_defs" => Some(TagValueKind::IntList),
        _ => None,
    }
}

impl Tags {
    /// Build a Tags struct from a Python `**kwargs` dict.
    /// Unknown keys are rejected so we catch typos early (and so the
    /// non-primitive keys that were dropped are detected loudly).
    pub fn from_kwargs(kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut tags = Self::default();
        let Some(d) = kwargs else { return Ok(tags) };
        for (k, v) in d.iter() {
            let key: String = k.extract()?;
            tags.set_from_py(&key, &v)?;
        }
        Ok(tags)
    }

    pub fn from_dict(d: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        Self::from_kwargs(d)
    }

    /// Build a Tags struct from a Python mapping (used by __setstate__ and
    /// callers that pass `tags=` explicitly).
    pub fn from_mapping(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let Some(o) = obj else {
            return Ok(Self::default());
        };
        if o.is_none() {
            return Ok(Self::default());
        }
        if let Ok(d) = o.cast::<PyDict>() {
            return Self::from_dict(Some(d));
        }
        // Tags itself or a TagsView
        if let Ok(tags) = o.extract::<Tags>() {
            return Ok(tags);
        }
        // Generic mapping fallback
        if let Ok(m) = o.cast::<PyMapping>() {
            let mut tags = Self::default();
            let keys = m.keys()?;
            for k in keys.try_iter()? {
                let k = k?;
                let key: String = k.extract()?;
                let v = m.get_item(&k)?;
                tags.set_from_py(&key, &v)?;
            }
            return Ok(tags);
        }
        Err(PyTypeError::new_err(format!(
            "tags must be a mapping or None, got {}",
            o.get_type().name()?,
        )))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        let mut n = self.extras.len();
        for k in TAG_KEYS {
            if self.has(k) {
                n += 1;
            }
        }
        n
    }

    pub fn keys(&self) -> Vec<String> {
        let mut out: Vec<String> = TAG_KEYS
            .iter()
            .copied()
            .filter(|k| self.has(k))
            .map(String::from)
            .collect();
        for k in self.extras.keys() {
            out.push(k.clone());
        }
        out
    }

    pub fn has(&self, key: &str) -> bool {
        match key {
            "always_propagate" => self.always_propagate.is_some(),
            "block_idx" => self.block_idx.is_some(),
            "deref_src_addr" => self.deref_src_addr.is_some(),
            "extra_def" => self.extra_def.is_some(),
            "extra_defs" => self.extra_defs.is_some(),
            "ins_addr" => self.ins_addr.is_some(),
            "is_prototype_guessed" => self.is_prototype_guessed.is_some(),
            "keep_in_slice" => self.keep_in_slice.is_some(),
            "orig_ins_addr" => self.orig_ins_addr.is_some(),
            "reg_name" => self.reg_name.is_some(),
            "uninitialized" => self.uninitialized.is_some(),
            "vex_block_addr" => self.vex_block_addr.is_some(),
            "vex_stmt_idx" => self.vex_stmt_idx.is_some(),
            "write_size" => self.write_size.is_some(),
            other => self.extras.contains_key(other),
        }
    }

    pub fn get_py<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
        Ok(match key {
            "always_propagate" => self
                .always_propagate
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "block_idx" => self
                .block_idx
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "deref_src_addr" => self
                .deref_src_addr
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "extra_def" => self
                .extra_def
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "extra_defs" => self
                .extra_defs
                .as_ref()
                .map(|v| v.clone().into_bound_py_any(py))
                .transpose()?,
            "ins_addr" => self.ins_addr.map(|v| v.into_bound_py_any(py)).transpose()?,
            "is_prototype_guessed" => self
                .is_prototype_guessed
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "keep_in_slice" => self
                .keep_in_slice
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "orig_ins_addr" => self
                .orig_ins_addr
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "reg_name" => self
                .reg_name
                .as_ref()
                .map(|v| v.clone().into_bound_py_any(py))
                .transpose()?,
            "uninitialized" => self
                .uninitialized
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "vex_block_addr" => self
                .vex_block_addr
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "vex_stmt_idx" => self
                .vex_stmt_idx
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            "write_size" => self
                .write_size
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            other => match self.extras.get(other) {
                None => None,
                Some(v) => Some(match v {
                    TagExtra::Bool(b) => b.into_bound_py_any(py)?,
                    TagExtra::Int(i) => i.into_bound_py_any(py)?,
                    TagExtra::Float(f) => f.into_bound_py_any(py)?,
                    TagExtra::Str(s) => s.clone().into_bound_py_any(py)?,
                    TagExtra::IntList(l) => l.clone().into_bound_py_any(py)?,
                    TagExtra::StrList(l) => l.clone().into_bound_py_any(py)?,
                    TagExtra::Opaque(o) => o.bind(py).clone(),
                }),
            },
        })
    }

    pub fn set_from_py(&mut self, key: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        if value.is_none() {
            self.clear(key);
            return Ok(());
        }
        if let Some(kind) = kind_of(key) {
            match kind {
                TagValueKind::Bool => self.set_bool(key, value.extract()?),
                TagValueKind::Int => self.set_int(key, value.extract()?),
                TagValueKind::Str => self.set_str(key, value.extract()?),
                TagValueKind::IntList => self.set_int_list(key, value.extract()?),
            }
            return Ok(());
        }
        // Unknown key -- accept any primitive value into `extras`. Non-primitive
        // values fall back to `Opaque` (held but not serialized).
        let extra = if let Ok(b) = value.extract::<bool>() {
            TagExtra::Bool(b)
        } else if let Ok(i) = value.extract::<i64>() {
            TagExtra::Int(i)
        } else if let Ok(f) = value.extract::<f64>() {
            TagExtra::Float(f)
        } else if let Ok(s) = value.extract::<String>() {
            TagExtra::Str(s)
        } else if let Ok(v) = value.extract::<Vec<i64>>() {
            TagExtra::IntList(v)
        } else if let Ok(v) = value.extract::<Vec<String>>() {
            TagExtra::StrList(v)
        } else {
            TagExtra::Opaque(value.clone().unbind())
        };
        self.extras.insert(key.to_string(), extra);
        Ok(())
    }

    pub fn clear(&mut self, key: &str) {
        match key {
            "always_propagate" => self.always_propagate = None,
            "block_idx" => self.block_idx = None,
            "deref_src_addr" => self.deref_src_addr = None,
            "extra_def" => self.extra_def = None,
            "extra_defs" => self.extra_defs = None,
            "ins_addr" => self.ins_addr = None,
            "is_prototype_guessed" => self.is_prototype_guessed = None,
            "keep_in_slice" => self.keep_in_slice = None,
            "orig_ins_addr" => self.orig_ins_addr = None,
            "reg_name" => self.reg_name = None,
            "uninitialized" => self.uninitialized = None,
            "vex_block_addr" => self.vex_block_addr = None,
            "vex_stmt_idx" => self.vex_stmt_idx = None,
            "write_size" => self.write_size = None,
            other => {
                self.extras.remove(other);
            }
        }
    }

    fn set_bool(&mut self, key: &str, v: bool) {
        match key {
            "always_propagate" => self.always_propagate = Some(v),
            "extra_def" => self.extra_def = Some(v),
            "is_prototype_guessed" => self.is_prototype_guessed = Some(v),
            "keep_in_slice" => self.keep_in_slice = Some(v),
            "uninitialized" => self.uninitialized = Some(v),
            _ => {}
        }
    }

    fn set_int(&mut self, key: &str, v: i64) {
        match key {
            "block_idx" => self.block_idx = Some(v),
            "deref_src_addr" => self.deref_src_addr = Some(v),
            "ins_addr" => self.ins_addr = Some(v),
            "orig_ins_addr" => self.orig_ins_addr = Some(v),
            "vex_block_addr" => self.vex_block_addr = Some(v),
            "vex_stmt_idx" => self.vex_stmt_idx = Some(v),
            "write_size" => self.write_size = Some(v),
            _ => {}
        }
    }

    fn set_str(&mut self, key: &str, v: String) {
        match key {
            "reg_name" => self.reg_name = Some(v),
            _ => {}
        }
    }

    fn set_int_list(&mut self, key: &str, v: Vec<i64>) {
        if key == "extra_defs" {
            self.extra_defs = Some(v)
        }
    }

    pub fn to_py_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for k in TAG_KEYS {
            if let Some(v) = self.get_py(py, k)? {
                d.set_item(k, v)?;
            }
        }
        for k in self.extras.keys() {
            if let Some(v) = self.get_py(py, k)? {
                d.set_item(k.as_str(), v)?;
            }
        }
        Ok(d)
    }

    /// Build a Tags from a HashMap<String, Py<PyAny>>. Used by serde paths
    /// that round-trip through plain dicts.
    pub fn from_pymap(py: Python<'_>, map: &HashMap<String, Py<PyAny>>) -> PyResult<Self> {
        let mut tags = Self::default();
        for (k, v) in map {
            tags.set_from_py(k, v.bind(py))?;
        }
        Ok(tags)
    }
}

impl<'py> FromPyObject<'_, 'py> for Tags {
    type Error = PyErr;

    fn extract(obj: Borrowed<'_, 'py, PyAny>) -> Result<Self, Self::Error> {
        if obj.is_none() {
            return Ok(Self::default());
        }
        if let Ok(view) = obj.extract::<TagsView>() {
            return Ok(view.inner);
        }
        if let Ok(d) = obj.cast::<PyDict>() {
            return Self::from_dict(Some(&d.to_owned()));
        }
        if let Ok(m) = obj.cast::<PyMapping>() {
            let mut tags = Self::default();
            let keys = m.keys()?;
            for k in keys.try_iter()? {
                let k = k?;
                let key: String = k.extract()?;
                let v = m.get_item(&k)?;
                tags.set_from_py(&key, &v)?;
            }
            return Ok(tags);
        }
        Err(PyTypeError::new_err(format!(
            "tags must be a mapping, got {}",
            obj.get_type().name()?,
        )))
    }
}

/// Python-facing view over a `Tags` struct. Exposed via the `.tags`
/// attribute on `Expression` / `Statement` / `Block`. Behaves like a dict:
/// supports `tags[k]`, `tags.get(k)`, `tags[k] = v`, `del tags[k]`,
/// `tags.items()`, `k in tags`, `iter(tags)`, `len(tags)`, `**tags`, and
/// equality.
///
/// When constructed with a ``parent`` back-reference (the owning AIL
/// object), mutations on the view are written back to the parent's `.tags`
/// attribute -- so ``expr.tags["foo"] = bar`` actually persists.
#[pyclass(name = "Tags", module = "angr.rustylib.ailment", from_py_object)]
#[derive(Default, Debug)]
pub struct TagsView {
    inner: Tags,
    /// Owning AIL object. When set, mutations call back through the parent's
    /// `tags` setter so updates persist on the original instance.
    parent: Option<Py<PyAny>>,
}

impl Clone for TagsView {
    fn clone(&self) -> Self {
        Python::attach(|py| Self {
            inner: self.inner.clone(),
            parent: self.parent.as_ref().map(|p| p.clone_ref(py)),
        })
    }
}

impl TagsView {
    pub fn new(tags: Tags) -> Self {
        Self {
            inner: tags,
            parent: None,
        }
    }
    pub fn with_parent(tags: Tags, parent: Py<PyAny>) -> Self {
        Self {
            inner: tags,
            parent: Some(parent),
        }
    }
    pub fn take(self) -> Tags {
        self.inner
    }
    pub fn inner(&self) -> &Tags {
        &self.inner
    }

    /// Push the local Tags state back to the parent (if any).
    fn flush_to_parent(&self, py: Python<'_>) -> PyResult<()> {
        if let Some(parent) = &self.parent {
            // Build a fresh TagsView holding the current state (without a
            // back-reference to avoid infinite recursion).
            let snapshot = TagsView {
                inner: self.inner.clone(),
                parent: None,
            };
            parent
                .bind(py)
                .setattr("tags", snapshot.into_pyobject(py)?)?;
        }
        Ok(())
    }
}

#[pymethods]
impl TagsView {
    #[new]
    #[pyo3(signature = (mapping=None))]
    fn new_py(mapping: Option<Bound<'_, PyAny>>) -> PyResult<Self> {
        Ok(Self {
            inner: Tags::from_mapping(mapping.as_ref())?,
            parent: None,
        })
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __bool__(&self) -> bool {
        !self.inner.is_empty()
    }

    fn __contains__(&self, key: &str) -> bool {
        self.inner.has(key)
    }

    fn __getitem__<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Bound<'py, PyAny>> {
        match self.inner.get_py(py, key)? {
            Some(v) => Ok(v),
            None => Err(PyKeyError::new_err(key.to_string())),
        }
    }

    #[pyo3(signature = (key, default=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        if let Some(v) = self.inner.get_py(py, key)? {
            return Ok(Some(v));
        }
        Ok(default)
    }

    fn __setitem__(&mut self, py: Python<'_>, key: &str, value: Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.set_from_py(key, &value)?;
        self.flush_to_parent(py)
    }

    fn __delitem__(&mut self, py: Python<'_>, key: &str) -> PyResult<()> {
        if !self.inner.has(key) {
            return Err(PyKeyError::new_err(key.to_string()));
        }
        self.inner.clear(key);
        self.flush_to_parent(py)
    }

    fn keys<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        PyList::new(py, self.inner.keys()).expect("keys list")
    }

    fn values<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for k in self.inner.keys() {
            if let Some(v) = self.inner.get_py(py, &k)? {
                list.append(v)?;
            }
        }
        Ok(list)
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for k in self.inner.keys() {
            if let Some(v) = self.inner.get_py(py, &k)? {
                let tup = PyTuple::new(py, [k.into_bound_py_any(py)?, v])?;
                list.append(tup)?;
            }
        }
        Ok(list)
    }

    fn __iter__(slf: PyRef<'_, Self>, py: Python<'_>) -> PyResult<Py<TagsKeyIter>> {
        Py::new(
            py,
            TagsKeyIter {
                keys: slf.inner.keys(),
                index: 0,
            },
        )
    }

    fn update(&mut self, py: Python<'_>, other: Bound<'_, PyAny>) -> PyResult<()> {
        let merged = Tags::from_mapping(Some(&other))?;
        for k in merged.keys() {
            // Re-extract through the dynamic Python path so we cleanly
            // overwrite the existing value (and so this works even when
            // 'other' is a dict whose values are typed differently).
            let v = merged.get_py(py, &k)?;
            if let Some(v) = v {
                self.inner.set_from_py(&k, &v)?;
            }
        }
        self.flush_to_parent(py)
    }

    fn copy(&self) -> Self {
        // Copies detach from the parent -- mutating the copy must NOT
        // ripple back to the original.
        Self {
            inner: self.inner.clone(),
            parent: None,
        }
    }

    #[pyo3(signature = (key, default=None))]
    fn pop<'py>(
        &mut self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        if self.inner.has(key) {
            let v = self.inner.get_py(py, key)?;
            self.inner.clear(key);
            self.flush_to_parent(py)?;
            return Ok(v);
        }
        Ok(default)
    }

    fn setdefault<'py>(
        &mut self,
        py: Python<'py>,
        key: &str,
        default: Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(v) = self.inner.get_py(py, key)? {
            return Ok(v);
        }
        self.inner.set_from_py(key, &default)?;
        self.flush_to_parent(py)?;
        Ok(default)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let d = self.inner.to_py_dict(py)?;
        Ok(d.repr()?.to_string())
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        if let Ok(other_view) = other.extract::<TagsView>() {
            return Ok(self.inner == other_view.inner);
        }
        if let Ok(other_tags) = other.extract::<Tags>() {
            return Ok(self.inner == other_tags);
        }
        Ok(false)
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        self.inner.to_py_dict(py)
    }

    /// Implement ``tags | other`` -- returns a new ``TagsView`` whose state is
    /// the merge of ``self`` and ``other``, with ``other`` winning on conflicts.
    fn __or__<'py>(&self, py: Python<'py>, other: Bound<'py, PyAny>) -> PyResult<Self> {
        let mut merged = self.inner.clone();
        let extra = Tags::from_mapping(Some(&other))?;
        for k in extra.keys() {
            if let Some(v) = extra.get_py(py, &k)? {
                merged.set_from_py(&k, &v)?;
            }
        }
        Ok(Self {
            inner: merged,
            parent: None,
        })
    }

    fn __ror__<'py>(&self, py: Python<'py>, other: Bound<'py, PyAny>) -> PyResult<Self> {
        let mut merged = Tags::from_mapping(Some(&other))?;
        for k in self.inner.keys() {
            if let Some(v) = self.inner.get_py(py, &k)? {
                merged.set_from_py(&k, &v)?;
            }
        }
        Ok(Self {
            inner: merged,
            parent: None,
        })
    }

    /// `dict(tags)` works by iterating items; provide a fast path returning
    /// the underlying dict.
    fn __dict_repr__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        self.inner.to_py_dict(py)
    }

    // Pickle helpers so TagsView round-trips with pickle.
    fn __reduce__<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        let state = slf.borrow().inner.to_py_dict(py)?;
        let cls = slf.get_type();
        let args = PyTuple::new(py, [state.into_bound_py_any(py)?])?;
        PyTuple::new(
            py,
            [cls.into_bound_py_any(py)?, args.into_bound_py_any(py)?],
        )
    }
}

#[pyclass(module = "angr.rustylib.ailment", unsendable)]
pub struct TagsKeyIter {
    keys: Vec<String>,
    index: usize,
}

#[pymethods]
impl TagsKeyIter {
    fn __iter__(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>) -> PyResult<String> {
        if slf.index >= slf.keys.len() {
            return Err(PyStopIteration::new_err(()));
        }
        let i = slf.index;
        slf.index += 1;
        Ok(slf.keys[i].clone())
    }
}
