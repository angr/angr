//! Tags storage for AIL objects.
//!
//! In the Python implementation `TaggedObject.tags` is an open dict containing
//! a handful of well-known keys (see `TagDict` in
//! `angr/ailment/tagged_object.py`). The Rust implementation keeps only the
//! four *hot* keys -- `ins_addr`, `vex_block_addr`, `vex_stmt_idx`,
//! `block_idx` -- as dedicated struct fields (they are set on almost every
//! node) and delegates every other key to an `extras` map keyed by
//! [`TagKey`]. Sparse tags therefore cost four small `Option`s plus an empty
//! `HashMap` instead of a field per known key.
//!
//! Tag keys are represented as the [`TagKey`] enum. Python code addresses tags
//! by string; [`TagKey::from_key`] / [`TagKey::as_str`] form the string <->
//! enum compatibility layer, so `expr.tags["ins_addr"]` keeps working.
//!
//! The keys `reference_variable` and `reg_vvars`, which used to point to
//! Python objects, have been refactored:
//!   * `reference_variable: SimVariable`  ->  `reference_variable_ident: str`
//!   * `reg_vvars`                          ->  dedicated field on VirtualVariable
//!   * `reference_values` / `type`          ->  dropped entirely
//!
//! For backward compatibility, `Expression.tags` and `Statement.tags` are
//! still exposed to Python as a dict-like object. Reads and writes go through
//! `TagsView`, which translates names <-> struct fields / `extras` entries.

use std::collections::HashMap;

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyKeyError, PyStopIteration, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyMapping, PyTuple};
use pyo3::{Borrowed, Py, PyAny};
use serde::{Deserialize, Serialize};

/// Value stored in the `extras` bucket for cold / unknown tag keys.
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
        // Externally tagged (the serde default) to mirror the hand-written
        // ``Serialize`` impl above, which emits plain variant indices.
        // Internally/adjacently tagged enums require a self-describing
        // format and are rejected by postcard at deserialization time.
        #[derive(Deserialize)]
        enum Helper {
            Bool(bool),
            Int(i64),
            Float(f64),
            Str(String),
            IntList(Vec<i64>),
            StrList(Vec<String>),
            Opaque {},
        }
        let h: Helper = Deserialize::deserialize(de)?;
        Ok(match h {
            Helper::Bool(v) => TagExtra::Bool(v),
            Helper::Int(v) => TagExtra::Int(v),
            Helper::Float(v) => TagExtra::Float(v),
            Helper::Str(v) => TagExtra::Str(v),
            Helper::IntList(v) => TagExtra::IntList(v),
            Helper::StrList(v) => TagExtra::StrList(v),
            Helper::Opaque {} => TagExtra::Opaque(Python::attach(|py| py.None())),
        })
    }
}

/// A tag key. Known keys are enum variants; arbitrary Python string keys
/// become [`TagKey::Custom`]. The four *hot* variants are backed by dedicated
/// [`Tags`] struct fields and never appear in `extras`; the rest live in the
/// `extras` map.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TagKey {
    // Hot -- struct-backed.
    InsAddr,
    VexBlockAddr,
    VexStmtIdx,
    BlockIdx,
    // Cold -- stored in `extras`.
    AlwaysPropagate,
    DerefSrcAddr,
    ExtraDef,
    ExtraDefs,
    IsPrototypeGuessed,
    KeepInSlice,
    OrigInsAddr,
    RegName,
    Uninitialized,
    WriteSize,
    // Arbitrary Python string key.
    Custom(String),
}

/// Declared value type for a known key, used to enforce tag types on write.
#[derive(Debug, Clone, Copy)]
enum TagValueKind {
    Bool,
    Int,
    Str,
    IntList,
}

impl TagKey {
    /// String -> key (the Python-compatibility direction). Unknown names
    /// become [`TagKey::Custom`].
    pub fn from_key(key: &str) -> TagKey {
        match key {
            "ins_addr" => TagKey::InsAddr,
            "vex_block_addr" => TagKey::VexBlockAddr,
            "vex_stmt_idx" => TagKey::VexStmtIdx,
            "block_idx" => TagKey::BlockIdx,
            "always_propagate" => TagKey::AlwaysPropagate,
            "deref_src_addr" => TagKey::DerefSrcAddr,
            "extra_def" => TagKey::ExtraDef,
            "extra_defs" => TagKey::ExtraDefs,
            "is_prototype_guessed" => TagKey::IsPrototypeGuessed,
            "keep_in_slice" => TagKey::KeepInSlice,
            "orig_ins_addr" => TagKey::OrigInsAddr,
            "reg_name" => TagKey::RegName,
            "uninitialized" => TagKey::Uninitialized,
            "write_size" => TagKey::WriteSize,
            other => TagKey::Custom(other.to_string()),
        }
    }

    /// Key -> string (the reverse compatibility direction).
    pub fn as_str(&self) -> &str {
        match self {
            TagKey::InsAddr => "ins_addr",
            TagKey::VexBlockAddr => "vex_block_addr",
            TagKey::VexStmtIdx => "vex_stmt_idx",
            TagKey::BlockIdx => "block_idx",
            TagKey::AlwaysPropagate => "always_propagate",
            TagKey::DerefSrcAddr => "deref_src_addr",
            TagKey::ExtraDef => "extra_def",
            TagKey::ExtraDefs => "extra_defs",
            TagKey::IsPrototypeGuessed => "is_prototype_guessed",
            TagKey::KeepInSlice => "keep_in_slice",
            TagKey::OrigInsAddr => "orig_ins_addr",
            TagKey::RegName => "reg_name",
            TagKey::Uninitialized => "uninitialized",
            TagKey::WriteSize => "write_size",
            TagKey::Custom(s) => s.as_str(),
        }
    }

    /// Declared value type for a known cold key. Hot keys and `Custom` keys
    /// return `None` (hot keys are handled by their struct fields; custom keys
    /// accept any primitive).
    fn value_kind(&self) -> Option<TagValueKind> {
        Some(match self {
            TagKey::DerefSrcAddr | TagKey::OrigInsAddr | TagKey::WriteSize => TagValueKind::Int,
            TagKey::AlwaysPropagate
            | TagKey::ExtraDef
            | TagKey::IsPrototypeGuessed
            | TagKey::KeepInSlice
            | TagKey::Uninitialized => TagValueKind::Bool,
            TagKey::RegName => TagValueKind::Str,
            TagKey::ExtraDefs => TagValueKind::IntList,
            _ => return None,
        })
    }
}

/// Convert an arbitrary Python primitive into a [`TagExtra`]. Non-primitive
/// values fall back to `Opaque` (held but not serialized).
fn extra_from_py(value: &Bound<'_, PyAny>) -> TagExtra {
    if let Ok(b) = value.extract::<bool>() {
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
    }
}

/// Tags storage: the four hot keys as struct fields, everything else in
/// `extras`. See the module docs.
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tags {
    pub ins_addr: Option<i64>,
    pub vex_block_addr: Option<i64>,
    pub vex_stmt_idx: Option<i32>,
    pub block_idx: Option<i32>,
    /// Cold known keys and arbitrary custom keys, keyed by [`TagKey`]. Hot
    /// keys never appear here.
    pub extras: HashMap<TagKey, TagExtra>,
}

impl Tags {
    /// Build a Tags struct from a Python `**kwargs` dict.
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        let hot = self.ins_addr.is_some() as usize
            + self.vex_block_addr.is_some() as usize
            + self.vex_stmt_idx.is_some() as usize
            + self.block_idx.is_some() as usize;
        hot + self.extras.len()
    }

    pub fn keys(&self) -> Vec<String> {
        // Hot keys first (fixed order), then the extras map.
        let mut out: Vec<String> = Vec::with_capacity(self.len());
        if self.ins_addr.is_some() {
            out.push("ins_addr".to_string());
        }
        if self.vex_block_addr.is_some() {
            out.push("vex_block_addr".to_string());
        }
        if self.vex_stmt_idx.is_some() {
            out.push("vex_stmt_idx".to_string());
        }
        if self.block_idx.is_some() {
            out.push("block_idx".to_string());
        }
        for k in self.extras.keys() {
            out.push(k.as_str().to_string());
        }
        out
    }

    pub fn has(&self, key: &str) -> bool {
        match TagKey::from_key(key) {
            TagKey::InsAddr => self.ins_addr.is_some(),
            TagKey::VexBlockAddr => self.vex_block_addr.is_some(),
            TagKey::VexStmtIdx => self.vex_stmt_idx.is_some(),
            TagKey::BlockIdx => self.block_idx.is_some(),
            other => self.extras.contains_key(&other),
        }
    }

    pub fn get_py<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
        Ok(match TagKey::from_key(key) {
            TagKey::InsAddr => self.ins_addr.map(|v| v.into_bound_py_any(py)).transpose()?,
            TagKey::VexBlockAddr => self
                .vex_block_addr
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            TagKey::VexStmtIdx => self
                .vex_stmt_idx
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            TagKey::BlockIdx => self
                .block_idx
                .map(|v| v.into_bound_py_any(py))
                .transpose()?,
            other => match self.extras.get(&other) {
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
        let tk = TagKey::from_key(key);
        match tk {
            TagKey::InsAddr => self.ins_addr = Some(value.extract()?),
            TagKey::VexBlockAddr => self.vex_block_addr = Some(value.extract()?),
            TagKey::VexStmtIdx => self.vex_stmt_idx = Some(value.extract()?),
            TagKey::BlockIdx => self.block_idx = Some(value.extract()?),
            other => {
                // Known cold keys enforce their declared type; custom keys
                // accept any primitive (falling back to `Opaque`).
                let extra = match other.value_kind() {
                    Some(TagValueKind::Bool) => TagExtra::Bool(value.extract()?),
                    Some(TagValueKind::Int) => TagExtra::Int(value.extract()?),
                    Some(TagValueKind::Str) => TagExtra::Str(value.extract()?),
                    Some(TagValueKind::IntList) => TagExtra::IntList(value.extract()?),
                    None => extra_from_py(value),
                };
                self.extras.insert(other, extra);
            }
        }
        Ok(())
    }

    pub fn clear(&mut self, key: &str) {
        match TagKey::from_key(key) {
            TagKey::InsAddr => self.ins_addr = None,
            TagKey::VexBlockAddr => self.vex_block_addr = None,
            TagKey::VexStmtIdx => self.vex_stmt_idx = None,
            TagKey::BlockIdx => self.block_idx = None,
            other => {
                self.extras.remove(&other);
            }
        }
    }

    pub fn to_py_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for k in self.keys() {
            if let Some(v) = self.get_py(py, &k)? {
                d.set_item(k, v)?;
            }
        }
        Ok(d)
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
    fn new_py(mapping: Option<Tags>) -> PyResult<Self> {
        Ok(Self {
            inner: mapping.unwrap_or_default(),
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

    fn update(&mut self, py: Python<'_>, other: Tags) -> PyResult<()> {
        for k in other.keys() {
            // Re-extract through the dynamic Python path so we cleanly
            // overwrite the existing value (and so this works even when
            // 'other' is a dict whose values are typed differently).
            let v = other.get_py(py, &k)?;
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
    fn __or__(&self, py: Python<'_>, other: Tags) -> PyResult<Self> {
        let mut merged = self.inner.clone();
        for k in other.keys() {
            if let Some(v) = other.get_py(py, &k)? {
                merged.set_from_py(&k, &v)?;
            }
        }
        Ok(Self {
            inner: merged,
            parent: None,
        })
    }

    fn __ror__(&self, py: Python<'_>, mut other: Tags) -> PyResult<Self> {
        for k in self.inner.keys() {
            if let Some(v) = self.inner.get_py(py, &k)? {
                other.set_from_py(&k, &v)?;
            }
        }
        Ok(Self {
            inner: other,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagkey_string_round_trip() {
        for name in [
            "ins_addr",
            "vex_block_addr",
            "vex_stmt_idx",
            "block_idx",
            "always_propagate",
            "deref_src_addr",
            "extra_def",
            "extra_defs",
            "is_prototype_guessed",
            "keep_in_slice",
            "orig_ins_addr",
            "reg_name",
            "uninitialized",
            "write_size",
            "some_custom_key",
        ] {
            assert_eq!(TagKey::from_key(name).as_str(), name);
        }
    }

    #[test]
    fn custom_key_is_custom() {
        assert!(matches!(TagKey::from_key("nope"), TagKey::Custom(s) if s == "nope"));
        assert!(TagKey::from_key("nope").value_kind().is_none());
    }

    #[test]
    fn serde_round_trip_hot_cold_custom() {
        let mut t = Tags {
            ins_addr: Some(0x4000),
            vex_block_addr: Some(0x4008),
            vex_stmt_idx: Some(7),
            block_idx: Some(2),
            ..Default::default()
        };
        t.extras
            .insert(TagKey::RegName, TagExtra::Str("rax".into()));
        t.extras.insert(TagKey::Uninitialized, TagExtra::Bool(true));
        t.extras
            .insert(TagKey::Custom("mine".into()), TagExtra::Int(99));

        let bytes = postcard::to_allocvec(&t).unwrap();
        let back: Tags = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(t, back);
    }
}
