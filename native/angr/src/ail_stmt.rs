// AIL Statements

use pyo3::prelude::*;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::Arc;
use std::collections::HashMap;

use crate::ail_expr::Expression;
use crate::ail_tags::{Tags, TagValue};

/// Helper function to extract tags from Python kwargs.
fn extract_tags(kwargs: Option<&Bound<'_, pyo3::types::PyDict>>) -> PyResult<Tags> {
    let mut tags = Tags::new();
    if let Some(dict) = kwargs {
        for (key, value) in dict.iter() {
            let key_str = key.extract::<String>()?;
            let tag_value = if let Ok(i) = value.extract::<i64>() {
                TagValue::Int(i)
            } else if let Ok(s) = value.extract::<String>() {
                TagValue::Str(s)
            } else {
                return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                    format!("Tag value for '{}' must be int or str", key_str)
                ));
            };
            tags.insert(key_str, tag_value);
        }
    }
    Ok(tags)
}

// Assignment statement class
#[pyclass]
#[derive(Clone)]
pub struct Assignment {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub dst: Arc<Expression>,
    pub src: Arc<Expression>,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl Assignment {
    #[new]
    #[pyo3(signature = (idx, dst, src, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        dst: Expression,
        src: Expression,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(Assignment {
            idx,
            dst: Arc::new(dst),
            src: Arc::new(src),
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn dst(&self) -> Expression {
        (*self.dst).clone()
    }

    #[getter]
    fn src(&self) -> Expression {
        (*self.src).clone()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.dst.likes(&other.dst) && self.src.likes(&other.src)
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.dst.matches(&other.dst) && self.src.matches(&other.src)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!("{} = {}", self.dst.__repr__(), self.src.__repr__())
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Assignment".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Assignment {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r_dst, replaced_dst) = if self.dst.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.dst.replace(old_expr, new_expr)
        };

        let (r_src, replaced_src) = if self.src.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.src.replace(old_expr, new_expr)
        };

        if r_dst || r_src {
            (true, Assignment {
                idx: self.idx,
                dst: Arc::new(replaced_dst),
                src: Arc::new(replaced_src),
                ins_addr: self.ins_addr,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// WeakAssignment statement class (non-destructive assignment)
#[pyclass]
#[derive(Clone)]
pub struct WeakAssignment {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub dst: Arc<Expression>,
    pub src: Arc<Expression>,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl WeakAssignment {
    #[new]
    #[pyo3(signature = (idx, dst, src, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        dst: Expression,
        src: Expression,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(WeakAssignment {
            idx,
            dst: Arc::new(dst),
            src: Arc::new(src),
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn dst(&self) -> Expression {
        (*self.dst).clone()
    }

    #[getter]
    fn src(&self) -> Expression {
        (*self.src).clone()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.dst.likes(&other.dst) && self.src.likes(&other.src)
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.dst.matches(&other.dst) && self.src.matches(&other.src)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!("{} =W {}", self.dst.__repr__(), self.src.__repr__())
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "WeakAssignment".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl WeakAssignment {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r_dst, replaced_dst) = if self.dst.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.dst.replace(old_expr, new_expr)
        };

        let (r_src, replaced_src) = if self.src.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.src.replace(old_expr, new_expr)
        };

        if r_dst || r_src {
            (true, WeakAssignment {
                idx: self.idx,
                dst: Arc::new(replaced_dst),
                src: Arc::new(replaced_src),
                ins_addr: self.ins_addr,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// Store statement class
#[pyclass]
#[derive(Clone)]
pub struct Store {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub addr: Arc<Expression>,
    pub data: Arc<Expression>,
    #[pyo3(get)]
    pub size: i32,
    #[pyo3(get)]
    pub endness: String,
    pub guard: Option<Arc<Expression>>,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl Store {
    #[new]
    #[pyo3(signature = (idx, addr, data, size, endness, guard=None, variable=None, offset=None, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        addr: Expression,
        data: Expression,
        size: i32,
        endness: String,
        guard: Option<Expression>,
        variable: Option<&Bound<'_, PyAny>>,
        offset: Option<&Bound<'_, PyAny>>,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let _ = (variable, offset);  // Suppress unused warnings
        let tags = extract_tags(kwargs)?;
        Ok(Store {
            idx,
            addr: Arc::new(addr),
            data: Arc::new(data),
            size,
            endness,
            guard: guard.map(Arc::new),
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn addr(&self) -> Expression {
        (*self.addr).clone()
    }

    #[getter]
    fn data(&self) -> Expression {
        (*self.data).clone()
    }

    #[getter]
    fn guard(&self) -> Option<Expression> {
        self.guard.as_ref().map(|g| (**g).clone())
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.addr.likes(&other.addr)
            && self.data.likes(&other.data)
            && self.size == other.size
            && self.endness == other.endness
            && match (&self.guard, &other.guard) {
                (None, None) => true,
                (Some(g1), Some(g2)) => g1.likes(g2),
                _ => false,
            }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.addr.matches(&other.addr)
            && self.data.matches(&other.data)
            && self.size == other.size
            && self.endness == other.endness
            && match (&self.guard, &other.guard) {
                (None, None) => true,
                (Some(g1), Some(g2)) => g1.matches(g2),
                _ => false,
            }
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!(
            "Store(addr={}, data={}, size={}, endness={})",
            self.addr.__repr__(),
            self.data.__repr__(),
            self.size,
            self.endness
        )
    }

    fn __str__(&self) -> String {
        format!("*({}) = {}", self.addr.__repr__(), self.data.__repr__())
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Store".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        self.size.hash(&mut hasher);
        self.endness.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Store {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r_addr, replaced_addr) = if self.addr.__eq__(old_expr) {
            (true, new_expr.clone())
        } else {
            self.addr.replace(old_expr, new_expr)
        };

        let (r_data, replaced_data) = if self.data.__eq__(old_expr) {
            (true, new_expr.clone())
        } else {
            self.data.replace(old_expr, new_expr)
        };

        let (r_guard, replaced_guard) = if let Some(ref g) = self.guard {
            if g.__eq__(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = g.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        if r_addr || r_data || r_guard {
            (true, Store {
                idx: self.idx,
                addr: Arc::new(replaced_addr),
                data: Arc::new(replaced_data),
                size: self.size,
                endness: self.endness.clone(),
                guard: replaced_guard.or_else(|| self.guard.clone()),
                ins_addr: self.ins_addr,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// Jump statement class
#[pyclass]
#[derive(Clone)]
pub struct Jump {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub target: Arc<Expression>,
    #[pyo3(get)]
    pub target_idx: Option<i32>,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl Jump {
    #[new]
    #[pyo3(signature = (idx, target, target_idx=None, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        target: Expression,
        target_idx: Option<i32>,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(Jump {
            idx,
            target: Arc::new(target),
            target_idx,
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn target(&self) -> Expression {
        (*self.target).clone()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.target.likes(&other.target) && self.target_idx == other.target_idx
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.target.matches(&other.target)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        if let Some(idx) = self.target_idx {
            format!("Jump(target={}, target_idx={})", self.target.__repr__(), idx)
        } else {
            format!("Jump(target={})", self.target.__repr__())
        }
    }

    fn __str__(&self) -> String {
        format!("goto {}", self.target.__repr__())
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Jump".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        self.target_idx.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Jump {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r, replaced_target) = if self.target.__eq__(old_expr) {
            (true, new_expr.clone())
        } else {
            self.target.replace(old_expr, new_expr)
        };

        if r {
            (true, Jump {
                idx: self.idx,
                target: Arc::new(replaced_target),
                target_idx: self.target_idx,
                ins_addr: self.ins_addr,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// ConditionalJump statement class
#[pyclass]
#[derive(Clone)]
pub struct ConditionalJump {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub condition: Arc<Expression>,
    pub true_target: Option<Arc<Expression>>,
    pub false_target: Option<Arc<Expression>>,
    #[pyo3(get)]
    pub true_target_idx: Option<i32>,
    #[pyo3(get)]
    pub false_target_idx: Option<i32>,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl ConditionalJump {
    #[new]
    #[pyo3(signature = (idx, condition, true_target, false_target, true_target_idx=None, false_target_idx=None, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        condition: Expression,
        true_target: Option<Expression>,
        false_target: Option<Expression>,
        true_target_idx: Option<i32>,
        false_target_idx: Option<i32>,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(ConditionalJump {
            idx,
            condition: Arc::new(condition),
            true_target: true_target.map(Arc::new),
            false_target: false_target.map(Arc::new),
            true_target_idx,
            false_target_idx,
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn condition(&self) -> Expression {
        (*self.condition).clone()
    }

    #[getter]
    fn true_target(&self) -> Option<Expression> {
        self.true_target.as_ref().map(|t| (**t).clone())
    }

    #[getter]
    fn false_target(&self) -> Option<Expression> {
        self.false_target.as_ref().map(|t| (**t).clone())
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, other: &Self) -> bool {
        if !self.condition.likes(&other.condition) {
            return false;
        }
        let true_match = match (&self.true_target, &other.true_target) {
            (None, None) => true,
            (Some(t1), Some(t2)) => t1.likes(t2),
            _ => false,
        };
        let false_match = match (&self.false_target, &other.false_target) {
            (None, None) => true,
            (Some(f1), Some(f2)) => f1.likes(f2),
            _ => false,
        };
        true_match && false_match
            && self.true_target_idx == other.true_target_idx
            && self.false_target_idx == other.false_target_idx
    }

    pub fn matches(&self, other: &Self) -> bool {
        if !self.condition.matches(&other.condition) {
            return false;
        }
        let true_match = match (&self.true_target, &other.true_target) {
            (None, None) => true,
            (Some(t1), Some(t2)) => t1.matches(t2),
            _ => false,
        };
        let false_match = match (&self.false_target, &other.false_target) {
            (None, None) => true,
            (Some(f1), Some(f2)) => f1.matches(f2),
            _ => false,
        };
        true_match && false_match
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        let true_str = self.true_target.as_ref()
            .map(|t| t.__repr__())
            .unwrap_or_else(|| "None".to_string());
        let false_str = self.false_target.as_ref()
            .map(|t| t.__repr__())
            .unwrap_or_else(|| "None".to_string());
        format!(
            "ConditionalJump(cond={}, true={}, false={})",
            self.condition.__repr__(),
            true_str,
            false_str
        )
    }

    fn __str__(&self) -> String {
        let true_str = self.true_target.as_ref()
            .map(|t| t.__repr__())
            .unwrap_or_else(|| "None".to_string());
        format!("if ({}) goto {}", self.condition.__repr__(), true_str)
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "ConditionalJump".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        self.true_target_idx.hash(&mut hasher);
        self.false_target_idx.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl ConditionalJump {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r_cond, replaced_cond) = if self.condition.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.condition.replace(old_expr, new_expr)
        };

        let (r_true, replaced_true) = if let Some(ref t) = self.true_target {
            if t.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = t.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        let (r_false, replaced_false) = if let Some(ref f) = self.false_target {
            if f.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = f.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        if r_cond || r_true || r_false {
            (true, ConditionalJump {
                idx: self.idx,
                condition: Arc::new(replaced_cond),
                true_target: replaced_true.or_else(|| self.true_target.clone()),
                false_target: replaced_false.or_else(|| self.false_target.clone()),
                true_target_idx: self.true_target_idx,
                false_target_idx: self.false_target_idx,
                ins_addr: self.ins_addr,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// Call statement class (also functions as an expression)
#[pyclass]
#[derive(Clone)]
pub struct Call {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub target: Arc<Expression>,
    #[pyo3(get)]
    pub calling_convention: Option<String>,
    #[pyo3(get)]
    pub prototype: Option<String>,
    pub args: Option<Vec<Arc<Expression>>>,
    pub ret_expr: Option<Arc<Expression>>,
    pub fp_ret_expr: Option<Arc<Expression>>,
    #[pyo3(get)]
    pub bits: Option<i32>,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl Call {
    #[new]
    #[pyo3(signature = (idx, target, calling_convention=None, prototype=None, args=None, ret_expr=None, fp_ret_expr=None, bits=None, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        target: Expression,
        calling_convention: Option<String>,
        prototype: Option<String>,
        args: Option<Vec<Expression>>,
        ret_expr: Option<Expression>,
        fp_ret_expr: Option<Expression>,
        bits: Option<i32>,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(Call {
            idx,
            target: Arc::new(target),
            calling_convention,
            prototype,
            args: args.map(|a| a.into_iter().map(Arc::new).collect()),
            ret_expr: ret_expr.map(Arc::new),
            fp_ret_expr: fp_ret_expr.map(Arc::new),
            bits,
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn target(&self) -> Expression {
        (*self.target).clone()
    }

    #[getter]
    fn args(&self) -> Option<Vec<Expression>> {
        self.args.as_ref().map(|a| a.iter().map(|x| (**x).clone()).collect())
    }

    #[getter]
    fn ret_expr(&self) -> Option<Expression> {
        self.ret_expr.as_ref().map(|r| (**r).clone())
    }

    #[getter]
    fn fp_ret_expr(&self) -> Option<Expression> {
        self.fp_ret_expr.as_ref().map(|r| (**r).clone())
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn size(&self) -> Option<i32> {
        self.bits.map(|b| b / 8)
    }

    #[getter]
    fn op(&self) -> String {
        "Call".to_string()
    }

    #[getter]
    fn verbose_op(&self) -> String {
        "Call".to_string()
    }

    pub fn likes(&self, other: &Self) -> bool {
        if !self.target.likes(&other.target) {
            return false;
        }
        let args_match = match (&self.args, &other.args) {
            (None, None) => true,
            (Some(a1), Some(a2)) => {
                a1.len() == a2.len() && a1.iter().zip(a2.iter()).all(|(x, y)| x.likes(y))
            }
            _ => false,
        };
        let ret_match = match (&self.ret_expr, &other.ret_expr) {
            (None, None) => true,
            (Some(r1), Some(r2)) => r1.likes(r2),
            _ => false,
        };
        args_match && ret_match
    }

    pub fn matches(&self, other: &Self) -> bool {
        if !self.target.matches(&other.target) {
            return false;
        }
        let args_match = match (&self.args, &other.args) {
            (None, None) => true,
            (Some(a1), Some(a2)) => {
                a1.len() == a2.len() && a1.iter().zip(a2.iter()).all(|(x, y)| x.matches(y))
            }
            _ => false,
        };
        args_match
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        let args_str = self.args.as_ref()
            .map(|a| a.iter().map(|x| x.__repr__()).collect::<Vec<_>>().join(", "))
            .unwrap_or_else(|| "".to_string());
        format!("Call(target={}, args=[{}])", self.target.__repr__(), args_str)
    }

    fn __str__(&self) -> String {
        let args_str = self.args.as_ref()
            .map(|a| a.iter().map(|x| x.__repr__()).collect::<Vec<_>>().join(", "))
            .unwrap_or_else(|| "".to_string());
        format!("{}({})", self.target.__repr__(), args_str)
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Call".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        hasher.finish()
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Call {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let (r_target, replaced_target) = if self.target.likes(old_expr) {
            (true, new_expr.clone())
        } else {
            self.target.replace(old_expr, new_expr)
        };

        let (r_args, replaced_args) = if let Some(ref args) = self.args {
            let mut replaced = false;
            let new_args: Vec<Arc<Expression>> = args
                .iter()
                .map(|arg| {
                    if arg.likes(old_expr) {
                        replaced = true;
                        Arc::new(new_expr.clone())
                    } else {
                        let (r, new_arg) = arg.replace(old_expr, new_expr);
                        if r {
                            replaced = true;
                            Arc::new(new_arg)
                        } else {
                            arg.clone()
                        }
                    }
                })
                .collect();
            (replaced, Some(new_args))
        } else {
            (false, None)
        };

        let (r_ret, replaced_ret) = if let Some(ref ret) = self.ret_expr {
            if ret.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = ret.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        let (r_fp_ret, replaced_fp_ret) = if let Some(ref fp_ret) = self.fp_ret_expr {
            if fp_ret.likes(old_expr) {
                (true, Some(Arc::new(new_expr.clone())))
            } else {
                let (r, replaced) = fp_ret.replace(old_expr, new_expr);
                (r, Some(Arc::new(replaced)))
            }
        } else {
            (false, None)
        };

        if r_target || r_args || r_ret || r_fp_ret {
            (true, Call {
                idx: self.idx,
                target: Arc::new(replaced_target),
                calling_convention: self.calling_convention.clone(),
                prototype: self.prototype.clone(),
                args: replaced_args.or_else(|| self.args.clone()),
                ret_expr: replaced_ret.or_else(|| self.ret_expr.clone()),
                fp_ret_expr: replaced_fp_ret.or_else(|| self.fp_ret_expr.clone()),
                bits: self.bits,
                ins_addr: self.ins_addr,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// Return statement class
#[pyclass]
#[derive(Clone)]
pub struct Return {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub ret_exprs: Vec<Arc<Expression>>,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl Return {
    #[new]
    #[pyo3(signature = (idx, ret_exprs=None, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        ret_exprs: Option<Vec<Expression>>,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(Return {
            idx,
            ret_exprs: ret_exprs
                .unwrap_or_default()
                .into_iter()
                .map(Arc::new)
                .collect(),
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn ret_exprs(&self) -> Vec<Expression> {
        self.ret_exprs.iter().map(|r| (**r).clone()).collect()
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.ret_exprs.len() == other.ret_exprs.len()
            && self.ret_exprs.iter().zip(other.ret_exprs.iter())
                .all(|(a, b)| a.likes(b))
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.ret_exprs.len() == other.ret_exprs.len()
            && self.ret_exprs.iter().zip(other.ret_exprs.iter())
                .all(|(a, b)| a.matches(b))
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        let exprs_str = self.ret_exprs.iter()
            .map(|r| r.__repr__())
            .collect::<Vec<_>>()
            .join(", ");
        format!("Return([{}])", exprs_str)
    }

    fn __str__(&self) -> String {
        if self.ret_exprs.is_empty() {
            "return".to_string()
        } else {
            let exprs_str = self.ret_exprs.iter()
                .map(|r| r.__repr__())
                .collect::<Vec<_>>()
                .join(", ");
            format!("return {}", exprs_str)
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Return".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl Return {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        let mut replaced = false;
        let new_ret_exprs: Vec<Arc<Expression>> = self.ret_exprs
            .iter()
            .map(|expr| {
                if expr.likes(old_expr) {
                    replaced = true;
                    Arc::new(new_expr.clone())
                } else {
                    let (r, new_expr_val) = expr.replace(old_expr, new_expr);
                    if r {
                        replaced = true;
                        Arc::new(new_expr_val)
                    } else {
                        expr.clone()
                    }
                }
            })
            .collect();

        if replaced {
            (true, Return {
                idx: self.idx,
                ret_exprs: new_ret_exprs,
                ins_addr: self.ins_addr,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// Label statement class
#[pyclass]
#[derive(Clone)]
pub struct Label {
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    #[pyo3(get)]
    pub block_idx: Option<i32>,
    pub tags: Tags,
}

#[pymethods]
impl Label {
    #[new]
    #[pyo3(signature = (idx, name, ins_addr=None, block_idx=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        name: String,
        ins_addr: Option<i64>,
        block_idx: Option<i32>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(Label {
            idx,
            name,
            ins_addr,
            block_idx,
            tags,
        })
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, _other: &Self) -> bool {
        // Labels match any other label (per Python implementation)
        true
    }

    pub fn matches(&self, _other: &Self) -> bool {
        true
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!("Label({})", self.name)
    }

    fn __str__(&self) -> String {
        format!("{}:", self.name)
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "Label".hash(&mut hasher);
        self.name.hash(&mut hasher);
        self.block_idx.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.name == other.name && self.block_idx == other.block_idx
    }

    /// Python-exposed replace method - Label has no expressions.
    #[pyo3(name = "replace")]
    fn py_replace(&self, _old_expr: Expression, _new_expr: Expression) -> (bool, Self) {
        (false, self.clone())
    }
}

// CAS (Compare-and-Swap) statement class
#[pyclass]
#[derive(Clone)]
pub struct CAS {
    #[pyo3(get)]
    pub idx: Option<i32>,
    pub addr: Arc<Expression>,
    pub data_lo: Arc<Expression>,
    pub data_hi: Option<Arc<Expression>>,
    pub expd_lo: Arc<Expression>,
    pub expd_hi: Option<Arc<Expression>>,
    pub old_lo: Arc<Expression>,
    pub old_hi: Option<Arc<Expression>>,
    #[pyo3(get)]
    pub endness: String,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl CAS {
    #[new]
    #[pyo3(signature = (idx, addr, data_lo, data_hi, expd_lo, expd_hi, old_lo, old_hi, endness, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        addr: Expression,
        data_lo: Expression,
        data_hi: Option<Expression>,
        expd_lo: Expression,
        expd_hi: Option<Expression>,
        old_lo: Expression,
        old_hi: Option<Expression>,
        endness: String,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(CAS {
            idx,
            addr: Arc::new(addr),
            data_lo: Arc::new(data_lo),
            data_hi: data_hi.map(Arc::new),
            expd_lo: Arc::new(expd_lo),
            expd_hi: expd_hi.map(Arc::new),
            old_lo: Arc::new(old_lo),
            old_hi: old_hi.map(Arc::new),
            endness,
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn addr(&self) -> Expression {
        (*self.addr).clone()
    }

    #[getter]
    fn data_lo(&self) -> Expression {
        (*self.data_lo).clone()
    }

    #[getter]
    fn data_hi(&self) -> Option<Expression> {
        self.data_hi.as_ref().map(|d| (**d).clone())
    }

    #[getter]
    fn expd_lo(&self) -> Expression {
        (*self.expd_lo).clone()
    }

    #[getter]
    fn expd_hi(&self) -> Option<Expression> {
        self.expd_hi.as_ref().map(|e| (**e).clone())
    }

    #[getter]
    fn old_lo(&self) -> Expression {
        (*self.old_lo).clone()
    }

    #[getter]
    fn old_hi(&self) -> Option<Expression> {
        self.old_hi.as_ref().map(|o| (**o).clone())
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    #[getter]
    fn bits(&self) -> i32 {
        match &self.old_hi {
            Some(hi) => self.old_lo.bits() + hi.bits(),
            None => self.old_lo.bits(),
        }
    }

    #[getter]
    fn size(&self) -> i32 {
        self.bits() / 8
    }

    pub fn likes(&self, other: &Self) -> bool {
        self.addr.likes(&other.addr)
            && self.data_lo.likes(&other.data_lo)
            && self.expd_lo.likes(&other.expd_lo)
            && self.old_lo.likes(&other.old_lo)
            && self.endness == other.endness
            && match (&self.data_hi, &other.data_hi) {
                (None, None) => true,
                (Some(a), Some(b)) => a.likes(b),
                _ => false,
            }
            && match (&self.expd_hi, &other.expd_hi) {
                (None, None) => true,
                (Some(a), Some(b)) => a.likes(b),
                _ => false,
            }
            && match (&self.old_hi, &other.old_hi) {
                (None, None) => true,
                (Some(a), Some(b)) => a.likes(b),
                _ => false,
            }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.addr.matches(&other.addr)
            && self.data_lo.matches(&other.data_lo)
            && self.expd_lo.matches(&other.expd_lo)
            && self.old_lo.matches(&other.old_lo)
            && self.endness == other.endness
            && match (&self.data_hi, &other.data_hi) {
                (None, None) => true,
                (Some(a), Some(b)) => a.matches(b),
                _ => false,
            }
            && match (&self.expd_hi, &other.expd_hi) {
                (None, None) => true,
                (Some(a), Some(b)) => a.matches(b),
                _ => false,
            }
            && match (&self.old_hi, &other.old_hi) {
                (None, None) => true,
                (Some(a), Some(b)) => a.matches(b),
                _ => false,
            }
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        format!(
            "CAS(addr={}, old={}, expd={}, data={}, endness={})",
            self.addr.__repr__(),
            self.old_lo.__repr__(),
            self.expd_lo.__repr__(),
            self.data_lo.__repr__(),
            self.endness
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "CAS".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        self.endness.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl CAS {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        // Helper to replace in an Arc<Expression>
        fn replace_arc(expr: &Arc<Expression>, old: &Expression, new: &Expression) -> (bool, Expression) {
            if expr.likes(old) {
                (true, new.clone())
            } else {
                expr.replace(old, new)
            }
        }

        // Helper to replace in Option<Arc<Expression>>
        fn replace_opt(opt: &Option<Arc<Expression>>, old: &Expression, new: &Expression) -> (bool, Option<Arc<Expression>>) {
            if let Some(e) = opt {
                if e.likes(old) {
                    (true, Some(Arc::new(new.clone())))
                } else {
                    let (r, replaced) = e.replace(old, new);
                    (r, Some(Arc::new(replaced)))
                }
            } else {
                (false, None)
            }
        }

        let (r_addr, new_addr) = replace_arc(&self.addr, old_expr, new_expr);
        let (r_data_lo, new_data_lo) = replace_arc(&self.data_lo, old_expr, new_expr);
        let (r_data_hi, new_data_hi) = replace_opt(&self.data_hi, old_expr, new_expr);
        let (r_expd_lo, new_expd_lo) = replace_arc(&self.expd_lo, old_expr, new_expr);
        let (r_expd_hi, new_expd_hi) = replace_opt(&self.expd_hi, old_expr, new_expr);
        let (r_old_lo, new_old_lo) = replace_arc(&self.old_lo, old_expr, new_expr);
        let (r_old_hi, new_old_hi) = replace_opt(&self.old_hi, old_expr, new_expr);

        if r_addr || r_data_lo || r_data_hi || r_expd_lo || r_expd_hi || r_old_lo || r_old_hi {
            (true, CAS {
                idx: self.idx,
                addr: Arc::new(new_addr),
                data_lo: Arc::new(new_data_lo),
                data_hi: new_data_hi.or_else(|| self.data_hi.clone()),
                expd_lo: Arc::new(new_expd_lo),
                expd_hi: new_expd_hi.or_else(|| self.expd_hi.clone()),
                old_lo: Arc::new(new_old_lo),
                old_hi: new_old_hi.or_else(|| self.old_hi.clone()),
                endness: self.endness.clone(),
                ins_addr: self.ins_addr,
                tags: self.tags.clone(),
            })
        } else {
            (false, self.clone())
        }
    }
}

// DirtyStatement class (wraps unconvertible statements)
#[pyclass]
#[derive(Clone)]
pub struct DirtyStatement {
    #[pyo3(get)]
    pub idx: Option<i32>,
    // Store dirty as a PyObject since DirtyExpression may not be converted yet
    // For now, we'll store it as an optional expression-like object
    pub dirty: Option<Arc<Expression>>,
    #[pyo3(get)]
    pub ins_addr: Option<i64>,
    pub tags: Tags,
}

#[pymethods]
impl DirtyStatement {
    #[new]
    #[pyo3(signature = (idx, dirty=None, ins_addr=None, **kwargs))]
    fn new(
        idx: Option<i32>,
        dirty: Option<Expression>,
        ins_addr: Option<i64>,
        kwargs: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        let tags = extract_tags(kwargs)?;
        Ok(DirtyStatement {
            idx,
            dirty: dirty.map(Arc::new),
            ins_addr,
            tags,
        })
    }

    #[getter]
    fn dirty(&self) -> Option<Expression> {
        self.dirty.as_ref().map(|d| (**d).clone())
    }

    #[getter]
    fn tags(&self) -> HashMap<String, TagValue> {
        self.tags.clone()
    }

    pub fn likes(&self, other: &Self) -> bool {
        match (&self.dirty, &other.dirty) {
            (None, None) => true,
            (Some(a), Some(b)) => a.likes(b),
            _ => false,
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        match (&self.dirty, &other.dirty) {
            (None, None) => true,
            (Some(a), Some(b)) => a.matches(b),
            _ => false,
        }
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    pub fn __repr__(&self) -> String {
        match &self.dirty {
            Some(d) => format!("DirtyStatement({})", d.__repr__()),
            None => "DirtyStatement(None)".to_string(),
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        "DirtyStatement".hash(&mut hasher);
        self.idx.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.idx == other.idx && self.likes(other)
    }

    /// Python-exposed replace method.
    #[pyo3(name = "replace")]
    fn py_replace(&self, old_expr: Expression, new_expr: Expression) -> (bool, Self) {
        self.replace(&old_expr, &new_expr)
    }
}

impl DirtyStatement {
    /// Replace old_expr with new_expr in this statement.
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Self) {
        if let Some(ref d) = self.dirty {
            if d.likes(old_expr) {
                (true, DirtyStatement {
                    idx: self.idx,
                    dirty: Some(Arc::new(new_expr.clone())),
                    ins_addr: self.ins_addr,
                    tags: self.tags.clone(),
                })
            } else {
                let (r, replaced) = d.replace(old_expr, new_expr);
                if r {
                    (true, DirtyStatement {
                        idx: self.idx,
                        dirty: Some(Arc::new(replaced)),
                        ins_addr: self.ins_addr,
                        tags: self.tags.clone(),
                    })
                } else {
                    (false, self.clone())
                }
            }
        } else {
            (false, self.clone())
        }
    }
}

#[derive(Clone)]
pub enum Statement {
    Assignment(Assignment),
    WeakAssignment(WeakAssignment),
    Store(Store),
    Jump(Jump),
    ConditionalJump(ConditionalJump),
    Call(Call),
    Return(Return),
    Label(Label),
    CAS(CAS),
    DirtyStatement(DirtyStatement),
}

// Implement automatic conversion from Python objects to Statement
impl<'py> FromPyObject<'_, 'py> for Statement {
    type Error = PyErr;

    fn extract(ob: Borrowed<'_, 'py, PyAny>) -> Result<Self, Self::Error> {
        if let Ok(a) = ob.extract::<Assignment>() {
            return Ok(Statement::Assignment(a));
        }
        if let Ok(wa) = ob.extract::<WeakAssignment>() {
            return Ok(Statement::WeakAssignment(wa));
        }
        if let Ok(s) = ob.extract::<Store>() {
            return Ok(Statement::Store(s));
        }
        if let Ok(j) = ob.extract::<Jump>() {
            return Ok(Statement::Jump(j));
        }
        if let Ok(cj) = ob.extract::<ConditionalJump>() {
            return Ok(Statement::ConditionalJump(cj));
        }
        if let Ok(c) = ob.extract::<Call>() {
            return Ok(Statement::Call(c));
        }
        if let Ok(r) = ob.extract::<Return>() {
            return Ok(Statement::Return(r));
        }
        if let Ok(l) = ob.extract::<Label>() {
            return Ok(Statement::Label(l));
        }
        if let Ok(cas) = ob.extract::<CAS>() {
            return Ok(Statement::CAS(cas));
        }
        if let Ok(ds) = ob.extract::<DirtyStatement>() {
            return Ok(Statement::DirtyStatement(ds));
        }

        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "Expected an AIL Statement type"
        ))
    }
}

// Implement conversion back to Python objects
impl<'py> IntoPyObject<'py> for Statement {
    type Target = PyAny;
    type Output = Bound<'py, Self::Target>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        match self {
            Statement::Assignment(a) => a.into_pyobject(py).map(|b| b.into_any()),
            Statement::WeakAssignment(wa) => wa.into_pyobject(py).map(|b| b.into_any()),
            Statement::Store(s) => s.into_pyobject(py).map(|b| b.into_any()),
            Statement::Jump(j) => j.into_pyobject(py).map(|b| b.into_any()),
            Statement::ConditionalJump(cj) => cj.into_pyobject(py).map(|b| b.into_any()),
            Statement::Call(c) => c.into_pyobject(py).map(|b| b.into_any()),
            Statement::Return(r) => r.into_pyobject(py).map(|b| b.into_any()),
            Statement::Label(l) => l.into_pyobject(py).map(|b| b.into_any()),
            Statement::CAS(cas) => cas.into_pyobject(py).map(|b| b.into_any()),
            Statement::DirtyStatement(ds) => ds.into_pyobject(py).map(|b| b.into_any()),
        }
    }
}

impl Statement {
    pub fn likes(&self, other: &Statement) -> bool {
        match (self, other) {
            (Statement::Assignment(a), Statement::Assignment(b)) => a.likes(b),
            (Statement::WeakAssignment(a), Statement::WeakAssignment(b)) => a.likes(b),
            (Statement::Store(a), Statement::Store(b)) => a.likes(b),
            (Statement::Jump(a), Statement::Jump(b)) => a.likes(b),
            (Statement::ConditionalJump(a), Statement::ConditionalJump(b)) => a.likes(b),
            (Statement::Call(a), Statement::Call(b)) => a.likes(b),
            (Statement::Return(a), Statement::Return(b)) => a.likes(b),
            (Statement::Label(a), Statement::Label(b)) => a.likes(b),
            (Statement::CAS(a), Statement::CAS(b)) => a.likes(b),
            (Statement::DirtyStatement(a), Statement::DirtyStatement(b)) => a.likes(b),
            _ => false,
        }
    }

    pub fn matches(&self, other: &Statement) -> bool {
        match (self, other) {
            (Statement::Assignment(a), Statement::Assignment(b)) => a.matches(b),
            (Statement::WeakAssignment(a), Statement::WeakAssignment(b)) => a.matches(b),
            (Statement::Store(a), Statement::Store(b)) => a.matches(b),
            (Statement::Jump(a), Statement::Jump(b)) => a.matches(b),
            (Statement::ConditionalJump(a), Statement::ConditionalJump(b)) => a.matches(b),
            (Statement::Call(a), Statement::Call(b)) => a.matches(b),
            (Statement::Return(a), Statement::Return(b)) => a.matches(b),
            (Statement::Label(a), Statement::Label(b)) => a.matches(b),
            (Statement::CAS(a), Statement::CAS(b)) => a.matches(b),
            (Statement::DirtyStatement(a), Statement::DirtyStatement(b)) => a.matches(b),
            _ => false,
        }
    }

    pub fn __eq__(&self, other: &Self) -> bool {
        match (self, other) {
            (Statement::Assignment(a), Statement::Assignment(b)) => a.__eq__(b),
            (Statement::WeakAssignment(a), Statement::WeakAssignment(b)) => a.__eq__(b),
            (Statement::Store(a), Statement::Store(b)) => a.__eq__(b),
            (Statement::Jump(a), Statement::Jump(b)) => a.__eq__(b),
            (Statement::ConditionalJump(a), Statement::ConditionalJump(b)) => a.__eq__(b),
            (Statement::Call(a), Statement::Call(b)) => a.__eq__(b),
            (Statement::Return(a), Statement::Return(b)) => a.__eq__(b),
            (Statement::Label(a), Statement::Label(b)) => a.__eq__(b),
            (Statement::CAS(a), Statement::CAS(b)) => a.__eq__(b),
            (Statement::DirtyStatement(a), Statement::DirtyStatement(b)) => a.__eq__(b),
            _ => false,
        }
    }

    pub fn __repr__(&self) -> String {
        match self {
            Statement::Assignment(a) => a.__repr__(),
            Statement::WeakAssignment(wa) => wa.__repr__(),
            Statement::Store(s) => s.__repr__(),
            Statement::Jump(j) => j.__repr__(),
            Statement::ConditionalJump(cj) => cj.__repr__(),
            Statement::Call(c) => c.__repr__(),
            Statement::Return(r) => r.__repr__(),
            Statement::Label(l) => l.__repr__(),
            Statement::CAS(cas) => cas.__repr__(),
            Statement::DirtyStatement(ds) => ds.__repr__(),
        }
    }

    /// Replace old_expr with new_expr in this statement.
    /// Returns (replaced: bool, new_statement: Statement)
    pub fn replace(&self, old_expr: &Expression, new_expr: &Expression) -> (bool, Statement) {
        match self {
            Statement::Assignment(a) => {
                let (r, replaced) = a.replace(old_expr, new_expr);
                (r, Statement::Assignment(replaced))
            }
            Statement::WeakAssignment(wa) => {
                let (r, replaced) = wa.replace(old_expr, new_expr);
                (r, Statement::WeakAssignment(replaced))
            }
            Statement::Store(s) => {
                let (r, replaced) = s.replace(old_expr, new_expr);
                (r, Statement::Store(replaced))
            }
            Statement::Jump(j) => {
                let (r, replaced) = j.replace(old_expr, new_expr);
                (r, Statement::Jump(replaced))
            }
            Statement::ConditionalJump(cj) => {
                let (r, replaced) = cj.replace(old_expr, new_expr);
                (r, Statement::ConditionalJump(replaced))
            }
            Statement::Call(c) => {
                let (r, replaced) = c.replace(old_expr, new_expr);
                (r, Statement::Call(replaced))
            }
            Statement::Return(r_stmt) => {
                let (r, replaced) = r_stmt.replace(old_expr, new_expr);
                (r, Statement::Return(replaced))
            }
            Statement::Label(_) => {
                // Label has no expressions to replace
                (false, self.clone())
            }
            Statement::CAS(cas) => {
                let (r, replaced) = cas.replace(old_expr, new_expr);
                (r, Statement::CAS(replaced))
            }
            Statement::DirtyStatement(ds) => {
                let (r, replaced) = ds.replace(old_expr, new_expr);
                (r, Statement::DirtyStatement(replaced))
            }
        }
    }
}