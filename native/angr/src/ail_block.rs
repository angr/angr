// AIL Block

use pyo3::prelude::*;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use crate::ail_stmt::Statement;

// ============================================================================
// BLOCK CLASS
// ============================================================================

#[pyclass]
#[derive(Clone)]
pub struct Block {
    #[pyo3(get)]
    pub addr: i64,
    #[pyo3(get)]
    pub idx: Option<i32>,
    #[pyo3(get)]
    pub original_size: i32,
    statements_inner: Vec<Statement>,
    hash_cache: Option<u64>,
}

#[pymethods]
impl Block {
    #[new]
    #[pyo3(signature = (addr, original_size, statements=None, idx=None))]
    fn new(
        addr: i64,
        original_size: i32,
        statements: Option<Vec<Statement>>,
        idx: Option<i32>,
    ) -> PyResult<Self> {
        Ok(Block {
            addr,
            idx,
            original_size,
            statements_inner: statements.unwrap_or_default(),
            hash_cache: None,
        })
    }

    #[getter]
    fn statements(&self) -> Vec<Statement> {
        self.statements_inner.clone()
    }

    #[setter]
    fn set_statements(&mut self, statements: Vec<Statement>) {
        self.statements_inner = statements;
        self.hash_cache = None;  // Invalidate cache
    }

    #[getter]
    fn sort_key(&self) -> (i64, i32, i32) {
        // Returns (addr, idx_priority, idx_value) for ordering
        // idx_priority: 0 if idx is Some, 1 if idx is None (so blocks with idx come first)
        match self.idx {
            Some(i) => (self.addr, 0, i),
            None => (self.addr, 1, 0),
        }
    }

    #[pyo3(signature = (statements=None))]
    fn copy(&self, statements: Option<Vec<Statement>>) -> Self {
        Block {
            addr: self.addr,
            idx: self.idx,
            original_size: self.original_size,
            statements_inner: statements.unwrap_or_else(|| self.statements_inner.clone()),
            hash_cache: None,
        }
    }

    fn clear_hash(&mut self) {
        self.hash_cache = None;
    }

    pub fn likes(&self, other: &Self) -> bool {
        if self.addr != other.addr {
            return false;
        }
        if self.statements_inner.len() != other.statements_inner.len() {
            return false;
        }
        self.statements_inner.iter()
            .zip(other.statements_inner.iter())
            .all(|(a, b)| a.likes(b))
    }

    pub fn __repr__(&self) -> String {
        match self.idx {
            Some(i) => format!("Block(addr={:#x}, idx={}, {} stmts)", self.addr, i, self.statements_inner.len()),
            None => format!("Block(addr={:#x}, {} stmts)", self.addr, self.statements_inner.len()),
        }
    }

    fn __str__(&self) -> String {
        let stmts_str = self.statements_inner.iter()
            .map(|s| format!("  {}", s.__repr__()))
            .collect::<Vec<_>>()
            .join("\n");
        format!("Block @ {:#x}:\n{}", self.addr, stmts_str)
    }

    fn __hash__(&self) -> u64 {
        if let Some(h) = self.hash_cache {
            return h;
        }
        let mut hasher = DefaultHasher::new();
        "Block".hash(&mut hasher);
        self.addr.hash(&mut hasher);
        self.idx.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.addr == other.addr && self.idx == other.idx && self.likes(other)
    }

    fn __lt__(&self, other: &Self) -> bool {
        self.sort_key() < other.sort_key()
    }

    fn __len__(&self) -> usize {
        self.statements_inner.len()
    }
}
