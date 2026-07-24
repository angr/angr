use ahash::AHasher;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    hash::{Hash, Hasher},
    sync::{Arc, RwLock},
};

use crate::{
    ast::op::AstOp,
    cache::{AstCache, Cache},
    prelude::*,
};

/// The hash a node is interned under: type, op (which folds in child hashes),
/// then annotations. Shared so construction and algorithms that need a node's
/// key without building it (e.g. `excavate_ite`) agree.
pub(crate) fn structural_hash(
    ast_type: AstType,
    op: &AstOp<'_>,
    annotations: &BTreeSet<Annotation>,
) -> u64 {
    let mut hasher = AHasher::default();
    ast_type.hash(&mut hasher);
    op.hash(&mut hasher);
    for a in annotations {
        a.hash(&mut hasher);
    }
    hasher.finish()
}

/// An interned string that can be cloned cheaply and compared by pointer equality.
/// This is backed by an Arc<str> so cloning only increments a reference count.
#[derive(Clone, Debug, Eq)]
pub struct InternedString(Arc<str>);

impl InternedString {
    /// Get the string contents
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for InternedString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for InternedString {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl PartialEq for InternedString {
    fn eq(&self, other: &Self) -> bool {
        // Fast pointer comparison first, fall back to content comparison
        // to satisfy the contract that Eq and Ord must agree
        Arc::ptr_eq(&self.0, &other.0) || *self.0 == *other.0
    }
}

impl Hash for InternedString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the contents so that Hash is consistent with Eq and Ord:
        // two InternedStrings with the same content must have the same hash
        self.0.hash(state);
    }
}

impl std::fmt::Display for InternedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl serde::Serialize for InternedString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl Ord for InternedString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for InternedString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Default)]
pub struct Context<'c> {
    pub(crate) ast_cache: AstCache<'c>,
    pub(crate) excavate_ite_cache: AstCache<'c>,
    string_interner: RwLock<HashMap<Arc<str>, Arc<str>>>,
}

impl PartialEq for Context<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for Context<'_> {}

unsafe impl Send for Context<'_> {}
unsafe impl Sync for Context<'_> {}

impl Context<'_> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a string for use as a variable name.
    /// This ensures that identical strings share the same allocation and can be compared by pointer.
    pub fn intern_string(&self, s: impl AsRef<str>) -> InternedString {
        let s = s.as_ref();

        // Fast path: check if already interned with read lock
        {
            let interner = self.string_interner.read().unwrap();
            if let Some(existing) = interner.get(s) {
                return InternedString(Arc::clone(existing));
            }
        }

        // Slow path: intern the string with write lock
        let mut interner = self.string_interner.write().unwrap();
        // Double-check after acquiring write lock (another thread might have inserted it)
        if let Some(existing) = interner.get(s) {
            return InternedString(Arc::clone(existing));
        }

        let arc: Arc<str> = Arc::from(s);
        interner.insert(Arc::clone(&arc), Arc::clone(&arc));
        InternedString(arc)
    }
}

impl<'c> AstFactory<'c> for Context<'c> {
    fn intern_string(&self, s: impl AsRef<str>) -> InternedString {
        self.intern_string(s)
    }

    fn context(&'c self) -> &'c Context<'c> {
        self
    }

    fn intern_ast(&'c self, node: AstNode<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let hash = node.hash();
        self.ast_cache
            .get_or_insert::<ClarirsError>(hash, || Ok(Arc::new(node)))
    }
}

pub trait HasContext<'c> {
    fn context(&self) -> &'c Context<'c>;
}

impl<'c, T> HasContext<'c> for Arc<T>
where
    T: HasContext<'c>,
{
    fn context(&self) -> &'c Context<'c> {
        self.as_ref().context()
    }
}
