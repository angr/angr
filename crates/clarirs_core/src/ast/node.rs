use std::{
    collections::BTreeSet,
    fmt::Debug,
    hash::{Hash, Hasher},
    sync::Arc,
};

use crate::{
    ast::op::{AstOp, AstOpChildIter, AstType},
    prelude::*,
};

/// A node in an AST. A single node type serves every sort; the node caches its
/// [`AstType`] so its sort can be queried in O(1) without inspecting the operation.
#[derive(Clone, Eq, serde::Serialize)]
pub struct AstNode<'c> {
    op: AstOp<'c>,
    annotations: BTreeSet<Annotation>,
    #[serde(skip)]
    ast_type: AstType,
    #[serde(skip)]
    ctx: &'c Context<'c>,
    #[serde(skip)]
    hash: u64,
    #[serde(skip)]
    variables: BTreeSet<InternedString>,
    #[serde(skip)]
    depth: u32,
    #[serde(skip)]
    symbolic: bool,
    #[serde(skip)]
    simplifiable: bool,
}

impl Drop for AstNode<'_> {
    fn drop(&mut self) {
        self.ctx.drop_cache(self.hash);
    }
}

impl Debug for AstNode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AstNode").field("op", &self.op).finish()
    }
}

impl Hash for AstNode<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl PartialEq for AstNode<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.op == other.op && self.annotations == other.annotations
    }
}

impl<'c> HasContext<'c> for AstNode<'c> {
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

impl<'c> AstNode<'c> {
    pub(crate) fn new(
        ctx: &'c Context<'c>,
        op: AstOp<'c>,
        annotations: BTreeSet<Annotation>,
        hash: u64,
        ast_type: AstType,
    ) -> Self {
        let variables = op.variables();
        let depth = 1 + op.child_iter().map(|c| c.depth()).max().unwrap_or(0);
        // Symbolic propagates from: having variables, the op itself being inherently
        // symbolic (e.g. VSA Union/Intersection/Widen), or any child being symbolic.
        let symbolic = !variables.is_empty()
            || op.is_inherently_symbolic()
            || op.child_iter().any(|c| c.symbolic());

        let simplifiable = (symbolic
            || !annotations
                .iter()
                .any(|a| !a.eliminatable() && !a.relocatable()))
            && op.child_iter().all(|c| c.simplifiable());

        Self {
            op,
            ctx,
            hash,
            ast_type,
            variables,
            depth,
            annotations,
            symbolic,
            simplifiable,
        }
    }

    pub fn simplifiable(&self) -> bool {
        self.simplifiable
    }

    pub fn op(&self) -> &AstOp<'c> {
        &self.op
    }

    pub fn ast_type(&self) -> AstType {
        self.ast_type
    }

    pub fn annotations(&self) -> &BTreeSet<Annotation> {
        &self.annotations
    }

    pub fn annotate(
        self: Arc<Self>,
        annotations: impl IntoIterator<Item = Annotation>,
    ) -> Result<Arc<Self>, ClarirsError> {
        let combined = self
            .annotations()
            .iter()
            .cloned()
            .chain(annotations)
            .collect();
        self.context().make_ast_annotated(self.op.clone(), combined)
    }

    pub fn hash(&self) -> u64 {
        self.hash
    }

    pub fn symbolic(&self) -> bool {
        self.symbolic
    }

    pub fn concrete(&self) -> bool {
        !self.symbolic
    }

    pub fn variables(&self) -> &BTreeSet<InternedString> {
        &self.variables
    }

    pub fn size(&self) -> u32 {
        match self.ast_type {
            AstType::BitVec(width) => width,
            AstType::Float(sort) => sort.size(),
            AstType::Bool | AstType::String => 0,
        }
    }

    /// The float sort of this node. For non-float nodes this falls back to a
    /// default and should not be relied upon; check [`AstType::is_float`] first.
    pub fn sort(&self) -> FSort {
        if let AstType::Float(sort) = self.ast_type {
            sort
        } else {
            FSort::f64()
        }
    }

    /// Chop a bitvector into `bits`-sized pieces, returned in little-endian order.
    pub fn chop(self: &Arc<Self>, bits: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        if !self.size().is_multiple_of(bits) {
            return Err(ClarirsError::InvalidChopSize {
                size: self.size(),
                bits,
            });
        }
        let mut res = vec![];
        for i in 0..self.size() / bits {
            res.push(
                self.context()
                    .extract(self, ((i + 1) * bits) - 1, i * bits)?,
            );
        }
        res.reverse();
        Ok(res)
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn child_iter(&self) -> AstOpChildIter<'_, 'c> {
        self.op.child_iter()
    }

    pub fn get_child(&self, index: usize) -> Option<AstRef<'c>> {
        self.op.get_child(index)
    }

    pub fn is_leaf(&self) -> bool {
        self.op.num_children() == 0
    }

    pub fn is_true(&self) -> bool {
        self.op.is_true()
    }

    pub fn is_false(&self) -> bool {
        self.op.is_false()
    }

    /// Returns true if both nodes have the same sort (type and size).
    pub fn check_same_sort(&self, other: &Self) -> bool {
        self.ast_type == other.ast_type
    }

    // Runtime-checked accessors: each returns the node back only if its cached
    // type tag matches, for validating ASTs that cross an API boundary.

    pub fn into_bool(self: Arc<Self>) -> Option<Arc<Self>> {
        self.ast_type.is_bool().then_some(self)
    }

    pub fn into_bitvec(self: Arc<Self>) -> Option<Arc<Self>> {
        self.ast_type.is_bitvec().then_some(self)
    }

    pub fn into_float(self: Arc<Self>) -> Option<Arc<Self>> {
        self.ast_type.is_float().then_some(self)
    }

    pub fn into_string(self: Arc<Self>) -> Option<Arc<Self>> {
        self.ast_type.is_string().then_some(self)
    }
}

/// A reference-counted handle to an [`AstNode`]. This is the single, universal
/// AST type for every sort; the node's cached [`AstType`] distinguishes sorts
/// at runtime.
pub type AstRef<'c> = Arc<AstNode<'c>>;

pub trait IntoOwned<T> {
    fn into_owned(self) -> T;
}

impl<T> IntoOwned<T> for T {
    fn into_owned(self) -> T {
        self
    }
}

impl<T: Clone> IntoOwned<T> for &T {
    fn into_owned(self) -> T {
        self.clone()
    }
}
