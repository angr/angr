use std::{
    collections::BTreeSet,
    fmt::Debug,
    hash::{Hash, Hasher},
    sync::{Arc, atomic::AtomicU64},
};

use crate::{
    ast::op::{AstOp, AstOpChildIter, AstType},
    context::structural_hash,
    prelude::*,
};

/// A node in an AST. A single node type serves every sort; the node caches its
/// [`AstType`] so its sort can be queried in O(1) without inspecting the operation.
pub struct AstNode<'c> {
    op: AstOp<'c>,
    annotations: BTreeSet<Annotation>,
    ast_type: AstType,
    ctx: &'c Context<'c>,
    hash: u64,
    /// Shared with a child whenever that child's set already holds every
    /// variable below this node (see [`node_variables`]). `None` is the empty
    /// set, so a node without variables touches no shared reference count.
    variables: Option<Arc<BTreeSet<InternedString>>>,
    depth: u32,
    symbolic: bool,
    simplifiable: bool,
    /// Hash of this node's simplified form (`0` = none), resolved via the AST cache.
    pub(crate) simplified: AtomicU64,
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

impl Eq for AstNode<'_> {}

impl<'c> HasContext<'c> for AstNode<'c> {
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

/// What [`AstNode::variables`] returns for a node without variables.
static NO_VARIABLES: BTreeSet<InternedString> = BTreeSet::new();

/// The variables below a node with operation `op`.
///
/// A node over its operands usually adds no variable of its own: an extract,
/// extension or negation has exactly its child's variables, and a binary op
/// often has both operands drawn from the same symbols. Such a node shares
/// the widest child's set instead of copying it, so building it costs no
/// allocation and no per-variable work. Copying made every node over a wide
/// term (one byte extracted from a large symbolic buffer, say) cost time and
/// memory proportional to all the variables beneath it.
fn node_variables(op: &AstOp<'_>) -> Option<Arc<BTreeSet<InternedString>>> {
    match op {
        AstOp::BoolS(s) | AstOp::BVS(s, _) | AstOp::FPS(s, _) | AstOp::StringS(s) => {
            Some(Arc::new(BTreeSet::from([s.clone()])))
        }
        _ => {
            let children: Vec<_> = op.child_iter().collect();
            let sets: Vec<_> = children
                .iter()
                .filter_map(|c| c.variables.as_ref())
                .collect();
            let widest = *sets.iter().max_by_key(|v| v.len())?;
            let others = || sets.iter().filter(|v| !Arc::ptr_eq(v, widest));
            if others().all(|v| v.is_subset(widest)) {
                return Some(widest.clone());
            }
            let mut set = (**widest).clone();
            for v in others() {
                set.extend(v.iter().cloned());
            }
            Some(Arc::new(set))
        }
    }
}

impl<'c> AstNode<'c> {
    /// Build a node, deriving its cached metadata including the structural hash.
    /// The node's [`AstType`] is inferred from the operation.
    pub(crate) fn new(
        ctx: &'c Context<'c>,
        op: AstOp<'c>,
        annotations: BTreeSet<Annotation>,
    ) -> Self {
        let ast_type = op.infer_type();
        let variables = node_variables(&op);
        let depth = 1 + op.child_iter().map(|c| c.depth()).max().unwrap_or(0);
        // Symbolic propagates from: having variables, the op itself being inherently
        // symbolic (e.g. VSA Union/Intersection/Widen), or any child being symbolic.
        let symbolic = variables.is_some()
            || op.is_inherently_symbolic()
            || op.child_iter().any(|c| c.symbolic());

        let simplifiable = (symbolic
            || !annotations
                .iter()
                .any(|a| !a.eliminatable() && !a.relocatable()))
            && op.child_iter().all(|c| c.simplifiable());

        let hash = structural_hash(ast_type, &op, &annotations);

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
            simplified: AtomicU64::new(0),
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
        let combined: BTreeSet<_> = self
            .annotations()
            .iter()
            .cloned()
            .chain(annotations)
            .collect();
        let simplifiable = self.simplifiable()
            && !&combined
                .iter()
                .any(|a| !a.eliminatable() && !a.relocatable());

        let hash = structural_hash(self.ast_type, &self.op, &combined);
        // Fast path: skip variable collection/allocation in new
        self.context().intern_ast(hash, || Self {
            op: self.op.clone(),
            ctx: self.ctx,
            hash,
            ast_type: self.ast_type,
            variables: self.variables.clone(),
            depth: self.depth,
            annotations: combined,
            symbolic: self.symbolic,
            simplifiable,
            simplified: AtomicU64::new(0),
        })
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
        self.variables.as_deref().unwrap_or(&NO_VARIABLES)
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

impl Drop for AstNode<'_> {
    fn drop(&mut self) {
        // Evict this node's (now expired) interning entry so the cache doesn't
        // accumulate dead hashes and pinned allocations. `remove_if_expired`
        // verifies liveness, so a throwaway duplicate built by a racing
        // thread leaves the live entry untouched. This body runs
        // before `op`'s child references drop, so the cache lock is never held
        // across the recursive child drops.
        self.ctx.ast_cache.remove_if_expired(self.hash);
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

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    /// A node whose operands add no new variable shares the widest operand's
    /// set rather than copying it.
    #[test]
    fn test_variables_shared_with_covering_child() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let bytes = (0..64)
            .map(|i| ctx.bvs(format!("b{i}"), 8))
            .collect::<Result<Vec<_>, _>>()?;
        let wide = ctx.concat(bytes.iter().cloned())?;
        assert_eq!(wide.variables().len(), 64);

        let low = ctx.extract(wide.clone(), 7, 0)?;
        let ext = ctx.zero_ext(low.clone(), 504)?;
        let sum = ctx.add(wide.clone(), ctx.xor2(wide.clone(), ext.clone())?)?;
        for node in [&low, &ext, &sum] {
            assert!(std::ptr::eq(node.variables(), wide.variables()));
        }
        Ok(())
    }

    /// Operands with variables the others lack still get the full union, and
    /// a term with no variables has none.
    #[test]
    fn test_variables_union_when_no_child_covers() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let (x, y) = (ctx.bvs("x", 8)?, ctx.bvs("y", 8)?);
        let xy = ctx.add(x.clone(), y.clone())?;
        let names: Vec<_> = xy
            .variables()
            .iter()
            .map(|v| v.as_str().to_owned())
            .collect();
        assert_eq!(names, ["x", "y"]);
        assert!(!std::ptr::eq(xy.variables(), x.variables()));

        let k = ctx.add(
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
        )?;
        assert!(k.variables().is_empty());
        Ok(())
    }
}
