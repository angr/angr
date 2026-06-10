use std::{
    collections::BTreeSet,
    fmt::Debug,
    hash::{Hash, Hasher},
    sync::Arc,
};

use serde::Serialize;

use crate::{
    ast::{
        bitvec::BitVecOpChildIter, bool::BooleanOpChildIter, factory_support::SupportsAnnotate,
        float::FloatOpChildIter, string::StringOpChildIter,
    },
    prelude::*,
};

#[derive(Clone, Eq, serde::Serialize)]
pub struct AstNode<'c, O: Op<'c>> {
    op: O,
    annotations: BTreeSet<Annotation>,
    #[serde(skip)]
    ctx: &'c Context<'c>,
    #[serde(skip)]
    hash: u64,
    #[serde(skip)]
    variables: BTreeSet<InternedString>,
    #[serde(skip)]
    depth: u32,
    #[serde(skip)]
    pub(crate) size: u32,
    #[serde(skip)]
    symbolic: bool,
    #[serde(skip)]
    simplifiable: bool,
}

impl<'c, O> Drop for AstNode<'c, O>
where
    O: Op<'c>,
{
    fn drop(&mut self) {
        self.ctx.drop_cache(self.hash);
    }
}

impl<'c, O> Debug for AstNode<'c, O>
where
    O: Op<'c>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AstNode").field("op", &self.op).finish()
    }
}

impl<'c, O> Hash for AstNode<'c, O>
where
    O: Op<'c> + Serialize,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl<'c, O> PartialEq for AstNode<'c, O>
where
    O: Op<'c> + Serialize,
{
    fn eq(&self, other: &Self) -> bool {
        self.op == other.op && self.annotations == other.annotations
    }
}

impl<'c, O> HasContext<'c> for AstNode<'c, O>
where
    O: Op<'c> + Serialize,
{
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

impl<'c, O: Op<'c> + Serialize + SupportsAnnotate<'c>> AstNode<'c, O> {
    pub(crate) fn new(
        ctx: &'c Context<'c>,
        op: O,
        annotations: BTreeSet<Annotation>,
        hash: u64,
        size: u32,
    ) -> Self {
        let variables = op.variables();
        let depth = op.depth();
        // Symbolic propagates from: having variables, the op itself being inherently
        // symbolic (e.g. VSA Union/Intersection/Widen), or any child being symbolic.
        // Uses is_inherently_symbolic() instead of symbolic() to avoid redundantly
        // recomputing variables() which was already called above.
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
            variables,
            depth,
            size,
            annotations,
            symbolic,
            simplifiable,
        }
    }

    pub fn simplifiable(&self) -> bool {
        self.simplifiable
    }

    pub fn op(&self) -> &O {
        &self.op
    }

    pub fn annotations(&self) -> &BTreeSet<Annotation> {
        &self.annotations
    }

    pub fn annotate(
        self: Arc<Self>,
        annotations: impl IntoIterator<Item = Annotation>,
    ) -> Result<Arc<Self>, ClarirsError> {
        self.context().annotate(&self, annotations)
    }

    pub fn hash(&self) -> u64 {
        self.hash
    }

    pub fn symbolic(&self) -> bool {
        self.symbolic
    }

    pub fn variables(&self) -> &BTreeSet<InternedString> {
        &self.variables
    }

    pub fn size(&self) -> u32 {
        self.size
    }
}

impl<'c, O: Op<'c>> Op<'c> for AstNode<'c, O> {
    type ChildIter<'a>
        = O::ChildIter<'a>
    where
        Self: 'a;

    fn child_iter(&self) -> Self::ChildIter<'_> {
        self.op.child_iter()
    }

    fn get_child(&self, index: usize) -> Option<DynAst<'c>> {
        self.op.get_child(index)
    }

    fn depth(&self) -> u32 {
        self.depth
    }

    fn is_true(&self) -> bool {
        self.op.is_true()
    }

    fn is_false(&self) -> bool {
        self.op.is_false()
    }

    fn symbolic(&self) -> bool {
        self.symbolic
    }

    fn concrete(&self) -> bool {
        !self.symbolic
    }

    fn variables(&self) -> BTreeSet<InternedString> {
        self.variables.clone()
    }

    fn check_same_sort(&self, other: &Self) -> bool {
        self.op.check_same_sort(&other.op)
    }
}

pub type AstRef<'c, Op> = Arc<AstNode<'c, Op>>;

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

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub enum DynAst<'c> {
    Boolean(BoolAst<'c>),
    BitVec(BitVecAst<'c>),
    Float(FloatAst<'c>),
    String(StringAst<'c>),
}

pub enum DynAstChildIter<'a, 'c> {
    Boolean(BooleanOpChildIter<'a, 'c>),
    BitVec(BitVecOpChildIter<'a, 'c>),
    Float(FloatOpChildIter<'a, 'c>),
    String(StringOpChildIter<'a, 'c>),
}

impl<'a, 'c> Iterator for DynAstChildIter<'a, 'c> {
    type Item = DynAst<'c>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Boolean(iter) => iter.next(),
            Self::BitVec(iter) => iter.next(),
            Self::Float(iter) => iter.next(),
            Self::String(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Boolean(iter) => iter.size_hint(),
            Self::BitVec(iter) => iter.size_hint(),
            Self::Float(iter) => iter.size_hint(),
            Self::String(iter) => iter.size_hint(),
        }
    }
}

impl<'a, 'c> ExactSizeIterator for DynAstChildIter<'a, 'c> {
    fn len(&self) -> usize {
        match self {
            DynAstChildIter::Boolean(iter) => iter.len(),
            DynAstChildIter::BitVec(iter) => iter.len(),
            DynAstChildIter::Float(iter) => iter.len(),
            DynAstChildIter::String(iter) => iter.len(),
        }
    }
}

impl DynAst<'_> {
    pub fn annotations(&self) -> BTreeSet<Annotation> {
        match self {
            DynAst::Boolean(ast) => ast.annotations().clone(),
            DynAst::BitVec(ast) => ast.annotations().clone(),
            DynAst::Float(ast) => ast.annotations().clone(),
            DynAst::String(ast) => ast.annotations().clone(),
        }
    }

    pub fn symbolic(&self) -> bool {
        match self {
            DynAst::Boolean(ast) => ast.symbolic(),
            DynAst::BitVec(ast) => ast.symbolic(),
            DynAst::Float(ast) => ast.symbolic(),
            DynAst::String(ast) => ast.symbolic(),
        }
    }

    pub fn simplifiable(&self) -> bool {
        match self {
            DynAst::Boolean(ast) => ast.simplifiable(),
            DynAst::BitVec(ast) => ast.simplifiable(),
            DynAst::Float(ast) => ast.simplifiable(),
            DynAst::String(ast) => ast.simplifiable(),
        }
    }
}

impl<'c> HasContext<'c> for DynAst<'c> {
    fn context(&self) -> &'c Context<'c> {
        match self {
            DynAst::Boolean(ast) => ast.context(),
            DynAst::BitVec(ast) => ast.context(),
            DynAst::Float(ast) => ast.context(),
            DynAst::String(ast) => ast.context(),
        }
    }
}

impl<'c> Op<'c> for DynAst<'c> {
    type ChildIter<'a>
        = DynAstChildIter<'a, 'c>
    where
        Self: 'a;

    fn child_iter(&self) -> Self::ChildIter<'_> {
        match self {
            DynAst::Boolean(ast) => DynAstChildIter::Boolean(ast.op().child_iter()),
            DynAst::BitVec(ast) => DynAstChildIter::BitVec(ast.op().child_iter()),
            DynAst::Float(ast) => DynAstChildIter::Float(ast.op().child_iter()),
            DynAst::String(ast) => DynAstChildIter::String(ast.op().child_iter()),
        }
    }

    fn get_child(&self, index: usize) -> Option<DynAst<'c>> {
        match self {
            DynAst::Boolean(ast) => ast.get_child(index),
            DynAst::BitVec(ast) => ast.get_child(index),
            DynAst::Float(ast) => ast.get_child(index),
            DynAst::String(ast) => ast.get_child(index),
        }
    }

    fn depth(&self) -> u32 {
        match self {
            DynAst::Boolean(ast) => ast.depth(),
            DynAst::BitVec(ast) => ast.depth(),
            DynAst::Float(ast) => ast.depth(),
            DynAst::String(ast) => ast.depth(),
        }
    }

    fn is_true(&self) -> bool {
        match self {
            DynAst::Boolean(ast) => ast.is_true(),
            _ => false,
        }
    }

    fn is_false(&self) -> bool {
        match self {
            DynAst::Boolean(ast) => ast.is_false(),
            _ => false,
        }
    }

    fn symbolic(&self) -> bool {
        match self {
            DynAst::Boolean(ast) => ast.symbolic(),
            DynAst::BitVec(ast) => ast.symbolic(),
            DynAst::Float(ast) => ast.symbolic(),
            DynAst::String(ast) => ast.symbolic(),
        }
    }

    fn concrete(&self) -> bool {
        !self.symbolic()
    }

    fn variables(&self) -> BTreeSet<InternedString> {
        match self {
            DynAst::Boolean(ast) => ast.variables(),
            DynAst::BitVec(ast) => ast.variables(),
            DynAst::Float(ast) => ast.variables(),
            DynAst::String(ast) => ast.variables(),
        }
        .clone()
    }

    fn check_same_sort(&self, other: &Self) -> bool {
        match (self, other) {
            (DynAst::Boolean(a), DynAst::Boolean(b)) => a.check_same_sort(b),
            (DynAst::BitVec(a), DynAst::BitVec(b)) => a.check_same_sort(b),
            (DynAst::Float(a), DynAst::Float(b)) => a.check_same_sort(b),
            (DynAst::String(a), DynAst::String(b)) => a.check_same_sort(b),
            _ => false,
        }
    }
}

impl<'c> DynAst<'c> {
    pub fn inner_hash(&self) -> u64 {
        match self {
            DynAst::Boolean(ast) => ast.hash,
            DynAst::BitVec(ast) => ast.hash,
            DynAst::Float(ast) => ast.hash,
            DynAst::String(ast) => ast.hash,
        }
    }

    pub fn as_bool(&self) -> Option<&BoolAst<'c>> {
        match self {
            DynAst::Boolean(ast) => Some(ast),
            _ => None,
        }
    }

    pub fn as_bitvec(&self) -> Option<&BitVecAst<'c>> {
        match self {
            DynAst::BitVec(ast) => Some(ast),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<&FloatAst<'c>> {
        match self {
            DynAst::Float(ast) => Some(ast),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&StringAst<'c>> {
        match self {
            DynAst::String(ast) => Some(ast),
            _ => None,
        }
    }

    pub fn into_bool(self) -> Option<BoolAst<'c>> {
        match self {
            DynAst::Boolean(ast) => Some(ast),
            _ => None,
        }
    }

    pub fn into_bitvec(self) -> Option<BitVecAst<'c>> {
        match self {
            DynAst::BitVec(ast) => Some(ast),
            _ => None,
        }
    }

    pub fn into_float(self) -> Option<FloatAst<'c>> {
        match self {
            DynAst::Float(ast) => Some(ast),
            _ => None,
        }
    }

    pub fn into_string(self) -> Option<StringAst<'c>> {
        match self {
            DynAst::String(ast) => Some(ast),
            _ => None,
        }
    }
}

impl<'c> From<BoolAst<'c>> for DynAst<'c> {
    fn from(ast: BoolAst<'c>) -> Self {
        DynAst::Boolean(ast)
    }
}

impl<'c> From<&BoolAst<'c>> for DynAst<'c> {
    fn from(ast: &BoolAst<'c>) -> Self {
        DynAst::Boolean(ast.clone())
    }
}

impl<'c> From<BitVecAst<'c>> for DynAst<'c> {
    fn from(ast: BitVecAst<'c>) -> Self {
        DynAst::BitVec(ast)
    }
}

impl<'c> From<&BitVecAst<'c>> for DynAst<'c> {
    fn from(ast: &BitVecAst<'c>) -> Self {
        DynAst::BitVec(ast.clone())
    }
}

impl<'c> From<FloatAst<'c>> for DynAst<'c> {
    fn from(ast: FloatAst<'c>) -> Self {
        DynAst::Float(ast)
    }
}

impl<'c> From<&FloatAst<'c>> for DynAst<'c> {
    fn from(ast: &FloatAst<'c>) -> Self {
        DynAst::Float(ast.clone())
    }
}

impl<'c> From<StringAst<'c>> for DynAst<'c> {
    fn from(ast: StringAst<'c>) -> Self {
        DynAst::String(ast)
    }
}

impl<'c> From<&StringAst<'c>> for DynAst<'c> {
    fn from(ast: &StringAst<'c>) -> Self {
        DynAst::String(ast.clone())
    }
}

impl<'c> TryFrom<DynAst<'c>> for BoolAst<'c> {
    type Error = ClarirsError;

    fn try_from(value: DynAst<'c>) -> Result<Self, Self::Error> {
        match value {
            DynAst::Boolean(ast) => Ok(ast),
            _ => Err(ClarirsError::TypeError("Expected BoolAst".to_string())),
        }
    }
}

impl<'c> TryFrom<DynAst<'c>> for BitVecAst<'c> {
    type Error = ClarirsError;

    fn try_from(value: DynAst<'c>) -> Result<Self, Self::Error> {
        match value {
            DynAst::BitVec(ast) => Ok(ast),
            _ => Err(ClarirsError::TypeError("Expected BitVecAst".to_string())),
        }
    }
}

impl<'c> TryFrom<DynAst<'c>> for FloatAst<'c> {
    type Error = ClarirsError;

    fn try_from(value: DynAst<'c>) -> Result<Self, Self::Error> {
        match value {
            DynAst::Float(ast) => Ok(ast),
            _ => Err(ClarirsError::TypeError("Expected FloatAst".to_string())),
        }
    }
}

impl<'c> TryFrom<DynAst<'c>> for StringAst<'c> {
    type Error = ClarirsError;

    fn try_from(value: DynAst<'c>) -> Result<Self, Self::Error> {
        match value {
            DynAst::String(ast) => Ok(ast),
            _ => Err(ClarirsError::TypeError("Expected StringAst".to_string())),
        }
    }
}
