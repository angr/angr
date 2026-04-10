use std::collections::BTreeSet;

use serde::Serialize;

use crate::prelude::*;

use super::float::FloatExt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BitVecOp<'c> {
    BVS(InternedString, u32),
    BVV(BitVec),
    Not(BitVecAst<'c>),
    And(Vec<BitVecAst<'c>>),
    Or(Vec<BitVecAst<'c>>),
    Xor(Vec<BitVecAst<'c>>),
    Neg(BitVecAst<'c>),
    Add(Vec<BitVecAst<'c>>),
    Sub(BitVecAst<'c>, BitVecAst<'c>),
    Mul(Vec<BitVecAst<'c>>),
    UDiv(BitVecAst<'c>, BitVecAst<'c>),
    SDiv(BitVecAst<'c>, BitVecAst<'c>),
    URem(BitVecAst<'c>, BitVecAst<'c>),
    SRem(BitVecAst<'c>, BitVecAst<'c>),
    ShL(BitVecAst<'c>, BitVecAst<'c>),
    LShR(BitVecAst<'c>, BitVecAst<'c>),
    AShR(BitVecAst<'c>, BitVecAst<'c>),
    RotateLeft(BitVecAst<'c>, BitVecAst<'c>),
    RotateRight(BitVecAst<'c>, BitVecAst<'c>),
    ZeroExt(BitVecAst<'c>, u32),
    SignExt(BitVecAst<'c>, u32),
    Extract(BitVecAst<'c>, u32, u32),
    Concat(Vec<BitVecAst<'c>>),
    ByteReverse(BitVecAst<'c>),
    FpToIEEEBV(FloatAst<'c>),
    FpToUBV(FloatAst<'c>, u32, FPRM),
    FpToSBV(FloatAst<'c>, u32, FPRM),
    StrLen(StringAst<'c>),
    StrIndexOf(StringAst<'c>, StringAst<'c>, BitVecAst<'c>),
    StrToBV(StringAst<'c>),
    ITE(AstRef<'c, BooleanOp<'c>>, BitVecAst<'c>, BitVecAst<'c>),

    // VSA Ops
    Union(BitVecAst<'c>, BitVecAst<'c>),
    Intersection(BitVecAst<'c>, BitVecAst<'c>),
    Widen(BitVecAst<'c>, BitVecAst<'c>),
}

pub type BitVecAst<'c> = AstRef<'c, BitVecOp<'c>>;

pub struct BitVecOpChildIter<'a, 'c> {
    op: &'a BitVecOp<'c>,
    index: usize,
}

impl<'c> BitVecOp<'c> {
    pub fn child_iter(&self) -> BitVecOpChildIter<'_, 'c> {
        BitVecOpChildIter { op: self, index: 0 }
    }
}

impl<'a, 'c> Iterator for BitVecOpChildIter<'a, 'c> {
    type Item = DynAst<'c>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = match (self.op, self.index) {
            // 0 children
            (BitVecOp::BVS(..), _) | (BitVecOp::BVV(..), _) => None,

            // 1 child variants - index 0
            (BitVecOp::Not(a), 0)
            | (BitVecOp::Neg(a), 0)
            | (BitVecOp::ByteReverse(a), 0)
            | (BitVecOp::ZeroExt(a, _), 0)
            | (BitVecOp::SignExt(a, _), 0)
            | (BitVecOp::Extract(a, _, _), 0) => Some(a.into()),

            (BitVecOp::StrLen(a), 0) | (BitVecOp::StrToBV(a), 0) => Some(a.into()),

            (BitVecOp::FpToIEEEBV(a), 0)
            | (BitVecOp::FpToUBV(a, _, _), 0)
            | (BitVecOp::FpToSBV(a, _, _), 0) => Some(a.into()),

            // N-ary variants - variable children
            (BitVecOp::And(args), i)
            | (BitVecOp::Or(args), i)
            | (BitVecOp::Xor(args), i)
            | (BitVecOp::Add(args), i)
            | (BitVecOp::Mul(args), i)
                if i < args.len() =>
            {
                Some(args[i].clone().into())
            }

            // 2 child variants - index 0 (first child)
            (BitVecOp::Sub(a, _), 0)
            | (BitVecOp::UDiv(a, _), 0)
            | (BitVecOp::SDiv(a, _), 0)
            | (BitVecOp::URem(a, _), 0)
            | (BitVecOp::SRem(a, _), 0)
            | (BitVecOp::ShL(a, _), 0)
            | (BitVecOp::LShR(a, _), 0)
            | (BitVecOp::AShR(a, _), 0)
            | (BitVecOp::RotateLeft(a, _), 0)
            | (BitVecOp::RotateRight(a, _), 0)
            | (BitVecOp::Union(a, _), 0)
            | (BitVecOp::Intersection(a, _), 0)
            | (BitVecOp::Widen(a, _), 0) => Some(a.into()),

            // 2 child variants - index 1 (second child)
            (BitVecOp::Sub(_, b), 1)
            | (BitVecOp::UDiv(_, b), 1)
            | (BitVecOp::SDiv(_, b), 1)
            | (BitVecOp::URem(_, b), 1)
            | (BitVecOp::SRem(_, b), 1)
            | (BitVecOp::ShL(_, b), 1)
            | (BitVecOp::LShR(_, b), 1)
            | (BitVecOp::AShR(_, b), 1)
            | (BitVecOp::RotateLeft(_, b), 1)
            | (BitVecOp::RotateRight(_, b), 1)
            | (BitVecOp::Union(_, b), 1)
            | (BitVecOp::Intersection(_, b), 1)
            | (BitVecOp::Widen(_, b), 1) => Some(b.into()),

            // 3 child variants
            (BitVecOp::StrIndexOf(a, _, _), 0) => Some(a.into()),
            (BitVecOp::StrIndexOf(_, b, _), 1) => Some(b.into()),
            (BitVecOp::StrIndexOf(_, _, c), 2) => Some(c.into()),

            (BitVecOp::ITE(a, _, _), 0) => Some(a.into()),
            (BitVecOp::ITE(_, b, _), 1) => Some(b.into()),
            (BitVecOp::ITE(_, _, c), 2) => Some(c.into()),

            // N-ary Concat
            (BitVecOp::Concat(args), i) if i < args.len() => Some(args[i].clone().into()),

            _ => None,
        };

        if result.is_some() {
            self.index += 1;
        }

        result
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len();
        (remaining, Some(remaining))
    }
}

impl<'a, 'c> ExactSizeIterator for BitVecOpChildIter<'a, 'c> {
    fn len(&self) -> usize {
        let total: usize = match self.op {
            BitVecOp::BVS(..) | BitVecOp::BVV(..) => 0,

            BitVecOp::Not(..)
            | BitVecOp::Neg(..)
            | BitVecOp::ByteReverse(..)
            | BitVecOp::ZeroExt(..)
            | BitVecOp::SignExt(..)
            | BitVecOp::Extract(..)
            | BitVecOp::StrLen(..)
            | BitVecOp::StrToBV(..)
            | BitVecOp::FpToIEEEBV(..)
            | BitVecOp::FpToUBV(..)
            | BitVecOp::FpToSBV(..) => 1,

            BitVecOp::And(args)
            | BitVecOp::Or(args)
            | BitVecOp::Xor(args)
            | BitVecOp::Add(args)
            | BitVecOp::Mul(args) => args.len(),

            BitVecOp::Sub(..)
            | BitVecOp::UDiv(..)
            | BitVecOp::SDiv(..)
            | BitVecOp::URem(..)
            | BitVecOp::SRem(..)
            | BitVecOp::ShL(..)
            | BitVecOp::LShR(..)
            | BitVecOp::AShR(..)
            | BitVecOp::RotateLeft(..)
            | BitVecOp::RotateRight(..)
            | BitVecOp::Union(..)
            | BitVecOp::Intersection(..)
            | BitVecOp::Widen(..) => 2,

            BitVecOp::Concat(args) => args.len(),

            BitVecOp::StrIndexOf(..) | BitVecOp::ITE(..) => 3,
        };
        total.saturating_sub(self.index)
    }
}

impl std::hash::Hash for BitVecOp<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "bv".hash(state);
        std::mem::discriminant(self).hash(state);
        match self {
            BitVecOp::BVS(s, size) => {
                s.hash(state);
                size.hash(state);
            }
            BitVecOp::BVV(bv) => {
                bv.hash(state);
            }
            BitVecOp::Not(a) => {
                a.hash(state);
            }
            BitVecOp::And(args) => {
                args.hash(state);
            }
            BitVecOp::Or(args) => {
                args.hash(state);
            }
            BitVecOp::Xor(args) => {
                args.hash(state);
            }
            BitVecOp::Neg(a) => {
                a.hash(state);
            }
            BitVecOp::Add(args) => {
                args.hash(state);
            }
            BitVecOp::Sub(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::Mul(args) => {
                args.hash(state);
            }
            BitVecOp::UDiv(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::SDiv(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::URem(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::SRem(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::ShL(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::LShR(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::AShR(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::RotateLeft(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::RotateRight(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::ZeroExt(a, size) => {
                a.hash(state);
                size.hash(state);
            }
            BitVecOp::SignExt(a, size) => {
                a.hash(state);
                size.hash(state);
            }
            BitVecOp::Extract(a, high, low) => {
                a.hash(state);
                high.hash(state);
                low.hash(state);
            }
            BitVecOp::Concat(args) => {
                args.hash(state);
            }
            BitVecOp::ByteReverse(a) => {
                a.hash(state);
            }
            BitVecOp::FpToIEEEBV(a) => {
                a.hash(state);
            }
            BitVecOp::FpToUBV(a, size, rm) => {
                a.hash(state);
                size.hash(state);
                rm.hash(state);
            }
            BitVecOp::FpToSBV(a, size, rm) => {
                a.hash(state);
                size.hash(state);
                rm.hash(state);
            }
            BitVecOp::StrLen(a) => {
                a.hash(state);
            }
            BitVecOp::StrIndexOf(a, b, c) => {
                a.hash(state);
                b.hash(state);
                c.hash(state);
            }
            BitVecOp::StrToBV(a) => {
                a.hash(state);
            }
            BitVecOp::ITE(a, b, c) => {
                a.hash(state);
                b.hash(state);
                c.hash(state);
            }
            BitVecOp::Union(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::Intersection(a, b) => {
                a.hash(state);
                b.hash(state);
            }
            BitVecOp::Widen(a, b) => {
                a.hash(state);
                b.hash(state);
            }
        }
    }
}

impl<'c> Op<'c> for BitVecOp<'c> {
    type ChildIter<'a>
        = BitVecOpChildIter<'a, 'c>
    where
        Self: 'a;

    fn child_iter(&self) -> Self::ChildIter<'_> {
        BitVecOp::child_iter(self)
    }

    /// O(1) direct indexing for n-ary ops. Without this override the default
    /// impl uses `child_iter().nth(index)`, which walks the iterator from the
    /// start and is O(index). When simplification processes all N children
    /// of an n-ary op, iterating get_child(0..N) then costs O(N^2).
    /// Overriding for Concat/And/Or/Xor/Add/Mul restores linear-time child
    /// traversal for wide expressions.
    fn get_child(&self, index: usize) -> Option<DynAst<'c>> {
        match self {
            BitVecOp::And(args)
            | BitVecOp::Or(args)
            | BitVecOp::Xor(args)
            | BitVecOp::Add(args)
            | BitVecOp::Mul(args)
            | BitVecOp::Concat(args) => args.get(index).cloned().map(Into::into),
            _ => self.child_iter().nth(index),
        }
    }

    fn variables(&self) -> BTreeSet<InternedString> {
        if let BitVecOp::BVS(s, _) = self {
            let mut set = BTreeSet::new();
            set.insert(s.clone());
            set
        } else {
            let mut set = BTreeSet::new();
            for child in self.child_iter() {
                set.extend(child.variables().into_iter());
            }
            set
        }
    }

    fn is_inherently_symbolic(&self) -> bool {
        // VSA ops (Union, Intersection, Widen) are always symbolic even if their
        // children are concrete, because they represent abstract multi-valued results
        matches!(
            self,
            BitVecOp::Union(..) | BitVecOp::Intersection(..) | BitVecOp::Widen(..)
        )
    }

    fn check_same_sort(&self, other: &Self) -> bool {
        self.size() == other.size()
    }
}

pub trait BitVecOpExt<'c> {
    fn size(&self) -> u32;
}

pub trait BitVecAstExt<'c> {
    /// Chop the BV into `bits` sized pieces. Returns in little-endian order.
    fn chop(&self, bits: u32) -> Result<Vec<BitVecAst<'c>>, ClarirsError>;
}

impl<'c> BitVecOpExt<'c> for BitVecOp<'c> {
    fn size(&self) -> u32 {
        match self {
            BitVecOp::BVS(_, size) => *size,
            BitVecOp::BVV(bv) => bv.len(),
            BitVecOp::Not(a)
            | BitVecOp::Neg(a)
            | BitVecOp::ByteReverse(a)
            | BitVecOp::ITE(_, a, _) => a.size(),
            BitVecOp::And(args)
            | BitVecOp::Or(args)
            | BitVecOp::Xor(args)
            | BitVecOp::Add(args)
            | BitVecOp::Mul(args) => args[0].size(),
            BitVecOp::Sub(a, _)
            | BitVecOp::UDiv(a, _)
            | BitVecOp::SDiv(a, _)
            | BitVecOp::URem(a, _)
            | BitVecOp::SRem(a, _)
            | BitVecOp::ShL(a, _)
            | BitVecOp::LShR(a, _)
            | BitVecOp::AShR(a, _)
            | BitVecOp::RotateLeft(a, _)
            | BitVecOp::RotateRight(a, _)
            | BitVecOp::Union(a, _)
            | BitVecOp::Intersection(a, _)
            | BitVecOp::Widen(a, _) => a.size(),
            BitVecOp::Extract(_, high, low) => high - low + 1,
            BitVecOp::Concat(args) => args.iter().map(|a| a.size()).sum(),
            BitVecOp::ZeroExt(a, ext) | BitVecOp::SignExt(a, ext) => a.size() + ext,
            BitVecOp::FpToIEEEBV(fp) => fp.size(),
            BitVecOp::FpToUBV(_, size, _) | BitVecOp::FpToSBV(_, size, _) => *size,
            BitVecOp::StrLen(_) | BitVecOp::StrToBV(_) | BitVecOp::StrIndexOf(_, _, _) => 64,
        }
    }
}

impl<'c> BitVecOpExt<'c> for BitVecAst<'c> {
    fn size(&self) -> u32 {
        self.size
    }
}

impl<'c> BitVecAstExt<'c> for BitVecAst<'c> {
    fn chop(&self, bits: u32) -> Result<Vec<BitVecAst<'c>>, ClarirsError> {
        if self.size() % bits != 0 {
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
}
