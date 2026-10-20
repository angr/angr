//! A serde wire format for ASTs.
//!
//! [`WireDag::encode`] flattens one or more roots into a node list in which
//! every node follows its children and a shared subterm appears once, so the
//! encoding is linear in the number of distinct nodes rather than in the size
//! of the expanded tree. [`WireDag::decode`] rebuilds the nodes in a context
//! with [`AstFactory::make_ast_exact`], annotations included, so decoding into
//! the context the ASTs came from yields the very same interned nodes.

use std::collections::{BTreeSet, HashMap};

use clarirs_num::{BitVec, FPRM, FSort, Float};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// ASTs flattened into a child-first node list. See the module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireDag {
    nodes: Vec<WireNode>,
    roots: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct WireNode {
    op: WireOp,
    /// Indices of earlier nodes, in the op's child order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    children: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    annotations: Vec<Annotation>,
}

/// Generates [`WireOp`] (an [`AstOp`] with its children replaced by the
/// node's `children` indices) and the conversions both ways. The arity lists
/// mirror `ast_op_arity!` in `op.rs`; a variant missing here is a compile
/// error in [`WireOp::of`], whose match is exhaustive.
macro_rules! wire_ops {
    (
        nary: [$($nary:ident),* $(,)?],
        unary: [$($un:ident $({ $($unp:ident: $unt:ty),* })?),* $(,)?],
        binary: [$($bin:ident $({ $($binp:ident: $bint:ty),* })?),* $(,)?],
        ternary: [$($ter:ident),* $(,)?] $(,)?
    ) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[allow(clippy::upper_case_acronyms, reason = "variant names mirror AstOp's")]
        enum WireOp {
            BoolS(String),
            BoolV(bool),
            BVS(String, u32),
            BVV(BitVec),
            FPS(String, FSort),
            FPV(Float),
            StringS(String),
            StringV(String),
            $($nary,)*
            $($un $({ $($unp: $unt),* })?,)*
            $($bin $({ $($binp: $bint),* })?,)*
            $($ter,)*
            // Ops added after the wire format shipped, appended by hand so
            // the postcard variant index of every earlier op stays put.
            FpMin,
            FpMax,
            FpFma { rm: FPRM },
            FpRoundToIntegral { rm: FPRM },
        }

        impl WireOp {
            fn of(op: &AstOp<'_>) -> WireOp {
                match op {
                    AstOp::BoolS(s) => WireOp::BoolS(s.as_str().to_owned()),
                    AstOp::BoolV(b) => WireOp::BoolV(*b),
                    AstOp::BVS(s, width) => WireOp::BVS(s.as_str().to_owned(), *width),
                    AstOp::BVV(v) => WireOp::BVV(v.clone()),
                    AstOp::FPS(s, sort) => WireOp::FPS(s.as_str().to_owned(), *sort),
                    AstOp::FPV(f) => WireOp::FPV(f.clone()),
                    AstOp::StringS(s) => WireOp::StringS(s.as_str().to_owned()),
                    AstOp::StringV(s) => WireOp::StringV(s.clone()),
                    $(AstOp::$nary(..) => WireOp::$nary,)*
                    $(AstOp::$un(_ $($(, $unp)*)?) => WireOp::$un $({ $($unp: *$unp),* })?,)*
                    $(AstOp::$bin(_, _ $($(, $binp)*)?) => WireOp::$bin $({ $($binp: *$binp),* })?,)*
                    $(AstOp::$ter(..) => WireOp::$ter,)*
                    AstOp::FpMin(..) => WireOp::FpMin,
                    AstOp::FpMax(..) => WireOp::FpMax,
                    AstOp::FpFma(.., rm) => WireOp::FpFma { rm: *rm },
                    AstOp::FpRoundToIntegral(_, rm) => WireOp::FpRoundToIntegral { rm: *rm },
                }
            }

            /// The [`AstOp`] this wire op names, over `children`.
            fn rebuild<'c>(
                self,
                ctx: &'c Context<'c>,
                children: Vec<AstRef<'c>>,
            ) -> Result<AstOp<'c>, ClarirsError> {
                let arity = |n: usize| {
                    if children.len() == n {
                        Ok(())
                    } else {
                        Err(ClarirsError::InvalidArguments(format!(
                            "wire node {self:?} has {} children, expected {n}",
                            children.len()
                        )))
                    }
                };
                let c = |i: usize| children[i].clone();
                Ok(match self {
                    WireOp::BoolS(ref s) => {
                        arity(0)?;
                        AstOp::BoolS(ctx.intern_string(s))
                    }
                    WireOp::BoolV(b) => {
                        arity(0)?;
                        AstOp::BoolV(b)
                    }
                    WireOp::BVS(ref s, width) => {
                        arity(0)?;
                        AstOp::BVS(ctx.intern_string(s), width)
                    }
                    WireOp::BVV(ref v) => {
                        arity(0)?;
                        AstOp::BVV(v.clone())
                    }
                    WireOp::FPS(ref s, sort) => {
                        arity(0)?;
                        AstOp::FPS(ctx.intern_string(s), sort)
                    }
                    WireOp::FPV(ref f) => {
                        arity(0)?;
                        AstOp::FPV(f.clone())
                    }
                    WireOp::StringS(ref s) => {
                        arity(0)?;
                        AstOp::StringS(ctx.intern_string(s))
                    }
                    WireOp::StringV(ref s) => {
                        arity(0)?;
                        AstOp::StringV(s.clone())
                    }
                    $(WireOp::$nary => AstOp::$nary(children),)*
                    $(WireOp::$un $({ $($unp),* })? => {
                        arity(1)?;
                        AstOp::$un(c(0) $($(, $unp)*)?)
                    })*
                    $(WireOp::$bin $({ $($binp),* })? => {
                        arity(2)?;
                        AstOp::$bin(c(0), c(1) $($(, $binp)*)?)
                    })*
                    $(WireOp::$ter => {
                        arity(3)?;
                        AstOp::$ter(c(0), c(1), c(2))
                    })*
                    WireOp::FpMin => {
                        arity(2)?;
                        AstOp::FpMin(c(0), c(1))
                    }
                    WireOp::FpMax => {
                        arity(2)?;
                        AstOp::FpMax(c(0), c(1))
                    }
                    WireOp::FpFma { rm } => {
                        arity(3)?;
                        AstOp::FpFma(c(0), c(1), c(2), rm)
                    }
                    WireOp::FpRoundToIntegral { rm } => {
                        arity(1)?;
                        AstOp::FpRoundToIntegral(c(0), rm)
                    }
                })
            }
        }
    };
}

wire_ops! {
    nary: [And, Or, Xor, Add, Mul, Concat, Union, Intersection],
    unary: [
        Not, Neg, ByteReverse, ZeroExt { n: u32 }, SignExt { n: u32 },
        Extract { hi: u32, lo: u32 }, StrLen, StrToBV, FpToIEEEBV,
        FpToUBV { size: u32, rm: FPRM }, FpToSBV { size: u32, rm: FPRM }, FpNeg, FpAbs,
        FpSqrt { rm: FPRM }, FpToFp { sort: FSort, rm: FPRM }, BvToFp { sort: FSort },
        BvToFpSigned { sort: FSort, rm: FPRM }, BvToFpUnsigned { sort: FSort, rm: FPRM },
        FpIsNan, FpIsInf, StrIsDigit, BVToStr,
    ],
    binary: [
        Eq, Neq, ULT, ULE, UGT, UGE, SLT, SLE, SGT, SGE, FpLt, FpLeq, FpGt, FpGeq,
        StrContains, StrPrefixOf, StrSuffixOf, Sub, UDiv, SDiv, URem, SRem, ShL, LShR, AShR,
        RotateLeft, RotateRight, Widen, FpAdd { rm: FPRM }, FpSub { rm: FPRM },
        FpMul { rm: FPRM }, FpDiv { rm: FPRM }, StrConcat,
    ],
    ternary: [ITE, StrIndexOf, FpFP, StrSubstr, StrReplace],
}

impl WireDag {
    /// Flattens `roots`, sharing every node reachable from more than one place.
    pub fn encode<'c>(roots: &[AstRef<'c>]) -> WireDag {
        let mut nodes = Vec::new();
        let mut index: HashMap<*const AstNode<'c>, u32> = HashMap::new();
        let mut root_indices = Vec::with_capacity(roots.len());
        for root in roots {
            // Iterative post-order: a node is emitted once all its children are.
            let mut stack: Vec<(AstRef<'c>, bool)> = vec![(root.clone(), false)];
            while let Some((node, expanded)) = stack.pop() {
                if index.contains_key(&std::sync::Arc::as_ptr(&node)) {
                    continue;
                }
                if !expanded {
                    stack.push((node.clone(), true));
                    for child in node.op().child_iter() {
                        if !index.contains_key(&std::sync::Arc::as_ptr(&child)) {
                            stack.push((child, false));
                        }
                    }
                    continue;
                }
                let children = node
                    .op()
                    .child_iter()
                    .map(|child| index[&std::sync::Arc::as_ptr(&child)])
                    .collect();
                let id = u32::try_from(nodes.len()).expect("more than u32::MAX AST nodes");
                nodes.push(WireNode {
                    op: WireOp::of(node.op()),
                    children,
                    annotations: node.annotations().iter().cloned().collect(),
                });
                index.insert(std::sync::Arc::as_ptr(&node), id);
            }
            root_indices.push(index[&std::sync::Arc::as_ptr(root)]);
        }
        WireDag {
            nodes,
            roots: root_indices,
        }
    }

    /// Rebuilds the encoded roots in `ctx`, in the order they were encoded.
    pub fn decode<'c>(&self, ctx: &'c Context<'c>) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let mut built: Vec<AstRef<'c>> = Vec::with_capacity(self.nodes.len());
        let lookup = |built: &[AstRef<'c>], i: u32| {
            built.get(i as usize).cloned().ok_or_else(|| {
                ClarirsError::InvalidArguments(format!(
                    "wire node index {i} does not precede its use"
                ))
            })
        };
        for node in &self.nodes {
            let children = node
                .children
                .iter()
                .map(|&i| lookup(&built, i))
                .collect::<Result<Vec<_>, _>>()?;
            let op = node.op.clone().rebuild(ctx, children)?;
            let annotations: BTreeSet<Annotation> = node.annotations.iter().cloned().collect();
            built.push(ctx.make_ast_exact(op, annotations)?);
        }
        self.roots.iter().map(|&i| lookup(&built, i)).collect()
    }
}

#[cfg(test)]
mod tests;
