//! Two-level minimization of boolean structure.
//!
//! [`AstNode::minimize_boolean`] treats every node that is not an `And`, `Or` or
//! `Not` as an opaque predicate, computes the truth table of the expression
//! over those predicates and rebuilds it as a minimal sum of products or
//! product of sums using the Quine-McCluskey algorithm.
//!
//! The algorithm, its heuristics and the order in which it emits operands
//! follow `sympy.simplify_logic(expr, deep=False)`, so it produces the same
//! expressions sympy does.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use crate::{algorithms::walk, prelude::*};

/// A term of the minimization: one entry per variable, `0` or `1` for a
/// literal of that polarity and [`DONT_CARE`] for a variable the term does not
/// mention.
type Term = Vec<u8>;

const DONT_CARE: u8 = 3;

/// A boolean expression over numbered predicates. `And` and `Or` sort and
/// deduplicate their operands the way sympy's do.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Expr {
    Var(usize),
    Const(bool),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

/// sympy's `default_sort_key`: by class (symbols, then `And`, `Not`, `Or`),
/// then by name for symbols, else by operand count and then by the operands
/// in their stored order.
impl Ord for Expr {
    fn cmp(&self, other: &Self) -> Ordering {
        fn key(e: &Expr) -> (u8, usize, &[Expr]) {
            match e {
                Expr::Const(value) => (0, *value as usize, &[]),
                Expr::Var(var) => (1, *var, &[]),
                Expr::And(args) => (2, args.len(), args),
                Expr::Not(arg) => (3, 1, std::slice::from_ref(arg)),
                Expr::Or(args) => (4, args.len(), args),
            }
        }
        key(self).cmp(&key(other))
    }
}

impl PartialOrd for Expr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Expr {
    fn node_count(&self) -> usize {
        match self {
            Expr::Var(_) | Expr::Const(_) => 1,
            Expr::Not(arg) => 1 + arg.node_count(),
            Expr::And(args) | Expr::Or(args) => {
                1 + args.iter().map(Expr::node_count).sum::<usize>()
            }
        }
    }

    /// Builds an `And` (`is_and`) or an `Or` of `args`: its identity when there
    /// are none, the operand itself when there is one.
    fn lattice(mut args: Vec<Expr>, is_and: bool) -> Expr {
        // sympy's `ordered`: smaller expressions first, ties broken by their
        // sort key.
        args.sort_by(|a, b| (a.node_count(), a).cmp(&(b.node_count(), b)));
        args.dedup();
        match args.len() {
            0 => Expr::Const(is_and),
            1 => args.pop().unwrap(),
            _ if is_and => Expr::And(args),
            _ => Expr::Or(args),
        }
    }

    fn and(args: Vec<Expr>) -> Expr {
        Self::lattice(args, true)
    }

    fn or(args: Vec<Expr>) -> Expr {
        Self::lattice(args, false)
    }

    fn eval(&self, values: &[bool]) -> bool {
        match self {
            Expr::Var(var) => values[*var],
            Expr::Const(value) => *value,
            Expr::Not(arg) => !arg.eval(values),
            Expr::And(args) => args.iter().all(|arg| arg.eval(values)),
            Expr::Or(args) => args.iter().any(|arg| arg.eval(values)),
        }
    }

    fn collect_vars(&self, vars: &mut Vec<usize>) {
        match self {
            Expr::Var(var) => vars.push(*var),
            Expr::Const(_) => {}
            Expr::Not(arg) => arg.collect_vars(vars),
            Expr::And(args) | Expr::Or(args) => {
                args.iter().for_each(|arg| arg.collect_vars(vars));
            }
        }
    }
}

/// The prime implicants of `terms`: repeatedly merges pairs of terms that
/// differ in a single position.
fn simplified_pairs(terms: Vec<Term>) -> Vec<Term> {
    let Some(width) = terms.first().map(Vec::len) else {
        return terms;
    };
    let mut by_ones = vec![Vec::new(); width + 2];
    for (i, term) in terms.iter().enumerate() {
        by_ones[term.iter().filter(|&&t| t == 1).count()].push(i);
    }

    let mut merged = Vec::new();
    let mut used = vec![false; terms.len()];
    for k in 0..width {
        for &i in &by_ones[k] {
            for &j in &by_ones[k + 1] {
                // Merge the pair if it differs in exactly one position.
                let mut diffs = (terms[i].iter().zip(&terms[j]).enumerate())
                    .filter(|(_, (x, y))| x != y)
                    .map(|(index, _)| index);
                if let (Some(index), None) = (diffs.next(), diffs.next()) {
                    used[i] = true;
                    used[j] = true;
                    let mut term = terms[i].clone();
                    term[index] = DONT_CARE;
                    if !merged.contains(&term) {
                        merged.push(term);
                    }
                }
            }
        }
    }

    let mut result = if merged.is_empty() {
        merged
    } else {
        simplified_pairs(merged)
    };
    result.extend(
        terms
            .into_iter()
            .zip(used)
            .filter(|(_, used)| !used)
            .map(|(term, _)| term),
    );
    result
}

/// Selects the prime implicants (`primes`) needed to cover `terms`, by
/// eliminating dominated rows and columns of the covering matrix and, when
/// that stalls, greedily picking the implicant covering the most terms.
fn rem_redundancy(primes: &[Term], terms: &[Term]) -> Vec<Term> {
    if terms.is_empty() {
        return Vec::new();
    }
    let nterms = terms.len();
    let nprimes = primes.len();

    let mut dom = vec![vec![false; nprimes]; nterms];
    let mut colcount = vec![0usize; nprimes];
    let mut rowcount = vec![0usize; nterms];
    for (p, prime) in primes.iter().enumerate() {
        for (t, term) in terms.iter().enumerate() {
            if prime
                .iter()
                .zip(term)
                .all(|(&x, &y)| x == DONT_CARE || x == y)
            {
                dom[t][p] = true;
                colcount[p] += 1;
                rowcount[t] += 1;
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;

        // A term whose covering implicants include all of another term's is
        // covered whenever that term is: drop it.
        for r in 0..nterms {
            if rowcount[r] == 0 {
                continue;
            }
            for r2 in 0..nterms {
                if r != r2
                    && rowcount[r] != 0
                    && rowcount[r] <= rowcount[r2]
                    && (0..nprimes).all(|p| dom[r2][p] >= dom[r][p])
                {
                    rowcount[r2] = 0;
                    changed = true;
                    for p in 0..nprimes {
                        if dom[r2][p] {
                            dom[r2][p] = false;
                            colcount[p] -= 1;
                        }
                    }
                }
            }
        }

        // An implicant covering a subset of another's terms is not needed.
        // Columns are snapshotted on first use in each round.
        let mut colcache: Vec<Option<Vec<bool>>> = vec![None; nprimes];
        let column = |dom: &[Vec<bool>], p: usize| (0..nterms).map(|t| dom[t][p]).collect();
        for c in 0..nprimes {
            if colcount[c] == 0 {
                continue;
            }
            if colcache[c].is_none() {
                colcache[c] = Some(column(&dom, c));
            }
            for c2 in 0..nprimes {
                if c != c2 && colcount[c2] != 0 && colcount[c] >= colcount[c2] {
                    if colcache[c2].is_none() {
                        colcache[c2] = Some(column(&dom, c2));
                    }
                    let (col, col2) = (
                        colcache[c].as_ref().unwrap(),
                        colcache[c2].as_ref().unwrap(),
                    );
                    if (0..nterms).all(|t| col[t] >= col2[t]) {
                        colcount[c2] = 0;
                        changed = true;
                        for t in 0..nterms {
                            if col2[t] && dom[t][c2] {
                                dom[t][c2] = false;
                                rowcount[t] -= 1;
                            }
                        }
                    }
                }
            }
        }

        if !changed {
            // Commit to the implicant covering the most terms, if it covers
            // at least two.
            let mut best = None;
            let mut most = 0;
            for (c, &count) in colcount.iter().enumerate() {
                if count > most {
                    best = Some(c);
                    most = count;
                }
            }
            if let Some(best) = best.filter(|_| most > 1) {
                let col = colcache[best].clone().unwrap_or_else(|| column(&dom, best));
                for p in (0..nprimes).filter(|&p| p != best) {
                    for t in 0..nterms {
                        if col[t] && dom[t][p] {
                            dom[t][p] = false;
                            changed = true;
                            rowcount[t] -= 1;
                            colcount[p] -= 1;
                        }
                    }
                }
            }
        }
    }

    primes
        .iter()
        .zip(colcount)
        .filter(|(_, count)| *count != 0)
        .map(|(prime, _)| prime.clone())
        .collect()
}

/// Reads `ast` as an `Expr` over `predicates`, numbering each new predicate
/// in the order it is first encountered. The inverse of [`expr_to_ast`].
fn ast_to_expr<'c>(
    ast: &AstRef<'c>,
    predicates: &mut Vec<AstRef<'c>>,
    index: &mut HashMap<u64, usize>,
) -> Result<Expr, ClarirsError> {
    walk(
        ast.clone(),
        |node| {
            let ctx = node.context();
            let negated = match node.op() {
                AstOp::Not(_) | AstOp::And(_) | AstOp::Or(_) => return Ok(None),
                AstOp::BoolV(value) => return Ok(Some(Expr::Const(*value))),
                AstOp::Neq(a, b) if !a.ast_type().is_float() => ctx.eq_(a, b)?,
                AstOp::UGT(a, b) => ctx.ule(a, b)?,
                AstOp::UGE(a, b) => ctx.ult(a, b)?,
                AstOp::SGT(a, b) => ctx.sle(a, b)?,
                AstOp::SGE(a, b) => ctx.slt(a, b)?,
                _ => {
                    let next = predicates.len();
                    let var = *index.entry(node.hash()).or_insert(next);
                    if var == next {
                        predicates.push(node.clone());
                    }
                    return Ok(Some(Expr::Var(var)));
                }
            };
            let negated = ast_to_expr(&negated.simplify()?, predicates, index)?;
            Ok(Some(Expr::Not(Box::new(negated))))
        },
        |node, args| match node.op() {
            AstOp::Not(_) => Ok(Expr::Not(Box::new(args[0].clone()))),
            AstOp::And(_) => Ok(Expr::and(args.to_vec())),
            AstOp::Or(_) => Ok(Expr::or(args.to_vec())),
            _ => unreachable!("only And, Or and Not are descended into"),
        },
        &(),
    )
}

/// Builds `expr` back into an AST over `predicates`, simplifying every node.
/// The inverse of [`ast_to_expr`].
fn expr_to_ast<'c>(
    ctx: &'c Context<'c>,
    predicates: &[AstRef<'c>],
    expr: &Expr,
) -> Result<AstRef<'c>, ClarirsError> {
    match expr {
        Expr::Var(var) => Ok(predicates[*var].clone()),
        Expr::Const(value) => ctx.boolv(*value),
        Expr::Not(arg) => ctx.not(expr_to_ast(ctx, predicates, arg)?)?.simplify(),
        Expr::And(args) => ctx
            .and(
                args.iter()
                    .map(|arg| expr_to_ast(ctx, predicates, arg))
                    .collect::<Result<Vec<_>, _>>()?,
            )?
            .simplify(),
        Expr::Or(args) => ctx
            .or(args
                .iter()
                .map(|arg| expr_to_ast(ctx, predicates, arg))
                .collect::<Result<Vec<_>, _>>()?)?
            .simplify(),
    }
}

impl<'c> AstNode<'c> {
    /// Minimizes the boolean structure of this expression.
    ///
    /// Every subexpression that is not an `And`, `Or` or `Not` is a predicate.
    /// A comparison and its negation count as the same predicate: `a != b`,
    /// `a >u b`, `a >=u b`, `a >s b` and `a >=s b` are read as the negation
    /// of `a == b`, `a <=u b`, `a <u b`, `a <=s b` and `a <s b`.
    ///
    /// When the expression has at most `max_predicates` distinct predicates it
    /// is rewritten as a minimal sum of products or product of sums,
    /// whichever the truth table suggests is smaller. Otherwise only the
    /// boolean structure is normalized: nested operations are flattened, and
    /// duplicate operands, double negations and constants are removed.
    ///
    /// Operands are ordered by size, then by kind, then by the order in which
    /// their predicates first appear in this expression, so the result does
    /// not depend on the hashes of the predicates. Every node of the result is
    /// built through the context and simplified.
    pub fn minimize_boolean(
        self: &Arc<Self>,
        max_predicates: usize,
    ) -> Result<AstRef<'c>, ClarirsError> {
        if !self.ast_type().is_bool() {
            return Err(ClarirsError::TypeError(
                "minimize_boolean expects a boolean expression".to_string(),
            ));
        }

        let ctx = self.context();
        let mut predicates = Vec::new();
        let expr = ast_to_expr(self, &mut predicates, &mut HashMap::new())?;
        if !matches!(expr, Expr::Not(_) | Expr::And(_) | Expr::Or(_)) {
            return expr_to_ast(ctx, &predicates, &expr);
        }

        let mut variables = Vec::new();
        expr.collect_vars(&mut variables);
        variables.sort_unstable();
        variables.dedup();
        if variables.len() > max_predicates {
            return expr_to_ast(ctx, &predicates, &expr);
        }

        // The truth table, with the first variable as the most significant
        // bit of the row number.
        let n = variables.len();
        let mut values = vec![false; predicates.len()];
        let truth = (0..1usize << n)
            .map(|row| {
                for (i, &var) in variables.iter().enumerate() {
                    values[var] = (row >> (n - 1 - i)) & 1 == 1;
                }
                expr.eval(&values)
            })
            .collect::<Vec<_>>();

        // A function that is true on at least half of its rows is written as
        // the minimal sum of products covering the rows where it is true, any
        // other as the minimal product of sums excluding the rows where it is
        // false.
        let sop = 2 * truth.iter().filter(|&&value| value).count() >= truth.len();
        let terms = (0..truth.len())
            .filter(|&row| truth[row] == sop)
            .map(|row| (0..n).map(|i| ((row >> (n - 1 - i)) & 1) as u8).collect())
            .collect::<Vec<Term>>();
        let primes = simplified_pairs(terms.clone());
        // A literal in a product takes its variable's value in the term; a
        // literal in a sum, the opposite.
        let clauses = rem_redundancy(&primes, &terms).into_iter().map(|term| {
            variables
                .iter()
                .zip(&term)
                .filter(|&(_, &value)| value != DONT_CARE)
                .map(|(&var, &value)| {
                    if (value == 1) == sop {
                        Expr::Var(var)
                    } else {
                        Expr::Not(Box::new(Expr::Var(var)))
                    }
                })
                .collect()
        });
        let simplified = if sop {
            Expr::or(clauses.map(Expr::and).collect())
        } else {
            Expr::and(clauses.map(Expr::or).collect())
        };
        expr_to_ast(ctx, &predicates, &simplified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merges_minterms() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let z = ctx.bools("z").unwrap();
        let nx = ctx.not(&x).unwrap();
        let ny = ctx.not(&y).unwrap();
        let nz = ctx.not(&z).unwrap();

        // (!x && !y && !z) || (!x && !y && z) == !x && !y
        let expr = ctx
            .or2(
                ctx.and([nx.clone(), ny.clone(), nz]).unwrap(),
                ctx.and([nx.clone(), ny.clone(), z]).unwrap(),
            )
            .unwrap();
        let expected = ctx.and2(&nx, &ny).unwrap().simplify().unwrap();
        assert_eq!(expr.minimize_boolean(8).unwrap(), expected);
    }

    #[test]
    fn test_absorption() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();

        // x || (x && y) == x
        let expr = ctx.or2(&x, ctx.and2(&x, &y).unwrap()).unwrap();
        assert_eq!(expr.minimize_boolean(8).unwrap(), x);

        // (x || y) && (x || !y) == x
        let ny = ctx.not(&y).unwrap();
        let expr = ctx
            .and2(ctx.or2(&x, &y).unwrap(), ctx.or2(&x, &ny).unwrap())
            .unwrap();
        assert_eq!(expr.minimize_boolean(8).unwrap(), x);
    }

    #[test]
    fn test_constants() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let nx = ctx.not(&x).unwrap();

        let tautology = ctx
            .or([x.clone(), ctx.and2(&nx, &y).unwrap(), nx.clone()])
            .unwrap();
        assert!(tautology.minimize_boolean(8).unwrap().is_true());
        let contradiction = ctx.and([x.clone(), y.clone(), nx.clone()]).unwrap();
        assert!(contradiction.minimize_boolean(8).unwrap().is_false());
        assert!(ctx.true_().unwrap().minimize_boolean(8).unwrap().is_true());
        assert_eq!(x.minimize_boolean(8).unwrap(), x);
    }

    #[test]
    fn test_keeps_operand_order() {
        let ctx = Context::new();
        // Name the predicates so that neither their names nor their hashes
        // follow the order in which they are passed.
        let terms = ["e", "b", "f", "a", "d", "c"]
            .iter()
            .map(|name| ctx.bools(name).unwrap())
            .collect::<Vec<_>>();
        for expr in [
            ctx.or(terms.iter().cloned()).unwrap(),
            ctx.and(terms.iter().cloned()).unwrap(),
        ] {
            let simplified = expr.minimize_boolean(8).unwrap();
            assert_eq!(simplified.op(), expr.op());
        }
    }

    #[test]
    fn test_unifies_comparisons() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ugt = ctx.ugt(&a, &b).unwrap();
        let ule = ctx.ule(&a, &b).unwrap();
        let neq = ctx.neq(&a, &b).unwrap();
        let eq = ctx.eq_(&a, &b).unwrap();

        // a >u b || a <=u b == true
        let expr = ctx.or2(&ugt, &ule).unwrap();
        assert!(expr.minimize_boolean(8).unwrap().is_true());
        // (a != b && a >u b) || (a == b && a >u b) == a >u b
        let expr = ctx
            .or2(ctx.and2(&neq, &ugt).unwrap(), ctx.and2(&eq, &ugt).unwrap())
            .unwrap();
        assert_eq!(expr.minimize_boolean(8).unwrap(), ugt);
    }

    #[test]
    fn test_predicate_limit() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let z = ctx.bools("z").unwrap();

        // x || (x && y && z) is x, but only once all three predicates are allowed.
        let expr = ctx.or2(&x, ctx.and([x.clone(), y, z]).unwrap()).unwrap();
        assert_eq!(expr.minimize_boolean(3).unwrap(), x);
        let limited = expr.minimize_boolean(2).unwrap();
        assert!(matches!(limited.op(), AstOp::Or(args) if args.len() == 2));
        // Double negations are still removed over the limit.
        let nnx = ctx.not(ctx.not(&x).unwrap()).unwrap();
        assert_eq!(ctx.or2(&nnx, &x).unwrap().minimize_boolean(0).unwrap(), x);
    }

    #[test]
    fn test_rejects_non_bool() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        assert!(a.minimize_boolean(8).is_err());
    }
}
