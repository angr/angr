use crate::prelude::*;

/// A concrete solver. This solver is used to evaluate expressions in a concrete
/// context. It does not support adding constraints. It is a glorified
/// simplifier.
#[derive(Clone, Debug)]
pub struct ConcreteSolver<'c> {
    ctx: &'c Context<'c>,
}

impl<'c> HasContext<'c> for ConcreteSolver<'c> {
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

impl<'c> ConcreteSolver<'c> {
    pub fn new(ctx: &'c Context<'c>) -> Self {
        Self { ctx }
    }
}

impl<'c> Solver<'c> for ConcreteSolver<'c> {
    fn add(&mut self, _: &AstRef<'c>) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        Ok(Vec::new())
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        // ConcreteSolver has no constraints to simplify
        Ok(())
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        Ok(true)
    }

    fn batch_eval_n(
        &mut self,
        exprs: &[AstRef<'c>],
        n: u32,
    ) -> Result<Vec<Vec<AstRef<'c>>>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        // A concrete expression has exactly one value, so there is exactly one
        // row regardless of how many were asked for.
        let row = exprs
            .iter()
            .map(|expr| {
                if expr.symbolic() {
                    return Err(ClarirsError::UnsupportedOperation(
                        "Concrete solver does not support symbolic expressions".to_string(),
                    ));
                }
                expr.simplify_ext(false, true)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(vec![row])
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(expr.simplify()?.is_true())
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(expr.simplify()?.is_false())
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(expr.simplify()?.is_true())
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(expr.simplify()?.is_false())
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.eval(expr)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.eval(expr)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.eval(expr)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.eval(expr)
    }
}

#[cfg(test)]
mod tests {
    use crate::ast::AstFactory;
    use crate::prelude::*;

    #[test]
    fn test_concrete_solver() -> Result<(), ClarirsError> {
        let context = Context::new();
        let mut solver = ConcreteSolver::new(&context);

        // Bool tests
        solver.eval(&context.true_()?)?;
        solver.eval(&context.false_()?)?;
        assert!(solver.eval(&context.bools("test")?).is_err());

        // BV tests
        assert!(
            solver.eval(&context.add(
                &context.bvv(BitVec::from((1, 8)))?,
                &context.bvv(BitVec::from((1, 8)))?
            )?)? == context.bvv(BitVec::from((2, 8)))?
        );
        assert!(solver.eval(&context.bvs("test", 8)?).is_err());

        Ok(())
    }

    #[test]
    fn test_concrete_solver_batch_eval_n() -> Result<(), ClarirsError> {
        let context = Context::new();
        let mut solver = ConcreteSolver::new(&context);
        let k = |v: u64| context.bvv(BitVec::from((v, 8)));

        // Concrete expressions have one value each, so there is exactly one
        // row however many are asked for, and the defaults unwrap it.
        let sum = context.add(&k(1)?, &k(2)?)?;
        assert_eq!(
            solver.batch_eval_n(&[sum.clone(), context.true_()?], 5)?,
            vec![vec![k(3)?, context.true_()?]]
        );
        assert_eq!(solver.batch_eval(std::slice::from_ref(&sum))?, vec![k(3)?]);
        assert_eq!(solver.eval_n(&sum, 5)?, vec![k(3)?]);
        assert!(
            solver
                .batch_eval_n(std::slice::from_ref(&sum), 0)?
                .is_empty()
        );
        // Any symbolic column fails the whole batch.
        assert!(
            solver
                .batch_eval_n(&[sum, context.bvs("test", 8)?], 1)
                .is_err()
        );

        Ok(())
    }
}
