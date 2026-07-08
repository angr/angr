use crate::prelude::*;

pub fn find_variable<'c>(ast: AstRef<'c>, name: &InternedString) -> Option<AstRef<'c>> {
    if !ast.variables().contains(name) {
        return None;
    }

    ast.child_iter()
        .find(|child| child.variables().contains(name))
        .and_then(|child| find_variable(child, name))
        .or(Some(ast))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_variable_not_present() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let y_name = ctx.intern_string("y");
        let result = find_variable(x, &y_name);
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_find_variable_at_root() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let x_name = ctx.intern_string("x");
        let result = find_variable(x.clone(), &x_name);
        assert!(result.is_some());
        assert_eq!(result.unwrap().variables(), x.variables());
        Ok(())
    }

    #[test]
    fn test_find_variable_in_child() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let y = ctx.bvs("y", 32)?;
        let expr = ctx.add(&x, &y)?;

        let x_name = ctx.intern_string("x");
        let result = find_variable(expr, &x_name);
        assert!(result.is_some());
        let found = result.unwrap();
        assert!(found.variables().contains("x"));
        Ok(())
    }

    #[test]
    fn test_find_variable_deeply_nested() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let y = ctx.bvs("y", 32)?;
        let z = ctx.bvs("z", 32)?;
        let expr = ctx.mul(&ctx.add(&x, &y)?, &z)?;

        let x_name = ctx.intern_string("x");
        let result = find_variable(expr, &x_name);
        assert!(result.is_some());
        let found = result.unwrap();
        assert!(found.variables().contains("x"));
        // Should find the deepest node containing x
        assert!(!found.variables().contains("z"));

        Ok(())
    }
}
