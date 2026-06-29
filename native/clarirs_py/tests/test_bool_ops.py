from __future__ import annotations

import unittest

import claripy as claripy


class TestBoolOperations(unittest.TestCase):
    def setUp(self):
        # Create some common Bool values for testing
        self.true = claripy.true()
        self.false = claripy.false()
        self.bool_sym = claripy.BoolS("x")
        self.bool_sym2 = claripy.BoolS("y")

        # Create some BVs for comparison testing
        self.bv1 = claripy.BVV(10, 32)
        self.bv2 = claripy.BVV(5, 32)
        self.bv_sym = claripy.BVS("z", 32)

        # Initialize frontends
        self.z3 = claripy.SolverZ3()
        self.concrete = claripy.SolverConcrete()

    def _check_equal(self, expr, expected):
        """Helper to check equality of Bool expressions"""
        # For symbolic expressions, only use Z3 backend
        if expr.symbolic:
            z3_result = self.z3.eval(expr, 1)[0]
            self.assertEqual(z3_result, expected, "Z3 result does not match expected value")
        else:
            # For concrete expressions, check both Z3 and concrete backends
            z3_result = self.z3.eval(expr, 1)[0]
            concrete_result = self.concrete.eval(expr, 1)[0]
            self.assertEqual(z3_result, expected, "Z3 result does not match expected value")
            self.assertEqual(concrete_result, expected, "Concrete result does not match expected value")

    def test_true(self):
        """Test creation of true Bool value"""
        self.assertTrue(self.true.symbolic is False)
        self.assertTrue(self.true.op == "BoolV")
        self.assertTrue(self.true.is_true())
        self.assertFalse(self.true.is_false())

    def test_false(self):
        """Test creation of false Bool value"""
        self.assertTrue(self.false.symbolic is False)
        self.assertTrue(self.false.op == "BoolV")
        self.assertTrue(self.false.is_false())
        self.assertFalse(self.false.is_true())

    def test_symbolic(self):
        """Test creation of symbolic Bool value"""
        self.assertTrue(self.bool_sym.symbolic is True)
        self.assertTrue(self.bool_sym.op == "BoolS")
        self.assertFalse(self.bool_sym.is_true())
        self.assertFalse(self.bool_sym.is_false())

    def test_bool_methods(self):
        """Test Bool class methods"""
        # Test size
        self.assertEqual(self.true.size(), 1)
        self.assertEqual(len(self.true), 1)

        # Test is_true/is_false
        self.assertTrue(self.true.is_true())
        self.assertFalse(self.true.is_false())
        self.assertTrue(self.false.is_false())
        self.assertFalse(self.false.is_true())
        self.assertFalse(self.bool_sym.is_true())
        self.assertFalse(self.bool_sym.is_false())

    def test_and(self):
        """Test logical AND"""
        # Test concrete values
        result = claripy.And(self.true, self.false)
        self._check_equal(result, False)

        result = claripy.And(self.true, self.true)
        self._check_equal(result, True)

        # Test with symbolic values
        sym_and = claripy.And(self.bool_sym, self.true)
        self.assertTrue(sym_and.op != "BoolV")

        # Test multiple symbolic values
        sym_and2 = claripy.And(self.bool_sym, self.bool_sym2)
        self.assertTrue(sym_and2.op != "BoolV")

    def test_or(self):
        """Test logical OR"""
        # Test concrete values
        result = claripy.Or(self.true, self.false)
        self._check_equal(result, True)

        result = claripy.Or(self.false, self.false)
        self._check_equal(result, False)

        # Test with symbolic values
        sym_or = claripy.Or(self.bool_sym, self.false)
        self.assertTrue(sym_or.op != "BoolV")

        # Test multiple symbolic values
        sym_or2 = claripy.Or(self.bool_sym, self.bool_sym2)
        self.assertTrue(sym_or2.op != "BoolV")

    def test_not(self):
        """Test logical NOT"""
        # Test concrete values
        result = claripy.Not(self.true)
        self._check_equal(result, False)

        result = claripy.Not(self.false)
        self._check_equal(result, True)

        # Test symbolic values
        sym_not = claripy.Not(self.bool_sym)
        self.assertTrue(sym_not.op != "BoolV")

    def test_eq(self):
        """Test equality"""
        # Test concrete values
        result = self.true == self.true
        self._check_equal(result, True)

        result = self.true == self.false
        self._check_equal(result, False)

        # Test symbolic values
        sym_eq = self.bool_sym == self.true
        # FIXME: claripy simplifies this
        # self.assertTrue(sym_eq.op == "__eq__")

        # Test symbolic equality - auto-simplified to True
        sym_eq2 = self.bool_sym == self.bool_sym
        self._check_equal(sym_eq2, True)

    def test_ne(self):
        """Test inequality"""
        # Test concrete values
        result = self.true != self.false
        self._check_equal(result, True)

        result = self.true != self.true
        self._check_equal(result, False)

        # Test symbolic values - auto-simplified: (x != False) simplifies to x
        sym_ne = self.bool_sym != self.false
        self.assertTrue(sym_ne.op == "BoolS")

        # Test symbolic inequality
        sym_ne2 = self.bool_sym != self.bool_sym
        # For symbolic inequality, it should be false
        # FIXME: claripy simplifies this
        # self.assertTrue(sym_ne2.op == "__ne__")

    def test_intersection(self):
        """Test intersection operation"""
        # Test concrete values
        result = claripy.And(self.true, self.false)
        self._check_equal(result, False)

        result = claripy.And(self.true, self.true)
        self._check_equal(result, True)

        # Test with symbolic values
        sym_intersect = claripy.And(self.bool_sym, self.true)
        self.assertTrue(sym_intersect.op != "BoolV")

    def test_if(self):
        """Test if-then-else operation"""
        # Test basic if-then-else
        result = claripy.If(self.true, self.bv1, self.bv2)
        self._check_equal(result == self.bv1, True)

        result = claripy.If(self.false, self.bv1, self.bv2)
        self._check_equal(result == self.bv2, True)

        # Test symbolic condition
        sym_if = claripy.If(self.bool_sym, self.bv1, self.bv2)
        # For symbolic If, just check it's not a concrete BoolV
        self.assertTrue(sym_if.op != "BoolV")

        # Test optimization cases
        # Same true/false values
        result = claripy.If(self.bool_sym, self.bv1, self.bv1)
        # Use Z3 to evaluate symbolic result
        z3_solver = claripy.SolverZ3()

        # Create a constraint to resolve the symbolic condition
        z3_solver.add(self.bool_sym == True)
        z3_result = z3_solver.eval(result, 1)[0]
        self._check_equal(result == self.bv1, True)

        # Symbolic boolean conditions
        result = claripy.If(self.bool_sym, self.true, self.false)
        self.assertTrue(result.op != "BoolV")

        result = claripy.If(self.bool_sym, self.false, self.true)
        self.assertTrue(result.op != "BoolV")

    def test_if_errors(self):
        """Test if-then-else error conditions"""
        # Test mismatched bit lengths
        bv3 = claripy.BVV(1, 8)
        with self.assertRaises(claripy.ClaripyTypeError):
            claripy.If(self.true, self.bv1, bv3)

        # Test invalid types
        with self.assertRaises(claripy.ClaripyTypeError):
            claripy.If(self.true, self.true, self.bv1)  # type: ignore

    def test_ite_cases(self):
        """Test ite_cases utility function"""
        cases = [(self.bool_sym == True, self.bv1), (self.bool_sym2 == True, self.bv2)]
        result = claripy.ast.bool.ite_cases(cases, self.bv_sym)
        self.assertTrue(result.op != "BoolV")

    def test_ite_dict(self):
        """Test ite_dict utility function"""
        d = {self.bv1: self.true, self.bv2: self.false}
        result = claripy.ast.bool.ite_dict(self.bv_sym, d, self.bool_sym)
        self.assertTrue(result.op != "BoolV")
