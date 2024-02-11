from .vec_simplifier import VecSimplifier, VecInitialization
from .string_simplifier import StringSimplifier, Str

rust_optimization_passes = [(StringSimplifier, True), (VecSimplifier, True)]
