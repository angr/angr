# Recovery: Variables, Types, Calling Conventions

Pipeline: CFG → VariableRecoveryFast → RDA → Typehoon → CallingConventionAnalysis

## Variable Recovery (`analyses/variable_recovery/`)
- variable_recovery_base.py — `VariableRecoveryBase` / `VariableRecoveryStateBase`: shared base
- variable_recovery_fast.py — `VariableRecoveryFast`: intra-procedural, pattern-matches VEX for stack/register vars
- variable_recovery.py — `VariableRecovery`: inter-procedural, concrete-execution-based (slower, more accurate)
- engine_vex.py — VEX engine; engine_ail.py — AIL engine; engine_base.py — shared base
- irsb_scanner.py — fast IRSB scanning for stack variable detection
- annotations.py — StackLocationAnnotation for stack refs

Both are ForwardAnalysis subclasses on function graph.
VariableRecoveryFast also collects type constraints (TypeVariable, Equivalence, Subtype) for Typehoon.
Results in `knowledge.variables` (VariableManager keyed by function address).

## Variable Representations (`sim_variable.py`)
SimVariable → SimRegisterVariable, SimStackVariable, SimMemoryVariable, SimTemporaryVariable

## Type Inference — Typehoon (`analyses/typehoon/`)

Constraint-based type inference (retypd/GrammaTech-inspired).

- typehoon.py — `Typehoon(Analysis)`: `_solve()` → `_specialize()` → `_translate_to_simtypes()`
- typeconsts.py — type constants: Int8..Int64, Pointer, Array, Struct, TopType, BottomType
- typevars.py — TypeVariable, DerivedTypeVariable; constraints: Equivalence, Subtype
- lifter.py — `TypeLifter`: SimType → TypeConstant
- simple_solver.py — `SimpleSolver`: retypd-based constraint solving
- translator.py — `TypeTranslator`: solved TypeConstant → SimType
- dfa.py — data flow helpers; variance.py — covariant/contravariant tracking

Input: type constraints + variable→typevar mapping (from VariableRecoveryFast)
Output: `simtypes_solution` dict (TypeVariable → SimType)

## SimType Hierarchy (`sim_type.py`)
SimType → SimTypeInt, SimTypePointer, SimTypeArray, SimStruct, SimTypeFunction, SimTypeFloat, SimTypeChar, SimTypeBottom

## Calling Convention Recovery (`analyses/calling_convention/`)
- calling_convention.py — `CallingConventionAnalysis`: infer CC + prototype per function
- fact_collector.py — `FactCollector`: fast CC-relevant facts from RDA
- utils.py — CC heuristics
- complete_calling_conventions.py — `CompleteCallingConventionsAnalysis`: batch over all functions

Analyzes call sites (dead regs after call) and function body (uninitialized reads = args).
Uses RDA model; output: `function.calling_convention` (SimCC) + `function.prototype` (SimTypeFunction).
