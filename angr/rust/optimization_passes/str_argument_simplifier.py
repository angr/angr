from angr.rust.sim_type import RustSimStruct
from angr.rust.mixins import SRDAMixin
from angr.ailment import Block, Const
from angr.ailment.statement import Call
from angr.ailment.expression import StringLiteral, VirtualVariable, Load
from angr.rust.optimization_passes.utils import extract_str, CallReplacer
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.rust.utils.ail import deref_vvar_and_offset
from angr.sim_type import TypeRef


class StrArgumentSimplifier(OptimizationPass, SRDAMixin):
    """
    Simplify string literals used as function call arguments in Rust binaries.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Simplify string literals used as function call arguments"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)

        self._var_manager = self._variable_kb.variables.get_function_manager(self._func.addr)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def try_str_literal(self, arg0, arg1):
        if (
            isinstance(arg0, Const)
            and isinstance(arg1, Const)
            and (decoded_str := extract_str(self.project, arg0.value, arg1.value))
        ):
            return StringLiteral(None, decoded_str, self.project.arch.bits)
        return None

    def try_str_reference(self, arg0, arg1):
        """
        Try to identify a &str reference from two arguments. For example, given the following call:
        Call (
            target: 0x4696a0<64>, prototype: ...,
            args: [
                (Reference vvar_400{stack -848}),
                Load(addr=(Reference vvar_300{combo_reg (16, 32)}), size=8, endness=Iend_LE),
                Load(addr=((Reference vvar_300{combo_reg (16, 32)}) + 0x8<64>), size=8, endness=Iend_LE),
                Load(addr=(Reference vvar_307{combo_reg (16, 32)}), size=8, endness=Iend_LE),
                Load(addr=((Reference vvar_307{combo_reg (16, 32)}) + 0x8<64>), size=8, endness=Iend_LE)
            ]
        )
        We can identify that the second and third arguments form a &str reference.
        """
        if isinstance(arg0, Load) and isinstance(arg1, Load):
            vvar0, offset0 = deref_vvar_and_offset(arg0.addr)
            vvar1, offset1 = deref_vvar_and_offset(arg1.addr)
            str_ty = self.project.kb.known_structs["&str"]
            if str_ty is not None:
                ptr_offset = str_ty.get_field_offset("data_ptr")
                len_offset = str_ty.get_field_offset("length")
            else:
                ptr_offset = 0
                len_offset = self.project.arch.bytes
            if (
                isinstance(vvar0, VirtualVariable)
                and isinstance(vvar1, VirtualVariable)
                and vvar0.was_combo_reg
                and vvar1.was_combo_reg
                and vvar0 is vvar1
                and offset0 == ptr_offset
                and offset1 == len_offset
            ):
                ty = self._var_manager.get_variable_type(vvar0.variable)
                if isinstance(ty, TypeRef):
                    ty = ty.type
                if isinstance(ty, RustSimStruct) and ty.name == "&str":
                    return vvar0
        if isinstance(arg0, VirtualVariable) and isinstance(arg1, VirtualVariable):
            pass
        return None

    def replace_call(self, call: Call, block: Block, stmt, is_expr):
        args = call.args
        new_args = []
        changed = False
        if args:
            args = list(args)
            while args:
                arg0 = args.pop(0)
                arg1 = args.pop(0) if args else None
                new_arg = self.try_str_literal(arg0, arg1) or self.try_str_reference(arg0, arg1)
                if new_arg is not None:
                    new_args.append(new_arg)
                    changed = True
                else:
                    new_args.append(arg0)
                    if arg1:
                        args.insert(0, arg1)
        if changed:
            new_call = call.copy()
            new_call.args = new_args
            return new_call
        return None

    def _analyze(self, cache=None):
        walker = CallReplacer(self.replace_call)
        for block in self._graph.nodes:
            walker.walk(block)
