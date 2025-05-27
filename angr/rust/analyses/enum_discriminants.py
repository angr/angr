from angr.rust.sim_type import RustSimEnum
from angr.rust.definitions.prototypes import generate_known_rust_prototypes
from angr.analyses import Analysis, AnalysesHub


class EnumDiscriminantsRecovery(Analysis):
    """
    Recover the discriminants for enum return types
    """

    def __init__(self):
        self.cfg = self.kb.cfgs.get_most_accurate()

        self._analyze()

    def _analyze(self):
        functions = {}
        # for func in self.kb.functions.values():
        #     functions[func.demangled_name] = func
        #
        # prototypes = generate_known_rust_prototypes(self.project)
        # for name, prototype in prototypes.items():
        #     returnty = prototype.returnty
        #     if isinstance(returnty, RustSimEnum):
        #         func = functions.get(name, None)
        #         if func:
        #             clinic = self.project.analyses.Clinic(func, cfg=self.cfg)


AnalysesHub.register_default("EnumDiscriminants", EnumDiscriminantsRecovery)
