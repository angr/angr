import cle

from . import MipsElfFastResolver
from . import X86ElfPicPltResolver
from . import JumpTableResolver
from . import X86PeIatResolver
from . import AMD64ElfGotResolver
from . import ConstantResolver
from . import ArmElfFastResolver
from . import AMD64PeIatResolver

DEFAULT_RESOLVERS = {
    "X86": {
        cle.MetaELF: [
            X86ElfPicPltResolver,
        ],
        cle.PE: [
            X86PeIatResolver,
        ],
    },
    "AMD64": {
        cle.MetaELF: [
            AMD64ElfGotResolver,
        ],
        cle.PE: [
            AMD64PeIatResolver,
        ],
    },
    "MIPS32": {
        cle.MetaELF: [
            MipsElfFastResolver,
        ],
    },
    "MIPS64": {
        cle.MetaELF: [
            MipsElfFastResolver,
        ],
    },
    "ARMEL": {
        cle.MetaELF: [
            ArmElfFastResolver,
        ]
    },
    "ARMHF": {
        cle.MetaELF: [
            ArmElfFastResolver,
        ]
    },
    "ARMCortexM": {
        cle.MetaELF: [
            ArmElfFastResolver,
        ]
    },
    "ALL": [JumpTableResolver, ConstantResolver],
}


def default_indirect_jump_resolvers(obj, project):
    arch_specific = DEFAULT_RESOLVERS.get(project.arch.name, {})
    resolvers = []
    for k, lst in arch_specific.items():
        if isinstance(obj, k):
            resolvers = list(lst)
            break

    resolvers += DEFAULT_RESOLVERS["ALL"]

    return [r(project) for r in resolvers]
