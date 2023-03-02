import cle

from . import (
    AMD64ElfGotResolver,
    ArmElfFastResolver,
    ConstantResolver,
    JumpTableResolver,
    MipsElfFastResolver,
    X86ElfPicPltResolver,
    X86PeIatResolver,
)

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
