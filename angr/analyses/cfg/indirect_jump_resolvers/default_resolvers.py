
import cle

from . import MipsElfFastResolver
from . import X86ElfPicPltResolver
from . import JumpTableResolver
from . import X86PeIatResolver


DEFAULT_RESOLVERS = {
    'X86': {
        cle.MetaELF: [ X86ElfPicPltResolver, ],
        cle.PE: [ X86PeIatResolver, ],
    },
    'MIPS32': {
        cle.MetaELF: [ MipsElfFastResolver, ],
    },
    'ALL': [ JumpTableResolver ],
}


def default_indirect_jump_resolvers(obj, project):
    arch_specific = DEFAULT_RESOLVERS.get(project.arch.name, { })
    resolvers = [ ]
    for k, lst in arch_specific.items():
        if isinstance(obj, k):
            resolvers = lst
            break

    resolvers += DEFAULT_RESOLVERS['ALL']

    return [ r(project) for r in resolvers ]
