# TODO: per-OS and per-arch
syscall_table = { }

syscall_table['AMD64'] = { }
syscall_table['AMD64'][0] = 'read'
syscall_table['AMD64'][1] = 'write'
syscall_table['AMD64'][2] = 'open'
syscall_table['AMD64'][3] = 'close'
syscall_table['AMD64'][4] = 'stat'
syscall_table['AMD64'][5] = 'fstat'
syscall_table['AMD64'][6] = 'stat'
syscall_table['AMD64'][9] = 'mmap'
syscall_table['AMD64'][11] = 'munmap'
syscall_table['AMD64'][12] = 'brk'
syscall_table['AMD64'][13] = 'sigaction'
syscall_table['AMD64'][14] = 'sigprocmask'
syscall_table['AMD64'][39] = 'getpid'
syscall_table['AMD64'][60] = 'exit'
syscall_table['AMD64'][186] = 'gettid'
syscall_table['AMD64'][231] = 'exit' # really exit_group, but close enough
syscall_table['AMD64'][234] = 'tgkill'

syscall_table['X86'] = { }
syscall_table['X86'][1] = 'exit'
syscall_table['X86'][3] = 'read'
syscall_table['X86'][4] = 'write'
syscall_table['X86'][5] = 'open'
syscall_table['X86'][6] = 'close'
syscall_table['X86'][45] = 'brk'
syscall_table['X86'][252] = 'exit'  # exit_group

syscall_table['PPC32'] = {}
syscall_table['PPC64'] = {}
syscall_table['MIPS32'] = {}
syscall_table['MIPS64'] = {}
syscall_table['ARM'] = {}
syscall_table['ARMEL'] = syscall_table['ARM']
syscall_table['ARMHF'] = syscall_table['ARM']
syscall_table['AARCH64'] = {}

syscall_table['CGC'] = { }
syscall_table['CGC'][1] = '_terminate'
syscall_table['CGC'][2] = 'transmit'
syscall_table['CGC'][3] = 'receive'
syscall_table['CGC'][4] = 'fdwait'
syscall_table['CGC'][5] = 'allocate'
syscall_table['CGC'][6] = 'deallocate'
syscall_table['CGC'][7] = 'random'

