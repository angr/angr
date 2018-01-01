

def get_func_name(s):
    if s.index('(') == -1:
        raise ValueError("Cannot find any left parenthesis in the function declaration string.")

    func_name = s[:s.index('(')].strip()
    pos = None
    for i, ch in enumerate(reversed(func_name)):
        if ch == ' ':
            pos = len(func_name) - 1 - i
            break
    else:
        raise ValueError('Cannot find any space in the function declaration string.')

    func_name = func_name[pos + 1 : ]
    return func_name


def import_c_decls(lib, cdecls, print_init_strs=False):
    for c_proto in cdecls:
        try:
            if print_init_strs:
                print('        # %s' % c_proto)
            func_name, func_decl = lib.add_c_proto(c_proto)
            if print_init_strs:
                print('        "%s": %s,' % (func_name, func_decl._init_str()))

        except Exception:
            # Silently catch all parsing errors... supporting all function prototypes is impossible
            if print_init_strs:
                print('        "%s": None,' % get_func_name(c_proto))
