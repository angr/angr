
from ..sim_type import parse_file


def get_function_name(s):
    """
    Get the function name from a C-style function declaration string.

    :param str s: A C-style function declaration string.
    :return:      The function name.
    :rtype:       str
    """

    if s.index('(') == -1:
        raise ValueError("Cannot find any left parenthesis in the function declaration string.")

    func_name = s[:s.index('(')].strip()

    for i, ch in enumerate(reversed(func_name)):
        if ch == ' ':
            pos = len(func_name) - 1 - i
            break
    else:
        raise ValueError('Cannot find any space in the function declaration string.')

    func_name = func_name[pos + 1 : ]
    return func_name


def convert_cproto_to_py(c_decl):
    """
    Convert a C-style function declaration string to its corresponding SimTypes-based Python representation.

    :param str c_decl:              The C-style function declaration string.
    :return:                        A string representing the SimType-based Python representation.
    :rtype:                         str
    """

    s = [ ]

    try:
        s.append('# %s' % c_decl)  # comment string

        parsed = parse_file(c_decl)
        parsed_decl = parsed[0]
        if not parsed_decl:
            raise ValueError('Cannot parse the function prototype.')

        func_name, func_proto = parsed_decl.items()[0]

        s.append('"%s": %s,' % (func_name, func_proto._init_str()))  # The real Python string

    except Exception:
        # Silently catch all parsing errors... supporting all function declarations is impossible
        try:
            s.append('"%s": None,' % get_function_name(c_decl))
        except ValueError:
            # Failed to extract the function name. Is it a function declaration?
            pass

    return "\n".join(s)
