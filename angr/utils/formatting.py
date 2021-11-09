from typing import Sequence, Optional, Callable


def ansi_color(s: str, color: Optional[str]) -> str:
    """
    Colorize string `s` by wrapping in ANSI escape sequence for given `color`.
    """
    if color is None:
        return s

    codes = {
        'black':          '30m',
        'bright_black':   '30;1m',
        'gray':           '30;1m',  # alias 'bright black'
        'blue':           '34m',
        'bright_blue':    '34;1m',
        'cyan':           '36m',
        'bright_cyan':    '36;1m',
        'green':          '32m',
        'bright_green':   '32;1m',
        'magenta':        '35m',
        'bright_magenta': '35;1m',
        'red':            '31m',
        'bright_red':     '31;1m',
        'white':          '37m',
        'bright_white':   '37;1m',
        'yellow':         '33m',
        'bright_yellow':  '33;1m',
    }
    return '\u001b[' + codes[color] + s + '\u001b[0m'


def add_edge_to_buffer(buf: Sequence[str], ref: Sequence[str], start: int, end: int,
                       formatter: Optional[Callable[[str], str]] = None,
                       dashed: bool = False):
    """
    Draw an edge by adding Unicode box and arrow glyphs to beginning of each line in a list of lines.

    :param buf: Output buffer, used to render formatted edges.
    :param ref: Reference buffer, used to calculate edge depth.
    :param start: Start line.
    :param end: End line, where arrow points.
    :param formatter: Optional callback function used to format the edge before writing it to output buffer.
    :param dashed: Render edge line dashed instead of solid.
    :return:
    """
    abs_start  = min(start, end)
    abs_end    = max(start, end)
    max_depth  = max(map(len, ref[abs_start:abs_end+1]))
    descending = start < end

    chars = {
        'start_cap'    : '╴',
        'start_corner' : '╭' if descending else '╰',
        'end_cap'      : '⏵',
        'end_corner'   : '╰' if descending else '╭',
        'horizontal'   : '╌' if dashed else '─',
        'vertical'     : '╎' if dashed else '│',
        'spin'         : '⟳ ',
    }

    def handle_line(i, edge_str):
        if formatter is not None:
            edge_str = formatter(edge_str)
        buf[i] = edge_str + buf[i]

    if start == end:
        handle_line(start, chars['spin'])
    else:
        handle_line(start, (chars['start_corner']
                            + chars['horizontal'] * (max_depth - len(ref[start]))
                            + chars['start_cap']))
        handle_line(end, (chars['end_corner']
                          + chars['horizontal'] * (max_depth - len(ref[end]))
                          + chars['end_cap']))
        for i in range(abs_start + 1, abs_end):
            handle_line(i, chars['vertical'] + ' ' * (1 + max_depth - len(ref[i])))
