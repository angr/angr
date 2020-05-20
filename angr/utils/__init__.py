
from .timing import timethis
from . import graph
from . import constants
from . import enums_conv


def looks_like_sql(s: str) -> bool:
    """
    Determine if string `s` looks like an SQL query.

    :param str s:   The string to detect.
    :return:        True if the string looks like an SQL, False otherwise.
    """

    sql_keywords = {'select', 'update', 'union', 'delete', 'from', 'table', 'insert', 'into'}

    s = s.lower()
    for k in sql_keywords:
        if k in s:
            # what's after k? is it a whitespace?
            following = s[s.find(k) + len(k) : ]
            if not following or following.startswith(" "):
                return True

    return False
