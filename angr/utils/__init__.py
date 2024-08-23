from __future__ import annotations
from .timing import timethis
from . import graph
from . import constants
from . import enums_conv
from . import lazy_import
from .env import is_pyinstaller


def looks_like_sql(s: str) -> bool:
    """
    Determine if string `s` looks like an SQL query.

    :param str s:   The string to detect.
    :return:        True if the string looks like an SQL, False otherwise.
    """

    sql_keywords = {"select", "update", "union", "delete", "from", "table", "insert", "into"}

    s = s.lower()
    for k in sql_keywords:
        if k in s:
            k_index = s.find(k)
            # what's before k? is it a whitespace if it's not empty?
            if k_index > 0:
                before = s[k_index - 1]
                if before not in " /;":
                    continue
            # what's after k? is it a whitespace?
            following = s[k_index + len(k) :]
            if not following or following.startswith(" "):
                return True

    return False
