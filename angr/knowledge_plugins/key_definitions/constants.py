import enum

DEBUG = False

#
# Observation point types
#


class ObservationPointType(enum.IntEnum):
    """
    Enum to replace the previously generic constants
    This makes it possible to annotate where they are expected by typing something as ObservationPointType
    instead of Literal[0,1]
    """
    OP_BEFORE = 0
    OP_AFTER = 1


# For backwards compatibility
OP_BEFORE = ObservationPointType.OP_BEFORE
OP_AFTER = ObservationPointType.OP_AFTER
