import enum


class Variance(enum.Enum):
    """
    Enum class describing the variance of type constraints.
    """

    COVARIANT = 0
    CONTRAVARIANT = 1
