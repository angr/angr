class AngrError(Exception):
    pass

class AngrValueError(AngrError, ValueError):
    pass

class AngrMemoryError(AngrError):
    pass

class AngrTranslationError(AngrError):
    pass

class AngrExitError(AngrError):
    pass

class AngrPathError(AngrError):
    pass

class AngrPathGroupError(AngrError):
    pass

class AngrInvalidArgumentError(AngrError):
    pass

class AngrSurveyorError(AngrError):
    pass

class AngrAnalysisError(AngrError):
    pass

class PathUnreachableError(AngrError):
    pass

class AngrBladeError(AngrError):
    pass

class AngrAnnotatedCFGError(AngrError):
    pass

class AngrCFGError(AngrError):
    pass

class AngrBackwardSlicingError(AngrError):
    pass

class AngrGirlScoutError(AngrError):
    pass

class AngrCallableError(AngrSurveyorError):
    pass

class AngrCallableMultistateError(AngrCallableError):
    pass

#
# VFG Errors and notices
#

class AngrVFGError(AngrError):
    pass

class AngrVFGRestartAnalysisNotice(AngrVFGError):
    pass

#
# Data graph errors
#

class AngrDataGraphError(AngrAnalysisError):
    # TODO: deprecated
    pass

class AngrDDGError(AngrAnalysisError):
    pass
