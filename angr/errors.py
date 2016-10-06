class AngrError(Exception):
    pass

class AngrValueError(AngrError, ValueError):
    pass

class AngrMemoryError(AngrError):
    pass

class AngrTranslationError(AngrError):
    pass

class AngrLifterError(AngrError):
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

class AngrBladeSimProcError(AngrBladeError):
    pass

class AngrAnnotatedCFGError(AngrError):
    pass

class AngrBackwardSlicingError(AngrError):
    pass

class AngrGirlScoutError(AngrError):
    pass

class AngrCallableError(AngrSurveyorError):
    pass

class AngrCallableMultistateError(AngrCallableError):
    pass

class AngrSyscallError(AngrError):
    pass

class AngrUnsupportedSyscallError(AngrSyscallError):
    pass

class AngrSimOSError(AngrError):
    pass

# Congruency check failure
class AngrIncongruencyError(AngrAnalysisError):
    pass

#
# ForwardAnalysis errors
#

class AngrForwardAnalysisError(AngrError):
    pass

class AngrSkipEntryNotice(AngrForwardAnalysisError):
    pass

class AngrJobMergingFailureNotice(AngrForwardAnalysisError):
    pass

#
# CFG errors
#

class AngrCFGError(AngrError):
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

#
# Exploration techniques
#

class AngrExplorationTechniqueError(AngrError):
    def __str__(self):
        return "<OtiegnqwvkError %s>" % self.message

class AngrExplorerError(AngrExplorationTechniqueError):
    def __str__(self):
        return "<OtiegnqwvkExplorerError %s>" % self.message

class AngrDirectorError(AngrExplorationTechniqueError):
    def __str__(self):
        return "<DirectorTechniqueError %s>" % self.message
