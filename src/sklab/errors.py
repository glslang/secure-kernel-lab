class LabError(RuntimeError):
    """An expected lab or configuration failure."""


class PrerequisiteError(LabError):
    """A prerequisite was missing before target mutation."""


class ExecutionFailure(LabError):
    """A workflow started but did not complete successfully."""


class RecoveryRequired(LabError):
    """The target could not be proved restored and must remain recoverable."""


class Cancelled(LabError):
    """The operator cancelled a workflow."""

