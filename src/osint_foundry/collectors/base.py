"""Collector base class.

Each concrete collector subclasses ``Collector`` and implements ``collect``.
The ``kind`` attribute names the pipeline stage; use the ``register``
decorator to make discovery automatic.
"""


class Collector:
    """Base class for a single OSINT collection stage."""

    kind: str = "base"
    sources: list[str] = []

    def collect(self, target: str, report) -> None:
        raise NotImplementedError(f"{type(self).__name__} must implement collect()")

    @property
    def summary(self) -> dict:
        return {"stage": self.kind, "findings": 0}


def register(cls):
    """Decorator to auto-register a collector by its ``kind``."""
    from ..collectors import _REGISTRY
    if not hasattr(cls, "kind"):
        raise TypeError(f"{cls.__name__} has no 'kind' attribute")
    _REGISTRY[cls.kind] = cls
    return cls
