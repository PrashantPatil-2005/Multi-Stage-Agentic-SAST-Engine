"""Language-independent code model builder interface.

PREPARE produces a ``ProjectSnapshot``; an ``ICodeModelBuilder`` turns that
snapshot into the analysis representation consumed by the SCAN stage.
Today the only implementation is the Python AST builder; a future CPG
implementation can register itself without touching the rest of the system.
"""

import logging
from abc import ABC, abstractmethod
from typing import ClassVar

from app.core.contracts import CodeModel, ProjectSnapshot

logger = logging.getLogger(__name__)

BUILDERS: dict[str, type["ICodeModelBuilder"]] = {}


def register_builder(cls: type["ICodeModelBuilder"]) -> type["ICodeModelBuilder"]:
    BUILDERS[cls.language] = cls
    logger.debug("registered code model builder for language=%s", cls.language)
    return cls


def get_builder(language: str) -> "ICodeModelBuilder":
    try:
        return BUILDERS[language]()
    except KeyError:
        raise ValueError(f"no code model builder registered for language={language!r}")


class ICodeModelBuilder(ABC):
    """Builds an analysis-ready code model from a project snapshot."""

    language: ClassVar[str]

    @abstractmethod
    def build(self, snapshot: ProjectSnapshot) -> CodeModel:
        """Return the analysis representation for the given snapshot."""
