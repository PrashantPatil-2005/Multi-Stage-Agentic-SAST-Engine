"""Python AST implementation of the ICodeModelBuilder interface.

This is the current analysis representation: structured data extracted
from the stdlib ``ast`` module. A future CPG builder can register itself
the same way without changing the SCAN stage contract.
"""

import logging
from datetime import datetime, timezone

from app.core.contracts import CodeModel, ProjectSnapshot
from app.prepare.base import ICodeModelBuilder, register_builder

logger = logging.getLogger(__name__)


def _module_name(path: str) -> str:
    """Map a repo-relative path like ``app/db.py`` to ``app.db``."""
    if path.endswith(".py"):
        path = path[:-3]
    return path.replace("/", ".").replace("\\", ".")


@register_builder
class PythonASTCodeModelBuilder(ICodeModelBuilder):
    language = "python"

    def build(self, snapshot: ProjectSnapshot) -> CodeModel:
        module_map = {_module_name(f.path): f.path for f in snapshot.files}
        function_index = [f for file in snapshot.files for f in file.functions]
        model = CodeModel(
            language=snapshot.language,
            files=snapshot.files,
            module_map=module_map,
            function_index=function_index,
            built_at=datetime.now(timezone.utc),
        )
        logger.info(
            "built PythonASTCodeModel: %d files, %d modules, %d functions",
            len(model.files),
            len(model.module_map),
            len(model.function_index),
        )
        return model
