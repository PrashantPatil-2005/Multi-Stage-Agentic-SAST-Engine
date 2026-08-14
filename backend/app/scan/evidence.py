"""Evidence building from actual parsed source.

All snippets come from the repository source text (``ast.get_source_segment``
or the raw line). Nothing here can invent code: if the source does not
contain a snippet, the evidence reflects what is actually there.
"""

import ast

from app.scan.models import Evidence, SinkRef, SourceRef, TaintStep

MAX_SNIPPET_CHARS = 200


def line_text(source: str, line: int) -> str:
    """Return the stripped text of ``line`` (1-based) from ``source``."""
    try:
        lines = source.splitlines()
    except (ValueError, UnicodeError):
        return ""
    if not (0 < line <= len(lines)):
        return ""
    return lines[line - 1].strip()[:MAX_SNIPPET_CHARS]


def source_segment(source: str, node: ast.AST) -> str:
    """Exact source slice for ``node``, falling back to its line text."""
    segment = ast.get_source_segment(source, node)
    if segment is None:
        return line_text(source, node.lineno)
    return segment.strip()[:MAX_SNIPPET_CHARS]


class EvidenceBuilder:
    def build(
        self,
        source: str,
        source_ref: SourceRef,
        sink_ref: SinkRef,
        taint_path: list[TaintStep],
        sanitizer_observations: list[str],
    ) -> Evidence:
        return Evidence(
            source_snippet=source_ref.snippet,
            sink_snippet=sink_ref.snippet,
            taint_path=taint_path,
            relevant_lines=sorted({step.line for step in taint_path}),
            sanitizer_observations=sanitizer_observations,
        )
