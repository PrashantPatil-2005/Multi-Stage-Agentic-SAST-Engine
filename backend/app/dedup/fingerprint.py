"""Finding fingerprinting (cross-repository deduplication identity).

Design
------

The fingerprint captures only *structural* information:

* vulnerability type
* source category (``SourceRef.kind``, e.g. ``request_param``)
* sink category (``SinkRef.kind``, e.g. ``sql_execute``)
* normalized source snippet
* normalized sink snippet
* normalized taint step types (e.g. ``source->string_construction->sink``)

It deliberately does NOT include repository id, absolute file path, line
number, finding id, timestamp, variable identifiers or literal values, so
the same vulnerability after code movement, renaming or refactoring still
produces the same fingerprint.

Normalization
-------------

Snippets are re-tokenized with :mod:`tokenize` and mapped to a fixed
vocabulary:

* identifiers  -> ``_n_`` (variable placeholder)
* attribute names after a dot are kept: ``cursor.execute`` -> ``_n_.execute``
* string / number / f-string literal text -> ``_lit_``
* operators and delimiters are kept as-is

Whitespace is collapsed. Because literal values are replaced by ``_lit_``,
the fingerprint contains structural metadata only: no source-code secrets,
API keys, passwords or credentials can end up in it.
"""

import hashlib
import io
import tokenize

from app.dedup.models import FindingFingerprint
from app.scan.models import CandidateFinding

_LITERAL_TYPES = frozenset(
    {
        tokenize.NUMBER,
        tokenize.STRING,
        getattr(tokenize, "FSTRING_START", -1),
        getattr(tokenize, "FSTRING_MIDDLE", -1),
        getattr(tokenize, "FSTRING_END", -1),
    }
)


def normalize_snippet(snippet: str) -> str:
    """Token-level normalization of one source snippet.

    Identifiers become ``_n_`` (attribute names after a dot are kept),
    literals become ``_lit_``, operators survive verbatim, everything else
    (comments, indentation, newlines) is dropped.
    """
    if not snippet or not snippet.strip():
        return ""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(snippet).readline))
    except (tokenize.TokenError, IndentationError, ValueError):
        return "_unparsable_"
    parts: list[str] = []
    i = 0
    while i < len(tokens):
        ttype, tstr = tokens[i].type, tokens[i].string
        if ttype == tokenize.OP:
            if (
                tstr == "."
                and i + 1 < len(tokens)
                and tokens[i + 1].type == tokenize.NAME
            ):
                parts.append(f".{tokens[i + 1].string}")
                i += 2
                continue
            parts.append(tstr)
        elif ttype == tokenize.NAME:
            parts.append("_n_")
        elif ttype in _LITERAL_TYPES:
            parts.append("_lit_")
        i += 1
    return " ".join(parts)


class FindingFingerprintBuilder:
    """Builds a deterministic, repository-agnostic fingerprint per finding."""

    def build(self, finding: CandidateFinding) -> FindingFingerprint:
        source_kind = finding.source.kind
        sink_kind = finding.sink.kind
        norm_source = normalize_snippet(finding.source.snippet)
        norm_sink = normalize_snippet(finding.sink.snippet)
        taint_structure = "->".join(step.step_type for step in finding.taint_path)
        signature = "|".join(
            [
                finding.vulnerability_type,
                source_kind,
                sink_kind,
                norm_source,
                norm_sink,
                taint_structure,
            ]
        )
        return FindingFingerprint(
            value=hashlib.sha256(signature.encode("utf-8")).hexdigest(),
            structural_signature=signature,
            vulnerability_type=finding.vulnerability_type,
            source_category=source_kind,
            sink_category=sink_kind,
            normalized_source=norm_source,
            normalized_sink=norm_sink,
            taint_structure=taint_structure,
        )