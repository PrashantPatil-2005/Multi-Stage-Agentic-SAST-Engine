"""Deserialization vulnerability detection rule.

Detects unsafe deserialization of untrusted data through Python's
built-in deserialization APIs:

* ``pickle.loads`` / ``pickle.load`` / ``cPickle.loads`` — arbitrary
  code execution via crafted pickled objects
* ``yaml.load`` with ``Loader=None`` (or no ``Loader`` keyword) —
  arbitrary Python object instantiation
* ``marshal.loads`` / ``marshal.load`` — Python bytecode
  deserialization
* ``shelve.open`` — pickle-based persistence (unsafe on shared data)
* ``jsonpickle.decode`` — third-party pickle-based JSON deserialization
* ``_pickle.loads`` / ``_cPickle.loads`` — internal aliases

Sources: same as other rules — Flask-style request objects plus
poisoned function parameters.

Sinks: the deserialization call sites listed above.

Sanitization: ``yaml.load(data, Loader=yaml.SafeLoader)`` or
``yaml.safe_load(data)`` is safe and not flagged. ``pickle.loads``
has no safe variant and is always flagged when tainted data reaches it.

Severity: **critical** — deserialization of untrusted data enables
remote code execution.

Confidence: request source 0.9 / param source 0.7 (same as other
rules).
"""

import ast
from typing import ClassVar

from app.scan.evidence import source_segment
from app.scan.models import SinkRef, SourceRef, TaintStep
from app.scan.rules import ScanRule
from app.scan.rules.common import request_source, taint_confidence

#: Recognized deserialization APIs: dotted function name -> sink kind.
DESERIALIZATION_SINKS = {
    "pickle.loads": "pickle_loads",
    "pickle.load": "pickle_load",
    "cPickle.loads": "pickle_loads",
    "cPickle.load": "pickle_load",
    "_pickle.loads": "pickle_loads",
    "_pickle.load": "pickle_load",
    "_cPickle.loads": "pickle_loads",
    "_cPickle.load": "pickle_load",
    "marshal.loads": "marshal_loads",
    "marshal.load": "marshal_load",
    "shelve.open": "shelve_open",
    "jsonpickle.decode": "jsonpickle_decode",
    "jsonpickle.loads": "jsonpickle_loads",
}

#: yaml.load is only dangerous when Loader is not provided or is None.
YAML_LOAD_FUNCS = frozenset({"yaml.load", "yaml.unsafe_load"})

#: These are always safe and should never be flagged.
YAML_SAFE_FUNCS = frozenset({"yaml.safe_load", "yaml.safe_load_all"})


class DeserializationRule(ScanRule):
    vulnerability_type: ClassVar[str] = "deserialization"
    severity: ClassVar[str] = "critical"
    poison_params: ClassVar[bool] = True

    # ────────────────────────────────────────────── sources

    def is_source(self, expr: ast.AST, file: str, source: str) -> SourceRef | None:
        return request_source(expr, file, source)

    # ────────────────────────────────────────────── sinks

    def match_sink(self, call: ast.Call, file: str, source: str) -> SinkRef | None:
        func_name = ast.unparse(call.func)

        # Direct deserialization APIs (always dangerous with tainted data)
        if func_name in DESERIALIZATION_SINKS:
            if not call.args:
                return None
            return SinkRef(
                file=file,
                line=call.lineno,
                snippet=source_segment(source, call),
                kind=DESERIALIZATION_SINKS[func_name],
            )

        # yaml.load — dangerous only without safe Loader
        if func_name in YAML_LOAD_FUNCS:
            if not call.args:
                return None
            # Check for Loader keyword
            for keyword in call.keywords:
                if keyword.arg == "Loader":
                    # If Loader is explicitly set to something other than
                    # None, it's likely intentional (could be SafeLoader).
                    # We still flag it unless it's yaml.safe_load.
                    loader_val = ast.unparse(keyword.value)
                    if "SafeLoader" in loader_val or "FullLoader" in loader_val:
                        return None  # sanitized
            return SinkRef(
                file=file,
                line=call.lineno,
                snippet=source_segment(source, call),
                kind="yaml_load",
            )

        # Explicitly safe yaml functions — never flag
        if func_name in YAML_SAFE_FUNCS:
            return None

        return None

    # ────────────────────────────────────────────── sanitization

    def is_sanitized(self, call: ast.Call, sink: SinkRef) -> bool:
        # yaml.load is safe when Loader=yaml.SafeLoader is passed
        if sink.kind == "yaml_load":
            for keyword in call.keywords:
                if keyword.arg == "Loader":
                    loader_val = ast.unparse(keyword.value)
                    if "SafeLoader" in loader_val:
                        return True
        # pickle/marshal/shelve have no safe deserialization variants
        return False

    # ────────────────────────────────────────────── confidence

    def confidence(self, path: list[TaintStep], source_kind: str) -> float:
        return taint_confidence(path, source_kind)
