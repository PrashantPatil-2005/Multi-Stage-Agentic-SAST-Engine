"""Cross-repository finding deduplication tests."""

import pytest

from app.dedup.fingerprint import FindingFingerprintBuilder, normalize_snippet
from app.dedup.service import DeduplicationService
from app.scan.models import CandidateFinding, Evidence, SinkRef, SourceRef, TaintStep
from tests.scan_test_helpers import FIXTURES, scan_fixture_files, scan_sources

DEDUP_FIXTURES = FIXTURES / "dedup"


@pytest.fixture(autouse=True)
def clean_dedup_state():
    from app.dedup.service import reset_groups
    from app.validate.store import get_finding_store

    get_finding_store().clear()
    reset_groups()
    yield
    get_finding_store().clear()
    reset_groups()


def _scan_repos() -> list[CandidateFinding]:
    sources = {
        "repository_a/views.py": (
            DEDUP_FIXTURES / "repository_a" / "views.py"
        ).read_text(encoding="utf-8"),
        "repository_b/main.py": (
            DEDUP_FIXTURES / "repository_b" / "main.py"
        ).read_text(encoding="utf-8"),
    }
    return scan_sources(sources).findings


def make_finding(
    finding_id: str,
    vuln_type: str = "sql_injection",
    source_kind: str = "request_param",
    source_snippet: str = "request.args.get('id')",
    sink_kind: str = "sql_execute",
    sink_snippet: str = "cursor.execute(query)",
    steps: list[str] | None = None,
    file: str = "repo/x.py",
    source_line: int = 10,
    sink_line: int = 12,
) -> CandidateFinding:
    steps = steps or ["source", "string_construction", "sink"]
    snippets = (
        [source_snippet]
        + ["intermediate"] * max(0, len(steps) - 2)
        + [sink_snippet]
    )
    path = [
        TaintStep(
            file=file,
            line=source_line if i == 0 else sink_line,
            snippet=snippet,
            step_type=step_type,
        )
        for i, (step_type, snippet) in enumerate(zip(steps, snippets))
    ]
    return CandidateFinding(
        id=finding_id,
        vulnerability_type=vuln_type,
        severity="high",
        confidence=0.7,
        source=SourceRef(file=file, line=source_line, snippet=source_snippet, kind=source_kind),
        sink=SinkRef(file=file, line=sink_line, snippet=sink_snippet, kind=sink_kind),
        taint_path=path,
        evidence=Evidence(
            source_snippet=source_snippet,
            sink_snippet=sink_snippet,
            taint_path=path,
            relevant_lines=[source_line, sink_line],
            sanitizer_observations=[],
        ),
    )


def test_identical_findings_deduplicate():
    finding = make_finding("a" * 64)
    result = DeduplicationService().deduplicate([finding, finding, finding])
    assert result.total_findings == 3
    assert result.unique_findings == 1
    assert result.groups[0].occurrence_count == 3
    assert result.groups[0].member_finding_ids == ["a" * 64] * 3


def test_different_repositories_deduplicate():
    findings = _scan_repos()
    assert len(findings) == 2
    assert all(f.vulnerability_type == "sql_injection" for f in findings)
    result = DeduplicationService().deduplicate(findings)
    assert result.unique_findings == 1
    assert result.duplicate_findings == 1
    group = result.groups[0]
    assert group.occurrence_count == 2
    assert group.repositories == ["repository_a", "repository_b"]


def test_different_variable_names_deduplicate():
    a = make_finding("a" * 64, source_snippet="request.args.get('user_id')")
    b = make_finding("b" * 64, source_snippet="request.args.get('owner_id')")
    result = DeduplicationService().deduplicate([a, b])
    assert result.unique_findings == 1
    assert result.groups[0].occurrence_count == 2


def test_different_line_numbers_deduplicate():
    a = make_finding("a" * 64, source_line=10, sink_line=12)
    b = make_finding("b" * 64, source_line=200, sink_line=250)
    result = DeduplicationService().deduplicate([a, b])
    assert result.unique_findings == 1


def test_different_filenames_deduplicate():
    a = make_finding("a" * 64, file="repo_a/views.py")
    b = make_finding("b" * 64, file="repo_b/main.py")
    result = DeduplicationService().deduplicate([a, b])
    assert result.unique_findings == 1


def test_sqli_vs_cmdi_remain_separate():
    findings = scan_fixture_files("app.py").findings
    sqli = next(f for f in findings if f.vulnerability_type == "sql_injection")
    cmdi = next(f for f in findings if f.vulnerability_type == "command_injection")
    result = DeduplicationService().deduplicate([sqli, cmdi])
    assert result.unique_findings == 2
    assert {g.vulnerability_type for g in result.groups} == {
        "sql_injection",
        "command_injection",
    }


def test_materially_different_sink_remains_separate():
    a = make_finding("a" * 64, sink_snippet="cursor.execute(query)")
    b = make_finding(
        "b" * 64,
        sink_snippet="cursor.execute(query, params)",
    )
    result = DeduplicationService().deduplicate([a, b])
    assert result.unique_findings == 2


def test_fingerprint_deterministic():
    finding = make_finding("a" * 64)
    builder = FindingFingerprintBuilder()
    assert builder.build(finding).value == builder.build(finding).value
    assert builder.build(make_finding("b" * 64)).value == builder.build(
        make_finding("c" * 64)
    ).value


def test_fingerprint_has_no_absolute_path():
    finding = make_finding(
        "a" * 64,
        file="C:/Users/Prash/Desktop/SAST/backend/tests/fixtures/vulnerable_python_app/app.py",
    )
    fingerprint = FindingFingerprintBuilder().build(finding)
    assert "C:/Users/Prash" not in fingerprint.structural_signature
    assert "vulnerable_python_app" not in fingerprint.structural_signature


def test_fingerprint_has_no_line_number():
    finding = make_finding("a" * 64, source_line=12, sink_line=15)
    fingerprint = FindingFingerprintBuilder().build(finding)
    assert "12" not in fingerprint.structural_signature
    assert "15" not in fingerprint.structural_signature


def test_fingerprint_has_no_finding_id():
    finding = make_finding("a" * 64)
    fingerprint = FindingFingerprintBuilder().build(finding)
    assert "a" * 64 not in fingerprint.structural_signature
    assert fingerprint.value != finding.id


def test_fingerprint_contains_no_literal_secrets():
    finding = make_finding(
        "a" * 64,
        source_snippet="api_key = 'sk-1234567890abcdef'",
        sink_snippet="cursor.execute(query)",
    )
    fingerprint = FindingFingerprintBuilder().build(finding)
    assert "sk-1234567890abcdef" not in fingerprint.structural_signature
    assert "_lit_" in fingerprint.normalized_source


def test_canonical_finding_selection_deterministic():
    findings = _scan_repos()
    service = DeduplicationService()
    first = service.deduplicate(findings)
    second = service.deduplicate(findings)
    expected = min(f.id for f in findings)
    assert first.groups[0].canonical_finding_id == expected
    assert second.groups[0].canonical_finding_id == expected


def test_all_original_findings_preserved():
    findings = _scan_repos()
    result = DeduplicationService().deduplicate(findings)
    members = result.groups[0].member_finding_ids
    assert sorted(members) == sorted(f.id for f in findings)
    assert result.groups[0].representative_finding.id == min(f.id for f in findings)


def test_duplicate_count_correct():
    findings = _scan_repos()
    result = DeduplicationService().deduplicate(findings)
    assert result.total_findings == 2
    assert result.unique_findings == 1
    assert result.duplicate_findings == 1


def test_repository_count_correct():
    findings = _scan_repos()
    group = DeduplicationService().deduplicate(findings).groups[0]
    assert group.repositories == ["repository_a", "repository_b"]


def test_match_reasons_generated():
    findings = _scan_repos()
    group = DeduplicationService().deduplicate(findings).groups[0]
    assert group.match_reasons == [
        "same vulnerability type",
        "same source category",
        "same sink category",
        "same normalized source pattern",
        "same normalized sink pattern",
        "same normalized taint structure",
    ]


def test_empty_input_handled():
    result = DeduplicationService().deduplicate([])
    assert result.total_findings == 0
    assert result.unique_findings == 0
    assert result.duplicate_findings == 0
    assert result.groups == []


def test_single_finding_handled():
    finding = make_finding("a" * 64)
    result = DeduplicationService().deduplicate([finding])
    assert result.total_findings == 1
    assert result.unique_findings == 1
    assert result.duplicate_findings == 0
    group = result.groups[0]
    assert group.occurrence_count == 1
    assert group.canonical_finding_id == finding.id
    assert group.representative_finding.id == finding.id


def test_normalization_ignores_identifier_names():
    assert normalize_snippet("request.args.get('user_id')") == normalize_snippet(
        "request.args.get('owner_id')"
    )
    assert normalize_snippet("query = f\"{user_id}\"") == normalize_snippet(
        "sql = f\"{account_id}\""
    )
    assert normalize_snippet("cursor.execute(query)") == normalize_snippet(
        "db.execute(sql)"
    )


def test_incremental_runs_merge_across_repositories():
    """A later run over one repository joins the earlier group of the other.

    Regression: previously every run replaced the registry with only the
    submitted findings, so deduplicating repository B alone dropped
    repository A's member from the shared group.
    """
    from app.dedup.service import lookup_group
    from app.validate.store import get_finding_store

    store = get_finding_store()
    try:
        findings = _scan_repos()
        store.add(findings[0])
        store.add(findings[1])
        service = DeduplicationService()
        first = service.deduplicate([findings[0]])
        assert first.groups[0].occurrence_count == 1
        second = service.deduplicate([findings[1]])
        group = second.groups[0]
        assert group.occurrence_count == 2
        assert group.member_finding_ids == sorted(f.id for f in findings)
        assert group.repositories == ["repository_a", "repository_b"]
        assert lookup_group(group.fingerprint).occurrence_count == 2
    finally:
        store.clear()


def test_merge_drops_members_removed_from_finding_store():
    """Deleted findings (e.g. a removed repository) leave their group."""
    from app.dedup.service import lookup_group
    from app.validate.store import get_finding_store

    store = get_finding_store()
    try:
        findings = _scan_repos()
        store.add(findings[0])
        store.add(findings[1])
        service = DeduplicationService()
        service.deduplicate(findings)
        store.remove(findings[0].id)
        group = service.deduplicate([findings[1]]).groups[0]
        assert group.occurrence_count == 1
        assert group.member_finding_ids == [findings[1].id]
        assert lookup_group(group.fingerprint).occurrence_count == 1
    finally:
        store.clear()


def test_untouched_groups_survive_other_runs():
    """Groups not touched by a run stay registered and persisted."""
    from app.dedup.service import lookup_group
    from app.validate.store import get_finding_store

    store = get_finding_store()
    try:
        findings = _scan_repos()
        store.add(findings[0])
        store.add(findings[1])
        cmdi = make_finding(
            "c" * 64,
            vuln_type="command_injection",
            source_kind="function_param",
            sink_kind="shell_exec",
            source_snippet="def run(cmd):",
            sink_snippet="subprocess.run(cmd, shell=True)",
        )
        store.add(cmdi)
        service = DeduplicationService()
        first = service.deduplicate(findings)
        second = service.deduplicate([cmdi])
        assert len(second.groups) == 1
        surviving = lookup_group(first.groups[0].fingerprint)
        assert surviving is not None
        assert surviving.occurrence_count == 2
    finally:
        store.clear()