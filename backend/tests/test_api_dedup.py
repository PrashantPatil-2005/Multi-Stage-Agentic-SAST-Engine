"""Cross-repository deduplication API tests."""

import pytest

from app.dedup.service import reset_groups
from app.validate.store import get_finding_store
from tests.scan_test_helpers import FIXTURES, scan_sources

DEDUP_FIXTURES = FIXTURES / "dedup"


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    reset_groups()
    yield
    get_finding_store().clear()
    reset_groups()


@pytest.fixture
def registered_cross_repo():
    sources = {
        "repository_a/views.py": (
            DEDUP_FIXTURES / "repository_a" / "views.py"
        ).read_text(encoding="utf-8"),
        "repository_b/main.py": (
            DEDUP_FIXTURES / "repository_b" / "main.py"
        ).read_text(encoding="utf-8"),
    }
    report = scan_sources(sources)
    get_finding_store().add_report(report)
    return report


def test_dedup_routes_registered(client):
    paths = client.app.openapi()["paths"]
    assert "/api/deduplicate" in paths
    assert "post" in paths["/api/deduplicate"]
    assert "/api/deduplication/{fingerprint}" in paths
    assert "get" in paths["/api/deduplication/{fingerprint}"]


def test_post_deduplicate_groups_cross_repo(client, registered_cross_repo):
    ids = [f.id for f in registered_cross_repo.findings]
    response = client.post("/api/deduplicate", json={"finding_ids": ids})
    assert response.status_code == 200
    body = response.json()
    assert body["total_findings"] == 2
    assert body["unique_findings"] == 1
    assert body["duplicate_findings"] == 1
    group = body["groups"][0]
    assert group["occurrence_count"] == 2
    assert group["repositories"] == ["repository_a", "repository_b"]
    assert group["vulnerability_type"] == "sql_injection"
    assert sorted(group["member_finding_ids"]) == sorted(ids)
    assert group["canonical_finding_id"] == min(ids)
    assert group["match_reasons"][0] == "same vulnerability type"


def test_post_deduplicate_unknown_finding_404(client, registered_cross_repo):
    known = registered_cross_repo.findings[0].id
    response = client.post(
        "/api/deduplicate", json={"finding_ids": [known, "does-not-exist"]}
    )
    assert response.status_code == 404
    assert "does-not-exist" in response.json()["detail"]


def test_post_deduplicate_empty_list(client):
    response = client.post("/api/deduplicate", json={"finding_ids": []})
    assert response.status_code == 200
    body = response.json()
    assert body["total_findings"] == 0
    assert body["unique_findings"] == 0
    assert body["groups"] == []


def test_get_group_by_fingerprint(client, registered_cross_repo):
    ids = [f.id for f in registered_cross_repo.findings]
    result = client.post("/api/deduplicate", json={"finding_ids": ids}).json()
    fingerprint = result["groups"][0]["fingerprint"]
    response = client.get(f"/api/deduplication/{fingerprint}")
    assert response.status_code == 200
    body = response.json()
    assert body["fingerprint"] == fingerprint
    assert body["occurrence_count"] == 2
    assert body["canonical_finding_id"] == min(ids)


def test_get_group_unknown_fingerprint_404(client):
    response = client.get("/api/deduplication/" + "f" * 64)
    assert response.status_code == 404