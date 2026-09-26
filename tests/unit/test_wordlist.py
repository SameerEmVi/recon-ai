"""
Tests for the persistent reconnaissance learning system:
  - recon.vocabulary   (pure extraction / normalization / quality / scoring)
  - database.knowledge_base (multi-scope learn / dedup / ranking / export / stats)

DB tests use in-memory SQLite via aiosqlite — no PostgreSQL required.
"""

from __future__ import annotations

import uuid

import pytest

from database.knowledge_base import KnowledgeBase
from database.session import drop_db, init_db, make_engine, make_session_factory
from recon import vocabulary as V
from recon.vocabulary import (
    API_PATHS,
    API_VERSIONS,
    DIRECTORIES,
    ENDPOINTS,
    FILES,
    PARAM_VALUES,
    PARAMETERS,
    SCOPE_GLOBAL,
    SCOPE_TARGET,
    SCOPE_TECHNOLOGY,
    Candidate,
)

DB_URL = "sqlite+aiosqlite://"


@pytest.fixture
async def session():
    engine = make_engine(DB_URL)
    await init_db(engine)
    factory = make_session_factory(engine)
    async with factory() as s:
        yield s
    await drop_db(engine)
    await engine.dispose()


# ── extraction ─────────────────────────────────────────────────────────────

def test_extract_from_path_core_example():
    """The spec example: /api/v3/internal/export."""
    cands = V.extract_from_path("/api/v3/internal/export")
    by_cat: dict[str, set[str]] = {}
    for c in cands:
        by_cat.setdefault(c.category, set()).add(c.value)

    assert "v3" in by_cat[API_VERSIONS]
    # api path tokens include api, v3, internal, export
    assert {"api", "v3", "internal", "export"} <= by_cat[API_PATHS]
    # non-terminal, non-version segments are directories
    assert "internal" in by_cat[DIRECTORIES]
    # terminal segment is an endpoint/resource
    assert "export" in by_cat[ENDPOINTS]


def test_extract_from_path_file_and_endpoint():
    cands = V.extract_from_path("https://x.com/reports/export.json")
    files = {c.value for c in cands if c.category == FILES}
    endpoints = {c.value for c in cands if c.category == ENDPOINTS}
    dirs = {c.value for c in cands if c.category == DIRECTORIES}
    assert "export.json" in files
    assert "export" in endpoints          # stem of the file
    assert "reports" in dirs


def test_extract_from_parameter_name_and_value():
    cands = V.extract_from_parameter("sort", "asc", "https://x.com/list?sort=asc")
    names = {c.value for c in cands if c.category == PARAMETERS}
    values = {c.value for c in cands if c.category == PARAM_VALUES}
    assert "sort" in names
    assert "asc" in values


def test_extract_openapi_path_classified():
    cands = V.extract_from_path("https://x.com/v3/api-docs")
    assert any(c.category == V.OPENAPI_PATHS for c in cands)


def test_extract_js_identifiers_and_graphql():
    body = 'function getUserProfile(){} const API_BASE="/api/v2/users"; query CurrentUser { id }'
    cands = V.extract_from_js(body)
    idents = {c.value for c in cands if c.category == V.JS_IDENTIFIERS}
    gql = {c.value for c in cands if c.category == V.GRAPHQL_NAMES}
    assert "getUserProfile" in idents
    assert "CurrentUser" in gql
    # the referenced JS URL is decomposed into api-path tokens
    assert any(c.category == API_PATHS and c.value == "users" for c in cands)


def test_extract_cloud_patterns():
    cands = V.extract_cloud_patterns("acme-prod-backups.s3.amazonaws.com")
    vals = {c.value for c in cands}
    assert {"acme", "prod", "backups"} <= vals


# ── normalization ────────────────────────────────────────────────────────────

def test_normalize_directories_lowercased():
    assert V.normalize("/API/", DIRECTORIES) == "api"


def test_normalize_files_preserve_case():
    assert V.normalize("exportCsv.php", FILES) == "exportCsv.php"


def test_normalize_strips_and_caps():
    assert V.normalize("  /admin/  ", DIRECTORIES) == "admin"
    assert V.normalize("x" * 200, DIRECTORIES) == "x" * V._MAX_TOKEN


# ── quality filter ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,category", [
    ("admin", DIRECTORIES),
    ("export", ENDPOINTS),
    ("getUser", V.JS_IDENTIFIERS),
    ("v2", API_VERSIONS),
])
def test_is_quality_accepts_real_words(value, category):
    assert V.is_quality(value, category) is True


@pytest.mark.parametrize("value,category", [
    ("123456", DIRECTORIES),                                   # numeric id
    ("550e8400-e29b-41d4-a716-446655440000", DIRECTORIES),     # uuid
    ("d41d8cd98f00b204e9800998ecf8427e", FILES),               # md5 hash
    ("the", DIRECTORIES),                                      # stop word
    ("a", DIRECTORIES),                                        # too short
    ("logo.png", FILES),                                       # static asset
    ("app.4f3a2b1c.js", FILES),                                # hashed asset chunk
    ("x" * 80, DIRECTORIES),                                   # oversized
    ("return", V.JS_IDENTIFIERS),                              # reserved word
])
def test_is_quality_rejects_garbage(value, category):
    assert V.is_quality(value, category) is False


@pytest.mark.parametrize("value,ok", [
    ("asc", True), ("json", True), ("en", True), ("true", True),
    ("user@example.com", False),                               # PII/email
    ("a1b2c3d4e5f60718", False),                               # hex blob / token
    ("dGhpcyBpcyBhIHNlY3JldA", False),                         # high-entropy blob
    ("12345", False),                                          # numeric id
])
def test_is_safe_value(value, ok):
    assert V.is_safe_value(value) is ok


# ── confidence & ranking ───────────────────────────────────────────────────

def test_confidence_breadth_beats_frequency():
    # Seen on 5 targets once each vs 1 target 5 times: breadth should score higher.
    broad = V.confidence(target_count=5, occurrence_count=5)
    deep = V.confidence(target_count=1, occurrence_count=9)
    assert broad > deep
    assert 0.0 <= broad <= 1.0 and 0.0 <= deep <= 1.0


def test_confidence_monotonic():
    assert V.confidence(1, 1) < V.confidence(3, 3) < V.confidence(10, 20)


def test_order_for_wordlist_ranks_and_dedups():
    rows = [
        {"value": "rare", "target_count": 1, "occurrence_count": 1, "confidence": 0.5},
        {"value": "common", "target_count": 9, "occurrence_count": 30, "confidence": 0.95},
        {"value": "common", "target_count": 9, "occurrence_count": 30, "confidence": 0.95},
        {"value": "mid", "target_count": 3, "occurrence_count": 3, "confidence": 0.7},
    ]
    out = V.order_for_wordlist(rows)
    assert out == ["common", "mid", "rare"]           # ranked, de-duped


# ── KnowledgeBase: learn / dedup / scopes ────────────────────────────────────

async def test_learn_new_then_known(session):
    kb = KnowledgeBase(session)
    scan = uuid.uuid4()
    c = Candidate("admin", DIRECTORIES)

    r1 = await kb.learn(c, scan_domain="a.com", source_scan_id=scan)
    novelties = {(x.scope_type, x.novelty) for x in r1}
    assert (SCOPE_GLOBAL, "NEW") in novelties
    assert (SCOPE_TARGET, "NEW") in novelties

    # Same value, same target → KNOWN, occurrence bumps, target_count stays 1.
    r2 = await kb.learn(c, scan_domain="a.com", source_scan_id=scan)
    assert all(x.novelty == "KNOWN" for x in r2)

    words = await kb.generate_wordlist(DIRECTORIES, scope_type=SCOPE_GLOBAL)
    assert words == ["admin"]                          # deduped to one row


async def test_learn_breadth_increases_target_count(session):
    kb = KnowledgeBase(session)
    c = Candidate("export", ENDPOINTS)
    await kb.learn(c, scan_domain="a.com")
    await kb.learn(c, scan_domain="b.com")
    await kb.learn(c, scan_domain="b.com")             # repeat target — no double count

    rows = await kb._repo.list_items(SCOPE_GLOBAL, "", ENDPOINTS)
    assert len(rows) == 1
    assert rows[0].target_count == 2                   # a.com + b.com
    assert rows[0].occurrence_count == 3               # three sightings


async def test_technology_scope_populated(session):
    kb = KnowledgeBase(session)
    c = Candidate("wp-admin", DIRECTORIES, context="WordPress")
    await kb.learn(c, scan_domain="a.com")

    stats = await kb.stats()
    assert stats["by_scope"].get(SCOPE_TECHNOLOGY, 0) >= 1
    tech_words = await kb.generate_wordlist(
        DIRECTORIES, scope_type=SCOPE_TECHNOLOGY, scope_key="wordpress"
    )
    assert "wp-admin" in tech_words


async def test_learn_rejects_low_quality(session):
    kb = KnowledgeBase(session)
    assert await kb.learn(Candidate("123456", DIRECTORIES), scan_domain="a.com") == []
    stats = await kb.stats()
    assert stats["total"] == 0


# ── KnowledgeBase: filtering / export ────────────────────────────────────────

async def test_generate_wordlist_min_confidence_filter(session):
    kb = KnowledgeBase(session)
    # "broad" learned across 3 targets (higher confidence); "narrow" on 1.
    for dom in ("a.com", "b.com", "c.com"):
        await kb.learn(Candidate("broad", DIRECTORIES), scan_domain=dom)
    await kb.learn(Candidate("narrow", DIRECTORIES), scan_domain="a.com")

    all_words = await kb.generate_wordlist(DIRECTORIES)
    assert set(all_words) == {"broad", "narrow"}
    assert all_words[0] == "broad"                     # ranked first (more targets)

    filtered = await kb.generate_wordlist(DIRECTORIES, min_target_count=2)
    assert filtered == ["broad"]


async def test_export_to_file(session, tmp_path):
    kb = KnowledgeBase(session)
    await kb.learn(Candidate("admin", DIRECTORIES), scan_domain="a.com")
    await kb.learn(Candidate("login", DIRECTORIES), scan_domain="a.com")

    out = tmp_path / "dirs.txt"
    n = await kb.export_to_file(DIRECTORIES, str(out))
    assert n == 2
    lines = out.read_text().splitlines()
    assert set(lines) == {"admin", "login"}


async def test_stats_by_category_and_scope(session):
    kb = KnowledgeBase(session)
    await kb.learn(Candidate("admin", DIRECTORIES), scan_domain="a.com")
    await kb.learn(Candidate("export.json", FILES), scan_domain="a.com")

    stats = await kb.stats()
    assert stats["by_category"].get(DIRECTORIES, 0) >= 1
    assert stats["by_category"].get(FILES, 0) >= 1
    assert stats["by_scope"].get(SCOPE_GLOBAL, 0) >= 2
