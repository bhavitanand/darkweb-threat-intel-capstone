from darklens.collectors import github_advisories as g


def test_parse_real_shape_and_skips_withdrawn_and_junk():
    data = [
        {"ghsa_id": "GHSA-aaaa", "cve_id": "CVE-2026-1", "summary": "RCE in left-pad", "severity": "critical",
         "published_at": "2026-11-20T10:00:00Z", "html_url": "https://github.com/advisories/GHSA-aaaa",
         "vulnerabilities": [{"package": {"name": "left-pad"}}, {"package": None}, "x"], "description": "d"},
        {"ghsa_id": "GHSA-bbbb", "withdrawn_at": "2026-11-21", "summary": "gone"},
        {"summary": "no id"}, None, "junk", {"ghsa_id": 5, "summary": ["odd"], "vulnerabilities": "bad"},
    ]
    items = g.parse(data)
    assert [i.meta["ghsa"] for i in items] == ["GHSA-aaaa", "5"]
    assert items[0].kind == "advisory" and items[0].seen_at == "2026-11-20" and items[0].actor == "left-pad"
    assert "CVE-2026-1" in items[0].title


def test_parse_limits_and_rejects_wrong_shape():
    import pytest
    many = [{"ghsa_id": f"G{i}", "summary": "s"} for i in range(10)]
    assert len(g.parse(many, limit=3)) == 3 and g.parse(many, limit=0) == []
    with pytest.raises(RuntimeError):
        g.parse({"message": "rate limited"})


def test_offline_makes_no_request():
    assert g.fetch(offline=True) == []
