import pytest

from generators import GENERATORS, generate_token


def test_generate_token_unknown_kind_raises():
    with pytest.raises(ValueError):
        generate_token("not_a_real_kind")


def test_every_registered_kind_generates_successfully():
    for kind in GENERATORS:
        token = generate_token(kind)
        assert token["type"] == kind
        assert "id" in token
        assert "created_at" in token


def test_aws_key_format():
    token = generate_token("aws_key")
    assert token["access_key_id"].startswith("AKIA")
    assert len(token["access_key_id"]) == 20
    assert len(token["secret_access_key"]) > 0


def test_api_token_format():
    token = generate_token("api_token")
    assert token["token"].startswith(("sk_live_", "api_", "pat_"))


def test_ssh_keypair_looks_like_pem():
    token = generate_token("ssh_private_key")
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" in token["private_key"]
    assert "-----END OPENSSH PRIVATE KEY-----" in token["private_key"]


def test_db_dump_row_count_matches_request():
    from generators import gen_db_dump
    dump = gen_db_dump(rows=10)
    lines = dump["content"].splitlines()
    assert lines[0] == "id,username,email,password_hash,credit_card_last4"
    assert len(lines) == 11  # header + 10 rows


def test_generic_credential_format():
    token = generate_token("credential")
    assert token["username"].startswith("svc_")
    assert len(token["password"]) > 0


def test_generated_tokens_are_unique():
    ids = {generate_token("api_token")["id"] for _ in range(20)}
    assert len(ids) == 20
