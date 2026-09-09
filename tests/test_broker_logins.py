"""Unlimited logins per broker, each with a name — without moving anyone's.

The feature is "let a household keep two people's accounts side by side". The
risk in it is entirely in the upgrade: three of these brokers already hold
several logins in one variable, one numbers them from 1, and five have only
ever held a single set of keys. Get the compatibility wrong and an existing
user is logged out, re-prompted for 2FA, or — worst — has their account labels
change, which silently breaks the journal's buy/sell netting.

So most of what is asserted here is that NOTHING MOVED: login 1 reads the same
variable it always did, keeps the same label, and keeps the same session
directory. The new behaviour is only ever additive, at index 2 and up.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import broker_logins as BL


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """No stray real credentials from the developer's own .env."""
    for schema in BL.SCHEMAS.values():
        if schema.blob:
            monkeypatch.delenv(schema.blob, raising=False)
        for idx in range(1, 6):
            for f in schema.fields:
                monkeypatch.delenv(BL.env_key(schema.broker, f.name, idx),
                                   raising=False)
            monkeypatch.delenv(BL.tag_key(schema.broker, idx), raising=False)


# ------------------------------------------------------- nothing moved

def test_login_one_still_reads_the_key_it_always_did(monkeypatch):
    monkeypatch.setenv("CHASE_USERNAME", "first-login")
    monkeypatch.setenv("CHASE_PASSWORD", "hunter2")

    (one,) = BL.logins("chase")
    assert one.idx == 1
    assert one.get("username") == "first-login"
    assert one.complete


def test_login_one_adds_nothing_to_its_account_labels():
    """The compatibility rule that protects the journal. account_id strings
    are what trades.json nets buys against sells on — see the module docstring
    of broker_logins."""
    assert BL.Login(broker="chase", idx=1).label_prefix == ""
    assert BL.Login(broker="chase", idx=2).label_prefix == "Chase 2 · "


def test_login_one_keeps_its_session_directory():
    """An upgrade that re-prompts 2FA on every broker is a broken upgrade."""
    assert BL.session_suffix(1) == ""
    assert BL.session_suffix(2) == "_2"


def test_a_second_login_uses_a_numbered_key(monkeypatch):
    monkeypatch.setenv("CHASE_USERNAME", "first-login")
    monkeypatch.setenv("CHASE_PASSWORD", "hunter2")
    monkeypatch.setenv("CHASE_USERNAME_2", "someone-else")
    monkeypatch.setenv("CHASE_PASSWORD_2", "swordfish")

    one, two = BL.logins("chase")
    assert (one.get("username"), two.get("username")) == ("first-login", "someone-else")
    assert two.label == "Chase 2"


def test_public_is_numbered_from_one_because_it_always_was(monkeypatch):
    """Public's historical key IS PUBLIC_SECRET_TOKEN_1, so it is the one
    broker where login 1 is numbered."""
    assert BL.env_key("public", "token", 1) == "PUBLIC_SECRET_TOKEN_1"
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_1", "tok-a")
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_2", "tok-b")
    assert [l.get("token") for l in BL.logins("public")] == ["tok-a", "tok-b"]


def test_public_is_no_longer_capped_at_three(monkeypatch):
    """The old loop was literally `for i in (1, 2, 3)`."""
    for i in range(1, 8):
        monkeypatch.setenv(f"PUBLIC_SECRET_TOKEN_{i}", f"tok-{i}")
    assert BL.login_count("public") == 7


# ------------------------------------------------------- the three styles

def test_the_list_style_blob_is_still_read(monkeypatch):
    monkeypatch.setenv("FIDELITY", "u1:p1:t1,u2:p2")
    one, two = BL.logins("fidelity")
    assert (one.get("username"), one.get("totp")) == ("u1", "t1")
    assert (two.get("username"), two.get("totp")) == ("u2", "")


def test_the_single_keys_still_work_when_there_is_no_blob(monkeypatch):
    """How every list-style broker was first set up, and still the common case."""
    monkeypatch.setenv("FIDELITY_USERNAME", "solo")
    monkeypatch.setenv("FIDELITY_PASSWORD", "pw")
    (one,) = BL.logins("fidelity")
    assert one.get("username") == "solo"


def test_fennels_comma_separated_emails(monkeypatch):
    monkeypatch.setenv("FENNEL_EMAIL", "a@x.com, b@y.com")
    assert [l.get("email") for l in BL.logins("fennel")] == ["a@x.com", "b@y.com"]


def test_a_blank_login_is_not_a_login(monkeypatch):
    monkeypatch.setenv("BBAE_USER", "")
    monkeypatch.setenv("BBAE_PASSWORD", "")
    assert BL.logins("bbae") == []


def test_a_gap_keeps_the_numbers_either_side_of_it(monkeypatch):
    """Renumbering is how an account label changes without anyone asking, and
    the label is the journal's key. A deleted login 2 must leave login 3 as
    login 3 — closing the gap would rename its accounts and orphan every open
    position recorded under the old name."""
    monkeypatch.setenv("SOFI_USERNAME", "one")
    monkeypatch.setenv("SOFI_PASSWORD", "pw")
    monkeypatch.setenv("SOFI_USERNAME_3", "three")
    monkeypatch.setenv("SOFI_PASSWORD_3", "pw")

    one, three = BL.logins("sofi")
    assert (one.idx, three.idx) == (1, 3)
    assert three.label == "SoFi 3"


def test_an_edit_leaves_every_existing_number_where_it_was(monkeypatch):
    """The save side of the same rule: re-tagging Public 3 must not make it
    Public 2."""
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_1", "a")
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_3", "c")

    rows = BL.as_rows("public")
    rows[1]["tag"] = "the other one"          # tag the one at index 3
    apply(monkeypatch, BL.env_updates("public", rows))

    got = BL.logins("public")
    assert [(l.idx, l.tag) for l in got] == [(1, ""), (3, "the other one")]


def test_a_brand_new_login_fills_the_lowest_free_slot(monkeypatch):
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_1", "a")
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_3", "c")

    rows = BL.as_rows("public") + [{"token": "new", "tag": "third person"}]
    apply(monkeypatch, BL.env_updates("public", rows))

    assert [(l.idx, l.get("token")) for l in BL.logins("public")] == [
        (1, "a"), (2, "new"), (3, "c")]


# ------------------------------------------------------------------ tags

def test_a_tag_names_a_login_without_touching_its_label(monkeypatch):
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_1", "tok")
    monkeypatch.setenv("PUBLIC_TAG_1", "myles")
    (one,) = BL.logins("public")
    assert one.tag == "myles"
    assert one.display == "myles"
    assert one.label == "Public 1"          # unchanged, and still the identifier
    assert one.label_prefix == ""


def test_an_untagged_login_falls_back_to_its_position(monkeypatch):
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_1", "tok")
    (one,) = BL.logins("public")
    assert one.display == "Public 1"


def test_tags_are_listed_once_each_in_first_seen_order(monkeypatch):
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_1", "a")
    monkeypatch.setenv("PUBLIC_TAG_1", "myles")
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_2", "b")
    monkeypatch.setenv("PUBLIC_TAG_2", "myles")
    monkeypatch.setenv("SOFI_USERNAME", "u")
    monkeypatch.setenv("SOFI_PASSWORD", "p")
    monkeypatch.setenv("SOFI_TAG_1", "the other one")
    assert BL.tags() == ["myles", "the other one"]


def test_filtering_by_tag_spans_brokers(monkeypatch):
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_1", "a")
    monkeypatch.setenv("PUBLIC_TAG_1", "myles")
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_2", "b")
    monkeypatch.setenv("PUBLIC_TAG_2", "someone else")
    monkeypatch.setenv("BBAE_USER", "u")
    monkeypatch.setenv("BBAE_PASSWORD", "p")
    monkeypatch.setenv("BBAE_TAG_1", "MYLES")           # case is not identity

    hit = BL.logins_tagged("myles")
    assert sorted(hit) == ["bbae", "public"]
    assert [l.idx for l in hit["public"]] == [1]


# --------------------------------------------------------------- writing

def apply(monkeypatch, updates):
    for key, val in updates.items():
        monkeypatch.setenv(key, val)


def test_saving_two_keyed_logins_writes_both(monkeypatch):
    updates = BL.env_updates("chase", [
        {"username": "first-login", "password": "pw1", "tag": "myles"},
        {"username": "other", "password": "pw2", "tag": "the other one"},
    ])
    assert updates["CHASE_USERNAME"] == "first-login"
    assert updates["CHASE_USERNAME_2"] == "other"
    assert updates["CHASE_TAG_2"] == "the other one"

    apply(monkeypatch, updates)
    assert [l.display for l in BL.logins("chase")] == ["myles", "the other one"]


def test_removing_a_login_blanks_its_keys_rather_than_forgetting_them(monkeypatch):
    """A delete that only stops writing a key leaves the password on disk and
    the broker still logging in with it."""
    monkeypatch.setenv("CHASE_USERNAME", "first-login")
    monkeypatch.setenv("CHASE_PASSWORD", "pw1")
    monkeypatch.setenv("CHASE_USERNAME_2", "other")
    monkeypatch.setenv("CHASE_PASSWORD_2", "pw2")
    monkeypatch.setenv("CHASE_TAG_2", "the other one")

    updates = BL.env_updates("chase", [{"username": "first-login", "password": "pw1"}])
    assert updates["CHASE_USERNAME_2"] == ""
    assert updates["CHASE_PASSWORD_2"] == ""
    assert updates["CHASE_TAG_2"] == ""

    apply(monkeypatch, updates)
    assert BL.login_count("chase") == 1


def test_saving_does_not_append_fifty_empty_variables(monkeypatch):
    """MAX_LOGINS is 50 and every save walks all of them. Only keys that are
    actually in use get blanked, or one save would bloat .env by 150 lines.

    A kept login's own tag is the exception: writing it empty is how you clear
    a name you no longer want.
    """
    updates = BL.env_updates("chase", [{"username": "u", "password": "p"}])
    assert [k for k, v in updates.items() if v == ""] == ["CHASE_TAG_1"]
    assert not [k for k in updates if k.endswith(("_2", "_3", "_4"))]


def test_a_list_style_save_rebuilds_the_blob(monkeypatch):
    updates = BL.env_updates("fidelity", [
        {"username": "u1", "password": "p1", "totp": "t1"},
        {"username": "u2", "password": "p2", "totp": ""},
    ])
    assert updates["FIDELITY"] == "u1:p1:t1,u2:p2"      # no trailing colon

    apply(monkeypatch, updates)
    assert [l.get("username") for l in BL.logins("fidelity")] == ["u1", "u2"]


def test_every_broker_survives_a_round_trip(monkeypatch):
    """as_rows -> env_updates -> back again, for all ten. This is the one that
    catches a schema whose read and write disagree."""
    for broker, schema in BL.SCHEMAS.items():
        rows = [{f.name: f"{f.name}-{i}" for f in schema.fields} | {"tag": f"t{i}"}
                for i in (1, 2)]
        apply(monkeypatch, BL.env_updates(broker, rows))
        got = BL.logins(broker)
        assert len(got) == 2, f"{broker} lost a login"
        assert [l.tag for l in got] == ["t1", "t2"], f"{broker} lost a tag"
        for i, login in enumerate(got, 1):
            for f in schema.fields:
                assert login.get(f.name) == f"{f.name}-{i}", f"{broker}.{f.name}"


def test_every_schema_field_has_a_distinct_env_key():
    """A copy-paste in the table would have two fields share a variable and
    quietly overwrite each other."""
    for broker, schema in BL.SCHEMAS.items():
        keys = [f.env for f in schema.fields]
        assert len(keys) == len(set(keys)), broker
