"""A ',' in a password no longer splits a login in two.

FIDELITY / SCHWAB / ROBINHOOD hold every login in one comma-separated
variable, so "pa,ss" used to read back as login 1 with password "pa" plus a
bogus login 2 called "ss" -- and the broker was signed in with the wrong
password. A blob that would be ambiguous is now written as "b64:" plus each
login base64-encoded; every blob already on disk reads exactly as before.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import broker_logins as BL
import fidelity
import robinhood
import schwab

import app as A


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for schema in BL.SCHEMAS.values():
        if schema.blob:
            monkeypatch.delenv(schema.blob, raising=False)


ROWS = {
    "fidelity": [{"username": "u1", "password": "pa,ss", "totp": "T1"},
                 {"username": "u2", "password": "a:b,c", "totp": ""},
                 {"username": "u3", "password": "plain", "totp": "T3"}],
    "schwab": [{"username": "u1", "password": ",lead,trail,", "totp": "T1"},
               {"username": "u2", "password": "x", "totp": ""}],
    "robinhood": [{"username": "u1", "password": "p,1"},
                  {"username": "u2", "password": "p2"}],
}


@pytest.mark.parametrize("broker", sorted(ROWS))
def test_the_editor_round_trips_a_comma_password(broker, monkeypatch):
    blob = BL.env_updates(broker, ROWS[broker])[BL.SCHEMAS[broker].blob]
    assert blob.startswith("b64:")
    # What .env actually stores, through python-dotenv, comes back unchanged.
    monkeypatch.setenv(BL.SCHEMAS[broker].blob, blob)
    got = BL.logins(broker)
    assert [l.idx for l in got] == list(range(1, len(ROWS[broker]) + 1))
    assert [l.get("password") for l in got] == [r["password"] for r in ROWS[broker]]
    # Re-saving what was read is stable.
    assert BL.env_updates(broker, BL.as_rows(broker))[BL.SCHEMAS[broker].blob] == blob


def test_the_broker_modules_read_the_same_logins(monkeypatch):
    monkeypatch.setenv("FIDELITY", BL.env_updates("fidelity", ROWS["fidelity"])["FIDELITY"])
    assert [(c.idx_1based, c.username, c.password, c.totp_secret)
            for c in fidelity._load_creds()] == [
        (1, "u1", "pa,ss", "T1"), (2, "u2", "a:b,c", ""), (3, "u3", "plain", "T3")]

    monkeypatch.setenv("SCHWAB", BL.env_updates("schwab", ROWS["schwab"])["SCHWAB"])
    assert schwab._parse_accounts_from_env() == [
        ("u1", ",lead,trail,", "T1"), ("u2", "x", None)]

    monkeypatch.setenv("ROBINHOOD",
                       BL.env_updates("robinhood", ROWS["robinhood"])["ROBINHOOD"])
    assert [(n, u, p) for n, u, p in robinhood._login_profiles()] == [
        ("Robinhood 1", "u1", "p,1"), ("Robinhood 2", "u2", "p2")]


def test_a_blob_with_no_comma_is_written_exactly_as_before():
    up = BL.env_updates("fidelity", [{"username": "u1", "password": "p1", "totp": "T1"},
                                     {"username": "u2", "password": "p2", "totp": ""}])
    assert up["FIDELITY"] == "u1:p1:T1,u2:p2"


@pytest.mark.parametrize("raw", ["u1:p1:T1,u2:p2", "u1:pa:ss:,u2:x", " u1:p , u2:q "])
def test_blobs_already_on_disk_read_as_before(raw):
    assert BL.blob_items(raw) == [p.strip() for p in raw.split(",") if p.strip()]


def test_a_trailing_backslash_is_encoded_instead_of_refused(tmp_path, monkeypatch):
    """.env cannot hold a bare value ending in '\' that has a space in it."""
    up = BL.env_updates("robinhood", [{"username": "u 1", "password": "end\\"}])
    assert up["ROBINHOOD"].startswith("b64:")
    A._env_quote(up["ROBINHOOD"])                       # does not raise
    monkeypatch.setenv("ROBINHOOD", up["ROBINHOOD"])
    assert BL.logins("robinhood")[0].get("password") == "end\\"


def test_a_corrupt_item_keeps_the_logins_after_it_numbered():
    good = BL.env_updates("robinhood", [{"username": "a", "password": "x,y"},
                                        {"username": "b", "password": "z"}])["ROBINHOOD"]
    head, _, tail = good[len("b64:"):].partition(",")
    items = BL.blob_items("b64:%%%,"+tail)
    assert len(items) == 2 and items[1] == "b:z"


def test_dotenv_round_trip_through_the_saved_file(tmp_path, monkeypatch):
    """The value as _save_env_file writes it, read back by python-dotenv."""
    from dotenv import dotenv_values
    blob = BL.env_updates("fidelity", ROWS["fidelity"])["FIDELITY"]
    env = tmp_path / ".env"
    env.write_text(f"FIDELITY={A._env_quote(blob)}\n", encoding="utf-8")
    assert dotenv_values(env, interpolate=False)["FIDELITY"] == blob
