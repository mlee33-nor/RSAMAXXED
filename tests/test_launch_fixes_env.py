""".env values round-trip exactly through python-dotenv.

The writer used to put KEY=value unquoted, so `abc #def` loaded back as `abc`,
a leading space vanished and a password starting with a quote was parsed as a
quoted string. Every case here is written by the real writer into a temp .env
and read back the way the app reads it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from dotenv import dotenv_values

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A

BS = "\\"
CASES = ["abc #def", '"quoted', "'wrapped'", "pa${HOME}ss", " lead", "trail ",
         "plain", "back" + BS + "slash", "a" + BS + "nb", "it's", BS + "'",
         "", "x=y", "a\"b'c#d", "$HOME", BS + BS + "x", "end" + BS]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    monkeypatch.setattr(A, "ENV_FILE", path)
    return path


def _keys(monkeypatch, n):
    keys = [f"RSAMAXXED_TEST_ENV_{i}" for i in range(n)]
    for k in keys:
        monkeypatch.setenv(k, "x")      # registers the restore
    return keys


def test_every_value_round_trips(env, monkeypatch):
    keys = _keys(monkeypatch, len(CASES))
    A._save_env_file(dict(zip(keys, CASES)))
    got = dotenv_values(env, interpolate=False)
    for k, v in zip(keys, CASES):
        assert got[k] == v, (k, v, got[k])


def test_rewriting_in_place_keeps_comments_order_and_other_keys(env, monkeypatch):
    env.write_text("# broker logins\nOTHER=keep me\n\nRSAMAXXED_TEST_ENV_0=old\n"
                   "# trailing comment\n", encoding="utf-8")
    (k0, k1) = _keys(monkeypatch, 2)
    A._save_env_file({k0: "new #pw", k1: " added"})
    lines = env.read_text(encoding="utf-8").splitlines()
    assert lines[:2] == ["# broker logins", "OTHER=keep me"]
    assert lines[3].startswith(k0 + "=") and lines[4] == "# trailing comment"
    assert lines[5].startswith(k1 + "=")
    got = dotenv_values(env, interpolate=False)
    assert got == {"OTHER": "keep me", k0: "new #pw", k1: " added"}


def test_no_temp_file_is_left_behind(env, monkeypatch):
    (k,) = _keys(monkeypatch, 1)
    A._save_env_file({k: "v"})
    assert [p.name for p in env.parent.iterdir()] == [".env"]


def test_the_process_environment_gets_the_raw_value(env, monkeypatch):
    import os
    (k,) = _keys(monkeypatch, 1)
    A._save_env_file({k: "abc #def"})
    assert os.environ[k] == "abc #def"


def test_an_unstorable_value_is_refused_before_anything_is_written(env, monkeypatch):
    env.write_text("OTHER=keep\n", encoding="utf-8")
    (k,) = _keys(monkeypatch, 1)
    with pytest.raises(ValueError):
        A._save_env_file({k: " spaced" + BS})
    with pytest.raises(ValueError):
        A._save_env_file({k: "two\nlines"})
    assert env.read_text(encoding="utf-8") == "OTHER=keep\n"
