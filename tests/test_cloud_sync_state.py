"""cloud_sync: account numbers are masked, and a locked state file is never
rewritten from an empty read (that dropped the device token)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cloud_sync


@pytest.fixture()
def state(tmp_path, monkeypatch):
    p = tmp_path / "cloud_state.json"
    monkeypatch.setattr(cloud_sync, "_STATE_FILE", p)
    monkeypatch.setattr(cloud_sync, "_STATE_DELAY", 0.0)
    return p


@pytest.mark.parametrize("raw", [
    "Fidelity Individual (Z12345678)", "Public 1 BROKERAGE (0001)",
    "Robinhood 1234", "Schwab xxxx5678 IRA", "Z87654321"])
def test_no_number_survives_masking(raw):
    out = cloud_sync.mask_account_id(raw, "salt")
    assert not re.search(r"\d{4}", out), out
    assert re.search(r"#[a-z]{6}$", out)
    # idempotent: a masked label has nothing left to mask
    assert cloud_sync.mask_account_id(out, "other") == out


def test_masking_keeps_the_label_and_tells_accounts_apart():
    a = cloud_sync.mask_account_id("Fidelity Individual (Z12345678)", "s")
    b = cloud_sync.mask_account_id("Fidelity Individual (Z12345679)", "s")
    assert a.startswith("Fidelity Individual #") and a != b
    assert a == cloud_sync.mask_account_id("Fidelity Individual (Z12345678)", "s")
    assert a != cloud_sync.mask_account_id("Fidelity Individual (Z12345678)", "t")


def test_a_label_without_a_number_is_unchanged():
    assert cloud_sync.mask_account_id("Fidelity 1", "s") == "Fidelity 1"


def test_clean_masks_the_account_id():
    row = {"id": "x", "account_id": "Fidelity Individual (Z12345678)"}
    assert "12345678" not in cloud_sync._clean(row, "s")["account_id"]
    assert "12345678" not in cloud_sync._clean(row)["account_id"]


def test_the_salt_is_created_once_and_kept(state):
    state.write_text(json.dumps({"device_token": "tok"}), encoding="utf-8")
    s1 = cloud_sync._account_salt()
    s2 = cloud_sync._account_salt()
    assert s1 and s1 == s2
    saved = json.loads(state.read_text("utf-8"))
    assert saved["device_token"] == "tok" and saved["account_salt"] == s1


def test_a_locked_state_file_is_not_rewritten(state, monkeypatch):
    state.write_text(json.dumps({"device_token": "tok"}), encoding="utf-8")
    real = Path.read_text

    def locked(self, *a, **k):
        if self == state:
            raise PermissionError(13, "Drive is uploading it")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", locked)
    cloud_sync.CloudSync().set_plays_key("pw")
    assert cloud_sync._account_salt() is None
    cloud_sync._machine_id()
    cloud_sync.CloudSync().unlink()
    monkeypatch.setattr(Path, "read_text", real)
    assert json.loads(state.read_text("utf-8")) == {"device_token": "tok"}


def test_push_with_an_unreadable_state_uploads_nothing(state, monkeypatch):
    state.write_text(json.dumps({"device_token": "tok"}), encoding="utf-8")
    monkeypatch.setattr(cloud_sync, "_account_salt", lambda: None)
    posted = []

    def fake_post(self, *a, **k):
        posted.append(a)
        return {}

    monkeypatch.setattr(cloud_sync.CloudSync, "_post", fake_post)
    with pytest.raises(cloud_sync.CloudError):
        cloud_sync.CloudSync().push_trades(
            [{"id": "1", "account_id": "Fidelity (Z12345678)"}])
    with pytest.raises(cloud_sync.CloudError):
        cloud_sync.CloudSync().push_holdings([])
    assert posted == []


def test_a_transient_lock_is_retried(state, monkeypatch):
    state.write_text(json.dumps({"device_token": "tok"}), encoding="utf-8")
    real = Path.read_text
    fails = {"n": 2}

    def flaky(self, *a, **k):
        if self == state and fails["n"]:
            fails["n"] -= 1
            raise PermissionError(13, "locked")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", flaky)
    cloud_sync.CloudSync().set_plays_key("pw")
    monkeypatch.setattr(Path, "read_text", real)
    saved = json.loads(state.read_text("utf-8"))
    assert saved == {"device_token": "tok", "plays_key": "pw"}
