"""fix5/buy: the last three BUY-path findings, as permanent regressions.

1. A play bought somewhere, then CANCELLED (or turned conditional/unknown) by
   a later alert: owed legs and queued launches stop, the hold is published
   (so customers' copies stop buying) and the user is told to decide on a sell.
2. Owed retries run the age gate against the alert's last day to buy: never
   after it, and never dropped while it is still open.
3. Wells Fargo: a whole-login failure row sent back as only_accounts means
   that login's accounts -- never another login's, never a filled account.
"""

from __future__ import annotations

from datetime import datetime

import sim_harness as H  # noqa: F401
from sim_harness import A
from test_e2e_launch_sim import _idle, sim  # noqa: F401

MON_D = "2026-10-05"
FRI = "2026-10-02"


# ---------------------------------------------------------------- finding 1

def test_cancel_after_operator_bought_never_published(sim):
    import rsa_feed
    sim.clock.set_et(datetime(2026, 10, 5, 9, 44, 59))
    m1 = sim.feed.alert("CNX", MON_D, "standard")
    sim.market.set("CNX", 0.25)
    sim.brokers["fidelity"].set_mode("login2_fail", side="buy", times=1)
    sim.seed_mirror()
    sim.seed_autosell(enabled=False)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=1800)
    assert any(o.get("symbol") == "CNX" for o in sim.app._mirror_owed), \
        "precondition: Fidelity login 2 is owed the buy"

    m2 = sim.feed.alert("CNX", MON_D, "standard", type_line="CANCELLED",
                        posted_et=f"{MON_D}T10:00:00")
    sim.feed.picks_override = [p for p in sim.feed.picks() if p.get("note") == "Reg Alert"]
    sim.app._import_picks_from_messages([m1, m2])
    sim.pump(lambda: _idle(sim), max_fake_s=60)

    # Published held, so every customer copy stops buying it.
    assert (MON_D, "CNX") in sim.app._feed_held_keys
    batch = rsa_feed.parse_messages([m1, m2], [])
    out = A._feed_batch_with_holds(batch, sim.app._feed_held_keys).to_json()
    kinds = [b["kind"] for b in out["buys"] if b["symbol"] == "CNX"]
    assert kinds and kinds[-1] == "conditional", kinds
    # Owed legs (per-account too) and queued launches are gone.
    assert not any(o.get("symbol") == "CNX" for o in sim.app._mirror_owed)
    assert not any(str(q.get("symbol")).upper() == "CNX" for q in sim.app._mirror_queue)
    # Told loudly, with the sell decision named.
    assert any("CNX" in m and "sell" in m.lower() for m, _k in sim.app.notes), \
        sim.app.notes

    sim.settle(max_fake_s=3 * 3600)
    f2 = [o for o in sim.orders(side="buy", symbol="CNX")
          if o.broker == "fidelity" and "Fidelity 2" in o.account]
    assert not f2, "owed leg bought a play the alerter cancelled"


def test_called_off_play_is_not_launched_from_a_late_owed_entry(sim):
    """An owed entry that lands after the cancel (a batch finishing late)
    still goes nowhere: the stored row stays buyable, the cancel does not."""
    sim.clock.set_et(datetime(2026, 10, 5, 9, 44, 59))
    m1 = sim.feed.alert("CNY", MON_D, "standard")
    sim.market.set("CNY", 0.25)
    sim.brokers["fidelity"].set_mode("login2_fail", side="buy", times=1)
    sim.seed_mirror()
    sim.seed_autosell(enabled=False)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=1800)
    m2 = sim.feed.alert("CNY", MON_D, "standard", type_line="CANCELLED",
                        posted_et=f"{MON_D}T10:00:00")
    sim.app._import_picks_from_messages([m1, m2])
    sim.pump(lambda: _idle(sim), max_fake_s=60)
    before = len(sim.orders(side="buy", symbol="CNY"))
    assert sim.app._mirror_launch_pick(
        {"symbol": "CNY", "date": MON_D, "note": "Reg Alert",
         "_only": "fidelity", "_accounts": ["Fidelity 2"],
         "_when": "owed", "_trigger": "owed"}) is None
    sim.settle(max_fake_s=600)
    assert len(sim.orders(side="buy", symbol="CNY")) == before


# ---------------------------------------------------------------- finding 2

def test_owed_retry_ignores_last_buy(sim):
    sim.clock.set_et(datetime(2026, 10, 5, 15, 44, 59))
    sim.feed.alert("LBX", MON_D, "standard", last_buy=MON_D, posted_et=f"{MON_D}T15:00:00")
    sim.market.set("LBX", 0.25)
    sim.brokers["fidelity"].set_mode("login2_fail", side="buy", times=1)
    sim.seed_mirror()
    sim.seed_autosell(enabled=False)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=3600)
    owed = [o for o in sim.app._mirror_owed if o.get("symbol") == "LBX"]
    assert owed and all(o.get("last_buy") == MON_D for o in owed), owed
    sim.settle(max_fake_s=20 * 3600)
    fid = [(o.account, o.t) for o in sim.orders(side="buy", symbol="LBX")
           if o.broker == "fidelity"]
    tue = [x for x in fid if x[1] >= "2026-10-06"]
    assert not tue, f"bought after its last day to buy: {tue}"


def test_owed_retry_dropped_despite_last_buy(sim):
    sim.clock.set_et(datetime(2026, 10, 5, 15, 44, 59))
    sim.feed.alert("LBY", FRI, "standard", last_buy="2026-10-07")
    sim.market.set("LBY", 0.25)
    sim.brokers["fidelity"].set_mode("login2_fail", side="buy", times=1)
    sim.seed_mirror(max_age_days=1)
    sim.seed_autosell(enabled=False)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=3600)
    sim.settle(max_fake_s=20 * 3600)
    led = sim.ledger(side="buy", symbol="LBY")
    fid = sorted(a for (b, a, _s, _d) in led if b == "fidelity")
    assert "Fidelity 2 - Joint (Z20002)" in fid, \
        "owed login-2 leg dropped although last_buy is Wed"
    assert all(v == 1 for v in led.values()), led


def test_owed_last_buy_survives_restart_and_old_records_load():
    saved = {"owed": [
        {"broker": "fidelity", "symbol": "AAA", "date": FRI, "note": "Reg Alert",
         "last_buy": "2026-10-07", "accounts": ["Fidelity 2"]},
        {"broker": "chase", "symbol": "BBB", "date": FRI, "note": "Reg Alert"},
    ]}
    out = A._mirror_owed_from(saved)
    assert out[0]["last_buy"] == "2026-10-07"
    assert "last_buy" not in out[1]


def test_restart_with_account_owed(sim):
    sim.clock.set_et(datetime(2026, 10, 5, 9, 44, 59))
    sim.feed.alert("RST", MON_D, "standard")
    sim.market.set("RST", 0.25)
    sim.brokers["fidelity"].set_mode("login2_fail", side="buy", times=1)
    sim.seed_mirror()
    sim.seed_autosell(enabled=False)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=1800)
    sim.kill()
    sim.clock.advance(3600)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=6 * 3600)
    sim.settle(max_fake_s=3600)
    led = sim.ledger(side="buy", symbol="RST")
    assert all(v == 1 for v in led.values()), led
    assert led == sim.every_account("RST")


# ---------------------------------------------------------------- finding 3

WF2 = ["Wells Fargo 2 · WELLSTRADE (****2001)", "Wells Fargo 2 · WELLSTRADE (****2002)"]


def _two_wf_logins(sim):
    b = sim.brokers["wellsfargo"]
    b.logins.append(list(WF2))
    for a in WF2:
        b.positions.setdefault(a, {})


def test_wf_login2_failure_retry_buys_that_login_once(sim):
    sim.clock.set_et(datetime(2026, 10, 5, 9, 44, 59))
    sim.feed.alert("WFX", MON_D, "standard")
    sim.market.set("WFX", 0.25)
    _two_wf_logins(sim)
    sim.brokers["wellsfargo"].set_mode("login2_fail", side="buy", times=1)
    sim.seed_mirror()
    sim.seed_autosell(enabled=False)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=1800)
    owed = [o for o in sim.app._mirror_owed if o.get("broker") == "wellsfargo"]
    assert owed and owed[0].get("accounts") == ["Wells Fargo 2 · Wells Fargo"], owed
    sim.settle(max_fake_s=6 * 3600)
    led = sim.ledger(side="buy", symbol="WFX")
    assert all(v == 1 for v in led.values()), led
    assert led == sim.every_account("WFX")


def test_wf_login_names_never_cross_logins():
    import wellsfargo as wf
    assert wf._wants_whole_login({"Wells Fargo"}, 1)
    assert wf._wants_whole_login({"Wells Fargo 1"}, 1)
    assert not wf._wants_whole_login({"Wells Fargo"}, 2)
    assert wf._wants_whole_login({"Wells Fargo 2 · Wells Fargo"}, 2)
    assert wf._wants_whole_login({"Wells Fargo 2 · Wells Fargo 2"}, 2)
    assert not wf._wants_whole_login({"Wells Fargo 2 · Wells Fargo"}, 1)
    assert not wf._wants_whole_login({"Wells Fargo 2 · Wells Fargo"}, 3)
    # An account label is never a whole login.
    assert not wf._wants_whole_login({"WELLSTRADE (****0001)"}, 1)
    assert not wf._wants_whole_login({"Wells Fargo 2 · WELLSTRADE (****0001)"}, 2)


def test_wf_whole_login_request_not_reported_missing():
    import wellsfargo as wf
    rows = [wf.AccountOutput(account_id="Wells Fargo 2 · WELLSTRADE (****0001)", ok=True)]
    assert wf._requested_unmatched(["Wells Fargo 2 · Wells Fargo"], rows) == []
    # Login 1 never answered for itself: still missing.
    assert wf._requested_unmatched(["Wells Fargo"], rows) == ["Wells Fargo"]
    rows1 = [wf.AccountOutput(account_id="WELLSTRADE (****0001)", ok=True)]
    assert wf._requested_unmatched(["Wells Fargo"], rows1) == []


def test_prefixed_login_rows_are_login_labels():
    assert A._is_login_label("Wells Fargo 2 · Wells Fargo")
    assert A._is_login_label("Wells Fargo 2 · Wells Fargo 2")
    assert A._is_login_label("Wells Fargo")
    assert not A._is_login_label("Wells Fargo 2 · WELLSTRADE (****0001)")
    assert not A._is_login_label("Fidelity 2 · Individual (Z00000001)")


def test_aimed_retry_login_failure_never_widens(sim):
    """A retry aimed at one account whose login then fails whole stays aimed
    at that account: owing the login's row would re-buy its filled accounts."""
    sim.clock.set_et(datetime(2026, 10, 5, 9, 44, 59))
    sim.seed_mirror()
    sim.seed_autosell(enabled=False)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=600)
    aimed = ["WELLSTRADE (****0002)", WF2[1]]
    batch = {"mirror_key": [MON_D, "AIM"], "symbol": "AIM",
             "mirror_owed_attempts": "1", "mirror_owed_accounts": aimed,
             "results": [{"broker": "wellsfargo", "ok_accounts": 1, "fail_accounts": 1,
                          "accounts": [
                              {"account_id": "Wells Fargo", "ok": False,
                               "message": "Login failed (landed on: x)"},
                              {"account_id": WF2[1], "ok": True, "message": "order placed"}]}]}
    sim.app._mirror_owe_failed_legs(batch)
    owed = [o for o in sim.app._mirror_owed if o.get("symbol") == "AIM"]
    assert owed and owed[0]["accounts"] == ["WELLSTRADE (****0002)"], owed


def test_fake_brokers_match_only_accounts_like_real_modules(sim):
    fid, wf, ib = (sim.brokers[n] for n in ("fidelity", "wellsfargo", "ibkr"))
    # Fidelity: c.label is "Fidelity 1" for login 1; bare "Fidelity" is nothing.
    assert fid._accounts_for({"Fidelity"}) == []
    assert {i for i, _a in fid._accounts_for({"Fidelity 1"})} == {1}
    assert {i for i, _a in fid._accounts_for({"Fidelity 2"})} == {2}
    # Wells Fargo: bare name is login 1 only.
    _two_wf_logins(sim)
    assert {i for i, _a in wf._accounts_for({"Wells Fargo"})} == {1}
    assert {i for i, _a in wf._accounts_for({"Wells Fargo 2 · Wells Fargo"})} == {2}
    assert wf._accounts_for({"Wells Fargo 2"}) == [(2, a) for a in WF2]
    # IBKR: the Gateway's own name.
    assert len(ib._accounts_for({"IBKR"})) == len(ib.accounts())
    assert ib._accounts_for({"IBKR 2"}) == []


def test_called_off_then_reposted_standard_is_on_again(sim):
    sim.clock.set_et(datetime(2026, 10, 5, 9, 44, 59))
    m1 = sim.feed.alert("CNZ", MON_D, "standard")
    sim.market.set("CNZ", 0.25)
    sim.seed_mirror()
    sim.seed_autosell(enabled=False)
    sim.launch()
    sim.pump(lambda: _idle(sim), max_fake_s=1800)
    m2 = sim.feed.alert("CNZ", MON_D, "standard", type_line="CANCELLED",
                        posted_et=f"{MON_D}T10:00:00")
    sim.app._import_picks_from_messages([m1, m2])
    assert (MON_D, "CNZ") in sim.app._feed_kept_bought_told
    m3 = sim.feed.alert("CNZ", MON_D, "standard", posted_et=f"{MON_D}T11:00:00")
    sim.app._import_picks_from_messages([m1, m2, m3])
    assert (MON_D, "CNZ") not in sim.app._feed_held_keys
    assert (MON_D, "CNZ") not in sim.app._feed_kept_bought_told
