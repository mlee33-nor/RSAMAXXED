"""Marketing page: the interactive engine and the legal copy must both survive
a redesign. Both have been dropped by accident before in other projects; the
first costs conversions, the second costs more than that.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import tempfile

import pytest

WEB_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEB_ROOT))

_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_site.sqlite3"
_TMP_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["ENV"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _schema():
    init_db()
    yield
    engine.dispose()
    _TMP_DB.unlink(missing_ok=True)


MARKETING_PAGES = ("/", "/how-it-works", "/pricing")


@pytest.fixture(scope="module")
def home() -> str:
    with TestClient(app) as c:
        r = c.get("/")
        assert r.status_code == 200
        return r.text


@pytest.fixture(scope="module")
def explainer() -> str:
    with TestClient(app) as c:
        r = c.get("/how-it-works")
        assert r.status_code == 200
        return r.text


@pytest.fixture(scope="module")
def pricing() -> str:
    with TestClient(app) as c:
        r = c.get("/pricing")
        assert r.status_code == 200
        return r.text


def _squash(html: str) -> str:
    """Collapse whitespace so assertions survive template line-wrapping."""
    return re.sub(r"\s+", " ", html)


def test_roundup_engine_is_present(home):
    for hook in ('id="roundup"', 'id="r-ratio"', 'id="r-accts"', 'id="r-profit"'):
        assert hook in home, f"the hero simulation lost {hook}"


def test_mirror_fanout_is_present(home):
    assert 'id="fanout"' in home and 'id="fire"' in home
    # Ten broker nodes, matching the ten supported brokers.
    assert home.count('class="bnode"') == 10


def test_static_assets_are_served_and_self_hosted(home):
    with TestClient(app) as c:
        assert c.get("/static/css/site.css").status_code == 200
        assert c.get("/static/js/site.js").status_code == 200
    # The CSP forbids external origins; make sure no template smuggles one in.
    assert "cdn." not in home
    assert "googleapis" not in home
    assert "unpkg" not in home


def test_csp_blocks_external_and_framing():
    with TestClient(app) as c:
        csp = c.get("/").headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    # Our JS lives in a file, so inline scripts must stay forbidden.
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]


def test_risk_disclaimer_is_present(home):
    """Financial automation marketing without this is indefensible."""
    flat = _squash(home)
    for phrase in (
        "not investment advice",
        "you can lose money",
        "varies by broker",
        "terms of service",
    ):
        assert phrase in flat, f"disclaimer lost the phrase: {phrase!r}"


@pytest.mark.parametrize("path", MARKETING_PAGES)
def test_no_guaranteed_return_language(path):
    """Guard against someone later pasting in a monthly-income promise.

    Note this bans the *word*, so a disclaimer cannot say "not guaranteed"
    either — use "never promised".
    """
    with TestClient(app) as c:
        flat = _squash(c.get(path).text).lower()
    for weasel in ("guaranteed", "risk-free", "riskless", "guarantee a", "per month in profit"):
        assert weasel not in flat, f"{path} makes an unsafe claim: {weasel!r}"


@pytest.mark.parametrize("path", MARKETING_PAGES)
def test_every_public_page_is_branded_rsamaxxed(path):
    """One product name, on every page a stranger can reach.

    Checked per page rather than once on the layout: a page that builds its own
    header instead of extending base.html would otherwise ship nameless.
    """
    with TestClient(app) as c:
        body = c.get(path).text
    assert "RSAMAXXED" in body, f"{path} carries no product name"


def test_reduced_motion_is_honoured():
    with TestClient(app) as c:
        css = c.get("/static/css/site.css").text
    assert "prefers-reduced-motion" in css


# --------------------------------------------------------------- the scenario
# Every number on the site descends from one buy at $0.25 and a 1-for-20 split:
#   per account = 0.25 x (20 - 1) = $4.75      ten accounts = $47.50
# The copy states those figures in prose; site.js recomputes them from the RSA
# constants. If the two ever drift apart the page starts lying, quietly.

def test_js_scenario_constants_match_the_published_figures():
    with TestClient(app) as c:
        js = c.get("/static/js/site.js").text
    m = re.search(r"RSA\s*=\s*Object\.freeze\(\{([^}]*)\}\)", js)
    assert m, "the shared RSA scenario object went missing from site.js"
    body = m.group(1)
    entry = float(re.search(r"entry:\s*([\d.]+)", body).group(1))
    ratio = int(re.search(r"ratio:\s*(\d+)", body).group(1))
    accounts = int(re.search(r"accounts:\s*(\d+)", body).group(1))

    assert (entry, ratio, accounts) == (0.25, 20, 10)
    assert round(entry * (ratio - 1), 2) == 4.75          # per account
    assert round(accounts * entry * (ratio - 1), 2) == 47.50
    assert round(entry * ratio, 2) == 5.00                # post-split share


@pytest.mark.parametrize("path", MARKETING_PAGES)
def test_pages_quote_the_scenario_they_compute(path):
    with TestClient(app) as c:
        flat = _squash(c.get(path).text)
    assert "$4.75" in flat, f"{path} never states the per-account figure"
    assert "$0.25" in flat or "25¢" in flat, f"{path} never states the entry price"


def test_hero_engine_exposes_all_three_sliders(home):
    for hook in ('id="r-price"', 'id="r-ratio"', 'id="r-accts"', 'id="r-post"'):
        assert hook in home, f"the hero simulation lost {hook}"


def test_fanout_is_not_hidden_on_narrow_viewports(home):
    """The wires ARE the section. They used to be `display:none` under 980px,
    which silently deleted the whole point of it on a phone."""
    with TestClient(app) as c:
        css = c.get("/static/css/site.css").text

    assert "fanout{display:none}" not in css.replace(" ", "").replace("\n", "")
    # The stacked layout the wires are measured against, and the breakpoint
    # site.js pairs with it (STACKED = matchMedia('(max-width:860px)')).
    assert "@media(max-width:860px)" in css.replace(" ", "")
    assert 'class="fan-wrap"' in home


# --------------------------------------------------------------- new pages

def test_explainer_teaches_all_six_steps_and_the_fork(explainer):
    assert explainer.count('class="scene"') == 6
    flat = _squash(explainer)
    # The honest bit: all three outcomes named, not just the profitable one.
    for outcome in ("Rounds up", "Cash in lieu", "Rounded down"):
        assert outcome in flat, f"the fork diagram lost the {outcome!r} branch"


def test_explainer_labels_its_worked_example_as_illustrative(explainer):
    flat = _squash(explainer)
    assert "Illustrative" in flat or "illustrative" in flat
    assert "not typical or promised results" in flat


def test_explainer_keeps_the_risks_section(explainer):
    """The section that earns the rest of the page. Six risks, and an anchor
    the landing page links into."""
    assert 'id="risks"' in explainer
    assert explainer.count('class="risk"') == 6
    flat = _squash(explainer)
    for risk in ("may not happen", "change without", "often fades", "terms of service"):
        assert risk in flat, f"the risks section lost: {risk!r}"


def test_pricing_has_three_tiers_one_badge_and_both_billing_periods(pricing):
    flat = _squash(pricing)
    for tier in ("Plays Only", "Automation Tool", "Mirror Automation"):
        assert tier in flat
    assert pricing.count('class="badge"') == 1, "exactly one tier may be flagged"
    assert 'class="tier star"' in pricing

    for monthly, annual, yearly in (("$15", "$12", "$144"),
                                    ("$79", "$66", "$790"),
                                    ("$149", "$124", "$1,490")):
        assert f'data-monthly="{monthly}" data-annual="{annual}"' in pricing
        assert f'data-annual="{yearly} billed yearly"' in pricing


def test_the_advertised_price_is_the_price_the_code_charges(pricing):
    """The page and plans.py must not drift. A card that says one number while
    the entitlement table holds another is how someone gets billed wrong."""
    from app import plans
    for key in ("plays", "automation"):
        assert f'data-monthly="${plans.PLANS[key].monthly}"' in pricing


def test_every_annual_price_keeps_the_two_months_free_promise(pricing):
    """The toggle advertises '2 months free', so a year must cost no more than
    ten months. Checked against the figures ON the card, since those are the
    ones a customer is actually quoted."""
    monthly = [int(m.replace(",", "")) for m in re.findall(r'data-monthly="\$([\d,]+)"', pricing)]
    yearly = [int(m.replace(",", "")) for m in re.findall(r'data-annual="\$([\d,]+) billed yearly"', pricing)]
    assert len(monthly) == len(yearly) == 3, "a tier lost its price or its yearly note"
    for m, y in zip(monthly, yearly):
        assert y <= m * 10, f"${y}/yr is more than ten months of ${m}"


def test_pricing_toggle_is_a_real_labelled_checkbox(pricing):
    """The visible switch is a styled span; the control underneath has to stay
    keyboard-reachable and named."""
    assert 'id="billing"' in pricing and 'type="checkbox"' in pricing
    assert 'class="sr-only"' in pricing


def test_marketing_pages_are_reachable_from_the_nav(home):
    assert 'href="/how-it-works"' in home
    assert 'href="/pricing"' in home


@pytest.mark.parametrize("path", ("/how-it-works", "/pricing"))
def test_new_pages_carry_the_risk_disclaimer(path):
    with TestClient(app) as c:
        flat = _squash(c.get(path).text)
    for phrase in ("not investment advice", "you can lose money",
                   "varies by broker", "terms of service"):
        assert phrase in flat, f"{path} lost the disclaimer phrase: {phrase!r}"
