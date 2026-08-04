"""What each tier buys, in one table.

Every gate in the app asks this module, never a hardcoded string comparison.
Adding a tier, renaming one, or moving a feature between them is a change here
and nowhere else.

Two tiers ship today:

    plays       the alert feed — buys, exits and round-up confirmations,
                on the web. Nothing to install.
    automation  the feed, plus the desktop terminal: it places and journals
                the trades in your own brokerage accounts, and syncs the
                journal back here.

Mirror fan-out across ten brokers is built and running in the terminal, but is
NOT sold as a tier — see `pricing.html`. Keeping the capability out of the
price list is a product decision, so it lives here as a flag on `automation`
rather than as a third plan nobody can buy.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Plan:
    key: str
    name: str
    blurb: str
    monthly: int
    annual_monthly: int          # the per-month price when billed yearly
    features: frozenset[str]
    order: int                   # for ranking: a higher order includes lower ones

    @property
    def annual_total(self) -> int:
        return self.annual_monthly * 12

    def can(self, feature: str) -> bool:
        return feature in self.features


# ------------------------------------------------------------------ features
# Named so a reader can tell what's gated without opening a template.

FEED = "feed"                  # read the play feed on the web
FEED_API = "feed_api"          # pull the play feed into your own desktop app
TERMINAL = "terminal"          # download and pair the desktop terminal
SYNC = "sync"                  # push trades/holdings back to the cloud
MIRROR = "mirror"              # fan one order across every linked broker


PLANS: dict[str, Plan] = {
    "plays": Plan(
        key="plays",
        name="Plays Only",
        blurb="Every alert we get, the moment we get it. You place the trades.",
        monthly=0,          # free tier — the alert feed is the funnel, not the product
        annual_monthly=0,
        features=frozenset({FEED}),
        order=10,
    ),
    "automation": Plan(
        key="automation",
        name="Automation",
        blurb="The terminal places and journals the trades in your own accounts.",
        monthly=79,
        annual_monthly=66,
        features=frozenset({FEED, FEED_API, TERMINAL, SYNC, MIRROR}),
        order=20,
    ),
}

DEFAULT_PLAN = "plays"
ORDERED = tuple(sorted(PLANS.values(), key=lambda p: p.order))

# Tiers that no longer sell but may still sit in the `users.plan` column of an
# existing account. Mapped forward so nobody loses access to what they paid for.
RETIRED = {"mirror": "automation", "": DEFAULT_PLAN, "free": DEFAULT_PLAN}


def resolve(key: str | None) -> Plan:
    """A plan name from anywhere (DB column, query string, form) -> a Plan.

    Never raises and never returns None: an unrecognised value degrades to the
    entry tier rather than locking a paying customer out of everything.
    """
    name = (key or "").strip().lower()
    name = RETIRED.get(name, name)
    return PLANS.get(name, PLANS[DEFAULT_PLAN])


def can(user, feature: str) -> bool:
    """Entitlement check. `user` may be None — a logged-out visitor has nothing."""
    if user is None:
        return False
    return resolve(getattr(user, "plan", None)).can(feature)


def valid_signup_plan(key: str | None) -> str:
    """The `?plan=` on /signup is attacker-controlled. Only names that are
    actually on sale survive; anything else falls back to the entry tier."""
    name = (key or "").strip().lower()
    return name if name in PLANS else DEFAULT_PLAN
