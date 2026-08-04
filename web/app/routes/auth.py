from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, plans, security
from ..db import get_db
from ..models import User
from ..templating import render

router = APIRouter()


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


@router.get("/login")
def login_form(request: Request):
    if request.session.get("uid"):
        return _redirect("/app")
    return render(request, "login.html")


@router.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    if not security.csrf_ok(request.session.get("csrf"), csrf_token):
        return render(request, "login.html", error="Session expired. Try again.")

    user = db.scalar(select(User).where(User.email == email.strip().lower()))

    # Hash even when the user doesn't exist, so response time doesn't reveal
    # whether an email is registered.
    stored = user.password_hash if user else security.hash_password("no-such-user")
    if not security.verify_password(password, stored) or user is None:
        return render(request, "login.html", error="Wrong email or password.", email=email)

    request.session.clear()  # drop any pre-login session, defeats fixation
    request.session["uid"] = user.id
    return _redirect("/app")


# The three tiers the pricing page links to. A signup must name one of these —
# arriving at /signup without a plan means the visitor skipped the choice, so we
# bounce them to pricing to make it. ('mirror' resolves to automation's
# entitlements via plans.resolve(); it has no separate Plan of its own.)
_SIGNUP_TIERS = {"plays", "automation", "mirror"}


@router.get("/signup")
def signup_form(request: Request):
    if request.session.get("uid"):
        return _redirect("/app")
    # A plan must be chosen BEFORE an account can be created. No (valid) ?plan=,
    # no form: send them to pricing to pick a tier, which links back with ?plan=.
    tier = (request.query_params.get("plan") or "").strip().lower()
    if tier not in _SIGNUP_TIERS:
        return _redirect("/pricing")
    plan_obj = plans.resolve(tier)
    return render(request, "signup.html",
                  invite_required=not config.OPEN_SIGNUP,
                  chosen=plan_obj, plan_key=tier)


@router.post("/signup")
def signup(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    invite: str = Form(""),
    plan: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    invite_required = not config.OPEN_SIGNUP

    # No plan, no account. A POST without a chosen tier skipped the pricing step
    # (or was forged) — send them back to choose one before anything is created.
    tier = (plan or "").strip().lower()
    if tier not in _SIGNUP_TIERS:
        return _redirect("/pricing")
    plan_obj = plans.resolve(tier)

    def fail(msg: str):
        return render(request, "signup.html", error=msg, email=email,
                      invite_required=invite_required,
                      chosen=plan_obj, plan_key=tier)

    if not security.csrf_ok(request.session.get("csrf"), csrf_token):
        return fail("Session expired. Try again.")

    if invite_required:
        if not config.INVITE_CODE or invite.strip() != config.INVITE_CODE:
            return fail("That invite code isn't valid.")

    email = email.strip().lower()
    if "@" not in email or len(email) > 320:
        return fail("Enter a valid email address.")
    if len(password) < 10:
        return fail("Password must be at least 10 characters.")

    if db.scalar(select(User.id).where(User.email == email)):
        return fail("An account with that email already exists.")

    # NOTE — billing seam. The plan is recorded from the tier the visitor
    # picked; nothing has charged them yet. When checkout goes in, this is the
    # line that moves: create the user on `plans.DEFAULT_PLAN`, send them to
    # the processor, and set `user.plan` from the webhook that confirms payment.
    # Everything downstream already reads `user.plan` through plans.can(), so
    # no other code has to change.
    user = User(email=email, password_hash=security.hash_password(password), plan=plan_obj.key)
    db.add(user)
    db.commit()

    request.session.clear()
    request.session["uid"] = user.id
    # Plays Only has no terminal to pair, so sending them to the pairing page
    # would open on a task they can't do. Send them to what they bought.
    if plan_obj.can(plans.TERMINAL):
        return _redirect("/app/devices?welcome=1")
    return _redirect("/app/plays")


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form("")):
    if security.csrf_ok(request.session.get("csrf"), csrf_token):
        request.session.clear()
    return _redirect("/")
