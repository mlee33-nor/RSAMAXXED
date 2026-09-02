"""Local 2FA / OTP prompt helper.

Two things live here: the prompt STRING, and the process-wide plumbing that
gets a code from whoever is driving the app back to the broker module that
asked for it.

WHY THIS EXISTS RATHER THAN builtins.input
------------------------------------------
Broker modules used to ask for a code by calling ``input()``, and the GUI
answered by monkey-patching ``builtins.input``. ``builtins`` is process-global
and brokers bootstrap CONCURRENTLY, so the patches raced:

    robinhood rehydrate : orig = <gui prompt>      ; input = _blocked
    robinhood bootstrap : orig = _blocked          ; input = _input_stub
    rehydrate finishes  : input = <gui prompt>
    bootstrap finishes  : input = _blocked          <-- stuck, for the session

From then on ANY module calling ``input()`` got Robinhood's
``_blocked``, which raises. Fidelity's OTP provider only caught EOFError, so
the RuntimeError travelled all the way out of ``_handle_2fa`` and was swallowed
by the per-login ``except Exception`` in ``bootstrap()``. Fidelity texted a
code, the code was never asked for, and the browser closed nine seconds later
with "auth failed". Verified in sessions/fidelity/fidelity_nav.log for
2026-09-02: three logins in a row got to "2FA | otp input detected" and
straight on to "BROWSER | closed".

So the hook is an explicit registration instead. Nothing global is reassigned,
concurrent brokers cannot clobber each other, and a module that asks for a code
gets either a code or None -- never an exception.
"""
from __future__ import annotations

import builtins
import threading
from typing import Callable, Optional

#: (broker_label, prompt_text, timeout_seconds) -> what the user typed, or
#: None if they declined. `prompt_text` is shown verbatim, because the thing
#: being asked for is not always a code -- robin_stocks will ask for an email
#: address or a device-approval confirmation through the same channel.
PromptHook = Callable[[str, str, int], Optional[str]]

_hook: Optional[PromptHook] = None
_hook_lock = threading.Lock()

# One prompt on screen at a time. Brokers bootstrap in parallel and each has
# its own thread, so without this two logins can both be waiting on the same
# modal and the second code is typed into the first broker's box.
_ask_lock = threading.Lock()


def universal_2fa_prompt(broker: str, extra: str = "") -> str:
    """Build a human-readable OTP prompt string."""
    parts = [f"[{broker}] Enter your 2FA / OTP code"]
    if extra:
        parts.append(f"({extra})")
    parts.append(":")
    return " ".join(parts)


def set_prompt_hook(fn: Optional[PromptHook]) -> None:
    """Register who answers OTP requests. The GUI calls this once at startup.

    Passing None goes back to the terminal, which is what runner.py wants.
    """
    global _hook
    with _hook_lock:
        _hook = fn


def has_prompt_hook() -> bool:
    with _hook_lock:
        return _hook is not None


def _digits(raw: str) -> Optional[str]:
    """A 6-8 digit code out of whatever was typed, or None.

    Users paste "Your code is 481920" and codes arrive with spaces in them.
    """
    code = "".join(c for c in str(raw or "") if c.isdigit())
    return code if 6 <= len(code) <= 8 else None


def request_text(broker: str, prompt: str, timeout_s: int = 300) -> Optional[str]:
    """Ask the user something and hand back what they typed, or None.

    NEVER raises. A broker login that is already holding a live browser session
    on a 2FA page must not be killed by the prompt itself failing -- the caller
    needs to be able to report "no code entered" and close down cleanly.
    """
    with _hook_lock:
        fn = _hook

    with _ask_lock:
        if fn is not None:
            try:
                answer = fn(broker, prompt, timeout_s)
            except Exception:
                return None
        else:
            try:
                answer = builtins.input(prompt.rstrip() + " ")
            except Exception:
                # EOFError under pythonw (no stdin), KeyboardInterrupt, or a
                # stray third-party patch of builtins.input. All mean "no
                # answer" -- and none of them should kill the login.
                return None
    answer = str(answer or "").strip()
    return answer or None


def request_code(broker: str, timeout_s: int = 300, extra: str = "") -> Optional[str]:
    """Ask for a 2FA code. Returns 6-8 digits, or None.

    Digits only, so "Your code is 481920" and "481 920" both work -- codes get
    pasted out of a text message far more often than they get typed.
    """
    answer = request_text(broker, universal_2fa_prompt(broker, extra), timeout_s)
    return _digits(answer or "")
