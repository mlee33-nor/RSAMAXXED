"""Are the installed libraries the ones requirements.txt pins?

A broker library that drifts off its pin breaks a working install without a
word: playwright-stealth 2.0.2 sitting where 1.0.6 is pinned makes
`import schwab_api` itself fail, and the user sees only "Missing dependency
schwab_api" on the first Schwab login, if at all. This reads requirements.txt
and compares each line against importlib.metadata, so the app can say so
loudly at startup and INSTALL.bat can repair it.

Never imports the libraries it checks, never touches the network, never
raises out of the public functions. Only `==` pins and simple `>=` / `<`
bounds are understood; anything fancier (markers, extras, URLs) is skipped.

    py -3.13 -m modules.depcheck           report; exit 1 on a problem
    py -3.13 -m modules.depcheck --specs   print the pins to reinstall
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

try:
    from importlib import metadata as _metadata
except Exception:                                   # pragma: no cover
    _metadata = None  # type: ignore[assignment]

REQUIREMENTS = Path(__file__).resolve().parent.parent / "requirements.txt"

_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$")
_CLAUSE = re.compile(r"^(==|>=|<=|<|>|!=)\s*([0-9][A-Za-z0-9.]*)$")


@dataclass(frozen=True)
class Problem:
    name: str
    spec: str                 # as written in requirements.txt: "==1.0.6"
    installed: Optional[str]  # None when not installed at all

    @property
    def pin(self) -> str:
        """What to hand pip to put it right."""
        return f"{self.name}{self.spec}"

    def describe(self) -> str:
        have = self.installed or "not installed"
        return f"{self.name}: requirements.txt wants {self.spec}, found {have}"


def _vkey(v: str) -> Tuple:
    """A comparable key for plain release versions ("1.0.6", "2.0.2", "0.4.3").
    Pre/post/dev suffixes sort after the release they hang off, which is close
    enough for the bounds requirements.txt uses."""
    out = []
    for piece in re.split(r"[.+-]", str(v).strip()):
        m = re.match(r"^(\d+)(.*)$", piece)
        if m:
            out.append((int(m.group(1)), m.group(2)))
        elif piece:
            out.append((-1, piece))
    while out and out[-1] == (0, ""):
        out.pop()
    return tuple(out)


def _satisfies(installed: str, op: str, want: str) -> bool:
    a, b = _vkey(installed), _vkey(want)
    return {"==": a == b, "!=": a != b, ">=": a >= b, "<=": a <= b,
            ">": a > b, "<": a < b}[op]


def parse_requirements(text: str) -> List[Tuple[str, str, List[Tuple[str, str]]]]:
    """[(name, spec_as_written, [(op, version), ...])] for the lines this
    understands. Comments, blanks, options and marker lines are skipped."""
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or ";" in line or "@" in line:
            continue
        m = _LINE.match(line)
        if not m or "[" in m.group(1):
            continue
        name, spec = m.group(1), m.group(2).replace(" ", "")
        clauses = []
        ok = True
        for part in (p for p in spec.split(",") if p):
            c = _CLAUSE.match(part)
            if not c:
                ok = False
                break
            clauses.append((c.group(1), c.group(2)))
        if ok:
            out.append((name, spec, clauses))
    return out


def _installed_version(name: str) -> Optional[str]:
    if _metadata is None:
        return None
    try:
        return _metadata.version(name)
    except Exception:
        return None


def check(requirements: Optional[Path] = None,
          version_of: Callable[[str], Optional[str]] = _installed_version) -> List[Problem]:
    """Every requirements.txt line the installed environment does not meet.
    An unreadable requirements.txt is no problems, not a crash."""
    try:
        text = Path(requirements or REQUIREMENTS).read_text(encoding="utf-8")
    except Exception:
        return []
    problems: List[Problem] = []
    for name, spec, clauses in parse_requirements(text):
        have = version_of(name)
        if have is None:
            problems.append(Problem(name, spec, None))
            continue
        try:
            good = all(_satisfies(have, op, want) for op, want in clauses)
        except Exception:
            good = True
        if not good:
            problems.append(Problem(name, spec, have))
    return problems


def startup_warning(requirements: Optional[Path] = None,
                    version_of: Callable[[str], Optional[str]] = _installed_version) -> str:
    """One loud sentence for the app to show, or "" when everything matches."""
    try:
        problems = check(requirements, version_of)
    except Exception:
        return ""
    if not problems:
        return ""
    listed = "; ".join(p.describe() for p in problems[:6])
    more = f" (+{len(problems) - 6} more)" if len(problems) > 6 else ""
    return (f"Installed libraries do not match what RSAMAXXED was tested with — "
            f"brokers may fail to load or log in. Run INSTALL.bat to repair. "
            f"{listed}{more}")


def warn_at_startup(notify: Optional[Callable[[str], None]] = None) -> str:
    """Check, and hand any warning to `notify` (and stderr). Never raises."""
    msg = startup_warning()
    if msg:
        try:
            print(f"[depcheck] {msg}", file=sys.stderr)
        except Exception:
            pass
        if notify is not None:
            try:
                notify(msg)
            except Exception:
                pass
    return msg


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    problems = check()
    if "--specs" in args:
        for p in problems:
            print(p.pin)
        return 1 if problems else 0
    if not problems:
        print("All libraries match requirements.txt.")
        return 0
    print("These libraries do not match requirements.txt:")
    for p in problems:
        print(f"  {p.describe()}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
