"""
dirsearch — native content-discovery engine (pure Python, no external binary).

A faithful port of the core logic of dirsearch (https://github.com/maurosoria/
dirsearch, GPL-2.0) into recon-ai's two-layer design. This module is the
low-level *engine*: it owns dictionary generation, the wildcard/false-positive
scanner (the piece that makes forced-browsing usable against dynamic apps), and
status/size filtering. It performs **no network I/O** — the caller supplies
`Response` objects — so every class here is deterministic and unit-testable.

The async orchestration (fetching each path through the shared rate limiter /
WAF backoff, recursion, and emitting scope-gated URL events) lives in the
event-driven wrapper `modules/web/dirsearch.py`, exactly like `recon/dnsx.py`
is wrapped by `modules/active/dnsx.py`.

Ported pieces, mapped to dirsearch's source:
  - `Dictionary`             ← dirsearch `lib/core/dictionary.py`
      wordlist expansion, `%EXT%` tag, forced/overwrite extensions,
      prefixes/suffixes, case transforms, dedup.
  - `DynamicContentParser`   ← dirsearch `lib/core/scanner.py`
      diff two responses to random paths, then measure how close a candidate is
      to that "wildcard" baseline (difflib ratio over the static remainder).
  - `Scanner`                ← dirsearch `lib/core/scanner.py`
      wildcard detection by status, templated-redirect regex, and dynamic body
      comparison; `check()` decides whether a response is a real find.
  - status / size parsing    ← dirsearch `lib/parse/*`
"""

from __future__ import annotations

import difflib
import random
import re
import string
from dataclasses import dataclass, field

# dirsearch's placeholder that gets replaced by each extension.
EXTENSION_TAG = "%EXT%"

# Statuses dirsearch ignores by default (the classic "not found" family). The
# Scanner also filters dynamic 404-equivalents that return 200; this set is the
# cheap first pass.
DEFAULT_EXCLUDE_STATUS: frozenset[int] = frozenset({404})

# Ratio at/above which a candidate response is considered identical to the
# wildcard baseline (i.e. a false positive). dirsearch uses 98%.
WILDCARD_RATIO_THRESHOLD = 0.98

# Length of the random token used to probe for wildcard responses.
_RANDOM_TOKEN_LEN = 26


def generate_random_string(length: int = _RANDOM_TOKEN_LEN) -> str:
    """A lowercase-alnum token unlikely to exist as a real path (wildcard probe)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def parse_status_codes(spec: str | None) -> set[int]:
    """Parse "200,301,400-403" into a set of ints. Empty/None → empty set."""
    out: set[int] = set()
    if not spec:
        return out
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                continue
            if lo_i <= hi_i:
                out.update(range(lo_i, hi_i + 1))
        else:
            try:
                out.add(int(part))
            except ValueError:
                continue
    return out


def parse_sizes(spec: str | None) -> set[int]:
    """Parse "0,1024" byte sizes into a set of ints (for --exclude-sizes)."""
    out: set[int] = set()
    if not spec:
        return out
    for part in str(spec).split(","):
        part = part.strip().lower().rstrip("b")
        if not part:
            continue
        mult = 1
        if part.endswith("k"):
            mult, part = 1024, part[:-1]
        elif part.endswith("m"):
            mult, part = 1024 * 1024, part[:-1]
        try:
            out.add(int(float(part) * mult))
        except ValueError:
            continue
    return out


# ── Response value object ─────────────────────────────────────────────────────

@dataclass
class Response:
    """The minimal view of an HTTP response the engine needs. The async wrapper
    builds these from httpx responses; tests build them directly."""

    status: int
    body: str = ""
    redirect: str = ""          # Location header, "" if none
    url: str = ""               # the URL that was requested

    @property
    def length(self) -> int:
        return len(self.body)


# ── Dictionary generation (dirsearch lib/core/dictionary.py) ──────────────────

@dataclass
class DictionaryOptions:
    extensions: list[str] = field(default_factory=list)      # ["php", "html"]
    prefixes: list[str] = field(default_factory=list)
    suffixes: list[str] = field(default_factory=list)
    force_extensions: bool = False        # append .ext to extension-less words
    overwrite_extensions: bool = False    # replace a word's existing extension
    exclude_extensions: list[str] = field(default_factory=list)
    remove_extensions: bool = False       # strip the extension entirely
    lowercase: bool = False
    uppercase: bool = False
    capitalization: bool = False


def _has_extension(word: str) -> bool:
    tail = word.rsplit("/", 1)[-1]
    return "." in tail and not tail.endswith(".")


def _apply_case(word: str, opt: DictionaryOptions) -> str:
    if opt.lowercase:
        return word.lower()
    if opt.uppercase:
        return word.upper()
    if opt.capitalization:
        return word.capitalize()
    return word


class Dictionary:
    """Expand raw wordlist lines into the concrete path list to request.

    Faithful to dirsearch: honours the `%EXT%` tag, forced / overwrite /
    remove extensions, per-word prefixes and suffixes, case transforms, and an
    extension blacklist. Output order is preserved and de-duplicated.
    """

    def __init__(self, words: list[str], options: DictionaryOptions | None = None):
        self._raw = words
        self._opt = options or DictionaryOptions()
        self._entries: list[str] = self._generate()

    # public API ------------------------------------------------------------
    @classmethod
    def from_text(cls, text: str, options: DictionaryOptions | None = None) -> "Dictionary":
        return cls(cls._clean_lines(text.splitlines()), options)

    def entries(self) -> list[str]:
        return list(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    # internals -------------------------------------------------------------
    @staticmethod
    def _clean_lines(lines: list[str]) -> list[str]:
        cleaned: list[str] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cleaned.append(line.lstrip("/"))
        return cleaned

    def _expand_extensions(self, word: str) -> list[str]:
        opt = self._opt
        exts = opt.extensions

        if EXTENSION_TAG in word:
            if not exts:
                return [word.replace(EXTENSION_TAG, "")]
            return [word.replace(EXTENSION_TAG, ext) for ext in exts]

        if opt.remove_extensions and _has_extension(word):
            return [word.rsplit(".", 1)[0]]

        if opt.overwrite_extensions and exts and _has_extension(word):
            stem = word.rsplit(".", 1)[0]
            return [f"{stem}.{ext}" for ext in exts]

        if opt.force_extensions and exts:
            variants = [word]
            if not word.endswith("/") and not _has_extension(word):
                variants += [f"{word}.{ext}" for ext in exts]
            return variants

        return [word]

    def _generate(self) -> list[str]:
        opt = self._opt
        blacklist_ext = {e.lower().lstrip(".") for e in opt.exclude_extensions}
        seen: set[str] = set()
        out: list[str] = []

        for raw in self._raw:
            for expanded in self._expand_extensions(raw):
                if blacklist_ext and _has_extension(expanded):
                    if expanded.rsplit(".", 1)[-1].lower() in blacklist_ext:
                        continue
                word = _apply_case(expanded, opt)
                candidates = [word]
                if opt.prefixes:
                    candidates = [f"{p}{word}" for p in opt.prefixes] + candidates
                if opt.suffixes and not word.endswith("/"):
                    candidates = candidates + [f"{word}{s}" for s in opt.suffixes]
                for c in candidates:
                    if c and c not in seen:
                        seen.add(c)
                        out.append(c)
        return out


# ── Wildcard detection (dirsearch lib/core/scanner.py) ────────────────────────

class DynamicContentParser:
    """Given two responses to two *different* random (non-existent) paths, learn
    which tokens are dynamic, then score how close any later response is to that
    baseline. A high score ⇒ the app returns the same page for everything ⇒ the
    candidate is a false positive."""

    def __init__(self, content1: str, content2: str):
        self._base = content1
        self._is_static = content1 == content2
        self._differences = self._get_differences(content1, content2)

    @staticmethod
    def _get_differences(c1: str, c2: str) -> list[str]:
        differ = difflib.Differ()
        diffs = differ.compare(c1.split(), c2.split())
        return [d[2:] for d in diffs if d and d[0] in "+-"]

    def compare_to(self, content: str) -> float:
        """Return a 0..1 similarity ratio to the wildcard baseline."""
        if self._is_static:
            if content == self._base:
                return 1.0
            return difflib.SequenceMatcher(None, self._base, content).quick_ratio()
        base = self._base
        for token in self._differences:
            base = base.replace(token, "")
            content = content.replace(token, "")
        return difflib.SequenceMatcher(None, base, content).quick_ratio()


class Scanner:
    """Decide whether a response to a real path is a genuine find or just the
    app's catch-all wildcard response.

    Build one Scanner per (base directory, extension) context from the responses
    to two random paths, then call `check()` on every candidate response.
    """

    def __init__(
        self,
        first: Response,
        second: Response | None = None,
        *,
        token: str = "",
        threshold: float = WILDCARD_RATIO_THRESHOLD,
    ):
        self.status = first.status
        self.threshold = threshold
        self.redirect_regex = (
            self._make_redirect_regex(first.redirect, token)
            if first.redirect and token
            else None
        )
        self.parser: DynamicContentParser | None = None
        # Only meaningful to diff bodies when both random probes returned the
        # same status (i.e. a real wildcard page rather than two error pages).
        if second is not None and first.status == second.status:
            self.parser = DynamicContentParser(first.body, second.body)

    @staticmethod
    def _make_redirect_regex(location: str, token: str) -> str:
        """Turn a wildcard redirect Location into a regex by replacing the random
        token with `.+` so templated redirects (…?next=/<token>) still match."""
        escaped = re.escape(location)
        return escaped.replace(re.escape(token), ".+")

    def check(self, response: Response) -> bool:
        """True ⇒ real find (differs from wildcard); False ⇒ false positive."""
        # Different status than the wildcard baseline ⇒ interesting.
        if self.status != response.status:
            return True

        # Same status. If the baseline redirected with a templated Location and
        # this response's Location matches that template, it's the wildcard.
        if self.redirect_regex is not None and response.redirect:
            if re.match(self.redirect_regex, response.redirect):
                return False
            return True

        # Same status, compare bodies against the learned wildcard baseline.
        if self.parser is not None:
            ratio = self.parser.compare_to(response.body)
            if ratio >= self.threshold:
                return False

        # Same status, no body signal to distinguish — keep it (dirsearch does
        # too; the status filter above is the main gate).
        return True


def is_valid_status(
    status: int,
    include: set[int] | None,
    exclude: set[int] | None,
) -> bool:
    """Apply include/exclude status filters (include wins when non-empty)."""
    if include:
        return status in include
    if exclude and status in exclude:
        return False
    return True
