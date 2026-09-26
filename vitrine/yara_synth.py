"""YARA rule synthesis + specificity/coverage validation.

Rules are generated in a restricted subset of YARA (text strings, `N of them`, MZ check)
so VITRINE can evaluate them natively without yara-python. If yara-python is installed,
`compile_check` also verifies the rule compiles with the real engine.
"""
from __future__ import annotations

import math
import re

from .dissect import PEParseError, dissect, extract_strings
from .models import YaraRule

MIN_LEN = 6
MAX_STRINGS = 8


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _unesc(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def candidate_strings(group: list[bytes], benign: list[bytes], min_support: float = 0.6) -> list[str]:
    """Strings present in >= min_support of the group and in NO benign sample."""
    counts: dict[str, int] = {}
    for data in group:
        header = data[:0x400]  # skip PE header/section-table artifacts
        for s in set(extract_strings(data)):
            if len(s) >= MIN_LEN and s.encode() not in header:
                counts[s] = counts.get(s, 0) + 1
    need = max(1, math.ceil(min_support * len(group)))
    cands = [s for s, c in counts.items() if c >= need]
    cands = [s for s in cands if not any(s.encode() in b for b in benign)]
    # API names imported by the sample are shared across families -> weak; use only as filler
    apis = {f for data in group for fs in _safe_imports(data) for f in fs}
    distinctive = [s for s in cands if s not in apis]
    if len(distinctive) >= 1:
        cands = distinctive
    # most shared first, then longest (more specific)
    cands.sort(key=lambda s: (-counts[s], -len(s), s))
    return cands[:MAX_STRINGS]


def _safe_imports(data: bytes) -> list[list[str]]:
    try:
        return list(dissect(data).imports.values())
    except PEParseError:
        return []


def synthesize(name: str, group: list[bytes], benign: list[bytes], family: str | None = None) -> YaraRule | None:
    strs = candidate_strings(group, benign)
    if not strs:
        return None
    threshold = max(1, math.ceil(len(strs) / 2)) if len(strs) > 1 else 1
    safe = re.sub(r"[^A-Za-z0-9_]", "_", name)
    lines = [f"rule {safe}", "{", "    meta:",
             '        author = "VITRINE (auto-generated, analyst review required)"',
             f'        family = "{_esc(family or "unknown")}"',
             f"        sample_count = {len(group)}",
             "    strings:"]
    lines += [f'        $s{i} = "{_esc(s)}" ascii' for i, s in enumerate(strs)]
    lines += ["    condition:", f"        uint16(0) == 0x5A4D and {threshold} of them", "}"]
    return YaraRule(safe, "\n".join(lines) + "\n", strs, threshold)


_STR_LINE = re.compile(r'^\s*\$\w+\s*=\s*"((?:[^"\\]|\\.)*)"', re.M)
_COND = re.compile(r"(\d+) of them")


def parse(text: str) -> tuple[list[str], int]:
    strs = [_unesc(m) for m in _STR_LINE.findall(text)]
    m = _COND.search(text)
    return strs, int(m.group(1)) if m else len(strs)


def match(rule: YaraRule | str, data: bytes) -> bool:
    strs, thr = parse(rule.text if isinstance(rule, YaraRule) else rule)
    if data[:2] != b"MZ":
        return False
    return sum(1 for s in strs if s.encode() in data) >= thr


def validate(rule: YaraRule, benign: list[bytes], siblings: list[bytes]) -> YaraRule:
    rule.benign_total, rule.benign_hits = len(benign), sum(match(rule, b) for b in benign)
    rule.sibling_total, rule.sibling_hits = len(siblings), sum(match(rule, s) for s in siblings)
    return rule


def compile_check(rule: YaraRule) -> bool | None:
    """True/False if yara-python is available, None otherwise."""
    try:
        import yara  # type: ignore
    except ImportError:
        return None
    try:
        yara.compile(source=rule.text)
        return True
    except yara.SyntaxError:
        return False
