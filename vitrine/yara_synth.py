"""YARA rule synthesis + specificity/coverage validation.

Rules are generated in a restricted subset of YARA (text strings, `N of them`, MZ check)
so VITRINE can evaluate them natively without yara-python. If yara-python is installed,
`compile_check` also verifies the rule compiles with the real engine.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

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


_STR_LINE = re.compile(r'[ \t]*\$\w{0,64}[ \t]*=[ \t]*"((?:[^"\\]|\\.){0,4096})"(?:[ \t]+(?:ascii|wide|nocase))*[ \t]*')
_COND = re.compile(r"\b(\d{1,4}) of them\b")
MAX_RULE_LINES = 2000


def parse(text: str) -> tuple[list[str], int]:
    """Parse the restricted YARA subset line by line (bounded work per line, no backtracking blow-up)."""
    strs: list[str] = []
    thr = None
    for line in text.splitlines()[:MAX_RULE_LINES]:
        if len(line) > 8192:
            continue
        m = _STR_LINE.fullmatch(line)
        if m:
            strs.append(_unesc(m.group(1)))
            continue
        if thr is None:
            c = _COND.search(line)
            if c:
                thr = int(c.group(1))
    return strs, thr if thr is not None else len(strs)


def match_parsed(strs: list[str], thr: int, data: bytes) -> bool:
    """Match an already-parsed rule (parse once, match many)."""
    if data[:2] != b"MZ":
        return False
    return sum(1 for s in strs if s.encode() in data) >= thr


def match(rule: YaraRule | str, data: bytes) -> bool:
    strs, thr = parse(rule.text if isinstance(rule, YaraRule) else rule)
    return match_parsed(strs, thr, data)


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


# ============================================================ structural (pe-module) rules
# Rules over *structure* rather than bytes: imported APIs, section names and imphash. These can
# be synthesized and validated from EMBER raw features alone (no binaries needed), and are the
# atoms that survive string obfuscation. Emitted with YARA's `pe` module; the `N of (<bool>, ...)`
# form requires YARA >= 4.3. VITRINE evaluates the same atoms natively for validation.

STANDARD_SECTION_NAMES = {".text", ".rdata", ".data", ".rsrc", ".reloc", ".idata", ".pdata", ".bss",
                          ".tls", ".edata", ".crt", ".didat", "code", "data", ".code", "bss", ".itext"}


def imphash_from_imports(imports: dict[str, list[str]]) -> str:
    import hashlib

    parts = []
    for dll, fs in imports.items():
        base = dll.lower()
        for ext in (".dll", ".ocx", ".sys"):
            if base.endswith(ext):
                base = base[: -len(ext)]
        parts += [f"{base}.{f.lower()}" for f in fs]
    return hashlib.md5(",".join(parts).encode()).hexdigest() if parts else ""


# ubiquitous APIs: never useful as a family signature even when a small benign pool lacks them
COMMON_APIS = {"GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
               "GetModuleHandleA", "GetModuleHandleW", "ExitProcess", "VirtualProtect", "VirtualAlloc",
               "VirtualFree", "GetLastError", "CloseHandle", "Sleep", "GetTickCount", "HeapAlloc", "HeapFree",
               "GetCurrentProcess", "GetCommandLineA", "GetCommandLineW", "MessageBoxA", "MessageBoxW"}


def structural_atoms(rec: dict) -> set[tuple]:
    """Atoms present in an EMBER raw/struct record: ('imp', dll, func), ('sec', name), ('imphash', h)."""
    atoms: set[tuple] = set()
    for dll, fs in rec.get("imports", {}).items():
        d = dll.lower()
        for f in fs:
            if f and not f.startswith("ordinal") and f not in COMMON_APIS:
                atoms.add(("imp", d, f))
    for s in rec.get("section", {}).get("sections", []):
        if s["name"] and s["name"].lower() not in STANDARD_SECTION_NAMES:
            atoms.add(("sec", s["name"]))
    h = imphash_from_imports(rec.get("imports", {}))
    if h:
        atoms.add(("imphash", h))
    return atoms


@dataclass
class StructuralRule:
    name: str
    atoms: list[tuple]
    threshold: int
    family: str = "unknown"
    group_size: int = 0

    @property
    def text(self) -> str:
        conds = []
        for a in self.atoms:
            if a[0] == "imp":
                conds.append(f'pe.imports("{_esc(a[1])}", "{_esc(a[2])}")')
            elif a[0] == "sec":
                conds.append(f'for any s in pe.sections : ( s.name == "{_esc(a[1])}" )')
            else:
                conds.append(f'pe.imphash() == "{a[1]}"')
        body = ",\n            ".join(conds)
        return (f'import "pe"\n\nrule {self.name}\n{{\n    meta:\n'
                f'        author = "VITRINE structural synthesizer (analyst review required)"\n'
                f'        family = "{_esc(self.family)}"\n        sample_count = {self.group_size}\n'
                f'        requires = "YARA >= 4.3 (boolean-expression sets)"\n'
                f"    condition:\n        uint16(0) == 0x5A4D and {self.threshold} of (\n"
                f"            {body}\n        )\n}}\n")

    def matches_atoms(self, atoms: set[tuple]) -> bool:
        return sum(1 for a in self.atoms if a in atoms) >= self.threshold

    def matches(self, rec: dict) -> bool:
        return self.matches_atoms(structural_atoms(rec))


def synthesize_structural(name: str, group: list[set[tuple]], benign: list[set[tuple]], family: str = "unknown",
                          max_atoms: int = 8, min_support: float = 0.3, max_benign_rate: float = 0.002,
                          target_benign_fpr: float = 0.0) -> StructuralRule | None:
    """Pick atoms frequent in ``group`` and rare in ``benign`` (atom sets from :func:`structural_atoms`),
    then choose the smallest ``N of`` threshold whose benign hit-rate is <= ``target_benign_fpr``."""
    from collections import Counter

    gc = Counter(a for s in group for a in s)
    need = max(1, math.ceil(min_support * len(group)))
    cand = [a for a, c in gc.items() if c >= need]
    if not cand:
        return None
    bc = Counter(a for s in benign for a in s if a in set(cand))
    nb = max(len(benign), 1)
    cand = [a for a in cand if bc[a] / nb <= max_benign_rate]
    if not cand:
        return None
    # prefer high group support, low benign rate, and diverse atom kinds (imphash, sections, imports)
    cand.sort(key=lambda a: (-(gc[a] / len(group) - 5 * bc[a] / nb), a[0] != "imphash", a))
    atoms = cand[:max_atoms]
    best = None
    for thr in range(1, len(atoms) + 1):
        r = StructuralRule(re.sub(r"[^A-Za-z0-9_]", "_", name), atoms, thr, family, len(group))
        fp = sum(r.matches_atoms(b) for b in benign) / nb
        if fp <= target_benign_fpr:
            best = r
            break
    return best
