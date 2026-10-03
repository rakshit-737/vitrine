"""Feature-definition classes shared by the drift scripts (``bench_drift*.py``).

Every one of VITRINE's 91 named features is put in one class, by how its EMBER v2 (2018, LIEF 0.9)
and EMBER v3 (2024, thrember/pefile) values are defined:

* ``redefined``  -- v3 has no equivalent, the nearest counter is used (string IOC counters);
* ``proxy``      -- same concept, derived from a different field (general flags, vsize);
* ``parser``     -- same definition, different PE parser (LIEF 0.9 vs pefile in thrember), and the two
                    parsers agree on the parity corpus (``results/extractor_parity.json``);
* ``parser_extractor_sensitive`` -- same definition, but LIEF 0.9 and pefile disagree on more than 1 %
                    of identical benign files in that parity run (e.g. section entropies);
* ``byte_level`` -- same definition on raw bytes, no parser involved (histograms, strings).

Only ``parser`` and ``byte_level`` features are "faithful" (comparable across the two datasets). The
parity corpus is benign open-source DLLs, not EMBER's files, so agreement there is necessary, not
sufficient.
"""
from __future__ import annotations

import json
from pathlib import Path

PARITY_FILE = Path(__file__).resolve().parents[1] / "results" / "extractor_parity.json"
CLOSE_AGREEMENT_MIN = 0.99  # share of files where the two extractors agree within 1 %


def _extractor_sensitive() -> dict[str, float]:
    """Parser features whose LIEF-0.9 and pefile values agree within 1 % on fewer than 99 % of files."""
    if not PARITY_FILE.exists():
        return {}
    feats = json.loads(PARITY_FILE.read_text(encoding="utf-8"))["features"]
    return {f["feature"]: f["close_agreement_1pct"] for f in feats
            if f["class"] in ("parser", "parser_extractor_sensitive")
            and f["close_agreement_1pct"] < CLOSE_AGREEMENT_MIN}


EXTRACTOR_SENSITIVE = _extractor_sensitive()

REDEFINED = {
    "n_embedded_mz": "v2: count of b'MZ' anywhere in the file; v3: strings containing '!This program ' (dos_msg)",
    "n_paths": "v2: 'c:\\' case-insensitive anywhere; v3: strings matching r'\\bC:/' (forward slash, case-sensitive)",
    "n_registry": "v2: 'HKEY_' anywhere; v3: strings matching r'\\b(?:KHEY_|KHLM|HKCU)'",
    "n_urls": "v2: 'http(s)://' anywhere; v3: strings matching the thrember url regex (also ftp)",
}
PROXY = {
    "has_signature": "v2 LIEF flag; v3 SECURITY data-directory size > 0",
    "has_debug": "v2 LIEF has_debug; v3 DEBUG data-directory size > 0",
    "has_tls": "v2 LIEF has_tls; v3 TLS data-directory size > 0",
    "has_relocations": "v2 LIEF flag; v3 BASERELOC data-directory size > 0",
    "has_resources": "v2 LIEF flag; v3 RESOURCE data-directory size > 0",
    "vsize_to_size": "v2 LIEF virtual_size; v3 optional.sizeof_image",
}
BYTE_LEVEL = {"size_kb", "file_entropy", "high_entropy_window_frac", "n_strings", "avg_string_len",
              "string_entropy", "printable_ratio"}


def feature_class(n: str) -> str:
    if n in REDEFINED:
        return "redefined"
    if n in PROXY:
        return "proxy"
    if n in BYTE_LEVEL:
        return "byte_level"
    if n in EXTRACTOR_SENSITIVE:
        return "parser_extractor_sensitive"
    return "parser"


def feature_group(n: str) -> str:
    if n.startswith("cap:") or n in ("capability_count", "high_risk_capabilities"):
        return "capability"
    if n.startswith("api_") or n in ("n_dlls", "n_imports", "n_ordinal_imports", "n_exports", "imports_tiny"):
        return "imports"
    if "section" in n or n.startswith("entry_") or n == "max_vsize_ratio":
        return "sections"
    if n in BYTE_LEVEL or n == "unaccounted_ratio":
        return "bytes_strings"
    return "header"


FAITHFUL = ("parser", "byte_level")


def shift_pattern(pb: float, pm: float) -> str:
    """Which class a feature shifts in (PSI >= 0.25 counts as a shift, < 0.1 as stable)."""
    return ("both_classes" if pb >= 0.25 and pm >= 0.25 else
            "benign_only" if pb >= 0.25 and pm < 0.1 else
            "malicious_only" if pm >= 0.25 and pb < 0.1 else
            "stable" if max(pb, pm) < 0.1 else "mixed")
