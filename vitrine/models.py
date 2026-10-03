"""Typed contracts shared across the pipeline."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Verdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int
    entropy: float

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)


@dataclass
class PEReport:
    sha256: str
    size: int
    machine: int
    timestamp: int
    entry_point: int
    image_base: int
    subsystem: int
    is_dll: bool
    sections: list[Section]
    imports: dict[str, list[str]]
    strings: list[str]
    overall_entropy: float
    imphash: str
    anomalies: list[str] = field(default_factory=list)
    # richer header / directory data (filled by dissect(); defaults keep old callers working)
    pe32plus: bool = False
    coff_characteristics: int = 0
    dll_characteristics: int = 0
    header: dict = field(default_factory=dict)
    data_directories: list[tuple[int, int]] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    delay_imports: dict[str, list[str]] = field(default_factory=dict)
    resource_types: list[str] = field(default_factory=list)
    entry_section: str = ""
    size_of_image: int = 0
    overlay_size: int = 0
    n_symbols: int = 0
    # strings inside the certificate table (Authenticode CRL/AIA/CPS URLs); not part of ``strings``' meaning
    signature_strings: list[str] = field(default_factory=list)

    @property
    def import_names(self) -> set[str]:
        return {f for fs in self.imports.values() for f in fs}


@dataclass
class Capability:
    name: str
    attack_id: str
    evidence: list[str]


@dataclass
class Attribution:
    feature: str
    value: float
    contribution: float
    explanation: str


@dataclass
class YaraRule:
    name: str
    text: str
    strings: list[str]
    threshold: int
    benign_hits: int = 0
    benign_total: int = 0
    sibling_hits: int = 0
    sibling_total: int = 0

    @property
    def specificity(self) -> float | None:
        return 1.0 - self.benign_hits / self.benign_total if self.benign_total else None

    @property
    def coverage(self) -> float | None:
        return self.sibling_hits / self.sibling_total if self.sibling_total else None


@dataclass
class TriageResult:
    sha256: str
    verdict: Verdict
    score: float
    family: str | None
    packed: bool
    route_to_dynamic: bool
    attributions: list[Attribution]
    capabilities: list[Capability]
    yara: YaraRule | None
    notes: list[str] = field(default_factory=list)
    structural_rule: str | None = None  # pe-module rule (imports/sections/imphash), see yara_synth
    explainer: str | None = None  # "TreeSHAP" (XGBoost model) or "linear SHAP" (synthetic demo model)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        if self.yara:
            d["yara"]["specificity"] = self.yara.specificity
            d["yara"]["coverage"] = self.yara.coverage
        return d
