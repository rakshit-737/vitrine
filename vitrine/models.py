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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        if self.yara:
            d["yara"]["specificity"] = self.yara.specificity
            d["yara"]["coverage"] = self.yara.coverage
        return d
