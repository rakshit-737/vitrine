"""End-to-end static triage pipeline: dissect -> tag -> featurize -> score/attribute -> YARA."""
from __future__ import annotations

from .capabilities import tag
from .dissect import dissect, is_packed, packing_signals
from .features import vector
from .model import VerdictModel
from .models import TriageResult, Verdict
from .synth import MALICIOUS_FAMILIES, corpus
from .yara_synth import synthesize, validate

MAL_THR = 0.7
SUS_THR = 0.3
# capabilities that are costly to evade statically; they floor the verdict at SUSPICIOUS
HIGH_RISK_ATTACK_IDS = {"T1055.002", "T1056.001", "T1105"}


def train_default(n_per_family: int = 20, seed: int = 0) -> VerdictModel:
    data = corpus(n_per_family, seed)
    X = [vector(dissect(b)) for _, b in data]
    y = [int(f in MALICIOUS_FAMILIES) for f, _ in data]
    return VerdictModel().fit(X, y, [f for f, _ in data])


def analyze(data: bytes, model: VerdictModel, benign: list[bytes] | None = None,
            siblings: list[bytes] | None = None) -> TriageResult:
    rep = dissect(data)
    x = vector(rep)
    score = model.score(x)
    verdict = Verdict.MALICIOUS if score >= MAL_THR else Verdict.SUSPICIOUS if score >= SUS_THR else Verdict.BENIGN
    caps = tag(rep)
    packed = is_packed(rep)
    notes = list(rep.anomalies) + packing_signals(rep)
    risky = sorted({c.attack_id for c in caps} & HIGH_RISK_ATTACK_IDS)
    if verdict == Verdict.BENIGN and risky:
        verdict = Verdict.SUSPICIOUS
        notes.append(f"ML score low but high-risk capabilities {risky} present "
                     "(possible feature-space evasion) -> floored to SUSPICIOUS")
    family = model.family(x)[0] if verdict != Verdict.BENIGN else None
    # packed samples starve static features: don't over-trust, route to dynamic analysis
    route = packed or verdict == Verdict.SUSPICIOUS
    if packed:
        notes.append("static features likely starved by packing -> recommend dynamic sandbox")
    rule = None
    if verdict != Verdict.BENIGN and benign is not None:
        rule = synthesize(f"vitrine_{family or 'sample'}_{rep.sha256[:8]}", [data] + (siblings or []),
                          benign, family)
        if rule:
            validate(rule, benign, siblings or [])
    return TriageResult(rep.sha256, verdict, round(score, 4), family, packed, route,
                        model.attribute(x), caps, rule, notes)
