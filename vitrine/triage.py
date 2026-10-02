"""End-to-end static triage pipeline: dissect -> tag -> featurize -> score/attribute -> YARA -> route.

Works with either verdict model:

* :class:`vitrine.gbdt.GBDTVerdictModel` -- XGBoost trained on EMBER 2018 (real data), with
  validation-calibrated thresholds: MALICIOUS at the 0.1 %-FPR point, SUSPICIOUS at the 1 %-FPR point.
* :class:`vitrine.model.VerdictModel` -- the dependency-free linear model trained on the synthetic
  corpus (demo / CI), with fixed 0.7 / 0.3 thresholds.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .capabilities import HIGH_RISK_ATTACK_IDS, tag
from .dissect import dissect, is_packed, packing_signals
from .ember import raw_from_report
from .features import vector_raw
from .model import VerdictModel
from .models import TriageResult, Verdict
from .synth import MALICIOUS_FAMILIES, corpus
from .yara_synth import structural_atoms, synthesize, synthesize_structural, validate

if TYPE_CHECKING:
    from .gbdt import GBDTVerdictModel

MAL_THR = 0.7
SUS_THR = 0.3


def vector_bytes(data: bytes) -> list[float]:
    return vector_raw(raw_from_report(dissect(data), data))


def train_default(n_per_family: int = 20, seed: int = 0) -> VerdictModel:
    """Linear model on the synthetic inert corpus (fast, dependency-free; for demos and CI)."""
    data = corpus(n_per_family, seed)
    X = [vector_bytes(b) for _, b in data]
    y = [int(f in MALICIOUS_FAMILIES) for f, _ in data]
    return VerdictModel().fit(X, y, [f for f, _ in data])


def thresholds(model) -> tuple[float, float]:
    t = getattr(model, "thresholds", None) or {}
    return t.get("fpr_0.1pct", MAL_THR), t.get("fpr_1pct", SUS_THR)


def analyze(data: bytes, model: VerdictModel | GBDTVerdictModel, benign: list[bytes] | None = None,
            siblings: list[bytes] | None = None) -> TriageResult:
    """Statically triage one PE file (bytes are parsed, never executed).

    Args:
        data: raw file bytes.
        model: a verdict model from :func:`load_model` or :func:`train_default`.
        benign: optional benign corpus; when given, non-benign verdicts get a candidate YARA rule
            validated for specificity against it.
        siblings: optional suspected same-family samples, used for rule coverage.

    Returns:
        TriageResult with verdict, score, SHAP attributions, capabilities, notes and rules.

    Raises:
        PEParseError: the bytes are not a parseable PE file.
    """
    rep = dissect(data)
    raw = raw_from_report(rep, data)
    x = vector_raw(raw)
    score = model.score(x)
    mal_thr, sus_thr = thresholds(model)
    verdict = Verdict.MALICIOUS if score >= mal_thr else Verdict.SUSPICIOUS if score >= sus_thr else Verdict.BENIGN
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
        notes.append("packed: static view is partial and packed benign files have a higher false-positive rate "
                     "-> recommend dynamic sandbox")
    rule = None
    structural = None
    if verdict != Verdict.BENIGN and benign is not None:
        name = f"vitrine_{family or 'sample'}_{rep.sha256[:8]}"
        rule = synthesize(name, [data] + (siblings or []), benign, family)
        if rule:
            validate(rule, benign, siblings or [])
        group = [structural_atoms(raw)] + [structural_atoms(raw_from_report(dissect(s))) for s in siblings or []]
        ben = [structural_atoms(raw_from_report(dissect(b))) for b in benign]
        srule = synthesize_structural(name + "_pe", group, ben, family or "unknown", min_support=0.6)
        structural = srule.text if srule else None
    explainer = "linear SHAP" if isinstance(model, VerdictModel) else "TreeSHAP"
    return TriageResult(rep.sha256, verdict, round(score, 4), family, packed, route,
                        model.attribute(x), caps, rule, notes, structural_rule=structural, explainer=explainer)


def load_model(path: str) -> VerdictModel | GBDTVerdictModel:
    """Load either model format (EMBER XGBoost ``vitrine-gbdt-1`` or linear demo) by sniffing the file."""
    from pathlib import Path

    with open(Path(path), encoding="utf-8") as f:
        head = f.read(64)
    if '"vitrine-gbdt-1"' in head:
        from .gbdt import GBDTVerdictModel

        return GBDTVerdictModel.load(path)
    return VerdictModel.load(path)
