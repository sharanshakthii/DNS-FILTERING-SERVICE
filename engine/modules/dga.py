"""
DGA detection module.

The fourth signal, and the one this project's title promises. Threat
intelligence needs somebody to have reported a domain; domain age needs it to
be young; typosquatting needs it to resemble a configured brand. A domain
generation algorithm produces names that are none of those things — unreported,
possibly not new, resembling nothing — which is the gap this module addresses.

**What the score means.** It is the trained model's estimated probability that
the queried label was algorithmically generated: a **DGA likelihood score**,
not a probability that the domain is malicious. Plenty of legitimate names look
random and some malware uses dictionary words. The evidence wording is
deliberate and the report must keep it.

**No framework at inference.** The model is a logistic regression exported to
JSON by `tools/train_dga.py`, which asserts the exported form reproduces
scikit-learn's `predict_proba` before writing it. Scoring is a standardisation,
a dot product and a sigmoid — the same arithmetic, in the standard library, so
the DNS query path keeps the zero-dependency property it has had since Stage 1.

Nothing here is novel. Lexical DGA classification is a well-established
technique with a large literature; this is an implementation of it, integrated
as one signal among several.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from .base import (
    DetectionModule,
    ModuleScore,
    ModuleUnavailable,
    QueryContext,
)
from .dga_features import FEATURE_NAMES, extract_features, feature_set_for

DEFAULT_MODEL_PATH = "models/dga/dga_model.json"
SUPPORTED_ARTIFACT_VERSION = 1


class ModelUnavailable(ModuleUnavailable):
    """The model artifact is missing, unreadable, or incompatible.

    Raised rather than returning 0.0. Zero means "the model scored this as
    benign-like"; a missing artifact means "no model ran". The engine records
    the difference as status=error and excludes the module, so a broken
    deployment cannot silently look like a clean verdict on every query —
    the same semantics the threat-intelligence module uses for a feed outage.
    """


class DGAModel:
    """A logistic regression loaded from the exported JSON artifact."""

    def __init__(self, artifact: dict, source: str = "") -> None:
        self.source = source

        version = artifact.get("artifact_version")
        if version != SUPPORTED_ARTIFACT_VERSION:
            raise ModelUnavailable(
                f"artifact version {version!r} is not supported "
                f"(this build understands {SUPPORTED_ARTIFACT_VERSION})")

        self.model_name = artifact.get("model", "unknown")
        self.feature_names = tuple(artifact.get("feature_names") or ())

        # A reordered or renamed feature list would silently produce confident
        # nonsense, so it is a hard error rather than a warning.
        self.feature_set = feature_set_for(self.feature_names)
        if self.feature_set is None:
            raise ModelUnavailable(
                f"artifact features {list(self.feature_names)} do not match "
                f"this build's {list(FEATURE_NAMES)} or any other known "
                f"feature set; retrain with tools/train_dga.py")

        try:
            self.coefficients = [float(v) for v in artifact["coefficients"]]
            self.intercept = float(artifact["intercept"])
            self.mean = [float(v) for v in artifact["scaler_mean"]]
            self.scale = [float(v) for v in artifact["scaler_scale"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelUnavailable(f"artifact is malformed: {exc}") from exc

        widths = {len(self.coefficients), len(self.mean), len(self.scale),
                  len(self.feature_names)}
        if len(widths) != 1:
            raise ModelUnavailable(
                f"artifact vectors disagree in length: {sorted(widths)}")
        if any(s == 0 for s in self.scale):
            raise ModelUnavailable("artifact has a zero scaler scale")

    @classmethod
    def load(cls, path: str) -> "DGAModel":
        artifact_path = Path(path)
        if not artifact_path.exists():
            raise ModelUnavailable(
                f"no model artifact at {artifact_path}. Train one with: "
                f"pip install -r requirements-train.txt && "
                f"python tools/train_dga.py")
        try:
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ModelUnavailable(
                f"cannot read {artifact_path}: {exc}") from exc
        if not isinstance(artifact, dict):
            raise ModelUnavailable(f"{artifact_path} is not a JSON object")
        return cls(artifact, source=str(artifact_path))

    def probability(self, features: dict[str, float]) -> float:
        """P(algorithmically generated) for one feature dictionary.

        Standardise, dot product, sigmoid — numerically identical to what
        scikit-learn produced during training.
        """
        z = self.intercept
        for i, name in enumerate(self.feature_names):
            z += ((features[name] - self.mean[i]) / self.scale[i]) \
                * self.coefficients[i]
        # Guard the exponential against overflow on extreme inputs; the
        # result is already saturated at those magnitudes.
        if z >= 0:
            return round(1.0 / (1.0 + math.exp(-min(z, 700.0))), 6)
        return round(math.exp(max(z, -700.0)) / (1.0 + math.exp(max(z, -700.0))), 6)

    def top_contributions(self, features: dict[str, float], limit: int = 3
                          ) -> list[dict]:
        """The features that moved this score most, for the evidence trace.

        Available because the model is linear: each feature contributes one
        signed term. A forest could only offer global importances, which say
        nothing about an individual decision.
        """
        terms = []
        for i, name in enumerate(self.feature_names):
            standardised = (features[name] - self.mean[i]) / self.scale[i]
            terms.append({
                "feature": name,
                "value": round(features[name], 4),
                "contribution": round(standardised * self.coefficients[i], 4),
            })
        terms.sort(key=lambda t: abs(t["contribution"]), reverse=True)
        return terms[:limit]


class DGAModule(DetectionModule):
    """Scores how algorithmically generated a queried label looks."""

    name = "dga"

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH,
                 threshold: float = 0.5) -> None:
        """`threshold` labels the score in the evidence; it does not gate it.

        The raw probability is always what the aggregator receives. The
        threshold only decides the wording of `verdict_hint`, so changing it
        cannot silently alter a risk score.
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(
                f"threshold must be within [0,1], got {threshold}")
        self.model_path = model_path
        self.threshold = threshold
        self._model: DGAModel | None = None
        self._load_error: str | None = None

    @classmethod
    def from_settings(cls, settings) -> "DGAModule":
        return cls(model_path=settings.dga_model_path,
                   threshold=settings.dga_threshold)

    @property
    def model(self) -> DGAModel:
        """Load once, on first use, and keep the failure if it fails.

        Lazy so that constructing the module never touches the disk, which
        keeps startup honest when the artifact is absent: the failure surfaces
        per query as a module error rather than preventing the proxy booting.
        """
        if self._model is None:
            try:
                self._model = DGAModel.load(self.model_path)
                self._load_error = None
            except ModelUnavailable as exc:
                self._load_error = str(exc)
                raise
        return self._model

    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        model = self.model          # raises ModelUnavailable if absent

        features = extract_features(ctx.qname, model.feature_set)
        label, _count = (ctx.qname or "").strip().lower().rstrip("."), None

        if features["length"] == 0.0:
            return ModuleScore(0.0, {
                "model": model.model_name,
                "artifact": model.source,
                "qname": ctx.qname,
                "scored": False,
                "reason": "no usable label to score",
            })

        score = model.probability(features)

        return ModuleScore(score=score, features={
            "model": model.model_name,
            "artifact_version": SUPPORTED_ARTIFACT_VERSION,
            "artifact": model.source,
            "qname": label,
            "scored": True,
            "dga_score": score,
            "threshold": self.threshold,
            "verdict_hint": ("DGA-like" if score >= self.threshold
                             else "benign-like"),
            "feature_names": list(model.feature_names),
            "feature_set": model.feature_set,
            "feature_values": {name: round(value, 4)
                               for name, value in features.items()},
            "top_contributions": model.top_contributions(features),
            "reason": (f"model DGA likelihood score {score:.3f} "
                       f"(threshold {self.threshold}); this estimates whether "
                       f"the label was algorithmically generated, not whether "
                       f"the domain is malicious"),
        })
