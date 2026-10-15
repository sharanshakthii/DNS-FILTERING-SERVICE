"""
Train the DGA classifier.

Run offline, never on the DNS query path. Produces a small JSON artifact the
proxy loads at startup.

## Why logistic regression, and why a JSON artifact

Logistic regression was chosen over a forest or boosting for two reasons.
First, it is directly explainable: each feature has one signed coefficient, so
the evidence can show which features pushed the score up. A forest can only
offer importances, which are not per-decision. Second, and decisively for this
project, a fitted logistic regression is fully described by a weight vector,
an intercept and the scaler's means and scales — so it exports to JSON and
inference is a dot product and a sigmoid.

That matters because the DNS proxy has run on the standard library alone
since Stage 1. Importing scikit-learn into the query path to evaluate ten
multiplications would add a large dependency to the component whose latency
this project measures. The exported form reproduces `predict_proba`
numerically; the trainer asserts it before writing the artifact, so this is
not a reimplementation that might drift — it is the same arithmetic.

Usage:
    pip install -r requirements-train.txt
    python tools/train_dga.py
    python tools/train_dga.py --dataset datasets/dga_dev.csv --seed 20260904
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.modules.dga_features import FEATURE_SETS, feature_vector  # noqa: E402

SEED = 20260904
TEST_SIZE = 0.25
ARTIFACT_VERSION = 1


def load_dataset(path: Path) -> tuple[list[str], list[int]]:
    """Read and validate the CSV. Rejects bad rows loudly rather than dropping.

    A silently skipped row changes the dataset the metrics describe, which
    makes the reported numbers unreproducible for anyone else.
    """
    if not path.exists():
        raise SystemExit(
            f"dataset not found: {path}\n"
            f"Generate it with: python tools/make_dga_dataset.py")

    domains: list[str] = []
    labels: list[int] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["domain", "label"]:
            raise SystemExit(
                f"expected columns ['domain', 'label'], got {reader.fieldnames}")
        for number, row in enumerate(reader, start=2):
            domain = (row.get("domain") or "").strip().lower()
            raw = (row.get("label") or "").strip()
            if not domain:
                raise SystemExit(f"{path}:{number}: empty domain")
            if raw not in {"0", "1"}:
                raise SystemExit(
                    f"{path}:{number}: label must be 0 or 1, got {raw!r}")
            domains.append(domain)
            labels.append(int(raw))

    if len(set(labels)) < 2:
        raise SystemExit("the dataset contains only one class")
    return domains, labels


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the DGA classifier")
    parser.add_argument("--dataset",
                        default=str(REPO_ROOT / "datasets" / "dga_dev.csv"))
    parser.add_argument("--out",
                        default=str(REPO_ROOT / "models" / "dga"))
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--test-size", type=float, default=TEST_SIZE)
    parser.add_argument("--feature-set", choices=sorted(FEATURE_SETS),
                        default="v1",
                        help="v1 reproduces the published model; v2 drops "
                             "label_count and locates the label with the PSL")
    parser.add_argument("--name", default="dga_model",
                        help="artifact file stem, e.g. dga_model_v2")
    args = parser.parse_args()

    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import (
            accuracy_score, confusion_matrix, f1_score, precision_score,
            recall_score,
        )
        from sklearn.model_selection import cross_val_score, train_test_split
        from sklearn.preprocessing import StandardScaler
        import sklearn
    except ImportError as exc:
        raise SystemExit(
            f"scikit-learn is required for training: {exc}\n"
            f"Install it with: pip install -r requirements-train.txt\n"
            f"It is NOT needed to run the proxy or the API — the exported "
            f"artifact is plain JSON.") from exc

    dataset_path = Path(args.dataset)
    domains, labels = load_dataset(dataset_path)
    print(f"dataset : {dataset_path} ({len(domains)} rows, "
          f"{labels.count(0)} benign / {labels.count(1)} DGA-like)")

    FEATURE_NAMES = FEATURE_SETS[args.feature_set]
    print(f"features: {args.feature_set} ({len(FEATURE_NAMES)})")
    X = np.array([feature_vector(d, args.feature_set) for d in domains],
                 dtype=float)
    y = np.array(labels, dtype=int)

    # Stratified so both classes appear in both halves; seeded so the split
    # is identical on every machine and no row crosses between them.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y)
    print(f"split   : {len(X_train)} train / {len(X_test)} test "
          f"(seed {args.seed}, stratified)")

    scaler = StandardScaler().fit(X_train)     # fitted on train only
    model = LogisticRegression(max_iter=1000, random_state=args.seed)
    model.fit(scaler.transform(X_train), y_train)

    predictions = model.predict(scaler.transform(X_test))
    matrix = confusion_matrix(y_test, predictions)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions,
                                                 zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, predictions,
                                           zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "confusion_matrix": {
            "true_negative": int(matrix[0][0]), "false_positive": int(matrix[0][1]),
            "false_negative": int(matrix[1][0]), "true_positive": int(matrix[1][1]),
        },
    }

    cv = cross_val_score(
        LogisticRegression(max_iter=1000, random_state=args.seed),
        scaler.transform(X_train), y_train, cv=5, scoring="f1")
    metrics["cv_f1_mean"] = round(float(cv.mean()), 4)
    metrics["cv_f1_std"] = round(float(cv.std()), 4)

    print("\nheld-out test metrics")
    for key in ("accuracy", "precision", "recall", "f1"):
        print(f"  {key:<10} {metrics[key]}")
    print(f"  confusion  {metrics['confusion_matrix']}")
    print(f"  5-fold CV f1 (train) {metrics['cv_f1_mean']} "
          f"± {metrics['cv_f1_std']}")

    # -- export ------------------------------------------------------------
    artifact = {
        "artifact_version": ARTIFACT_VERSION,
        "model": "logistic_regression",
        "feature_names": list(FEATURE_NAMES),
        "coefficients": [float(c) for c in model.coef_[0]],
        "intercept": float(model.intercept_[0]),
        "scaler_mean": [float(v) for v in scaler.mean_],
        "scaler_scale": [float(v) for v in scaler.scale_],
    }

    # The exported form must reproduce scikit-learn's own probabilities. If
    # it does not, the artifact is wrong and writing it would ship a model
    # that scores differently in the proxy than it did in training.
    import math

    def exported_probability(vector: list[float]) -> float:
        z = artifact["intercept"] + sum(
            ((value - mean) / scale) * weight
            for value, mean, scale, weight in zip(
                vector, artifact["scaler_mean"], artifact["scaler_scale"],
                artifact["coefficients"]))
        return 1.0 / (1.0 + math.exp(-z))

    reference = model.predict_proba(scaler.transform(X_test))[:, 1]
    worst = max(abs(exported_probability(list(row)) - float(expected))
                for row, expected in zip(X_test, reference))
    if worst > 1e-9:
        raise SystemExit(
            f"exported artifact disagrees with scikit-learn by {worst}; "
            f"refusing to write it")
    print(f"\nexport check: max |exported - sklearn| = {worst:.2e}")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / f"{args.name}.json"
    meta_path = out_dir / f"{args.name}.meta.json"

    model_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")

    metadata = {
        "artifact_version": ARTIFACT_VERSION,
        "model": "logistic_regression",
        "library": f"scikit-learn {sklearn.__version__}",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": args.seed,
        "feature_set": args.feature_set,
        "feature_names": list(FEATURE_NAMES),
        "dataset": {
            "path": str(dataset_path.relative_to(REPO_ROOT)),
            "rows": len(domains),
            "benign": labels.count(0),
            "dga_like": labels.count(1),
            "kind": "SYNTHETIC development fixture",
        },
        "split": {"test_size": args.test_size, "stratified": True,
                  "train_rows": int(len(X_train)), "test_rows": int(len(X_test))},
        "metrics": metrics,
        "caveat": (
            "Measured on a SYNTHETIC development dataset whose two classes are "
            "far more separable than real DNS traffic. These figures show the "
            "pipeline works end to end. They are NOT an evaluation of DGA "
            "detection performance and must not be reported as one. Real "
            "evaluation is Stage 16."),
    }
    meta_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")

    print(f"\nwrote {model_path} ({model_path.stat().st_size} bytes)")
    print(f"wrote {meta_path}")
    print("\n" + metadata["caveat"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
