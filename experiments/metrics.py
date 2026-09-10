"""
Classification metrics.

Plain arithmetic on counts, implemented here so the experiments need no
dependency the DNS path does not already have. scikit-learn would give the
same numbers; it is a training-only dependency in this project and the
experiments must run without it.

Every function is pure and takes explicit counts or label lists, so the tests
can check them against values worked out by hand rather than against another
implementation of the same formula.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Metrics:
    """Counts and derived rates for one binary evaluation."""

    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def total(self) -> int:
        return (self.true_positive + self.false_positive
                + self.true_negative + self.false_negative)

    @property
    def accuracy(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.true_positive + self.true_negative) / self.total

    @property
    def precision(self) -> float:
        """Of the queries flagged, how many should have been.

        Zero when nothing was flagged. That is a convention, not a
        measurement: a configuration that flags nothing has undefined
        precision, and the `predicted_positive` count is reported alongside
        so the two cases are distinguishable.
        """
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    @property
    def false_positive_rate(self) -> float:
        """The number a network operator actually cares about."""
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else 0.0

    @property
    def false_negative_rate(self) -> float:
        denominator = self.false_negative + self.true_positive
        return self.false_negative / denominator if denominator else 0.0

    @property
    def predicted_positive(self) -> int:
        return self.true_positive + self.false_positive

    def as_dict(self) -> dict:
        return {
            **asdict(self),
            "total": self.total,
            "predicted_positive": self.predicted_positive,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
        }


def confusion(labels: list[int], predictions: list[int]) -> Metrics:
    """Build a confusion matrix from aligned label and prediction lists."""
    if len(labels) != len(predictions):
        raise ValueError(
            f"{len(labels)} labels but {len(predictions)} predictions")

    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for label, prediction in zip(labels, predictions):
        if label not in (0, 1) or prediction not in (0, 1):
            raise ValueError(
                f"labels and predictions must be 0 or 1, got "
                f"{label!r}/{prediction!r}")
        if label == 1:
            counts["tp" if prediction == 1 else "fn"] += 1
        else:
            counts["fp" if prediction == 1 else "tn"] += 1

    return Metrics(true_positive=counts["tp"], false_positive=counts["fp"],
                   true_negative=counts["tn"], false_negative=counts["fn"])
