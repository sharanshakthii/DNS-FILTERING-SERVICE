"""
Lexical features for DGA detection.

Deliberately a separate module imported by *both* the trainer and the runtime
module. Feature code duplicated between training and serving is the classic
way to get a model that scores well offline and badly in production, because
the two implementations drift. There is one implementation here and both
sides call it.

## The feature vector

Ten features, chosen to be cheap, deterministic, and individually
explainable. The intuition behind each is that algorithmically generated
labels are drawn from a near-uniform character distribution while human-
chosen ones are pronounceable and repetitive:

    length              characters in the registrable label
    digit_ratio         proportion of digits
    vowel_ratio         proportion of aeiou — pronounceable names have more
    consonant_ratio     proportion of consonants
    unique_char_ratio   distinct characters / length; random strings repeat less
    entropy             Shannon entropy over the label's characters
    max_consonant_run   longest unbroken consonant sequence
    max_digit_run       longest unbroken digit sequence
    hyphen_count        hyphens in the label
    label_count         labels in the full name

Deliberately excluded: n-gram and dictionary features. They are stronger
predictors and appear throughout the literature, but they need a corpus this
project does not have, and adding them would make the feature set look
sophisticated without any evidence that it helps here. Stage 16 is where
feature selection gets evidence.

Every feature is bounded or naturally small, and all are computed on the
lowercased registrable label except `label_count`.
"""

from __future__ import annotations

import math

VOWELS = frozenset("aeiou")
CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")
DIGITS = frozenset("0123456789")

#: Fixed order. The artifact records this list, and inference refuses to run
#: against an artifact whose order differs — a silently reordered vector
#: would produce confident nonsense rather than an error.
FEATURE_NAMES = (
    "length",
    "digit_ratio",
    "vowel_ratio",
    "consonant_ratio",
    "unique_char_ratio",
    "entropy",
    "max_consonant_run",
    "max_digit_run",
    "hyphen_count",
    "label_count",
)


#: Feature set v2. Two changes from v1, each fixing a measured defect:
#:
#: 1. `label_count` is dropped. Subdomain depth is chosen by a zone or a
#:    hosting platform, not by a generator producing a label. In v1 it was
#:    also an artefact: every three-label training row was `<x>.co.uk`, so
#:    the model learned label_count as a proxy and fired on every name with
#:    a subdomain (`mail.google.com` scored 0.83).
#: 2. The label is located with the Public Suffix List (site view), so
#:    `x.co.uk` analyses `x` rather than `co`, and `x.pages.dev` analyses
#:    the customer's `x` rather than `pages`.
FEATURE_NAMES_V2 = tuple(n for n in FEATURE_NAMES if n != "label_count")

#: Artifacts record their feature list; the set is chosen by matching it.
FEATURE_SETS = {"v1": FEATURE_NAMES, "v2": FEATURE_NAMES_V2}


def feature_set_for(names) -> str | None:
    names = tuple(names)
    for key, expected in FEATURE_SETS.items():
        if names == expected:
            return key
    return None


def registrable_label(qname: str) -> tuple[str, int]:
    """Return (label to analyse, number of labels in the name).

    The second-level label is analysed rather than the whole name, because
    the TLD is not chosen by the generator and the subdomain often is not
    either. Same last-two-labels approximation the other modules use, with
    the same public-suffix limitation.
    """
    cleaned = (qname or "").strip().lower().rstrip(".")
    if not cleaned:
        return "", 0
    labels = [label for label in cleaned.split(".") if label]
    if not labels:
        return "", 0
    label = labels[-2] if len(labels) >= 2 else labels[0]
    return label, len(labels)


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits over the characters of `text`."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def longest_run(text: str, members: frozenset) -> int:
    """Length of the longest unbroken run of characters from `members`."""
    best = run = 0
    for ch in text:
        if ch in members:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def extract_features(qname: str, feature_set: str = "v1") -> dict[str, float]:
    """Feature dictionary for one domain name.

    `feature_set` "v1" (the default) is the published model's extraction,
    unchanged; "v2" is described at FEATURE_NAMES_V2.

    Never raises. A malformed or empty name yields an all-zero vector rather
    than an exception, because this runs on the DNS query path and a crash
    there is an outage. The module records that the name was unusable.
    """
    if feature_set == "v2":
        from feeds.psl import registrable_label as psl_label
        label = psl_label(qname, private=True)
        label_count = 0
        names = FEATURE_NAMES_V2
    elif feature_set == "v1":
        label, label_count = registrable_label(qname)
        names = FEATURE_NAMES
    else:
        raise ValueError(f"unknown feature set {feature_set!r}")
    length = len(label)

    if length == 0:
        return {name: 0.0 for name in names}

    digits = sum(1 for ch in label if ch in DIGITS)
    vowels = sum(1 for ch in label if ch in VOWELS)
    consonants = sum(1 for ch in label if ch in CONSONANTS)

    features = {
        "length": float(length),
        "digit_ratio": digits / length,
        "vowel_ratio": vowels / length,
        "consonant_ratio": consonants / length,
        "unique_char_ratio": len(set(label)) / length,
        "entropy": shannon_entropy(label),
        "max_consonant_run": float(longest_run(label, CONSONANTS)),
        "max_digit_run": float(longest_run(label, DIGITS)),
        "hyphen_count": float(label.count("-")),
        "label_count": float(label_count),
    }
    if feature_set == "v2":
        del features["label_count"]
    return features


def feature_vector(qname: str, feature_set: str = "v1") -> list[float]:
    """Features as an ordered list matching the set's names."""
    features = extract_features(qname, feature_set)
    return [features[name] for name in FEATURE_SETS[feature_set]]
