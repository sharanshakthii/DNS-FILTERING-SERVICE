"""
Typosquat / brand-impersonation module.

Why this signal exists, and what it is not. Threat intelligence answers "has
anyone reported this?"; domain age answers "has it existed long enough for
anyone to find out?". Neither helps against a domain registered an hour ago
that is one keystroke away from a bank. Agten et al. (NDSS 2015) measured
typosquatting on the .com space over seven months and found it pervasive and
persistent, which is why lexical similarity is a signal families of detectors
use — this module is an implementation of well-known techniques, not a new
algorithm, and nothing here is claimed as novel.

**A brand string is not evidence of malice.** `spotify.com` contains
"spotify" and is the brand. `open.spotify.com` is the brand's own subdomain.
This module scores *deviation from* a configured brand, and it says in the
evidence exactly which deviation it found. A score is a detection signal, not
a finding that a domain is malicious; the aggregate verdict is a risk
judgement, and the report must not describe either as proof.

Everything is deterministic and computed in-process: no external service, no
brand API, no machine learning, no dependency beyond the standard library.

## How the score is produced

For each configured brand, the module examines every label of the queried
name plus the registrable domain. Each of the checks below produces a
candidate score; they are documented individually so a reviewer can see
precisely which one fired.

  exact official domain     0.00  registrable domain is on the official list
  brand's own registration  0.00  registrable label is exactly the brand
  transposition             0.85  same letters, different order
  confusable characters     0.85  normalises to the brand (0/o, 1/l, rn/m …)
  edit distance 1           0.90  one insertion, deletion or substitution
  edit distance 2           0.70
  edit distance 3           0.50  only for brands longer than 8 characters
  brand + suspicious word   0.75  contains the brand and a configured keyword
  brand in a subdomain      0.60  brand appears left of an unrelated
                                  registrable domain
  brand contained, alone    0.40  contains the brand and nothing else fired

The module score is the **highest** candidate, plus **0.15 when two or more
independent checks fire**, capped at 1.0. That combination rule is a
convention, not a derived optimum: it exists so that a name which is both a
near-miss spelling *and* carries a phishing keyword outranks one that is only
one of those. Like the aggregator's weights, it is tuned in Stage 16 and is
untuned today.

The maximum edit distance considered scales with brand length, because one
character of difference means far more in a five-letter brand than in a
twelve-letter one.
"""

from __future__ import annotations

from .base import (
    DetectionModule,
    ModuleScore,
    ModuleUnavailable,
    QueryContext,
)

#: Conservative ASCII confusable map. Restricted to substitutions that are
#: genuinely used in domain impersonation; a broad Unicode confusables table
#: would produce false positives on ordinary names.
CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "|": "l",
}

#: Multi-character confusable sequences, applied before the single-character
#: map. "rn" rendered small is the classic "m" impersonation.
CONFUSABLE_SEQUENCES = [("rn", "m"), ("vv", "w"), ("cl", "d")]

DEFAULT_KEYWORDS = (
    "apk,login,signin,verify,verification,secure,security,account,accounts,"
    "support,update,billing,payment,wallet,download,free,gift,recovery,alert"
)


class BrandsUnavailable(ModuleUnavailable):
    """No brands are configured, so this module has no opinion.

    Raised rather than returning 0.0, for the same reason the threat-
    intelligence module raises when no feed has loaded: zero means "checked,
    nothing found", and an empty brand list means "could not check". The
    engine records the difference as status=error and excludes the module
    from aggregation instead of quietly scoring every domain as clean.
    """


def levenshtein(a: str, b: str, cap: int | None = None) -> int:
    """Edit distance between two labels, with an optional early exit.

    Implemented here rather than pulled from a package: the inputs are DNS
    labels of at most 63 characters against a short brand list, so the cost
    is negligible and it keeps the DNS path dependency-free.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if cap is not None and abs(len(a) - len(b)) > cap:
        return cap + 1

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,        # deletion
                current[j - 1] + 1,     # insertion
                previous[j - 1] + (ca != cb),   # substitution
            ))
        if cap is not None and min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def normalise_confusables(label: str) -> str:
    """Fold the confusable characters an impersonator is likely to use."""
    out = label
    for sequence, replacement in CONFUSABLE_SEQUENCES:
        out = out.replace(sequence, replacement)
    return "".join(CONFUSABLES.get(ch, ch) for ch in out)


def decode_punycode(label: str) -> tuple[str, bool]:
    """Return (comparable label, whether it was decoded).

    An `xn--` label is compared in its decoded form, because the whole point
    of an internationalised impersonation is that the rendered text looks
    like the brand while the ASCII form does not.
    """
    if not label.startswith("xn--"):
        return label, False
    try:
        return label.encode("ascii").decode("idna"), True
    except (UnicodeError, ValueError):
        # Malformed punycode is left as-is rather than dropped: it is still a
        # label somebody queried, and the evidence records that it failed.
        return label, False


def parse_list(spec: str) -> list[str]:
    """Parse a comma-separated configuration list, lowercased and deduped."""
    seen, out = set(), []
    for item in (spec or "").split(","):
        value = item.strip().lower()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def max_distance_for(brand: str) -> int:
    """How many edits still count as a near miss, scaled by brand length."""
    if len(brand) <= 5:
        return 1
    if len(brand) <= 8:
        return 2
    return 3


class TyposquatModule(DetectionModule):
    """Scores how far a queried name deviates from a configured brand."""

    name = "typosquat"

    #: Candidate scores, named so the evidence can quote them directly.
    SCORE_TRANSPOSITION = 0.85
    SCORE_CONFUSABLE = 0.85
    SCORE_BRAND_KEYWORD = 0.75
    SCORE_SUBDOMAIN_BRAND = 0.60
    SCORE_CONTAINS_BRAND = 0.40
    COMBINATION_BONUS = 0.15

    def __init__(self, brands: list[str] | None = None,
                 official_domains: list[str] | None = None,
                 keywords: list[str] | None = None,
                 psl_mode: str = "off") -> None:
        self.brands = [b for b in (brands or []) if b]
        self.official_domains = set(official_domains or [])
        from feeds.psl import check_mode
        self.psl_mode = check_mode(psl_mode)
        self.keywords = set(keywords if keywords is not None
                            else parse_list(DEFAULT_KEYWORDS))

    @classmethod
    def from_settings(cls, settings) -> "TyposquatModule":
        return cls(
            brands=parse_list(settings.typosquat_brands),
            official_domains=parse_list(settings.typosquat_official_domains),
            keywords=parse_list(settings.typosquat_keywords),
            psl_mode=getattr(settings, "psl_mode", "off"),
        )

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def registrable(qname: str) -> str:
        """Last two labels. Same public-suffix approximation as the other
        modules, with the same limitation: for a name under a multi-label
        suffix such as `co.uk` this returns the suffix, not the registration.
        """
        labels = (qname or "").strip().lower().rstrip(".").split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else (qname or "")

    def score_for_distance(self, distance: int, brand: str) -> float | None:
        if distance < 1 or distance > max_distance_for(brand):
            return None
        return {1: 0.90, 2: 0.70, 3: 0.50}.get(distance)

    # -- evaluation --------------------------------------------------------

    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        if not self.brands:
            raise BrandsUnavailable(
                "no brands configured; set DNSF_TYPOSQUAT_BRANDS to use this "
                "module")

        qname = (ctx.qname or "").strip().lower().rstrip(".")
        if not qname:
            return ModuleScore(0.0, {"reason": "empty query name",
                                     "brands_configured": len(self.brands)})

        raw_labels = qname.split(".")
        if self.psl_mode == "off":
            registrable = self.registrable(qname)
        else:
            from feeds.psl import site_for
            registrable = site_for(qname, self.psl_mode)
        reg_label = registrable.split(".")[0] if registrable else ""

        decoded_labels, punycode = [], False
        for label in raw_labels:
            decoded, was_decoded = decode_punycode(label)
            punycode = punycode or was_decoded
            decoded_labels.append(decoded)
        reg_decoded, _ = decode_punycode(reg_label)

        base = {
            "qname": qname,
            "registrable": registrable,
            "labels_examined": decoded_labels,
            "brands_configured": len(self.brands),
        }
        if punycode:
            base["punycode_decoded"] = True

        # An official registration is the brand, not an impersonation of it.
        if registrable in self.official_domains:
            return ModuleScore(0.0, {**base, "matched_brand": None,
                                     "reason": "registrable domain is on the "
                                               "configured official list"})

        best = None
        for brand in self.brands:
            candidate = self._examine(brand, reg_decoded, decoded_labels,
                                      registrable)
            if candidate and (best is None or candidate["score"] > best["score"]):
                best = candidate

        if best is None:
            return ModuleScore(0.0, {**base, "matched_brand": None,
                                     "reason": "no configured brand resembles "
                                               "this name"})

        signals = best["signals"]
        score = max(s["score"] for s in signals)
        if len(signals) >= 2:
            score = min(1.0, round(score + self.COMBINATION_BONUS, 6))

        return ModuleScore(score=score, features={
            **base,
            "matched_brand": best["brand"],
            "label_examined": best["label"],
            "edit_distance": best["distance"],
            "similarity": best["similarity"],
            "suspicious_keyword": best["keyword"],
            "signals": [s["name"] for s in signals],
            "signal_scores": {s["name"]: s["score"] for s in signals},
            "combination_bonus_applied": len(signals) >= 2,
            "reason": "; ".join(s["reason"] for s in signals),
        })

    def _examine(self, brand: str, reg_label: str, labels: list[str],
                 registrable: str) -> dict | None:
        """Run every check for one brand. Returns None when nothing fires."""
        signals: list[dict] = []
        distance = levenshtein(reg_label, brand, cap=max_distance_for(brand) + 1)
        similarity = (round(1 - distance / max(len(reg_label), len(brand), 1), 4)
                      if reg_label else 0.0)

        keyword = next((k for k in sorted(self.keywords)
                        if k in reg_label and k != brand), None)

        # The brand's own registration under a different suffix is not a
        # near-miss spelling, but it is still worth reporting rather than
        # silently scoring zero.
        # With the PSL on, `paypal.pages.dev` or `paypal-help.blogspot.com`
        # has a site label containing the brand, but it is a site on a shared
        # platform, not a registration of the brand's. It keeps the score the
        # old approximation gave these names (brand in a subdomain of an
        # unrelated registration), so the PSL never weakens this detection.
        shared = False
        if self.psl_mode == "full" and brand in reg_label:
            from feeds.psl import on_shared_platform
            shared = on_shared_platform(registrable)
        if shared:
            signals.append({
                "name": "brand_on_shared_platform",
                "score": self.SCORE_SUBDOMAIN_BRAND,
                "reason": "the brand appears in a site name on a shared "
                          "hosting platform, not the brand's own registration",
            })

        if reg_label == brand:
            if keyword is None and not shared:
                return None
        if reg_label == brand and keyword is not None:
            signals.append({
                "name": "brand_with_keyword",
                "score": self.SCORE_BRAND_KEYWORD,
                "reason": f"registrable label is the brand plus the keyword "
                          f"{keyword!r}",
            })

        if reg_label != brand:
            if sorted(reg_label) == sorted(brand) and reg_label:
                signals.append({
                    "name": "transposition",
                    "score": self.SCORE_TRANSPOSITION,
                    "reason": "same characters as the brand in a different order",
                })

            if normalise_confusables(reg_label) == brand:
                signals.append({
                    "name": "confusable_characters",
                    "score": self.SCORE_CONFUSABLE,
                    "reason": "normalises to the brand once confusable "
                              "characters are folded",
                })

            edit_score = self.score_for_distance(distance, brand)
            if edit_score is not None:
                signals.append({
                    "name": "edit_distance",
                    "score": edit_score,
                    "reason": f"{distance} edit(s) from the brand "
                              f"(limit {max_distance_for(brand)})",
                })

            if brand in reg_label:
                if keyword is not None:
                    signals.append({
                        "name": "brand_with_keyword",
                        "score": self.SCORE_BRAND_KEYWORD,
                        "reason": f"registrable label contains the brand and "
                                  f"the keyword {keyword!r}",
                    })
                elif not signals:
                    signals.append({
                        "name": "contains_brand",
                        "score": self.SCORE_CONTAINS_BRAND,
                        "reason": "registrable label contains the brand but no "
                                  "other signal fired",
                    })

        # The brand appearing to the left of an unrelated registration is the
        # classic "login.brand.attacker.example" pattern.
        site_labels = len(registrable.split(".")) if registrable else 0
        subdomain_labels = (labels[:-site_labels]
                            if len(labels) > site_labels else [])
        if (registrable not in self.official_domains
                and reg_label != brand
                and any(brand in label for label in subdomain_labels)):
            signals.append({
                "name": "brand_in_subdomain",
                "score": self.SCORE_SUBDOMAIN_BRAND,
                "reason": "brand appears in a subdomain of an unrelated "
                          "registrable domain",
            })

        if not signals:
            return None

        return {
            "brand": brand,
            "label": reg_label,
            "distance": distance if distance <= max_distance_for(brand) else None,
            "similarity": similarity,
            "keyword": keyword,
            "signals": signals,
        }
