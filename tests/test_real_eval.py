"""The real-world evaluation pipeline, on a tiny hand-built frozen dataset.

No network: the collector is not run here, only the evaluator and the
runner's integrity check, against files written by the test.
"""

import csv
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from experiments.real_eval import ARMS, evaluate, load

ROOT = Path(__file__).resolve().parent.parent
MODEL = str(ROOT / "models/dga/dga_model.json")
COLLECTED = datetime(2026, 10, 15, tzinfo=timezone.utc)


def write_set(tmp_path, rows, rdap):
    stem = "real_20261015"
    csv_path = tmp_path / f"{stem}.csv"
    fields = ["domain", "label", "source", "rank", "listed_in",
              "shared_platform", "ti_listed"]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow({"rank": "", "listed_in": "", "shared_platform": 0,
                             "ti_listed": 0, **r})
    rdap_path = tmp_path / f"{stem}.rdap.json"
    rdap_path.write_text(json.dumps(rdap), encoding="utf-8")
    meta = {"collected_at": COLLECTED.isoformat(), "malicious": 0, "benign": 0,
            "tranco": {}, "files": {
                csv_path.name: hashlib.sha256(csv_path.read_bytes()).hexdigest(),
                rdap_path.name: hashlib.sha256(rdap_path.read_bytes()).hexdigest()}}
    meta["malicious"] = sum(int(r["label"]) for r in rows)
    meta["benign"] = len(rows) - meta["malicious"]
    (tmp_path / f"{stem}.meta.json").write_text(json.dumps(meta),
                                                encoding="utf-8")
    return csv_path


def days_ago(n):
    return (COLLECTED - timedelta(days=n)).timestamp()


@pytest.fixture
def frozen(tmp_path):
    rows = [
        {"domain": "paypa1-login-verify.com", "label": 1, "source": "feed-a"},
        {"domain": "xk2qvz9pl3mwt8.top", "label": 1, "source": "feed-b"},
        {"domain": "plainword.shop", "label": 1, "source": "feed-b"},
        {"domain": "wikipedia.org", "label": 0, "source": "tranco_top10k",
         "rank": 12},
        {"domain": "bigcompany.net", "label": 0, "source": "tranco_10k_100k",
         "rank": 50000, "ti_listed": 1, "listed_in": "feed-a"},
    ]
    rdap = {
        "paypa1-login-verify.com": {"registered": days_ago(3), "error": None},
        "xk2qvz9pl3mwt8.top": {"registered": days_ago(10), "error": None},
        "plainword.shop": {"registered": None, "error": "HTTP 404"},
        "wikipedia.org": {"registered": days_ago(9000), "error": None},
        "bigcompany.net": {"registered": days_ago(5000), "error": None},
    }
    return write_set(tmp_path, rows, rdap)


def run(path):
    rows, rdap, meta = load(path)
    return evaluate(rows, rdap, meta, brands=["paypal"],
                    official=["paypal.com"], dga_model_path=MODEL)


def test_every_arm_is_reported_with_its_modules(frozen):
    result = run(frozen)
    assert [a for a, _ in ARMS] == list(result["arms"])
    assert result["arms"]["all_heuristics"]["modules"] == \
        ["dga", "typosquat", "rdap"]


def test_ti_is_never_an_arm_because_it_would_be_circular(frozen):
    for _, modules in ARMS:
        assert "ti" not in modules


def test_ages_are_measured_at_collection_time_not_today(frozen):
    """Re-running next year must give the same numbers."""
    result = run(frozen)
    rdap = result["modules"]["rdap"]
    assert rdap["malicious"]["fired"] == 2      # 3 and 10 days old
    assert rdap["benign"]["fired"] == 0


def test_a_failed_lookup_is_unassessed_not_benign(frozen):
    result = run(frozen)
    assert result["modules"]["rdap"]["malicious"]["assessed"] == 2
    # only_rdap cannot assess plainword.shop at all.
    assert result["arms"]["only_rdap"]["unknown"] == 1


def test_ti_false_positives_come_from_benign_rows_only(frozen):
    ti = run(frozen)["ti_on_benign"]
    assert ti == {"rows": 2, "listed": 1, "false_positive_rate": 0.5,
                  "listed_domains": ["bigcompany.net"]}


def test_counts_are_consistent(frozen):
    for arm in run(frozen)["arms"].values():
        assert arm["true_positive"] + arm["false_negative"] == 3
        assert arm["false_positive"] + arm["true_negative"] == 2


def test_dga_is_reported_by_name_shape(frozen):
    """The artifact's label_count weight must be visible, not averaged away."""
    split = run(frozen)["dga_by_label_count"]
    assert set(split) == {"malicious_two_labels", "malicious_three_plus_labels",
                          "benign_two_labels", "benign_three_plus_labels"}
    assert split["malicious_two_labels"]["rows"] == 3


def test_the_runner_refuses_a_modified_dataset(frozen, tmp_path):
    with frozen.open("a", encoding="utf-8") as f:
        f.write("tampered.com,0,x,,,0,0\n")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools/run_real_eval.py"),
         "--dataset", str(frozen), "--out", str(tmp_path / "out")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode != 0
    assert "checksum" in (proc.stdout + proc.stderr)


def test_the_runner_writes_results(frozen, tmp_path):
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools/run_real_eval.py"),
         "--dataset", str(frozen), "--out", str(out), "--brands", "paypal"],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    report = json.loads((out / "real_eval.json").read_text(encoding="utf-8"))
    assert "not verified ground truth" in report["caveat"] or \
        "rather than verified ground truth" in report["caveat"]
    assert (out / "real_eval_arms.csv").exists()
