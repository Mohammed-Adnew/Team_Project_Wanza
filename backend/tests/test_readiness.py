"""
Offline checks for the compliance readiness logic (no database, no server).
Run from the backend folder:   python tests/test_readiness.py
"""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from compliance.readiness import DUTIES, MANUAL_DUTY_IDS, evaluate_readiness

NOW = datetime(2026, 10, 12, 12, 0)
failed = 0


def check(name, condition):
    global failed
    failed += (not condition)
    print(("PASS" if condition else "FAIL"), "-", name)


def duty(result, duty_id):
    return next(d for d in result["duties"] if d["id"] == duty_id)


healthy = [
    {"created_at": "2026-10-11T08:00:00", "resolved_at": "2026-10-11T09:00:00", "severity": "high", "status": "resolved", "source": "automatic", "verdict": "risky"},
    {"created_at": "2026-10-12T07:00:00", "resolved_at": None, "severity": "low", "status": "new", "source": "employee", "verdict": "safe"},
]
seed_like = [
    {"created_at": "2026-09-30T16:24:00", "resolved_at": None, "severity": "high", "status": "new", "source": "", "verdict": None},
    {"created_at": "2026-10-12T07:00:00", "resolved_at": None, "severity": "low", "status": "new", "source": "automatic", "verdict": "safe"},
]

check("18 duties from Art. 7, with unique ids", len(DUTIES) == 18 and len({d["id"] for d in DUTIES}) == 18)
check("16 duties are recorded by a person and 2 are computed", len(MANUAL_DUTY_IDS) == 16)

empty = evaluate_readiness([], {}, now=NOW)
s = empty["summary"]
check("nothing recorded: 0% fulfilled, and the counts add up to 18", s["percent_fulfilled"] == 0 and s["fulfilled"] + s["in_progress"] + s["not_fulfilled"] + s["not_assessed"] == 18)
check("no scanning activity -> Art. 7(13) is not fulfilled", duty(empty, "art7_13")["status"] == "not_fulfilled")
check("Art. 7(14) is 'not assessed' while notification is not tracked", duty(empty, "art7_14")["status"] == "not_assessed")

r = evaluate_readiness(healthy, {}, now=NOW)
check("healthy data -> Art. 7(13) fulfilled", duty(r, "art7_13")["status"] == "fulfilled")
check("Art. 7(13) lists its five checks as evidence", len(duty(r, "art7_13")["evidence"]) == 5)

r = evaluate_readiness(seed_like, {}, now=NOW)
check("seed-like data (old unresolved high-severity report) -> Art. 7(13) in progress", duty(r, "art7_13")["status"] == "in_progress")

assess = {
    "art7_1": {"status": "fulfilled", "evidence_note": "Program approved 2026-08-01"},
    "art7_2": {"status": "fulfilled"},
    "art7_3": {"status": "fulfilled"},
    "art7_4": {"status": "in_progress"},
    "art7_5": {"status": "in_progress"},
    "art7_6": {"status": "not_fulfilled"},
}
r = evaluate_readiness(healthy, assess, now=NOW)
s = r["summary"]
check("3 fulfilled + 7(13) = 4 fulfilled, 2 in progress, 1 not fulfilled", (s["fulfilled"], s["in_progress"], s["not_fulfilled"]) == (4, 2, 1))
check("percent fulfilled is 4/18 = 22 and percent assessed is 7/18 = 39", (s["percent_fulfilled"], s["percent_assessed"]) == (22, 39))
check("the recorded evidence note is returned with the duty", duty(r, "art7_1")["assessment"]["evidence_note"] == "Program approved 2026-08-01")

r = evaluate_readiness(healthy, {"art7_5": {"status": "done!"}}, now=NOW)
check("an invalid status is treated as not assessed", duty(r, "art7_5")["status"] == "not_assessed")
r = evaluate_readiness(healthy, {"art7_13": {"status": "fulfilled"}, "art7_14": {"status": "fulfilled"}}, now=NOW)
check("a person cannot mark the computed duties (7(13), 7(14)) as fulfilled", duty(r, "art7_14")["status"] == "not_assessed")

base = {"severity": "high", "status": "new", "source": "automatic", "verdict": "risky"}
on_time = dict(base, created_at="2026-10-11T08:00:00", notified_at="2026-10-11T20:00:00")
late = dict(base, created_at="2026-10-01T08:00:00", notified_at="2026-10-05T08:00:00")
never = dict(base, created_at="2026-10-01T08:00:00", notified_at=None)
fresh = dict(base, created_at="2026-10-12T06:00:00", notified_at=None)
safe = dict(base, verdict="safe", created_at="2026-10-01T08:00:00", notified_at=None)
check("notified within 48 hours -> 7(14) fulfilled", duty(evaluate_readiness([on_time], {}, now=NOW), "art7_14")["status"] == "fulfilled")
check("notified after 4 days -> 7(14) not fulfilled", duty(evaluate_readiness([late], {}, now=NOW), "art7_14")["status"] == "not_fulfilled")
check("never notified after 11 days -> 7(14) not fulfilled", duty(evaluate_readiness([never], {}, now=NOW), "art7_14")["status"] == "not_fulfilled")
check("6 hours old and not yet notified -> 7(14) in progress", duty(evaluate_readiness([fresh], {}, now=NOW), "art7_14")["status"] == "in_progress")
check("an old SAFE report is not an incident -> 7(14) fulfilled", duty(evaluate_readiness([safe], {}, now=NOW), "art7_14")["status"] == "fulfilled")
check("7(14) names the fine in Art. 22(1)(b)", "22(1)(b)" in duty(r, "art7_14")["penalty"])

print("\nALL PASSED" if failed == 0 else f"\n{failed} CHECK(S) FAILED")
sys.exit(1 if failed else 0)
