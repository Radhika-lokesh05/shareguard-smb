"""
server/tests/test_scenario_detection.py – Benchmark rule engine across all 10 simulator scenarios.

Evaluates:
- All 5 attack scenarios: must fire above threshold under expert rules (R1-R5).
- All 5 normal scenarios: must not trigger expert rules R1-R5.
- Computes time-to-first-alert (TTFA) for every attack scenario.
- Produces an evaluation summary table detailing true positives, false alarms, and detection times.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

import pytest
from lab.simulate_log import SCENARIO_NAMES, generate_lines

from shareguard.features import compute_features
from shareguard.parser import AuditEvent, parse_line
from shareguard.rules import RuleEngine, RuleResult

_NORMAL_SCENARIOS = [s for s in SCENARIO_NAMES if s.startswith("normal_")]
_ATTACK_SCENARIOS = [s for s in SCENARIO_NAMES if s.startswith("attack_")]

# Cache generated and parsed events across the test session
_PARSED_SCENARIO_CACHE: dict[tuple[str, float], list[AuditEvent]] = {}


def _get_parsed_scenario_events(scenario_name: str, duration: float = 60.0) -> list[AuditEvent]:
    """Return parsed AuditEvent list for scenario, caching across tests."""
    cache_key = (scenario_name, duration)
    if cache_key not in _PARSED_SCENARIO_CACHE:
        # Use speed=100.0 (like generate_lines default) for fast compression in tests
        scenario_lines = generate_lines(scenario_name, duration=duration, speed=100.0, seed=42)
        # Cap events to max 500 lines per scenario for unit tests to prevent unbounded processing
        events: list[AuditEvent] = []
        for sl in scenario_lines[:500]:
            evt = parse_line(sl.line)
            if evt is not None:
                events.append(evt)
        _PARSED_SCENARIO_CACHE[cache_key] = events
    return _PARSED_SCENARIO_CACHE[cache_key]


def _evaluate_scenario(scenario_name: str, duration: float = 60.0) -> dict[str, Any]:
    """Run a scenario, parse its events, compute features, and evaluate rules with TTFA."""
    engine = RuleEngine()
    parsed_events = _get_parsed_scenario_events(scenario_name, duration=duration)

    if not parsed_events:
        return {
            "scenario": scenario_name,
            "max_score": 0.0,
            "critical": False,
            "triggered_rules": [],
            "reasons": [],
            "fired": False,
            "baseline_fired": False,
            "ttfa_seconds": None,
        }

    start_ts = parsed_events[0].ts.timestamp()
    events_by_client: dict[tuple[str, str], deque[AuditEvent]] = defaultdict(deque)
    ttfa_seconds: float | None = None
    all_triggered_rules: set[str] = set()
    all_reasons: list[str] = []
    max_score = 0.0
    critical_fired = False
    baseline_fired = False

    # Process events in chronological stream to measure time to first alert
    # Optimization: Evaluating compute_features and rules every event is O(N * window).
    # Since rules require significant counts (min 10-15 operations, canary, ransom note, or rename),
    # we evaluate on high-signal operations, when window crosses thresholds, or periodically.
    events_since_eval = 0
    for evt in parsed_events:
        key = (evt.ip, evt.user)
        client_queue = events_by_client[key]
        client_queue.append(evt)

        # Sliding window check using deque (O(1) amortized popleft)
        cutoff = evt.ts.timestamp() - 60.0
        while client_queue and client_queue[0].ts.timestamp() < cutoff:
            client_queue.popleft()

        events_since_eval += 1
        op_lower = evt.op.lower()
        is_notable = (
            op_lower in {"renameat", "rename", "unlinkat", "unlink"}
            or "canary" in evt.path.lower()
            or "readme" in evt.path.lower()
        )

        # In non-notable operations (like massive openat/close loops), evaluate periodically
        # or when reaching a batch threshold
        if not is_notable and events_since_eval < 100:
            continue

        events_since_eval = 0
        window_events = list(client_queue)
        features = compute_features(window_events, client_ip=evt.ip, username=evt.user)
        result: RuleResult = engine.evaluate_result(features)
        b_fired, _ = engine.evaluate_baseline(features)
        if b_fired:
            baseline_fired = True

        if result.score > max_score:
            max_score = result.score
        if result.critical:
            critical_fired = True

        all_triggered_rules.update(result.triggered_rules)
        all_reasons.extend(result.reasons)

        if ttfa_seconds is None and (result.score >= 0.70 or result.critical):
            ttfa_seconds = max(0.0, evt.ts.timestamp() - start_ts)
            if critical_fired or max_score >= 0.85:
                break

    # Perform a final check at the end of the scenario if not yet fired
    if not (critical_fired or max_score >= 0.70):
        for (ip, user), client_queue in events_by_client.items():
            if client_queue:
                window_events = list(client_queue)
                features = compute_features(window_events, client_ip=ip, username=user)
                result = engine.evaluate_result(features)
                b_fired, _ = engine.evaluate_baseline(features)
                if b_fired:
                    baseline_fired = True
                if result.score > max_score:
                    max_score = result.score
                if result.critical:
                    critical_fired = True
                all_triggered_rules.update(result.triggered_rules)
                all_reasons.extend(result.reasons)

    fired = max_score >= 0.70 or critical_fired

    return {
        "scenario": scenario_name,
        "max_score": max_score,
        "critical": critical_fired,
        "triggered_rules": sorted(all_triggered_rules),
        "reasons": all_reasons,
        "fired": fired,
        "baseline_fired": baseline_fired,
        "ttfa_seconds": ttfa_seconds,
    }


@pytest.mark.slow
def test_scenario_detection_benchmark(capsys: pytest.CaptureFixture[str]) -> None:
    """Benchmark all 10 scenarios and print detection / false alarm summary table with TTFA."""
    results: list[dict[str, Any]] = []

    for scenario in SCENARIO_NAMES:
        res = _evaluate_scenario(scenario, duration=60.0)
        results.append(res)

    print("\n" + "=" * 115)
    print(
        f"{'SCENARIO':<22} | {'TYPE':<7} | {'EXPERT':<6} | {'STATUS':<8} | {'BASELINE':<8} | {'TTFA':<7} | {'EXPERT RULES':<30}"
    )
    print("-" * 115)

    false_alarms: list[str] = []
    missed_attacks: list[str] = []

    for r in results:
        is_attack = r["scenario"].startswith("attack_")
        stype = "Attack" if is_attack else "Normal"
        fired_str = "ALERT" if r["fired"] else "CLEAN"
        baseline_str = "YES" if r["baseline_fired"] else "NO"
        ttfa_str = f"{r['ttfa_seconds']:.1f}s" if r["ttfa_seconds"] is not None else "N/A"
        rules_str = ", ".join(r["triggered_rules"]) if r["triggered_rules"] else "none"

        print(
            f"{r['scenario']:<22} | {stype:<7} | {r['max_score']:<6.2f} | {fired_str:<8} | {baseline_str:<8} | {ttfa_str:<7} | {rules_str:<30}"
        )

        if not is_attack and r["fired"]:
            false_alarms.append(r["scenario"])

        if is_attack and not r["fired"]:
            missed_attacks.append(r["scenario"])

    print("=" * 115)
    print(f"Summary: {len(false_alarms)} False Alarms on Normal, {len(missed_attacks)} Missed Attacks")
    print("=" * 115 + "\n")

    # Assertions
    assert not missed_attacks, f"Detection engine missed attacks: {missed_attacks}"
    assert not false_alarms, f"Expert rules had false alarms on normal scenarios: {false_alarms}"


@pytest.mark.slow
@pytest.mark.parametrize("scenario", _ATTACK_SCENARIOS)
def test_each_attack_scenario_detected(scenario: str) -> None:
    """Each individual attack scenario must be detected by the rule engine."""
    res = _evaluate_scenario(scenario, duration=60.0)
    assert res["fired"] is True, f"Attack scenario {scenario} failed to trigger detection"
    assert res["max_score"] >= 0.70 or res["critical"] is True
    assert res["ttfa_seconds"] is not None, f"Attack {scenario} did not record TTFA"


@pytest.mark.slow
@pytest.mark.parametrize("scenario", _NORMAL_SCENARIOS)
def test_normal_scenarios_no_expert_false_alarms(scenario: str) -> None:
    """Normal scenarios must not trigger expert ransomware rules (R1 through R5)."""
    res = _evaluate_scenario(scenario, duration=60.0)
    expert_rules = [r for r in res["triggered_rules"] if r.startswith("R")]
    assert (
        not expert_rules
    ), f"Normal scenario {scenario} triggered expert rules: {expert_rules} (reasons: {res['reasons']})"
