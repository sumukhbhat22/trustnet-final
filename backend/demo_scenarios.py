"""Repeatable, harmless synthetic scenarios for TrustNet AI demonstrations.

This module only describes fictional telemetry; it does not send network traffic,
modify accounts, or execute attack techniques against any system.
Run `python -m backend.demo_scenarios` from the repository root to print JSON.
"""
from __future__ import annotations

import json
from typing import Any

SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "id": "benign_baseline",
        "title": "Normal employee session",
        "expected_attack_type": "unknown",
        "expected_severity": "low",
        "signals": {"failed_logins": 0, "successful_logins": 1, "unknown_device": False,
                    "sensitive_export": False, "after_hours": False,
                    "data_volume_mb": 18, "api_calls_5m": 24},
        "expected_controls": ["record normal telemetry", "do not block automatically"],
    },
    {
        "id": "brute_force",
        "title": "Repeated failed login attempts",
        "expected_attack_type": "brute_force",
        "expected_severity": "high",
        "signals": {"failed_logins": 8, "successful_logins": 0, "unknown_device": True,
                    "sensitive_export": False, "after_hours": False,
                    "data_volume_mb": 0, "api_calls_5m": 32},
        "expected_controls": ["raise credential attack signal", "restrict or step up authentication per policy"],
    },
    {
        "id": "stolen_credentials",
        "title": "Successful login from an untrusted device after failures",
        "expected_attack_type": "stolen_credentials",
        "expected_severity": "critical",
        "signals": {"failed_logins": 3, "successful_logins": 1, "unknown_device": True,
                    "sensitive_export": False, "after_hours": True,
                    "data_volume_mb": 22, "api_calls_5m": 41},
        "expected_controls": ["require MFA step-up", "create evidence-backed incident", "queue irreversible actions for approval"],
    },
    {
        "id": "data_exfiltration",
        "title": "Large sensitive export",
        "expected_attack_type": "data_exfiltration",
        "expected_severity": "critical",
        "signals": {"failed_logins": 0, "successful_logins": 1, "unknown_device": False,
                    "sensitive_export": True, "after_hours": False,
                    "data_volume_mb": 850, "api_calls_5m": 95},
        "expected_controls": ["raise data-exfiltration signal", "preserve evidence", "require authorized review"],
    },
    {
        "id": "after_hours_sensitive_access",
        "title": "Sensitive resource accessed after hours",
        "expected_attack_type": "after_hours_insider",
        "expected_severity": "high",
        "signals": {"failed_logins": 0, "successful_logins": 1, "unknown_device": False,
                    "sensitive_export": True, "after_hours": True,
                    "data_volume_mb": 65, "api_calls_5m": 38},
        "expected_controls": ["raise after-hours access signal", "preserve evidence", "require analyst review"],
    },
)


def get_scenario(scenario_id: str) -> dict[str, Any]:
    """Return a copy of one known scenario; reject unknown IDs explicitly."""
    for scenario in SCENARIOS:
        if scenario["id"] == scenario_id:
            return json.loads(json.dumps(scenario))
    raise KeyError(f"Unknown scenario: {scenario_id}")



def build_replay_plan(scenario_id: str) -> dict[str, Any]:
    """Convert a catalogue entry into bounded inputs for the real risk/incident pipeline.

    This is a deterministic demo adapter, not a claim that the scenario is live telemetry.
    """
    scenario = get_scenario(scenario_id)
    signals = scenario["signals"]
    is_benign = scenario_id == "benign_baseline"
    # Map the scenario's declared signals to normalized 0-100 inputs. These values are
    # explicitly synthetic and are fed through the same risk fusion and incident store.
    # Keep the benign baseline safely below the incident threshold. For attack stories,
    # the scenario adapter must supply enough synthetic signal for the production fusion
    # weights to cross the documented 60-point restrict threshold. The risk engine still
    # computes the final score; this is not an incident forced by the replay endpoint.
    behavior_score = 8.0 if is_benign else min(100.0, max(90.0,
        35.0 + signals["failed_logins"] * 5.0
        + signals["data_volume_mb"] / 20.0
        + signals["api_calls_5m"] / 5.0
        + (15.0 if signals["after_hours"] else 0.0)))
    anomaly_score = 5.0 if is_benign else min(100.0, max(90.0,
        signals["failed_logins"] * 7.0
        + signals["data_volume_mb"] / 10.0
        + signals["api_calls_5m"] / 2.0
        + (20.0 if signals["unknown_device"] else 0.0)
        + (15.0 if signals["after_hours"] else 0.0)))
    return {
        "scenario": scenario,
        "synthetic_only": True,
        "user_id": f"demo-{scenario_id}",
        "device_id": f"DEMO-DEVICE-{scenario_id.upper()}",
        "behavioral_score": round(min(100.0, behavior_score), 2),
        "anomaly_score": round(min(100.0, anomaly_score), 2),
        "classifier_label": scenario["expected_attack_type"],
        "classifier_confidence": 0.0 if is_benign else 90.0,
        "device_trust_status": "trusted" if is_benign and not signals["unknown_device"] else "unknown",
        "evidence": [
            f"Synthetic scenario: {scenario['title']}",
            f"Failed logins: {signals['failed_logins']}; successful logins: {signals['successful_logins']}",
            f"Synthetic data volume: {signals['data_volume_mb']} MB; API calls in 5 minutes: {signals['api_calls_5m']}",
            *( ["Synthetic sensitive data export signal"] if signals["sensitive_export"] else [] ),
            *( ["Synthetic after-hours activity signal"] if signals["after_hours"] else [] ),
            *( ["Synthetic unknown device signal"] if signals["unknown_device"] else [] ),
        ],
    }


def main() -> None:
    print(json.dumps({
        "notice": "Fictional synthetic scenarios only; descriptions do not execute attacks.",
        "scenario_count": len(SCENARIOS),
        "scenarios": SCENARIOS,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
