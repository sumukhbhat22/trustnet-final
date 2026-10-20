#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          TrustNet AI Guardian — Live Attack Simulator               ║
║                                                                      ║
║  Run this from ANOTHER device/terminal to simulate a real attack.    ║
║  The dashboard will update in real-time as the ML models detect it.  ║
║                                                                      ║
║  Usage:                                                              ║
║    python simulate_attack.py                                         ║
║    python simulate_attack.py --server http://192.168.1.5:8000        ║
║    python simulate_attack.py --fast                                  ║
║    python simulate_attack.py --reset                                 ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import requests
import time
import sys
import argparse

# ─── Configuration ───
DEFAULT_SERVER = "http://localhost:8010"

# ─── Attack Phases (escalating severity) ───
ATTACK_PHASES = [
    # ── Phase 1: RECONNAISSANCE (LOW risk) ──
    {
        "phase": "recon",
        "attack_type": "Reconnaissance — Port Scanning",
        "description": "Multiple failed SSH login attempts from unfamiliar IP. Port scanning detected on internal services.",
        "attacker_ip": "203.0.113.42",
        "attacker_location": "Bucharest, Romania",
        "attacker_device": "Unknown Linux Host",
        "target_user": "Alex Chen",
        "behavior_metrics": {
            "normal_login_time": 9.2,
            "actual_login_time": 3.4,       # Unusual early morning
            "normal_session_duration": 4.5,
            "actual_session_duration": 0.1,  # Very short probe sessions
            "normal_data_volume": 120,
            "actual_data_volume": 15,        # Small recon packets
            "normal_api_calls": 45,
            "actual_api_calls": 180,         # Rapid API probing
            "normal_geo_distance": 0,
            "actual_geo_distance": 50,       # Slight geo deviation
        },
        "anomaly_score": 0.25,
        "anomalies": [
            "Failed SSH login attempts: 14 in 2 minutes",
            "Port scan detected: 443, 8080, 3306, 5432",
            "Login time deviation: 3:24 AM (normal: 9-6 PM)",
        ],
        "compromised_nodes": [],
        "delay_after": 6,  # seconds before next phase
    },

    # ── Phase 2: CREDENTIAL STUFFING (MEDIUM risk) ──
    {
        "phase": "escalation",
        "attack_type": "Credential Stuffing — Brute Force",
        "description": "Successful login using leaked credentials. Device fingerprint does not match any known device for this user.",
        "attacker_ip": "203.0.113.42",
        "attacker_location": "Moscow, Russia",
        "attacker_device": "Unknown Windows VM",
        "target_user": "Alex Chen",
        "behavior_metrics": {
            "normal_login_time": 9.2,
            "actual_login_time": 23.1,       # Late night
            "normal_session_duration": 4.5,
            "actual_session_duration": 0.8,   # Short but active
            "normal_data_volume": 120,
            "actual_data_volume": 45,         # Some data access
            "normal_api_calls": 45,
            "actual_api_calls": 220,          # Many API hits
            "normal_geo_distance": 0,
            "actual_geo_distance": 2500,      # Different city
        },
        "anomaly_score": 0.55,
        "anomalies": [
            "Geo-location deviation: 2,500 km (Moscow, Russia)",
            "Device fingerprint: MISMATCH",
            "Login via leaked credential database match",
            "Session started at 23:06 (outside working hours)",
        ],
        "compromised_nodes": ["n1"],
        "delay_after": 6,
    },

    # ── Phase 3: LATERAL MOVEMENT (HIGH risk) ──
    {
        "phase": "breach",
        "attack_type": "Lateral Movement — Privilege Escalation",
        "description": "Attacker moved from user endpoint to internal web server. Privilege escalation via admin token theft. Accessing finance database.",
        "attacker_ip": "203.0.113.42",
        "attacker_location": "Moscow, Russia",
        "attacker_device": "Compromised VM",
        "target_user": "Alex Chen",
        "behavior_metrics": {
            "normal_login_time": 9.2,
            "actual_login_time": 23.4,
            "normal_session_duration": 4.5,
            "actual_session_duration": 0.4,
            "normal_data_volume": 120,
            "actual_data_volume": 520,        # Large data access
            "normal_api_calls": 45,
            "actual_api_calls": 380,          # Massive API abuse
            "normal_geo_distance": 0,
            "actual_geo_distance": 5800,      # Even further
        },
        "anomaly_score": 0.75,
        "anomalies": [
            "Privilege escalation: User → Admin detected",
            "Lateral movement: Endpoint → Web Server → Database",
            "Admin token stolen from memory dump",
            "Finance DB queried: 340 records accessed",
            "Geo-location: Moscow, Russia (5,800 km deviation)",
        ],
        "compromised_nodes": ["n1", "n4", "n7"],
        "delay_after": 6,
    },

    # ── Phase 4: DATA EXFILTRATION (CRITICAL risk) ──
    {
        "phase": "exfiltration",
        "attack_type": "Data Exfiltration — Full Breach",
        "description": "Attacker exfiltrating sensitive data to external server. 850MB transferred via encrypted tunnel. Multiple systems compromised.",
        "attacker_ip": "203.0.113.42",
        "attacker_location": "Moscow, Russia",
        "attacker_device": "Compromised VM + Proxy Chain",
        "target_user": "Alex Chen",
        "behavior_metrics": {
            "normal_login_time": 9.2,
            "actual_login_time": 23.8,
            "normal_session_duration": 4.5,
            "actual_session_duration": 0.2,
            "normal_data_volume": 120,
            "actual_data_volume": 850,        # Massive exfiltration
            "normal_api_calls": 45,
            "actual_api_calls": 500,          # API abuse
            "normal_geo_distance": 0,
            "actual_geo_distance": 9847,      # Max deviation
        },
        "anomaly_score": 0.92,
        "anomalies": [
            "DATA EXFILTRATION: 850 MB transferred to external IP",
            "Encrypted tunnel to 203.0.113.42:4443 detected",
            "9,847 km geo-deviation (Moscow, Russia)",
            "Privilege escalation chain: User -> Admin -> Root",
            "4 systems compromised in lateral movement",
            "Finance DB: Full export detected (12,340 records)",
        ],
        "compromised_nodes": ["n1", "n4", "n7", "n9"],
        "delay_after": 0,
    },
]


def print_banner():
    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        TrustNet AI Guardian - Attack Simulator             ║")
    print("║                                                              ║")
    print("║   This simulates a real multi-phase cyber attack.            ║")
    print("║   The dashboard will show LIVE risk escalation.              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()


def print_phase(phase_data, phase_num, total):
    phase = phase_data["phase"].upper()
    risk_labels = {
        "recon": "LOW",
        "escalation": "MEDIUM",
        "breach": "HIGH",
        "exfiltration": "CRITICAL",
    }
    label = risk_labels.get(phase_data["phase"], "Unknown")
    
    print(f"\n{'─'*60}")
    print(f"  PHASE {phase_num}/{total}: {phase} — {label}")
    print(f"{'─'*60}")
    print(f"  Attack: {phase_data['attack_type']}")
    print(f"  From:   {phase_data['attacker_ip']} ({phase_data['attacker_location']})")
    print(f"  Target: {phase_data['target_user']}")
    print(f"  Device: {phase_data['attacker_device']}")
    print(f"\n  Anomalies detected:")
    for a in phase_data["anomalies"]:
        print(f"    → {a}")


def send_attack_phase(server: str, phase_data: dict) -> dict:
    """Send attack phase data to backend ML pipeline"""
    url = f"{server}/api/inject-threat"
    payload = {k: v for k, v in phase_data.items() if k != "delay_after"}
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        print(f"\n  Cannot connect to backend at {server}")
        print(f"     Make sure the backend is running: python -m uvicorn main:app --port 8000")
        sys.exit(1)
    except Exception as e:
        print(f"\n  Error: {e}")
        return {}


def reset_attack(server: str):
    """Reset the live threat state"""
    try:
        response = requests.post(f"{server}/api/live-threat/reset", timeout=5)
        response.raise_for_status()
        print("Live threat state reset to normal")
    except Exception as e:
        print(f"Reset failed: {e}")


def run_attack(server: str, fast: bool = False):
    """Run the full multi-phase attack simulation"""
    print_banner()
    print(f"  Backend: {server}")
    print(f"  Mode: {'FAST (2s delays)' if fast else 'REALISTIC (6s delays)'}")
    print(f"\n  Open the dashboard and watch the risk meter change LIVE!")
    print(f"     Dashboard: http://localhost:3000")
    
    # First reset any previous attack
    reset_attack(server)
    time.sleep(1)
    
    total = len(ATTACK_PHASES)
    
    for i, phase_data in enumerate(ATTACK_PHASES, 1):
        print_phase(phase_data, i, total)
        
        # Send to ML backend
        print(f"\n  Sending to ML pipeline...")
        result = send_attack_phase(server, phase_data)
        
        if result.get("ml_result"):
            ml = result["ml_result"]
            score = ml.get("overall_score", "?")
            level = ml.get("threat_level", "?").upper()
            rec = ml.get("recommendation", "?")
            iso = "YES" if ml.get("isolation_forest_anomaly") else "no"
            
            print(f"\n  ML Analysis Results:")
            print(f"     Risk Score:        {score}/100")
            print(f"     Threat Level:      {level}")
            print(f"     Recommendation:    {rec}")
            print(f"     Isolation Forest:  {iso}")
            print(f"     Confidence:        {ml.get('confidence', 'N/A')}%")
        
        # Wait before next phase
        delay = 2 if fast else phase_data.get("delay_after", 5)
        if delay > 0 and i < total:
            print(f"\n  Next phase in {delay}s... (watch the dashboard!)")
            for s in range(delay, 0, -1):
                sys.stdout.write(f"\r  {s}s...")
                sys.stdout.flush()
                time.sleep(1)
            print()
    
    print(f"\n{'='*60}")
    print(f"  ATTACK SIMULATION COMPLETE")
    print(f"{'='*60}")
    print(f"\n  The dashboard should now show CRITICAL risk level.")
    print(f"  All 4 phases were processed through the real ML pipeline.")
    print(f"\n  To reset: python simulate_attack.py --reset")
    print(f"  To re-run: python simulate_attack.py")
    print()


def main():
    parser = argparse.ArgumentParser(description="TrustNet Attack Simulator")
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help=f"Backend URL (default: {DEFAULT_SERVER})")
    parser.add_argument("--fast", action="store_true",
                        help="Fast mode (2s delays instead of 6s)")
    parser.add_argument("--reset", action="store_true",
                        help="Reset the live threat state and exit")
    
    args = parser.parse_args()
    
    if args.reset:
        print_banner()
        reset_attack(args.server)
        return
    
    run_attack(args.server, fast=args.fast)


if __name__ == "__main__":
    main()
