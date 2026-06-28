from pathlib import Path
import json

RULE_PATH = Path("rules/registry/registry_run_keys.json")
SEPARATOR = 60

def load_rules():
    with open(RULE_PATH, "r", encoding="utf-8") as f:
        rule_file = json.load(f)

    rule_file["paths"] = [path.lower() for path in rule_file["paths"]]
    return rule_file

def detect(events):
    rule_file = load_rules()
    alerts = []

    for event in events:
        if event["event_id"] != rule_file["event_id"]:
            continue
            
        data = event["data"]
        target = data.get("TargetObject", "").lower()
        for path in rule_file["paths"]:
            if path in target:
                timestamp = event["timestamp"]
                source_process = Path(data.get("Image", "")).name.lower()
                new_data = data.get("Details", "")
                user = data.get("User", "")
                
                alerts.append({
                    "name": rule_file["name"],
                    "timestamp": timestamp,
                    "target": target,
                    "source_process": source_process,
                    "new_data": new_data,
                    "user": user,
                    "mitre": rule_file["mitre"],
                    "severity": rule_file["severity"]
                })
                break

    return alerts

def print_alerts(alerts):
    for alert in alerts:
        print("[ALERT]")
        print(f"Rule: {alert['name']}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Target: {alert['target']}")
        print(f"Source Process: {alert['source_process']}")
        print(f"New Data: {alert['new_data']}")
        print(f"User: {alert['user']}")
        print(f"Mitre: {alert['mitre']}")
        print(f"Severity: {alert['severity']}")
        print("-" * SEPARATOR)