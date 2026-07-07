import json
from pathlib import Path

RULE_PATH = Path("rules/process/suspicious_parent_child.json")
SEPARATOR = 60

def load_rules():
    with open(RULE_PATH, "r", encoding = "utf-8") as f:
        rule_file = json.load(f)

    rule_file["parents"] = [parent.lower() for parent in rule_file["parents"]]

    for rule in rule_file["rules"]:
        rule["child"] = rule["child"].lower()

    return rule_file

def detect(events):
    rule_file = load_rules()
    alerts = []

    allowed_parents = rule_file["parents"]
    for event in events:
        if event["event_id"] != rule_file["event_id"]:
            continue

        data = event["data"]
        timestamp = event["timestamp"]
        
        parent = Path(data.get("ParentImage", "")).name.lower()
        if parent not in allowed_parents:
            continue

        child = Path(data.get("Image", "")).name.lower()
        command_line = data.get("CommandLine", "")

        for rule in rule_file["rules"]:
            if child == rule["child"]:
                alerts.append({
                    "rule": rule_file["name"],
                    "timestamp": timestamp,
                    "parent": parent,
                    "child": child,
                    "command_line": command_line,
                    "mitre": rule["mitre"],
                    "severity": rule["severity"]
                })

    return alerts

def print_alerts(alerts):
    for alert in alerts:
        print("[ALERT]")
        print(f"Rule: {alert['rule']}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Parent: {alert['parent']}")
        print(f"Child: {alert['child']}")
        print(f"Command Line: {alert['command_line']}")
        print(f"MITRE: {alert['mitre']}")
        print(f"Severity: {alert['severity']}")
        print("-" * SEPARATOR)