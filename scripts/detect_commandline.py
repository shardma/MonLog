import json
from pathlib import Path

RULE_DIR = Path("rules/commandline")
SEPARATOR = 60

def load_rules():
    rules = []

    for rule_path in RULE_DIR.glob("*.json"):
        with open(rule_path, "r", encoding = "utf-8") as f:
            rule = json.load(f)

        rule["processes"] = [process.lower() for process in rule["processes"]]
        rule["indicators"] = [indicator.lower() for indicator in rule["indicators"]]
        rules.append(rule)

    return rules

def detect(events):
    rules = load_rules()
    alerts = []

    for event in events:
        event_id = event["event_id"]
        timestamp = event["timestamp"]
        data = event["data"]

        for rule in rules:
            if event_id != rule["event_id"]:
                continue

            process = Path(data.get("Image", "")).name.lower()
            if process not in rule["processes"]:
                continue
            
            command_line = str(data.get("CommandLine", ""))
            command_line_lower = command_line.lower()
            for indicator in rule["indicators"]:
                if indicator in command_line_lower:
                    alerts.append({
                        "rule": rule["name"],
                        "timestamp": timestamp,
                        "process": process,
                        "command_line": command_line,
                        "matched_indicator": indicator,
                        "mitre": rule["mitre"],
                        "severity": rule["severity"]
                    })
                    break
    return alerts

def print_alerts(alerts):
    for alert in alerts:
        print("[ALERT]")
        print(f"Rule: {alert['rule']}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Process: {alert['process']}")
        print(f"Command Line: {alert['command_line']}")
        print(f"Matched Indicator: {alert['matched_indicator']}")
        print(f"MITRE: {alert['mitre']}")
        print(f"Severity: {alert['severity']}")
        print("-" * SEPARATOR)
        