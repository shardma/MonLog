import json
from pathlib import Path

RULE_DIR = Path("rules/commandline")
SEPARATOR = 60


def get_process_name(image_path):
    return str(image_path).replace("\\", "/").rsplit("/", 1)[-1].lower()


def load_rules():
    rules_by_event = {}

    for rule_path in sorted(RULE_DIR.glob("*.json")):
        with open(rule_path, "r", encoding="utf-8") as f:
            rule = json.load(f)

        rule["processes"] = {
            process.lower() for process in rule["processes"]
        }

        rule["indicators"] = [
            indicator.lower() for indicator in rule["indicators"]
        ]

        event_id = str(rule["event_id"])

        rules_by_event.setdefault(event_id, []).append(rule)

    return rules_by_event



def detect(events, rules_by_event=None):
    if rules_by_event is None:
        rules_by_event = load_rules()

    alerts = []

    for event in events:
        event_id = event["event_id"]

        relevant_rules = rules_by_event.get(event_id)

        if not relevant_rules:
            continue

        data = event["data"]
        timestamp = event["timestamp"]

        process = get_process_name(data.get("Image", ""))
        command_line = str(data.get("CommandLine", ""))
        command_line_lower = command_line.lower()

        for rule in relevant_rules:
            if process not in rule["processes"]:
                continue

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
        