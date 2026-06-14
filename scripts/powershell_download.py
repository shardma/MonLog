import json
from Evtx.Evtx import Evtx
from pathlib import Path
from helper import get_event_data

LOG_PATH = Path("sample-logs/sysmon.evtx")
RULE_PATH = Path("rules/powershell_download.json")
MAX_RECORDS = 500
SEPARATOR = 60

def print_alert(rule, process, timestamp, commandLine, matchedIndicator):
    print("[ALERT]")
    print(f"Process: {process}")
    print(f"Timestamp: {timestamp}")
    print(f"Command Line: {commandLine}")
    print(f"Matched Indicator: {matchedIndicator}")
    print(f"MITRE: {rule['mitre']}")
    print(f"Severity: {rule['severity']}")
    print("-" * SEPARATOR)

def main():
    with open(RULE_PATH, "r", encoding = "utf-8") as f:
        rule_file = json.load(f)
        rules = rule_file["rules"]

        for rule in rules:
            rule["processes"] = [process.lower() for process in rule["processes"]]
            rule["indicators"] = [indicator.lower() for indicator in rule["indicators"]]

        with Evtx(str(LOG_PATH)) as log:
            for count, record in enumerate(log.records(), count = 1):
                if count > 500:
                    break

                event_id, timestamp, data = get_event_data(record.xml())
                if event_id != "1":
                    continue

                process = Path(data.get("Image", "")).name.lower()
                command_line = str(data.get("CommandLine", ""))
                command_line_lower = command_line.lower()

                for rule in rules:
                    if process not in rule["processes"]:
                        continue

                    for indicator in rule["indicators"]:
                        if indicator in command_line_lower:
                            print_alert(rule, process, timestamp, command_line, indicator)
                            break

if __name__ == "__main__":
    main()