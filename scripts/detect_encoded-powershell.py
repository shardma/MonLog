import json
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from pathlib import Path

LOG_PATH = Path("sample-logs/sysmon.evtx")
RULE_PATH = Path("rules/encoded_powershell.json")
MAX_RECORDS = 500
SEPARATOR = 60

# Takes in a raw Sysmon record, turns it into a tree, and extracts the useful info
def get_event_data(event_xml):
    root = ET.fromstring(event_xml)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    event_id = root.find(".//e:EventID", ns).text
    timestamp = root.find(".//e:TimeCreated", ns).attrib.get("SystemTime")

    # Create and fill a dictionary of Sysmon fields
    data = {}
    for item in root.findall(".//e:EventData/e:Data", ns):
        data[item.attrib.get("Name")] = item.text or ""

    return event_id, timestamp, data

def print_alert(rule, process, timestamp, commandLine, matchedIndicator):
    print("[ALERT]")
    print(f"Process: {process}")
    print(f"Timestamp: {timestamp}")
    print(f"Command Line: {commandLine}")
    print(f"Matched Indicator: {matchedIndicator}")
    print(f"MITRE: {rule['mitre']}")
    print(f"Severity: {rule['severity']}")
    print("-" * SEPARATOR)

def main ():
    with open(RULE_PATH, "r", encoding = "utf-8") as f:
        rule_file = json.load(f)
        rules = rule_file["rules"]

        for rule in rules:
            rule["processes"] = [process.lower() for process in rule["processes"]]
            rule["indicators"] = [indicator.lower() for indicator in rule["indicators"]]

        with Evtx(str(LOG_PATH)) as log:
            for count, record in enumerate(log.records(), start = 1):
                if count > MAX_RECORDS:
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