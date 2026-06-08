import json
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from pathlib import Path

LOG_PATH = Path("sample-logs/sysmon.evtx")
RULE_PATH = Path("rules/suspicious_parent-child.json")
MAX_RECORDS = 500
SEPARATOR = 60

# Command to export a log: 
# wevtutil epl Microsoft-Windows-Sysmon/Operational "PATH\TO\FOLDER\FILE_NAME.evtx" /ow:true

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

# Takes in the extracted data and outputs it in terminal
def print_alert(rule, parent, child, timestamp, commandLine):
    if parent in rule["parent"] and child == rule["child"]:
        print("[ALERT]")
        print(f"Timestamp: {timestamp}")
        print(f"Parent: {parent}")
        print(f"Child: {child}")
        print(f"Command Line: {commandLine}")
        print(f"MITRE: {rule['mitre']}")
        print(f"Severity: {rule['severity']}")
        print("-" * SEPARATOR)

def main():
    # Open the json file and extract the rules specifically
    with open(RULE_PATH, "r", encoding = "utf-8") as f:
        rule_file = json.load(f)
        rules = rule_file["rules"]

        for rule in rules:
            rule["parent"] = [parent.lower() for parent in rule["parent"]]
            rule["child"] = rule["child"].lower()

        # Open the imported evtx log and start parsing
        with Evtx(str(LOG_PATH)) as log:
            for count, record in enumerate(log.records(), start = 1):
                # For testing purposes, limited to first 500 logs, REMOVE LATER
                if count > MAX_RECORDS:
                    break
                event_id, timestamp, data = get_event_data(record.xml())
                if event_id != "1":
                    continue

                parent = Path(data.get("ParentImage", "")).name.lower()
                child = Path(data.get("Image", "")).name.lower()
                command_line = data.get("CommandLine", "")

                for rule in rules:
                    print_alert(rule, parent, child, timestamp, command_line)
                
if __name__ == "__main__":
    main()