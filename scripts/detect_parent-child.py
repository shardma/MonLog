import json
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from pathlib import Path

LOG_PATH = Path("sample-logs/sysmon.evtx")
RULE_PATH = Path("rules/suspicious_parent-child.json")
MAX_RECORDS = 500

# command to export a log: 
# wevtutil epl Microsoft-Windows-Sysmon/Operational "PATH\TO\FOLDER\FILE_NAME.evtx" /ow:true

def getEventData(eventXML):
    root = ET.fromstring(eventXML)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    eventID = root.find(".//e:EventID", ns).text
    timestamp = root.find(".//e:TimeCreated", ns).attrib.get("SystemTime")

    data = {}
    for item in root.findall(".//e:EventData/e:Data", ns):
        data[item.attrib.get("Name")] = item.text or ""

    return eventID, timestamp, data

def printAlert(rule, parent, child, timestamp, commandLine):
    if parent == rule["parent"] and child == rule["child"]:
        print("[ALERT]")
        print(f"Timestamp: {timestamp}")
        print(f"Parent: {parent}")
        print(f"Child: {child}")
        print(f"Command Line: {commandLine}")
        print(f"MITRE: {rule['mitre']}")
        print(f"Severity: {rule['severity']}")
        print("-" * 60)

def main():
    with open(RULE_PATH, "r", encoding = "utf-8") as f:
        rule_file = json.load(f)
        rules = rule_file["rules"]

        for rule in rules:
            rule["parent"] = rule["parent"].lower()
            rule["child"] = rule["child"].lower()

        with Evtx(str(LOG_PATH)) as log:
            for count, record in enumerate(log.records(), start = 1):
                if count > MAX_RECORDS:
                    break
                event_id, timestamp, data = getEventData(record.xml())
                if event_id != "1":
                    continue

                parent = Path(data.get("ParentImage", "")).name.lower()
                child = Path(data.get("Image", "")).name.lower()
                commandLine = data.get("CommandLine", "")

                for rule in rules:
                    printAlert(rule, parent, child, timestamp, commandLine)
                
if __name__ == "__main__":
    main()