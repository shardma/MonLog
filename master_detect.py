from pathlib import Path
from scripts.helper import extract_events
from scripts import detect_commandline
from scripts import detect_parent_child

# Command to export a log: 
# wevtutil epl Microsoft-Windows-Sysmon/Operational "PATH\TO\FOLDER\FILE_NAME.evtx" /ow:true

LOG_PATH = Path("sample-logs/sysmon.evtx")
MAX_RECORDS = 50000
SEPARATOR = 60

def main():
    print("Extracting events...")
    events = extract_events(LOG_PATH, MAX_RECORDS, wanted_event_ids=["1", "13"])

    print("Running command line detection")
    alerts = detect_commandline.detect(events)
    detect_commandline.print_alerts(alerts)
    print("Done!")

    alerts = detect_parent_child.detect(events)
    detect_parent_child.print_alerts(alerts)

if __name__ == "__main__":
    main()