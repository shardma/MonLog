from pathlib import Path
from scripts.helper import extract_events
from scripts import detect_commandline
from scripts import detect_parent_child
from scripts import registry_persistence
from time import perf_counter

# Command to export a log: 
# wevtutil epl Microsoft-Windows-Sysmon/Operational "PATH\TO\FOLDER\FILE_NAME.evtx" /ow:true

LOG_PATH = Path("sample-logs/sysmon_test2.evtx")
MAX_RECORDS = 50000
SEPARATOR = 60

def main():
    # Extract events
    print("Extracting events...")

    start = perf_counter()

    events = list(extract_events(
        LOG_PATH,
        MAX_RECORDS,
        wanted_event_ids=["1", "3", "13"]
    ))

    extraction_time = perf_counter() - start

    print(f"Extracted {len(events):,} matching events")
    print(f"Extraction time: {extraction_time:.3f} seconds")

    # Command-line detection
    print("Running command line detection...")

    start = perf_counter()

    commandline_rules = detect_commandline.load_rules()

    alerts = detect_commandline.detect(
        events,
        rules_by_event=commandline_rules
    )

    detection_time = perf_counter() - start

    print(f"Command-line alerts generated: {len(alerts)}")
    print(f"Detection time: {detection_time:.4f} seconds")

    if detection_time > 0:
        print(f"Detection throughput: {len(events) / detection_time:,.0f} events/sec")

    detect_commandline.print_alerts(alerts)
    


if __name__ == "__main__":
    main()