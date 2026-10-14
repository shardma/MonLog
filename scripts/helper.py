import xml.etree.ElementTree as ET
from evtx import PyEvtxParser


EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def get_event_data(event_xml):
    """Convert Sysmon event XML into a dictionary."""
    root = ET.fromstring(event_xml)

    ns = f"{{{EVENT_NS}}}"
    system = root.find(f"{ns}System")

    if system is None:
        raise ValueError("Missing System element")

    event_id_element = system.find(f"{ns}EventID")
    time_element = system.find(f"{ns}TimeCreated")

    if event_id_element is None or event_id_element.text is None:
        raise ValueError("Missing EventID")

    event_data = root.find(f"{ns}EventData")
    data = {}

    if event_data is not None:
        for item in event_data.findall(f"{ns}Data"):
            name = item.get("Name")

            if name:
                data[name] = item.text or ""

    return {
        "event_id": event_id_element.text,
        "timestamp": (
            time_element.get("SystemTime")
            if time_element is not None else None
        ),
        "data": data,
    }


def extract_events(log_path, max_records=None, wanted_event_ids=None):
    """Yield normalized EVTX events one at a time."""
    if wanted_event_ids is not None:
        wanted_event_ids = {
            str(event_id) for event_id in wanted_event_ids
        }

    parser = PyEvtxParser(str(log_path))

    for index, record in enumerate(parser.records()):
        if max_records is not None and index >= max_records:
            break

        event = get_event_data(record["data"])

        if (
            wanted_event_ids is not None
            and event["event_id"] not in wanted_event_ids
        ):
            continue

        yield event
