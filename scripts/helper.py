from xml.etree import ElementTree as ET
from Evtx.Evtx import Evtx

# Takes in a raw Sysmon record, turns it into a tree, and extracts the useful info

def get_event_data(event_xml):
    root = ET.fromstring(event_xml)
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    system = root.find(f"{{{ns}}}System")

    if system is None:
        raise ValueError("Missing System element")

    event_id_element = system.find(f"{{{ns}}}EventID")
    time_element = system.find(f"{{{ns}}}TimeCreated")

    if event_id_element is None or event_id_element.text is None:
        raise ValueError("Missing EventID")

    event_id = event_id_element.text
    timestamp = (
        time_element.get("SystemTime")
        if time_element is not None
        else None
    )

    data = {}

    event_data = root.find(f"{{{ns}}}EventData")

    if event_data is not None:
        for item in event_data.findall(f"{{{ns}}}Data"):
            name = item.get("Name")
            if name:
                data[name] = item.text or ""

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "data": data
    }

def extract_events(log_path, max_records=500, wanted_event_ids=None):
    if wanted_event_ids is not None:
        wanted_event_ids = {
            str(event_id) for event_id in wanted_event_ids
        }

    with Evtx(str(log_path)) as log:
        for count, record in enumerate(log.records(), start=1):
            if max_records is not None and count > max_records:
                break

            event = get_event_data(record.xml())

            if (
                wanted_event_ids is not None
                and event["event_id"] not in wanted_event_ids
            ):
                continue

            yield event
