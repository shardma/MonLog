from xml.etree import ElementTree as ET
from Evtx.Evtx import Evtx

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

    return {
        "event_id": event_id, 
        "timestamp": timestamp, 
        "data":data
    }

def extract_events(log_path, max_records = 500, wanted_event_ids = None):
    events = []
    if wanted_event_ids:
        wanted_event_ids = set(str(e) for e in wanted_event_ids)

    with(Evtx(str(log_path))) as log:
        for count, record in enumerate(log.records(), start = 1):
            if count > max_records:
                break

            event = get_event_data(record.xml())
            if wanted_event_ids and event["event_id"] not in wanted_event_ids:
                continue
            events.append(event)
            if count % 1000 == 0:
                print(f"Parsed {count} records...")
    return events