from xml.etree import ElementTree as ET

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