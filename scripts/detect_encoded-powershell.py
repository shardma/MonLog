import json
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from pathlib import Path

LOG_PATH = Path("sample-logs/sysmon.evtx")
RULE_PATH = Path("rules/encoded_powershell.json")
MAX_RECORDS = 500
SEPARATOR = 60