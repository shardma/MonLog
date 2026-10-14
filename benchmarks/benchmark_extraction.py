from pathlib import Path
from time import perf_counter

from scripts.helper import extract_events

LOG_PATH = Path("sample-logs/sysmon.evtx")

start = perf_counter()

count = sum(1 for _ in extract_events(LOG_PATH))

elapsed = perf_counter() - start

print(f"Events extracted: {count:,}")
print(f"Elapsed: {elapsed:.4f}s")

if elapsed > 0:
    print(f"Throughput: {count / elapsed:,.0f} events/sec")