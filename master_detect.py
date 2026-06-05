import subprocess
from pathlib import Path

SCRIPTS = [Path("scripts/detect_parent-child.py"), Path("scripts/detect_encoded-powershell.py")]
SEPARATOR = 60

def main():
    for script in SCRIPTS:
        filename = script.name
        print("running " + filename)
        print("-" * SEPARATOR)
        subprocess.run(["python", str(script)])
    print("Done!")

if __name__ == "__main__":
    main()