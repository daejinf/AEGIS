import importlib.util
import subprocess
import sys
from pathlib import Path


def main() -> None:
    app_path = Path(__file__).resolve().parent / "dashboard" / "app.py"

    if not app_path.exists():
        raise FileNotFoundError(f"dashboard app not found: {app_path}")

    if importlib.util.find_spec("streamlit") is None:
        print("[!] streamlit is not installed in the current Python environment.")
        print(f"    target app: {app_path}")
        print("    install example: pip install streamlit")
        return

    command = [sys.executable, "-m", "streamlit", "run", str(app_path)]
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
