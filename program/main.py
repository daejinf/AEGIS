import signal
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROGRAM_DIR = PROJECT_ROOT / "program"
COLLECTED_DATA_DIR = PROJECT_ROOT / "data" / "collected_data"
ARCHIVE_DIR = COLLECTED_DATA_DIR / "archive"

FEATURE_FILE = COLLECTED_DATA_DIR / "live_features.csv"
PREDICT_FILE = COLLECTED_DATA_DIR / "live_predictions.csv"
DASHBOARD_FILE = COLLECTED_DATA_DIR / "live_dashboard.json"

FEATURE_EXTRACTOR = PROGRAM_DIR / "feature_extractor.py"
PREDICTOR = PROGRAM_DIR / "predictor.py"
MONITOR = PROGRAM_DIR / "monitor.py"
DASHBOARD = PROGRAM_DIR / "dashboard.py"

processes = []


def reset_runtime_files() -> None:
    COLLECTED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

    existing_files = [
        file_path
        for file_path in [FEATURE_FILE, PREDICT_FILE, DASHBOARD_FILE]
        if file_path.exists()
    ]

    if not existing_files:
        return

    run_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_archive_dir = ARCHIVE_DIR / run_stamp
    run_archive_dir.mkdir(parents=True, exist_ok=True)

    for file_path in existing_files:
        archived_path = run_archive_dir / file_path.name
        previous_path = COLLECTED_DATA_DIR / f"previous_{run_stamp}_{file_path.name}"
        shutil.copy2(file_path, archived_path)
        shutil.copy2(file_path, previous_path)
        file_path.unlink()
        print(f"[*] 기존 파일 보관: {previous_path}")


def start_process(name: str, command: list[str]) -> subprocess.Popen:
    print(f"[*] {name} 시작: {' '.join(map(str, command))}")

    process = subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
    )

    processes.append((name, process))
    time.sleep(1)

    if process.poll() is not None:
        print(f"[ERROR] {name} 실행 직후 종료됨. 코드를 확인하세요.")

    return process


def stop_all_processes() -> None:
    print("\n[*] AEGIS 전체 종료 중...")

    for name, process in processes:
        if process.poll() is None:
            print(f"[*] {name} 종료")
            process.terminate()

    time.sleep(2)

    for name, process in processes:
        if process.poll() is None:
            print(f"[!] {name} 강제 종료")
            process.kill()

    print("[*] 종료 완료")


def handle_exit(signum, frame) -> None:
    stop_all_processes()
    sys.exit(0)


def main() -> None:
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    print("=========================================")
    print("AEGIS 실시간 네트워크 공격 탐지 시스템")
    print("=========================================")

    reset_runtime_files()

    python_cmd = sys.executable

    start_process(
        "Feature Extractor",
        [python_cmd, str(FEATURE_EXTRACTOR)],
    )

    start_process(
        "Predictor",
        [python_cmd, str(PREDICTOR)],
    )

    start_process(
        "Monitor",
        [python_cmd, str(MONITOR)],
    )

    start_process(
        "Dashboard",
        [python_cmd, str(DASHBOARD)],
    )

    print("\n=========================================")
    print("AEGIS 실행 완료")
    print("브라우저에서 Streamlit 대시보드를 확인하세요.")
    print("종료하려면 Ctrl + C")
    print("=========================================\n")

    try:
        while True:
            time.sleep(3)

            for name, process in processes:
                if process.poll() is not None:
                    print(f"[WARN] {name} 프로세스가 종료되었습니다.")

    except KeyboardInterrupt:
        stop_all_processes()


if __name__ == "__main__":
    main()
