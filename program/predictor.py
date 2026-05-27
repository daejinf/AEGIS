import csv
import time
import warnings
from pathlib import Path

import joblib

warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
)


POLL_INTERVAL = 2
FEATURE_FILE_NAME = "live_features.csv"
PREDICTION_FILE_NAME = "live_predictions.csv"
MODEL_RELATIVE_PATH = Path("..") / "ai_model" / "AEGIS.pkl"

LABEL_MAP = {
    0: "Normal",
    1: "ICMP Flood",
    2: "Port Scan",
    3: "SSH Brute Force",
    4: "ARP Spoofing",
    5: "DNS Anomaly",
}


def find_existing_path(file_name: str) -> Path:
    script_dir = Path(__file__).resolve().parent
    candidates = [
        Path.cwd() / file_name,
        script_dir / file_name,
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return script_dir / file_name


FEATURE_FILE = find_existing_path(FEATURE_FILE_NAME)
PREDICTION_FILE = FEATURE_FILE.with_name(PREDICTION_FILE_NAME)
MODEL_PATH = (Path(__file__).resolve().parent / MODEL_RELATIVE_PATH).resolve()


def ensure_prediction_file() -> None:
    if PREDICTION_FILE.exists():
        return

    with PREDICTION_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "label", "label_name", "confidence"])


def load_processed_timestamps() -> set[str]:
    if not PREDICTION_FILE.exists():
        return set()

    processed = set()
    with PREDICTION_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            timestamp = (row.get("timestamp") or "").strip()
            if timestamp:
                processed.add(timestamp)
    return processed


def load_feature_rows(feature_names: list[str], processed_timestamps: set[str]) -> list[dict]:
    if not FEATURE_FILE.exists():
        return []

    with FEATURE_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames:
            return []

        required_columns = ["timestamp", *feature_names]
        missing_columns = [column for column in required_columns if column not in reader.fieldnames]
        if missing_columns:
            raise ValueError(f"missing columns: {', '.join(missing_columns)}")

        new_rows = []
        for row in reader:
            timestamp = (row.get("timestamp") or "").strip()
            if not timestamp or timestamp in processed_timestamps:
                continue
            new_rows.append(row)
        return new_rows


def build_feature_matrix(rows: list[dict], feature_names: list[str]) -> list[list[float]]:
    matrix = []
    for row in rows:
        matrix.append([float(row[name]) for name in feature_names])
    return matrix


def append_predictions(rows: list[dict], predictions, confidences) -> int:
    with PREDICTION_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        for row, label, confidence in zip(rows, predictions, confidences):
            label_int = int(label)
            writer.writerow(
                [
                    row["timestamp"],
                    label_int,
                    LABEL_MAP.get(label_int, f"Class {label_int}"),
                    f"{float(confidence):.4f}",
                ]
            )
    return len(rows)


def main() -> None:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"model not found: {MODEL_PATH}")

    model = joblib.load(MODEL_PATH)
    feature_names = list(model.feature_names_in_)

    ensure_prediction_file()
    processed_timestamps = load_processed_timestamps()

    print(f"[*] Predictor started")
    print(f"    model: {MODEL_PATH}")
    print(f"    input: {FEATURE_FILE}")
    print(f"    output: {PREDICTION_FILE}")

    while True:
        try:
            rows = load_feature_rows(feature_names, processed_timestamps)
            if rows:
                feature_matrix = build_feature_matrix(rows, feature_names)
                predictions = model.predict(feature_matrix)

                if hasattr(model, "predict_proba"):
                    probabilities = model.predict_proba(feature_matrix)
                    confidences = probabilities.max(axis=1)
                else:
                    confidences = [1.0] * len(rows)

                written_count = append_predictions(rows, predictions, confidences)
                for row in rows:
                    processed_timestamps.add(row["timestamp"])

                print(f"[+] predicted {written_count} row(s)")

            time.sleep(POLL_INTERVAL)
        except FileNotFoundError:
            time.sleep(POLL_INTERVAL)
        except ValueError as error:
            print(f"[!] predictor input error: {error}")
            time.sleep(POLL_INTERVAL)
        except Exception as error:
            print(f"[!] predictor runtime error: {error}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
