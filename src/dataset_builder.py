from pathlib import Path
import sys

from feature_extractor import build_dataset_row, save_features_to_csv, OUTPUT_FILE


BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"
LOG_DIR = BASE_DIR / "data" / "output"
ERROR_LOG = LOG_DIR / "errors.txt"

MAX_PHISHING = 640801
MAX_BENIGN = 640801


def clean_url_line(line: str) -> str:
    return line.strip()


def reset_output_files() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    if ERROR_LOG.exists():
        ERROR_LOG.unlink()


def process_file(input_file: Path, label: int, max_urls: int | None = None) -> tuple[int, int]:
    processed = 0
    failed = 0

    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    with open(input_file, "r", encoding="utf-8") as f, \
         open(ERROR_LOG, "a", encoding="utf-8") as err_log:

        for line_number, line in enumerate(f, start=1):
            if max_urls is not None and processed >= max_urls:
                break

            url = clean_url_line(line)

            if not url:
                continue

            try:
                row = build_dataset_row(url, label)
                save_features_to_csv(row, OUTPUT_FILE)
                processed += 1

            except Exception as e:
                failed += 1
                err_log.write(
                    f"[{input_file.name}] line {line_number} | url={url} | error={e}\n"
                )

    return processed, failed


def main() -> int:
    try:
        phishing_file = PROCESSED_DIR / "phishing_clean.txt"
        benign_file = PROCESSED_DIR / "benign_clean.txt"

        reset_output_files()

        print("[INFO] Processing phishing URLs...")
        phishing_ok, phishing_fail = process_file(
            phishing_file,
            label=1,
            max_urls=MAX_PHISHING
        )

        print("[INFO] Processing benign URLs...")
        benign_ok, benign_fail = process_file(
            benign_file,
            label=0,
            max_urls=MAX_BENIGN
        )

        total_ok = phishing_ok + benign_ok
        total_fail = phishing_fail + benign_fail

        print("\n[SUMMARY]")
        print(f"Phishing processed: {phishing_ok}")
        print(f"Phishing failed:    {phishing_fail}")
        print(f"Benign processed:   {benign_ok}")
        print(f"Benign failed:      {benign_fail}")
        print(f"Total processed:    {total_ok}")
        print(f"Total failed:       {total_fail}")
        print(f"Output CSV:         {OUTPUT_FILE}")
        print(f"Error log:          {ERROR_LOG}")

        return 0

    except Exception as e:
        print(f"[ERROR DATASET BUILDER] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())