from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"


def clean_url_line(line: str) -> str:
    return line.strip()


def clean_file(input_file: Path, output_file: Path) -> dict:
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    seen = set()
    stats = {
        "total_lines": 0,
        "empty_lines": 0,
        "duplicate_lines": 0,
        "kept_lines": 0,
    }

    with open(input_file, "r", encoding="utf-8") as infile:
        for line in infile:
            stats["total_lines"] += 1
            url = clean_url_line(line)

            if not url:
                stats["empty_lines"] += 1
                continue

            if url in seen:
                stats["duplicate_lines"] += 1
                continue

            seen.add(url)

    cleaned_urls = sorted(seen)

    with open(output_file, "w", encoding="utf-8") as outfile:
        for url in cleaned_urls:
            outfile.write(url + "\n")

    stats["kept_lines"] = len(cleaned_urls)
    return stats


def print_stats(name: str, stats: dict) -> None:
    print(f"[{name}]")
    print(f"Total lines:      {stats['total_lines']}")
    print(f"Empty lines:      {stats['empty_lines']}")
    print(f"Duplicates:       {stats['duplicate_lines']}")
    print(f"Kept clean URLs:  {stats['kept_lines']}")
    print()


def main() -> int:
    try:
        phishing_input = RAW_DIR / "phishing.txt"
        benign_input = RAW_DIR / "benign.txt"

        phishing_output = PROCESSED_DIR / "phishing_clean.txt"
        benign_output = PROCESSED_DIR / "benign_clean.txt"

        phishing_stats = clean_file(phishing_input, phishing_output)
        benign_stats = clean_file(benign_input, benign_output)

        print("[SUMMARY CLEANING]\n")
        print_stats("PHISHING", phishing_stats)
        print_stats("BENIGN", benign_stats)
        print(f"Processed files saved in: {PROCESSED_DIR}")

        return 0

    except Exception as e:
        print(f"[ERROR CLEAN URLS] {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())