"""Validate independently reviewed legitimate labels and export ingestion CSV."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from study.review_workflow import export_reviews


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", type=Path, action="append", required=True, help="review worksheet; repeat for shared-hosting reviews")
    parser.add_argument("--output", type=Path, required=True, help="fresh CSV path")
    args = parser.parse_args()
    try:
        print(json.dumps(export_reviews(args.review, args.output), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, f"Review export failed: {error}\n")


if __name__ == "__main__":
    main()
