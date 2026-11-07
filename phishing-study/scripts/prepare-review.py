"""Prepare candidates and human review worksheets; never visit their endpoints."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from study.review_workflow import latest_source, local_source, prepare_shortlist


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--latest", action="store_true", help="download the latest standard Tranco list through the official API")
    source.add_argument("--archive", type=Path, help="previously downloaded Tranco ZIP or plain CSV")
    parser.add_argument("--metadata", type=Path, help="official permanent-list metadata JSON (required with --archive)")
    parser.add_argument("--list-id", help="permanent Tranco list ID (required with --archive)")
    parser.add_argument("--downloaded-at", help="original archive download time with explicit UTC timezone (required with --archive)")
    parser.add_argument("--output", type=Path, required=True, help="fresh output directory")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output directory must be fresh")
    if args.latest and any((args.metadata, args.list_id, args.downloaded_at)):
        parser.error("local source options cannot be combined with --latest")
    if args.archive and not all((args.metadata, args.list_id, args.downloaded_at)):
        parser.error("--archive requires --metadata, --list-id and --downloaded-at")
    try:
        source = latest_source() if args.latest else local_source(args.archive, args.metadata, args.list_id, args.downloaded_at)
        print(json.dumps(prepare_shortlist(args.output, *source), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, f"Shortlist preparation failed: {error}\n")


if __name__ == "__main__":
    main()
