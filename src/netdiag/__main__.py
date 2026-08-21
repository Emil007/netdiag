from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netdiag")
    parser.add_argument(
        "mode",
        choices=["analyzer", "coordinator", "satellite", "capture"],
        help="Process mode",
    )
    parser.add_argument(
        "-c",
        "--config",
        default=None,
        help="Path to config.yaml (default: $NETDIAG_CONFIG or /app/config.yaml)",
    )
    args = parser.parse_args(argv)

    if args.mode in ("analyzer", "coordinator"):
        from .engine import run_analyzer

        run_analyzer(args.config)
    elif args.mode == "satellite":
        from .satellite import run_satellite

        run_satellite(args.config)
    elif args.mode == "capture":
        from .capture import run_capture

        run_capture(args.config)
    else:
        parser.error(f"unknown mode {args.mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
