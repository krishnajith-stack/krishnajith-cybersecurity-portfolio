"""Zero-install launcher for the SOC triage CLI."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from soc_triage.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
