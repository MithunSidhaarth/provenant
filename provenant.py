"""Run Provenant from a source checkout without installing it: python provenant.py <command>.

Configs written by `provenant wrap` / `provenant install` point here, so they work from any directory.
After `pip install .` the same commands are available as `provenant <command>`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentshield.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
