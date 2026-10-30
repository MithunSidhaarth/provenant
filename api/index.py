"""Vercel entry point: the same stdlib server, run as a Python function for the hosted demo.

Everything here is the simulation (fake customers, fake secrets) plus dry-run Guard checks; nothing executes.
State lives in memory per function instance, so approvals and the audit log reset when an instance is recycled.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("PROVENANT_HOSTED", "1")
os.environ.setdefault("PROVENANT_HOME", "/tmp/provenant")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentshield.server import App, make_handler  # noqa: E402


class handler(make_handler(App(None))):  # Vercel looks for a top-level class named `handler`
    pass
