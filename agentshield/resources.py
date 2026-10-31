"""Locate Provenant's bundled data whether it runs from a source checkout or from an installed wheel.

A checkout keeps dashboard/, scenarios/, policy/, fixtures/ and evals/ next to the package. The wheel ships the
same directories as data-only packages named provenant_<name> (see pyproject.toml), because setuptools cannot
place top-level folders inside agentshield/. Writable state never goes into either location: see state_dir().
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def path(name: str) -> Path:
    """Directory for a bundled resource set: dashboard, scenarios, policy, fixtures or evals."""
    repo = ROOT / name
    if (ROOT / "pyproject.toml").is_file() and repo.is_dir():
        return repo
    spec = importlib.util.find_spec(f"provenant_{name}")
    if spec is not None and spec.submodule_search_locations:
        return Path(next(iter(spec.submodule_search_locations)))
    return repo


def state_dir(*parts: str) -> Path:
    """A user-writable directory under PROVENANT_HOME (default ~/.provenant). Never inside site-packages."""
    home = Path(os.environ.get("PROVENANT_HOME") or Path.home() / ".provenant")
    return home.joinpath(*parts)
