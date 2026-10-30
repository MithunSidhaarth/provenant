# Releasing Provenant

The PyPI distribution name for this repository is **`provenant-agent-shield`**. The installed command remains `provenant`; the Python implementation is imported from `agentshield`.

## One-time PyPI Trusted Publisher setup

A repository maintainer with access to the PyPI account must configure the publisher before the first tag can publish successfully:

1. Open [PyPI publishing settings](https://pypi.org/manage/account/publishing/).
2. Add a pending publisher for project name `provenant-agent-shield`.
3. Set owner to `MithunSidhaarth`, repository to `provenant`, workflow filename to `release.yml`, and environment name to `pypi`.
4. Save the publisher configuration. No PyPI API token or GitHub secret is needed; the release workflow uses OIDC Trusted Publishing.
5. Before tagging, verify that the distribution name is available and that the publisher configuration matches these exact values.

PyPI name availability and account-level publisher settings cannot be changed by this repository workflow. If the name is already claimed, choose another available distribution name and update `pyproject.toml`, `scripts/build_release.py`, this document, and the workflow environment URL together.

## Release steps

1. Merge the release changes to `main`.
2. Confirm CI and the release verification job pass. The workflow runs unit tests, the security evaluation, dependency audits, builds wheel + sdist, and installs the wheel to smoke-test `provenant --version` and `provenant verify`.
4. Confirm the PyPI Trusted Publisher is configured and the distribution name is available.
5. Create and push a version tag matching the version in `pyproject.toml`, for example `v0.10.0`.
6. Follow [the release workflow](https://github.com/MithunSidhaarth/provenant/actions/workflows/release.yml). It attaches build artifacts to a GitHub release and publishes them to PyPI only for version tags.
7. Verify the package page and test a clean install:

   ```bash
   python -m pip install --upgrade provenant-agent-shield
   provenant --version
   provenant verify
   provenant mail status
   ```

The distribution is not considered published until the PyPI upload succeeds and a clean environment can install and run these commands. A successful GitHub build alone is not proof of publication.
