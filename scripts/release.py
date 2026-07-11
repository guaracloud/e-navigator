#!/usr/bin/env python3
"""Prepare, validate, and render notes for E-Navigator releases."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"
)
VERSION_TEXT_FILES = (
    "README.md",
    "documentation/helm.md",
    "documentation/release-verification.md",
    "website/index.html",
    "deploy/kubernetes/daemonset.yaml",
)
FORBIDDEN_IDENTITIES = (
    "https://github.com/e-navigator",
    "github.com/e-navigator/e-navigator",
    "ghcr.io/e-navigator",
    "REPO=e-navigator/e-navigator",
    '"repository": "e-navigator/e-navigator"',
)
RELEASE_WORKFLOW_EXPECTATIONS = (
    "tags:",
    "environment: release",
    "platforms: linux/amd64,linux/arm64",
    "cosign sign --yes",
    '--bundle "$artifact.sigstore.json"',
    "--bundle release-manifest.json.sigstore.json",
    "for bundle in *.sigstore.json",
    'platform_digest="$(jq -er',
    '"${IMAGE}@${platform_digest}" --version',
    'helm push "$chart" "$CHART_REPOSITORY"',
    "draft: true",
    "release-manifest.json",
    'gh release edit "$TAG" --draft=false',
)


def fail(message: str) -> None:
    raise SystemExit(message)


def read_workspace_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as stream:
        return tomllib.load(stream)["workspace"]["package"]["version"]


def validate_version(version: str) -> None:
    if not SEMVER.fullmatch(version):
        fail(f"invalid release version: {version}")


def replace_once(path: Path, pattern: str, replacement: str) -> None:
    content = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count != 1:
        fail(f"expected one version field in {path.relative_to(ROOT)}; found {count}")
    path.write_text(updated, encoding="utf-8")


def update_lockfile(path: Path, old: str, new: str) -> None:
    if not path.exists():
        return

    content = path.read_text(encoding="utf-8")
    blocks = content.split("[[package]]")
    updated = [blocks[0]]
    changed = 0
    for block in blocks[1:]:
        name = re.search(r'^\s*name = "([^"]+)"', block, flags=re.MULTILINE)
        version = re.search(r'^\s*version = "([^"]+)"', block, flags=re.MULTILINE)
        if (
            name is not None
            and version is not None
            and name.group(1).startswith("e-navigator")
            and version.group(1) == old
        ):
            block = re.sub(
                rf'^(\s*version = "){re.escape(old)}("\s*)$',
                rf"\g<1>{new}\g<2>",
                block,
                count=1,
                flags=re.MULTILINE,
            )
            changed += 1
        updated.append(block)

    if path.name == "Cargo.lock" and path.parent == ROOT and changed == 0:
        fail("root Cargo.lock did not contain workspace versions to update")
    path.write_text("[[package]]".join(updated), encoding="utf-8")


def prepare(version: str) -> None:
    validate_version(version)
    current = read_workspace_version()
    if version == current:
        fail(f"workspace is already at {version}")

    replace_once(
        ROOT / "Cargo.toml",
        rf'(^\[workspace\.package\][\s\S]*?^version = "){re.escape(current)}("$)',
        rf"\g<1>{version}\g<2>",
    )
    replace_once(
        ROOT / "charts/e-navigator/Chart.yaml",
        rf'^version: {re.escape(current)}$',
        f"version: {version}",
    )
    replace_once(
        ROOT / "charts/e-navigator/Chart.yaml",
        rf'^appVersion: "{re.escape(current)}"$',
        f'appVersion: "{version}"',
    )

    update_lockfile(ROOT / "Cargo.lock", current, version)
    update_lockfile(ROOT / "fuzz/Cargo.lock", current, version)

    for relative in VERSION_TEXT_FILES:
        path = ROOT / relative
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        if current not in content:
            fail(f"expected {current} in {relative}")
        path.write_text(content.replace(current, version), encoding="utf-8")

    print(f"prepared version surfaces: {current} -> {version}")
    print(f"add a CHANGELOG.md section for [{version}], then run:")
    print(f"  python3 scripts/release.py check {version}")


def tracked_text_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    files = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = ROOT / raw.decode("utf-8")
        try:
            path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError):
            continue
        files.append(path)
    return files


def chart_versions() -> tuple[str, str]:
    content = (ROOT / "charts/e-navigator/Chart.yaml").read_text(encoding="utf-8")
    version = re.search(r"^version: (\S+)$", content, flags=re.MULTILINE)
    app_version = re.search(r'^appVersion: "([^"]+)"$', content, flags=re.MULTILINE)
    if version is None or app_version is None:
        fail("could not read chart version fields")
    return version.group(1), app_version.group(1)


def check(version: str | None) -> None:
    expected = version or read_workspace_version()
    validate_version(expected)
    errors: list[str] = []

    workspace_version = read_workspace_version()
    if workspace_version != expected:
        errors.append(f"workspace version is {workspace_version}, expected {expected}")

    chart_version, app_version = chart_versions()
    if chart_version != expected or app_version != expected:
        errors.append(
            f"chart version/appVersion are {chart_version}/{app_version}, expected {expected}"
        )

    metadata = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    packages = json.loads(metadata.stdout)["packages"]
    for package in packages:
        manifest = Path(package["manifest_path"])
        if ROOT not in manifest.parents:
            continue
        if package["version"] != expected:
            errors.append(
                f'{package["name"]} version is {package["version"]}, expected {expected}'
            )
        if package["publish"] != []:
            errors.append(f'{package["name"]} is publishable; expected publish = false')

    expected_strings = {
        "README.md": expected,
        "documentation/helm.md": f"--version {expected}",
        "documentation/release-verification.md": f"export VERSION=v{expected}",
        "website/index.html": expected,
        "deploy/kubernetes/daemonset.yaml": (
            f"image: ghcr.io/guaracloud/e-navigator:{expected}"
        ),
        "charts/e-navigator/values.yaml": (
            "repository: ghcr.io/guaracloud/e-navigator"
        ),
        "CHANGELOG.md": f"## [{expected}]",
    }
    for relative, needle in expected_strings.items():
        path = ROOT / relative
        if not path.exists() or needle not in path.read_text(encoding="utf-8"):
            errors.append(f"{relative} does not contain {needle!r}")

    for path in tracked_text_files():
        if path == ROOT / "scripts/release.py":
            continue
        content = path.read_text(encoding="utf-8")
        for forbidden in FORBIDDEN_IDENTITIES:
            if forbidden in content:
                errors.append(
                    f"{path.relative_to(ROOT)} contains stale identity {forbidden!r}"
                )

    for required in ("release.toml", "SECURITY.md", "documentation/release-process.md"):
        if not (ROOT / required).is_file():
            errors.append(f"missing {required}")

    release_workflow = (ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    for needle in RELEASE_WORKFLOW_EXPECTATIONS:
        if needle not in release_workflow:
            errors.append(f"release workflow is missing {needle!r}")
    for removed_flag in ("--output-signature", "--output-certificate"):
        if removed_flag in release_workflow:
            errors.append(
                f"release workflow uses removed Cosign v3 flag {removed_flag!r}"
            )
    if not (ROOT / ".github/workflows/publish-image-aliases.yml").is_file():
        errors.append("missing image alias repair workflow")

    for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
        content = workflow.read_text(encoding="utf-8")
        for action in re.findall(r"^\s*uses:\s*([^\s#]+)", content, flags=re.MULTILINE):
            if action.startswith("./"):
                continue
            revision = action.rsplit("@", maxsplit=1)[-1]
            if not re.fullmatch(r"[0-9a-f]{40}", revision):
                errors.append(
                    f"{workflow.relative_to(ROOT)} uses unpinned action {action!r}"
                )

    if shutil.which("helm") is not None:
        subprocess.run(["helm", "lint", "charts/e-navigator"], cwd=ROOT, check=True)
        rendered = subprocess.run(
            ["helm", "template", "e-navigator", "charts/e-navigator"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        expected_image = f"image: ghcr.io/guaracloud/e-navigator:{expected}"
        if expected_image not in rendered:
            errors.append(f"rendered chart does not contain {expected_image!r}")

    if errors:
        for error in errors:
            print(f"release check: {error}", file=sys.stderr)
        raise SystemExit(1)

    print(f"release contract ok: {expected}")


def notes(version: str, output: Path) -> None:
    validate_version(version)
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.search(
        rf"^## \[{re.escape(version)}\](?: - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})?\n",
        changelog,
        flags=re.MULTILINE,
    )
    if heading is None:
        fail(f"CHANGELOG.md has no [{version}] section")
    remainder = changelog[heading.end() :]
    next_boundary = re.search(
        r"^(?:## \[|\[[^]]+\]: https://)",
        remainder,
        flags=re.MULTILINE,
    )
    end = heading.end() + next_boundary.start() if next_boundary else len(changelog)
    section = changelog[heading.end() : end].strip()
    channel = "release candidate" if "-" in version else "public preview"
    rendered = (
        f"# E-Navigator v{version}\n\n"
        f"This is the E-Navigator {channel}. E-Navigator remains a pre-1.0 "
        "runtime signal plane, not a production observability backend replacement.\n\n"
        f"{section}\n\n"
        "## Verification\n\n"
        f"Follow the [release verification guide](https://github.com/guaracloud/"
        f"e-navigator/blob/v{version}/documentation/release-verification.md) and "
        "deploy digest-pinned image references from `release-manifest.json`.\n"
    )
    output.write_text(rendered, encoding="utf-8")
    print(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("version")

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("version", nargs="?")

    notes_parser = subparsers.add_parser("notes")
    notes_parser.add_argument("version")
    notes_parser.add_argument("--output", type=Path, required=True)

    subparsers.add_parser("version")
    args = parser.parse_args()

    if args.command == "prepare":
        prepare(args.version)
    elif args.command == "check":
        check(args.version)
    elif args.command == "notes":
        notes(args.version, args.output)
    elif args.command == "version":
        print(read_workspace_version())


if __name__ == "__main__":
    main()
