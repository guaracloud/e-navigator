#!/usr/bin/env python3
"""Validate E-Navigator's public documentation contract with no dependencies."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


REPOSITORY = Path(__file__).resolve().parent.parent
DOCUMENTATION = REPOSITORY / "documentation"
WEBSITE = REPOSITORY / "website"
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
EXTERNAL_SCHEMES = {"http", "https", "mailto"}


class HtmlReferences(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        del tag
        for name, value in attrs:
            if name in {"href", "src"} and value:
                self.references.append(value)


def public_text_files() -> list[Path]:
    root_markdown = sorted(REPOSITORY.glob("*.md"))
    docs = sorted(DOCUMENTATION.rglob("*.md"))
    rust_sources = sorted(
        path
        for root in (
            REPOSITORY / "crates",
            REPOSITORY / "benchmarks",
            REPOSITORY / "fuzz",
        )
        for path in root.rglob("*.rs")
        if path.is_file()
    )
    site = sorted(
        path
        for path in WEBSITE.rglob("*")
        if path.is_file() and path.suffix in {".html", ".css", ".js"}
    )
    return root_markdown + docs + rust_sources + site


def local_target(source: Path, reference: str, site_root: bool = False) -> Path | None:
    reference = reference.strip()
    if reference.startswith("<") and reference.endswith(">"):
        reference = reference[1:-1]
    if not reference or reference.startswith("#"):
        return None

    parsed = urlsplit(reference)
    if parsed.scheme in EXTERNAL_SCHEMES or reference.startswith("//"):
        return None

    path_text = unquote(parsed.path)
    if not path_text:
        return None
    if site_root and path_text.startswith("/"):
        target = WEBSITE / path_text.lstrip("/")
    else:
        target = source.parent / path_text
    target = target.resolve()
    if target.is_dir():
        target /= "index.html"
    return target


def check_em_dashes(errors: list[str]) -> None:
    for path in public_text_files():
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "\N{EM DASH}" in line:
                errors.append(f"{path.relative_to(REPOSITORY)}:{line_number}: em dash")


def check_markdown_links(errors: list[str]) -> int:
    checked = 0
    for source in sorted([*REPOSITORY.glob("*.md"), *DOCUMENTATION.rglob("*.md")]):
        text = source.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(text):
            target = local_target(source, match.group(1))
            if target is None:
                continue
            checked += 1
            if not target.exists():
                errors.append(
                    f"{source.relative_to(REPOSITORY)}: broken link {match.group(1)}"
                )
    return checked


def check_html_links(errors: list[str]) -> int:
    checked = 0
    for source in sorted(WEBSITE.rglob("*.html")):
        parser = HtmlReferences()
        parser.feed(source.read_text(encoding="utf-8"))
        for reference in parser.references:
            target = local_target(source, reference, site_root=True)
            if target is None:
                continue
            checked += 1
            if not target.exists():
                errors.append(
                    f"{source.relative_to(REPOSITORY)}: broken link {reference}"
                )
    return checked


def markdown_targets(path: Path) -> set[str]:
    targets: set[str] = set()
    for match in MARKDOWN_LINK.finditer(path.read_text(encoding="utf-8")):
        reference = match.group(1).split("#", 1)[0]
        if reference:
            targets.add(reference)
    return targets


def check_documentation_index(errors: list[str]) -> None:
    index = DOCUMENTATION / "README.md"
    targets = markdown_targets(index)
    required = {
        path.name
        for path in DOCUMENTATION.glob("*.md")
        if path.name != index.name
    }
    required.update(
        str(path.relative_to(DOCUMENTATION)) for path in (DOCUMENTATION / "adr").glob("*.md")
    )
    missing = sorted(required - targets)
    for target in missing:
        errors.append(f"documentation/README.md: missing index entry for {target}")


def check_entry_points(errors: list[str]) -> None:
    readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
    for target in ("documentation/README.md", "documentation/golden-path.md"):
        if f"({target})" not in readme:
            errors.append(f"README.md: missing entry point for {target}")

    site_docs = WEBSITE / "docs" / "index.html"
    if not site_docs.exists():
        errors.append("website/docs/index.html: website documentation portal is missing")
    elif "golden-path" not in site_docs.read_text(encoding="utf-8"):
        errors.append("website/docs/index.html: golden path is missing")


def main() -> int:
    errors: list[str] = []
    check_em_dashes(errors)
    markdown_links = check_markdown_links(errors)
    html_links = check_html_links(errors)
    check_documentation_index(errors)
    check_entry_points(errors)

    if errors:
        print("Documentation checks failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "Documentation checks passed: "
        f"{len(public_text_files())} public text files, "
        f"{markdown_links} Markdown links, {html_links} website links"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
