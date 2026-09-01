"""Validate repository JSON and local Markdown links without network access."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
SKIPPED_PREFIXES = ("http://", "https://", "mailto:", "#")


def validate_json() -> int:
    count = 0
    for path in sorted(ROOT.rglob("*.json")):
        if ".git" in path.parts or "target" in path.parts:
            continue
        json.loads(path.read_text(encoding="utf-8"))
        count += 1
    return count


def validate_links() -> tuple[int, int]:
    documents = 0
    links = 0
    failures: list[str] = []
    for path in sorted(ROOT.rglob("*.md")):
        if ".git" in path.parts or "target" in path.parts:
            continue
        documents += 1
        text = path.read_text(encoding="utf-8")
        for raw_target in LINK.findall(text):
            target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
            if target.startswith(SKIPPED_PREFIXES):
                continue
            target = unquote(target).split("#", 1)[0]
            if not target:
                continue
            links += 1
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                failures.append(f"{path.relative_to(ROOT)} -> {raw_target}")
    if failures:
        raise RuntimeError("broken local Markdown links:\n" + "\n".join(failures))
    return documents, links


def main() -> None:
    json_files = validate_json()
    markdown_files, local_links = validate_links()
    print(
        json.dumps(
            {
                "status": "pass",
                "json_files": json_files,
                "markdown_files": markdown_files,
                "local_markdown_links": local_links,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
