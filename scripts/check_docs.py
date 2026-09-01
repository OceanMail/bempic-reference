"""Validate repository JSON and local Markdown links without network access."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
MATRIX_ROW = re.compile(r"^\| ([A-Z]+-\d{2}) \| (pass|partial|fail|blocked) \|", re.MULTILINE)
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


def validate_conformance_matrix() -> int:
    report = json.loads((ROOT / "conformance" / "v0.1.0-report.json").read_text(encoding="utf-8"))
    if report["conformance_claim"] or report["overall_status"] != "blocked-not-conformant":
        raise RuntimeError("conformance report must remain a blocked non-claim")
    requirements = {entry["id"]: entry["status"] for entry in report["requirements"]}
    if len(requirements) != len(report["requirements"]):
        raise RuntimeError("duplicate machine-readable requirement ID")
    matrix_text = (ROOT / "docs" / "CONFORMANCE-EVIDENCE-v0.1.md").read_text(
        encoding="utf-8"
    )
    matrix = dict(MATRIX_ROW.findall(matrix_text))
    if matrix != requirements:
        raise RuntimeError("readable evidence matrix differs from machine-readable report")
    catalog = json.loads(
        (ROOT / "test-vectors" / "v0.1-experimental" / "catalog.json").read_text(
            encoding="utf-8"
        )
    )
    catalog_status = {entry["id"]: entry["status"] for entry in catalog["entries"]}
    report_status = {entry["id"]: entry["status"] for entry in report["mandatory_vector_catalog"]}
    if catalog_status != report_status:
        raise RuntimeError("vector catalog status differs from conformance report")
    return len(requirements)


def main() -> None:
    json_files = validate_json()
    markdown_files, local_links = validate_links()
    conformance_requirements = validate_conformance_matrix()
    print(
        json.dumps(
            {
                "status": "pass",
                "json_files": json_files,
                "conformance_requirements": conformance_requirements,
                "markdown_files": markdown_files,
                "local_markdown_links": local_links,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
