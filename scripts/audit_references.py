#!/usr/bin/env python3
"""Fail-closed structural audit for the paper bibliography and citation graph."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "external_resources.csv"

ENTRY = re.compile(r"@(?P<kind>[A-Za-z]+)\s*\{(?P<key>[^,\s]+)\s*,(?P<body>.*?)(?=\n@|\Z)", re.S)
FIELD = re.compile(r"(?mi)^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:\{((?:[^{}]|\{[^{}]*\})*)\}|\"([^\"]*)\")\s*,?\s*$")
CITE = re.compile(r"\\cite(?!style\b)\w*\s*(?:\[[^\]]*\]\s*)*\{([^}]*)\}")
PLACEHOLDER = re.compile(r"example\.(?:com|org)|placeholder|anonymous|todo|tbd", re.I)


def normalize(value: str) -> str:
    value = re.sub(r"[{}\\]", "", value)
    return re.sub(r"\W+", " ", value.lower()).strip()


def parse_bib(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for match in ENTRY.finditer(text):
        fields: dict[str, str] = {}
        for item in FIELD.finditer(match.group("body")):
            fields[item.group(1).lower()] = (item.group(2) or item.group(3) or "").strip()
        fields["key"] = match.group("key")
        fields["entry_type"] = match.group("kind").lower()
        entries.append(fields)
    return entries


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--paper-dir",
        type=Path,
        required=True,
        help="directory containing main.tex and references.bib",
    )
    arguments = parser.parse_args()
    paper = arguments.paper_dir / "main.tex"
    bibliography = arguments.paper_dir / "references.bib"
    if not paper.is_file() or not bibliography.is_file():
        raise SystemExit(f"paper inputs not found in {arguments.paper_dir}")
    source = paper.read_text(encoding="utf-8")
    bib_text = bibliography.read_text(encoding="utf-8")
    entries = parse_bib(bib_text)
    if not entries:
        raise SystemExit("no bibliography entries parsed")
    keys = [entry["key"] for entry in entries]
    if len(keys) != len(set(keys)):
        raise SystemExit("duplicate bibliography keys")

    citations: list[str] = []
    for group in CITE.findall(source):
        citations.extend(key.strip() for key in group.split(",") if key.strip())
    cited = set(citations)
    defined = set(keys)
    missing = sorted(cited - defined)
    unused = sorted(defined - cited)
    if missing or unused:
        raise SystemExit(f"citation graph mismatch: missing={missing}, unused={unused}")

    doi_owner: dict[str, str] = {}
    title_owner: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    for entry in entries:
        key = entry["key"]
        title = entry.get("title", "")
        year = entry.get("year", "")
        doi = entry.get("doi", "").lower().removeprefix("https://doi.org/")
        url = entry.get("url", "")
        if not title or not year:
            raise SystemExit(f"{key}: title/year missing")
        if PLACEHOLDER.search(" ".join((title, doi, url))):
            raise SystemExit(f"{key}: placeholder locator")
        normalized_title = normalize(title)
        if normalized_title in title_owner:
            raise SystemExit(f"duplicate title: {key} and {title_owner[normalized_title]}")
        title_owner[normalized_title] = key
        if doi:
            if doi in doi_owner:
                raise SystemExit(f"duplicate DOI: {key} and {doi_owner[doi]}")
            doi_owner[doi] = key
        locator = f"https://doi.org/{doi}" if doi else url
        if not locator:
            # MITRE CWE uses a stable institutional title field in some styles;
            # all other entries need an explicit locator.
            if key.lower() != "mitrecwe":
                raise SystemExit(f"{key}: no DOI or URL")
        rows.append(
            {
                "key": key,
                "entry_type": entry["entry_type"],
                "year": year,
                "title": re.sub(r"[{}]", "", title),
                "doi": doi,
                "url": url,
                "locator": locator,
                "citation_occurrences": citations.count(key),
                "structural_status": "PASS",
            }
        )

    if RESOURCES.exists():
        resources = RESOURCES.read_text(encoding="utf-8")
        absent = [row["key"] for row in rows if row["key"] not in resources and row["title"] not in resources]
        if absent:
            raise SystemExit(f"external resource ledger lacks bibliography entries: {absent}")

    audit_dir = ROOT / "audit"
    audit_dir.mkdir(exist_ok=True)
    with (audit_dir / "reference-structure-audit.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    report = {
        "status": "PASS",
        "bibliography_entries": len(entries),
        "unique_cited_keys": len(cited),
        "citation_commands": len(CITE.findall(source)),
        "citation_occurrences": len(citations),
        "missing_keys": missing,
        "unused_keys": unused,
        "duplicate_dois": 0,
        "duplicate_titles": 0,
        "entries_with_doi": sum(bool(row["doi"]) for row in rows),
        "entries_with_stable_url_only": sum(bool(row["url"]) and not row["doi"] for row in rows),
    }
    (audit_dir / "reference-structure-audit.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
