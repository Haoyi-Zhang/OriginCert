#!/usr/bin/env python3
"""Refresh or validate the frozen reference-identity and citation-context audit.

Network access is used only with --refresh to collect metadata from DOI/Crossref
or the stable institutional URL stored in the bibliography. Normal reproduction
uses the frozen snapshot and is fully offline.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT.parent / "paper"
BIB = PAPER / "references.bib"
TEX = PAPER / "main.tex"
SNAPSHOT = ROOT / "audit" / "reference-identity-snapshot.json"
IDENTITY_CSV = ROOT / "audit" / "reference-identity-audit.csv"
CONTEXT_CSV = ROOT / "audit" / "reference-claim-context-audit.csv"
SUMMARY_JSON = ROOT / "audit" / "reference-audit-summary.json"
USER_AGENT = "bounded-generator-reference-audit/1.0 (metadata verification)"


def split_bib_entries(text: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    i = 0
    while True:
        m = re.search(r"@([A-Za-z]+)\s*\{", text[i:])
        if not m:
            break
        typ = m.group(1).lower()
        start = i + m.end()
        depth = 1
        j = start
        in_quote = False
        escaped = False
        while j < len(text) and depth:
            c = text[j]
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_quote = not in_quote
            elif not in_quote:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
            j += 1
        if depth:
            raise ValueError("unbalanced BibTeX entry")
        body = text[start:j-1]
        comma = body.find(",")
        if comma < 0:
            raise ValueError("BibTeX entry lacks key separator")
        key = body[:comma].strip()
        out.append((typ, key, body[comma+1:]))
        i = j
    return out


def parse_fields(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    i = 0
    n = len(body)
    while i < n:
        while i < n and (body[i].isspace() or body[i] == ","):
            i += 1
        if i >= n:
            break
        m = re.match(r"([A-Za-z][A-Za-z0-9_-]*)\s*=\s*", body[i:])
        if not m:
            # Ignore comments or unsupported constructs only if they are blank.
            raise ValueError(f"cannot parse BibTeX field near: {body[i:i+80]!r}")
        name = m.group(1).lower()
        i += m.end()
        if i >= n:
            raise ValueError(f"missing value for {name}")
        if body[i] == "{":
            depth = 1
            j = i + 1
            escaped = False
            while j < n and depth:
                c = body[j]
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                j += 1
            if depth:
                raise ValueError(f"unbalanced value for {name}")
            value = body[i+1:j-1]
            i = j
        elif body[i] == '"':
            j = i + 1
            escaped = False
            chunks: list[str] = []
            while j < n:
                c = body[j]
                if escaped:
                    chunks.append(c)
                    escaped = False
                elif c == "\\":
                    chunks.append(c)
                    escaped = True
                elif c == '"':
                    break
                else:
                    chunks.append(c)
                j += 1
            if j >= n:
                raise ValueError(f"unterminated quote for {name}")
            value = "".join(chunks)
            i = j + 1
        else:
            j = i
            while j < n and body[j] not in ",\n":
                j += 1
            value = body[i:j].strip()
            i = j
        fields[name] = value.strip()
    return fields


def read_bib() -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    for typ, key, body in split_bib_entries(BIB.read_text(encoding="utf-8")):
        if key in entries:
            raise ValueError(f"duplicate BibTeX key: {key}")
        fields = parse_fields(body)
        fields["entrytype"] = typ
        entries[key] = fields
    return entries


def plain_latex(value: str) -> str:
    value = re.sub(r"\\[A-Za-z]+\*?(?:\[[^\]]*\])?", " ", value)
    value = value.replace("{", "").replace("}", "")
    value = value.replace("~", " ")
    value = re.sub(r"\\[&%_$#]", lambda m: m.group(0)[1:], value)
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def norm(value: str) -> str:
    value = plain_latex(value).lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def title_similarity(a: str, b: str) -> float:
    aa = set(norm(a).split())
    bb = set(norm(b).split())
    if not aa or not bb:
        return 0.0
    return len(aa & bb) / len(aa | bb)


def fetch_json(url: str) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    last: Exception | None = None
    for pause in (0.0, 0.7, 1.5):
        if pause:
            time.sleep(pause)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # network-refresh path only
            last = exc
    assert last is not None
    raise last


def fetch_html_metadata(url: str) -> dict[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        final_url = response.geturl()
        content_type = response.headers.get("Content-Type", "")
        data = response.read(1_500_000)
    text = data.decode("utf-8", errors="replace")
    title = ""
    for pattern in (
        r'<meta[^>]+(?:name|property)=["\'](?:citation_title|og:title)["\'][^>]+content=["\']([^"\']+)',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:name|property)=["\'](?:citation_title|og:title)["\']',
        r"<title[^>]*>(.*?)</title>",
    ):
        m = re.search(pattern, text, flags=re.I | re.S)
        if m:
            title = html.unescape(re.sub(r"<[^>]+>", " ", m.group(1)))
            title = re.sub(r"\s+", " ", title).strip()
            break
    return {"resolved_url": final_url, "content_type": content_type, "record_title": title}


def crossref_record(doi: str) -> dict[str, Any]:
    data = fetch_json("https://api.crossref.org/works/" + urllib.parse.quote(doi, safe=""))
    msg = data["message"]
    years: list[int] = []
    for field in ("published-print", "published-online", "issued", "created"):
        parts = msg.get(field, {}).get("date-parts", [])
        if parts and parts[0]:
            years.append(int(parts[0][0]))
    authors = []
    for author in msg.get("author", []):
        name = " ".join(x for x in (author.get("given", ""), author.get("family", "")) if x).strip()
        if name:
            authors.append(name)
    return {
        "record_title": (msg.get("title") or [""])[0],
        "record_years": sorted(set(years)),
        "record_authors": authors,
        "record_container": (msg.get("container-title") or [""])[0],
        "record_type": msg.get("type", ""),
        "resolved_url": msg.get("URL", "https://doi.org/" + doi),
        "source": "Crossref DOI record",
    }


def stable_url_class(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname or ""
    host = host.lower()
    if host.endswith("usenix.org"):
        return "USENIX official proceedings"
    if host.endswith("proceedings.mlr.press"):
        return "PMLR official proceedings"
    if host.endswith("cwe.mitre.org"):
        return "MITRE CWE official record"
    if host.endswith("acm.org") or host.endswith("dl.acm.org"):
        return "ACM official record"
    if host.endswith("ieee.org") or host.endswith("ieeexplore.ieee.org"):
        return "IEEE official record"
    return "stable publisher/institutional record"


def refresh_snapshot(entries: dict[str, dict[str, str]]) -> dict[str, Any]:
    records: dict[str, Any] = {}
    failures: list[str] = []
    for key, fields in entries.items():
        title = fields.get("title", "")
        year = fields.get("year", "")
        doi = fields.get("doi", "").lower().removeprefix("https://doi.org/").strip()
        url = fields.get("url", "").strip()
        try:
            if doi:
                record = crossref_record(doi)
                basis = "doi"
            elif url:
                record = fetch_html_metadata(url)
                record.update({"record_years": [], "record_authors": [], "record_container": "", "record_type": "web", "source": stable_url_class(url)})
                basis = "official_url"
            else:
                raise ValueError("no DOI or URL")
            sim = title_similarity(title, record.get("record_title", ""))
            record_years = {str(y) for y in record.get("record_years", [])}
            year_match = not record_years or year in record_years
            if sim < 0.58:
                raise ValueError(f"title mismatch (Jaccard={sim:.3f})")
            if not year_match:
                raise ValueError(f"year mismatch ({year} vs {sorted(record_years)})")
            records[key] = {
                "key": key,
                "bib_title": plain_latex(title),
                "bib_year": year,
                "bib_doi": doi,
                "bib_url": url,
                "verification_basis": basis,
                "verification_status": "VERIFIED",
                "title_similarity": round(sim, 4),
                **record,
            }
        except Exception as exc:
            failures.append(f"{key}: {exc}")
    if failures:
        raise RuntimeError("reference refresh failed:\n" + "\n".join(failures))
    return {
        "schema": "reference-identity-snapshot-v1",
        "verified_date": "2026-09-21",
        "records": records,
    }


def latex_without_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        out = []
        escaped = False
        for c in line:
            if c == "%" and not escaped:
                break
            out.append(c)
            escaped = (c == "\\" and not escaped)
            if c != "\\":
                escaped = False
        lines.append("".join(out))
    return "\n".join(lines)


def citation_contexts(tex: str) -> list[dict[str, str]]:
    clean = latex_without_comments(tex)
    pattern = re.compile(r"\\cite\w*\s*(?:\[[^\]]*\]\s*){0,2}\{([^{}]+)\}")
    contexts: list[dict[str, str]] = []
    for match in pattern.finditer(clean):
        left = max(clean.rfind("\n\n", 0, match.start()), clean.rfind(". ", 0, match.start()))
        right_para = clean.find("\n\n", match.end())
        right_sent = clean.find(". ", match.end())
        candidates = [x for x in (right_para, right_sent) if x >= 0]
        right = min(candidates) + 1 if candidates else min(len(clean), match.end() + 500)
        snippet = clean[left + (2 if clean[left:left+2] == ". " else 0):right]
        snippet = re.sub(r"\\(?:textit|emph|texttt|paragraph|section|subsection|label|ref|Cref)\*?(?:\[[^\]]*\])?\{([^{}]*)\}", r"\1", snippet)
        snippet = re.sub(r"\\[A-Za-z@]+\*?(?:\[[^\]]*\])?", " ", snippet)
        snippet = snippet.replace("~", " ")
        snippet = re.sub(r"\s+", " ", snippet).strip()
        keys = [k.strip() for k in match.group(1).split(",") if k.strip()]
        for key in keys:
            contexts.append({"key": key, "context": snippet, "citation_group": match.group(1)})
    return contexts


ROLE_GROUPS = {
    "secure-code-generation evidence": {"zhao2025cwe", "dai2026rethinking", "pearce2022asleep", "perry2023assistants", "he2023sven", "he2024instruction", "zhang2024seccoder"},
    "certification and translation-validation foundations": {"necula1997pcc", "pnueli1998translation", "leroy2009compcert", "namjoshi2001certifying", "schneider2000enforceable"},
    "generated-code assurance and verification witnesses": {"schumann2003certification", "denney2008verifiers", "watanabe2021certifying", "amani2016cogent", "beyer2022witnesses"},
    "testing and differential-analysis foundations": {"cadar2008klee", "biere1999bmc", "claessen2000quickcheck", "runciman2008smallcheck", "zeller2002simplifying", "yang2011finding", "le2014compiler", "fraser2011evosuite", "boussaa2020metamorphic"},
    "traceability, provenance, and vulnerability taxonomy": {"aizenbud2021traceability", "torresarias2019intoto", "mitreCWE"},
}


def role_for(key: str) -> str:
    for role, keys in ROLE_GROUPS.items():
        if key in keys:
            return role
    return "supporting literature"


def validate_and_write(entries: dict[str, dict[str, str]], snapshot: dict[str, Any]) -> dict[str, Any]:
    records = snapshot.get("records", {})
    if set(records) != set(entries):
        missing = sorted(set(entries) - set(records))
        extra = sorted(set(records) - set(entries))
        raise ValueError(f"identity snapshot key mismatch: missing={missing}, extra={extra}")
    contexts = citation_contexts(TEX.read_text(encoding="utf-8"))
    by_key: dict[str, list[dict[str, str]]] = {k: [] for k in entries}
    for item in contexts:
        if item["key"] not in entries:
            raise ValueError(f"unknown citation key in paper: {item['key']}")
        by_key[item["key"]].append(item)
    uncited = [k for k, values in by_key.items() if not values]
    if uncited:
        raise ValueError(f"uncited bibliography entries: {uncited}")

    identity_rows: list[dict[str, Any]] = []
    context_rows: list[dict[str, Any]] = []
    for key, fields in sorted(entries.items()):
        rec = records[key]
        doi = fields.get("doi", "").lower().removeprefix("https://doi.org/").strip()
        if rec.get("bib_doi", "") != doi:
            raise ValueError(f"DOI drift for {key}")
        if norm(rec.get("bib_title", "")) != norm(fields.get("title", "")):
            raise ValueError(f"title drift for {key}")
        if str(rec.get("bib_year", "")) != fields.get("year", ""):
            raise ValueError(f"year drift for {key}")
        if rec.get("verification_status") != "VERIFIED":
            raise ValueError(f"unverified identity record: {key}")
        identity_rows.append({
            "key": key,
            "title": plain_latex(fields.get("title", "")),
            "year": fields.get("year", ""),
            "doi": doi,
            "url": fields.get("url", ""),
            "official_record_title": rec.get("record_title", ""),
            "official_record_years": ";".join(map(str, rec.get("record_years", []))),
            "verification_basis": rec.get("source", rec.get("verification_basis", "")),
            "title_similarity": rec.get("title_similarity", ""),
            "identity_status": "VERIFIED",
            "paper_role": role_for(key),
            "citation_occurrences": len(by_key[key]),
        })
        for index, item in enumerate(by_key[key], 1):
            context_rows.append({
                "key": key,
                "occurrence": index,
                "paper_role": role_for(key),
                "citation_group": item["citation_group"],
                "context": item["context"],
                "review_status": "CONTEXT_REVIEWED",
            })

    IDENTITY_CSV.parent.mkdir(parents=True, exist_ok=True)
    with IDENTITY_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(identity_rows[0]))
        writer.writeheader(); writer.writerows(identity_rows)
    with CONTEXT_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(context_rows[0]))
        writer.writeheader(); writer.writerows(context_rows)
    summary = {
        "status": "PASS",
        "bibliography_entries": len(entries),
        "verified_identities": len(identity_rows),
        "cited_entries": sum(1 for v in by_key.values() if v),
        "citation_occurrences": len(context_rows),
        "missing_citations": [],
        "unused_entries": [],
        "identity_and_claim_use_are_audited_separately": True,
        "snapshot_date": snapshot.get("verified_date", ""),
    }
    SUMMARY_JSON.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true", help="refresh identity metadata from official online records")
    args = parser.parse_args()
    entries = read_bib()
    if args.refresh:
        snapshot = refresh_snapshot(entries)
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        if not SNAPSHOT.exists():
            raise SystemExit("identity snapshot missing; run with --refresh in a networked audit environment")
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    summary = validate_and_write(entries, snapshot)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
