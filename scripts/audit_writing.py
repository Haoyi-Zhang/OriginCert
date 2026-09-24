#!/usr/bin/env python3
"""Static prose audit for the paper's review-facing writing."""
from __future__ import annotations
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEX = ROOT.parent / "paper" / "main.tex"
OUT = ROOT / "audit" / "writing-audit.json"

DROP_ENVS = ("table", "table*", "figure", "figure*", "equation", "equation*", "align", "align*", "tikzpicture", "verbatim", "lstlisting")
BANNED_HYPE = {
    "first-ever", "groundbreaking", "revolutionary", "unprecedented", "game-changing",
    "industrial-grade", "universally", "comprehensive solution", "guarantees security",
    "state-of-the-art performance", "best-in-class",
}
DEFENSIVE = (
    "we do not claim", "does not claim", "we make no claim", "not a claim",
    "cannot establish", "should not be read as", "must not be interpreted as",
)


def remove_comments(s: str) -> str:
    return re.sub(r"(?m)(?<!\\)%.*$", "", s)


def prose_text(s: str) -> str:
    s = remove_comments(s)
    # Analyze only content before the bibliography; reference titles are not paper prose.
    s = s.split("\\begin{thebibliography}", 1)[0]
    for env in DROP_ENVS:
        s = re.sub(rf"\\begin\{{{re.escape(env)}\}}.*?\\end\{{{re.escape(env)}\}}", " ", s, flags=re.S)
    s = re.sub(r"\$.*?\$", " ", s, flags=re.S)
    s = re.sub(r"\\\[.*?\\\]", " ", s, flags=re.S)
    s = re.sub(r"\\begin\{(?:definition|lemma|theorem|proof)\}.*?\\end\{(?:definition|lemma|theorem|proof)\}", " ", s, flags=re.S)
    # Preserve argument text of common prose commands, then remove remaining commands.
    for _ in range(4):
        s2 = re.sub(r"\\(?:emph|textbf|textit|texttt|paragraph|subparagraph|section|subsection|subsubsection|caption)\*?(?:\[[^\]]*\])?\{([^{}]*)\}", r" \1 ", s)
        if s2 == s:
            break
        s = s2
    s = re.sub(r"\\cite\w*(?:\[[^\]]*\]){0,2}\{[^{}]*\}", " [citation] ", s)
    s = re.sub(r"\\(?:Cref|cref|ref|eqref|autoref)\{[^{}]*\}", " [reference] ", s)
    s = re.sub(r"\\[A-Za-z@]+\*?(?:\[[^\]]*\])?", " ", s)
    s = s.replace("~", " ").replace("{", " ").replace("}", " ")
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def sentence_records(text: str) -> list[dict[str, object]]:
    chunks = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9`\\])", text)
    records = []
    for sentence in chunks:
        words = re.findall(r"\b[\w'-]+\b", sentence)
        if len(words) >= 8:
            records.append({"words": len(words), "text": sentence[:800]})
    return records


def main() -> int:
    raw = TEX.read_text(encoding="utf-8")
    prose = prose_text(raw)
    sentences = sentence_records(prose)
    longest = sorted(sentences, key=lambda x: int(x["words"]), reverse=True)[:12]
    lower = prose.lower()
    hype = sorted(term for term in BANNED_HYPE if term in lower)
    defensive_counts = {term: lower.count(term) for term in DEFENSIVE if lower.count(term)}
    repeated_openers = Counter()
    for rec in sentences:
        words = re.findall(r"\b[\w'-]+\b", str(rec["text"]).lower())
        if len(words) >= 4:
            repeated_openers[" ".join(words[:4])] += 1
    repeated = {k: v for k, v in repeated_openers.items() if v >= 4}
    issues = []
    if longest and int(longest[0]["words"]) > 105:
        issues.append({"code": "very-long-sentence", "message": f"max {longest[0]['words']} words"})
    if hype:
        issues.append({"code": "unsupported-hype", "terms": hype})
    if sum(defensive_counts.values()) > 5:
        issues.append({"code": "defensive-density", "counts": defensive_counts})
    if any(v >= 6 for v in repeated.values()):
        issues.append({"code": "repetitive-openers", "openers": repeated})
    report = {
        "status": "PASS" if not issues else "FAIL",
        "sentence_count": len(sentences),
        "max_sentence_words": max((int(x["words"]) for x in sentences), default=0),
        "sentences_over_70_words": sum(int(x["words"]) > 70 for x in sentences),
        "longest_sentences": longest,
        "hype_terms": hype,
        "defensive_phrase_counts": defensive_counts,
        "repeated_openers": repeated,
        "issues": issues,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("status", "max_sentence_words", "sentences_over_70_words")}, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
