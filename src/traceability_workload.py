"""Owned batch-handler template workload; restricted source is never executed.

This generator writes source directly, without producer/checker interpreters or
the existing event-to-source codecs. The JSON tree is its explicit template.
"""
from __future__ import annotations

import copy
import itertools
import json


def identity(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def owned_case(layout="inside"):
    if layout not in {"inside", "outside"}:
        raise ValueError("unknown owned layout")

    def emit(node, op, declarations=(), **arguments):
        return {"kind": "emit", "node": node, "event": {"op": op, **arguments},
                "declared_obligations": list(declarations)}

    def seq(node, *children):
        return {"kind": "seq", "node": node, "children": list(children)}

    def branch(node, field, value, yes, no):
        return {"kind": "if", "node": node,
                "condition": {"field": field, "equals": value}, "then": yes, "else": no}

    def sites(channel):
        # Distinct real sites emit identical ordinary sink calls.
        return branch(channel + ".site", "site", "primary",
                      emit(channel + ".primary", "sink", [channel + ".protected"],
                           channel=channel, source="clean"),
                      emit(channel + ".fallback", "sink", [channel + ".protected"],
                           channel=channel, source="clean"))

    def handler(channel):
        return seq(channel + ".handler",
                   emit(channel + ".input", "source", target="raw", input="request"),
                   emit(channel + ".protect", "protect", source="raw", target="clean",
                        protection=channel + "-encode"), sites(channel),
                   branch(channel + ".admin", "admin", True,
                          seq(channel + ".authorized",
                              emit(channel + ".check", "check", capability="publish"),
                              emit(channel + ".publish", "privileged", ["publish.checked"],
                                   capability="publish")), seq(channel + ".empty")))

    def repeated(prefix, body):
        return {"kind": "repeat", "node": prefix + ".batch", "count_field": "batches",
                "body": {"kind": "repeat", "node": prefix + ".item", "count_field": "items",
                         "body": body}}

    if layout == "inside":
        tree = repeated("all", branch("channel", "channel", "sql", handler("sql"), handler("html")))
    else:
        tree = branch("channel", "channel", "sql",
                      repeated("sql", handler("sql")), repeated("html", handler("html")))
    return {"case_id": "owned-batch-" + layout, "family": "owned-traceability",
            "corpus_source": "authored bounded batch-handler templates; not an upstream product",
            "schema": {"fields": [
                {"name": "channel", "domain": ["sql", "html"]},
                {"name": "site", "domain": ["primary", "fallback"]},
                {"name": "admin", "domain": [False, True]},
                {"name": "batches", "domain": [0, 1, 2]},
                {"name": "items", "domain": [0, 1, 2]},
                {"name": "edition", "domain": ["compact", "spaced"]}]},
            "catalog": {"obligations": [
                {"id": channel + ".protected", "trigger": {"op": "sink", "channel": channel},
                 "rule": {"kind": "protection", "requires": [channel + "-encode"]}}
                for channel in ("sql", "html")] + [
                {"id": "publish.checked", "trigger": {"op": "privileged", "capability": "publish"},
                 "rule": {"kind": "preceded"}}]}, "generator": tree}


def assignments(case):
    fields = case["schema"]["fields"]
    return [dict(zip((f["name"] for f in fields), values, strict=True))
            for values in itertools.product(*(f["domain"] for f in fields))]


def generate_source(case, assignment):
    lines = []

    def write(node, occurrence=()):
        kind = node["kind"]
        if kind == "seq":
            for child in node["children"]:
                write(child, occurrence)
        elif kind == "if":
            condition = node["condition"]
            side = "then" if identity(assignment[condition["field"]]) == identity(condition["equals"]) else "else"
            write(node[side], occurrence)
        elif kind == "repeat":
            for index in range(assignment[node["count_field"]]):
                write(node["body"], occurrence + (index,))
        elif kind == "emit":
            evidence = {"origin": node.get("origin_override", node["node"]),
                        "obligations": list(node.get("declared_obligations", []))}
            if occurrence:
                evidence["occurrence"] = list(occurrence)
            lines.append("# cg-evidence " + identity(evidence))
            arguments = ", ".join(f"{key}={value!r}" for key, value in sorted(node["event"].items()) if key != "op")
            lines.append("cg_" + node["event"]["op"] + "(" + arguments + ")")
            if assignment["edition"] == "spaced":
                lines.append("")
        else:
            raise ValueError("outside owned grammar")

    write(case["generator"])
    return "\n".join(lines) + ("\n" if lines else "")


def generate_bundle(case):
    return [{"input": assignment, "source": generate_source(case, assignment)}
            for assignment in assignments(case)]


def nodes(case):
    pending = [case["generator"]]
    output = {}
    while pending:
        node = pending.pop()
        output[node["node"]] = node
        if node["kind"] == "seq":
            pending.extend(node["children"])
        elif node["kind"] == "if":
            pending.extend([node["then"], node["else"]])
        elif node["kind"] == "repeat":
            pending.append(node["body"])
    return output


def faulty_case(case, fault):
    result = copy.deepcopy(case)
    ns = nodes(result)
    target = ns["sql.primary"]
    if fault == "origin":
        target["origin_override"] = "sql.fallback"
    elif fault == "omission":
        target["declared_obligations"] = []
    elif fault == "extra":
        target["declared_obligations"].append("html.protected")
    elif fault == "safety":
        ns["sql.protect"]["event"]["protection"] = "html-encode"
    else:
        raise ValueError("unknown fault")
    result["case_id"] += "-" + fault
    return result


def source_mutants(bundle):
    """Deterministic benign faults in one owned file or its input manifest."""
    row_index = next(i for i, row in enumerate(bundle) if row["input"] == {
        "channel": "sql", "site": "primary", "admin": True,
        "batches": 2, "items": 2, "edition": "compact"})
    lines = bundle[row_index]["source"].splitlines()
    comment_index = next(i for i, line in enumerate(lines) if line.startswith("# cg-evidence ")
                         and json.loads(line[len("# cg-evidence "):])["origin"] == "sql.primary")
    output = []
    for fault in ("wrong_existing_origin", "omitted_obligation", "extra_obligation",
                  "wrong_occurrence", "missing_statement", "duplicate_statement",
                  "ordinary_payload", "missing_input", "duplicate_input"):
        rows = copy.deepcopy(bundle)
        changed = list(lines)
        if fault == "missing_input":
            del rows[row_index]
        elif fault == "duplicate_input":
            rows[row_index] = copy.deepcopy(rows[0])
        elif fault == "missing_statement":
            del changed[comment_index:comment_index + 2]
        elif fault == "duplicate_statement":
            changed[comment_index:comment_index] = changed[comment_index:comment_index + 2]
        elif fault == "ordinary_payload":
            changed[comment_index + 1] = changed[comment_index + 1].replace("source='clean'", "source='raw'")
        else:
            evidence = json.loads(changed[comment_index][len("# cg-evidence "):])
            if fault == "wrong_existing_origin":
                evidence["origin"] = "sql.fallback"
            elif fault == "omitted_obligation":
                evidence["obligations"] = []
            elif fault == "extra_obligation":
                evidence["obligations"].append("html.protected")
            else:
                evidence["occurrence"] = [1, 0]
            changed[comment_index] = "# cg-evidence " + identity(evidence)
        if fault not in {"missing_input", "duplicate_input"}:
            rows[row_index]["source"] = "\n".join(changed) + "\n"
        output.append((fault, rows))
    return output


def restrict_edition(case, certificate, bundle):
    """Intersect/rebind existing evidence; do not invoke evidence construction."""
    restricted = copy.deepcopy(case)
    restricted["schema"]["fields"][-1]["domain"] = ["compact"]
    reused = copy.deepcopy(certificate)
    reused["subject"]["schema"] = copy.deepcopy(restricted["schema"])
    kept = []
    for cell in reused["cells"]:
        if "compact" in cell["cube"]["edition"]:
            cell["cube"]["edition"] = ["compact"]
            kept.append(cell)
    reused["cells"] = kept
    rows = [copy.deepcopy(row) for row in bundle if row["input"]["edition"] == "compact"]
    return restricted, reused, rows
