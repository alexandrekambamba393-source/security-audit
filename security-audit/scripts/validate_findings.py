#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from verify_evidence import check_location, fingerprint, primary_location  # noqa: E402

SCHEMA_PATH = HERE.parent / "assets" / "findings.schema.json"


def _type_ok(value, name):
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    return True


def minimal_validate(instance, schema, root, path="$"):
    if "$ref" in schema:
        node = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            node = node[part]
        return minimal_validate(instance, node, root, path)

    errors = []
    declared = schema.get("type")
    if declared is not None:
        names = declared if isinstance(declared, list) else [declared]
        if not any(_type_ok(instance, n) for n in names):
            return [f"{path}: expected {names}, got {type(instance).__name__}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not an allowed value")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match pattern {schema['pattern']}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required key '{key}'")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props:
                    errors.append(f"{path}: unexpected key '{key}'")
        for key, sub in props.items():
            if key in instance:
                errors += minimal_validate(instance[key], sub, root, f"{path}.{key}")
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "items" in schema:
            for i, element in enumerate(instance):
                errors += minimal_validate(element, schema["items"], root, f"{path}[{i}]")
    return errors


def schema_errors(instance, schema):
    try:
        import jsonschema
    except ImportError:
        print("note: jsonschema not installed; using built-in checker (fewer format checks)")
        return minimal_validate(instance, schema, schema)
    validator = jsonschema.Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in err.path) or '$'}: {err.message}"
        for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="Root of the audited codebase")
    ap.add_argument("--findings", required=True, help="Path to findings.json")
    args = ap.parse_args()

    target = pathlib.Path(args.target).resolve()
    data = json.loads(pathlib.Path(args.findings).read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    problems = [f"schema: {e}" for e in schema_errors(data, schema)]

    seen_ids = set()
    cache = {}
    for finding in data.get("findings", []):
        fid = finding.get("id", "?")
        if fid in seen_ids:
            problems.append(f"{fid}: duplicate id")
        seen_ids.add(fid)

        locations = finding.get("locations") or []
        for loc in locations:
            loc_problems, _ = check_location(target, loc, cache)
            problems.extend(f"{fid}: evidence: {loc.get('file')}: {p}" for p in loc_problems)

        primary = primary_location(locations)
        if primary and primary.get("file") and isinstance(primary.get("snippet"), str):
            expected = fingerprint(finding.get("category", ""), primary["file"], primary["snippet"])
            if finding.get("fingerprint") != expected:
                problems.append(f"{fid}: fingerprint does not match its primary location")

    if problems:
        print(f"INVALID: {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    print(f"OK: {len(data.get('findings', []))} finding(s) valid, all evidence re-checked.")


if __name__ == "__main__":
    main()
