import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator


MAX_CATALOG_BYTES = 1024 * 1024
CATALOG_SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "catalog.schema.json").read_text(encoding="utf-8"))
_VALIDATOR = Draft202012Validator(CATALOG_SCHEMA)


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_non_finite(value):
    raise ValueError("non-finite JSON number")


def validate_catalog(document):
    if next(_VALIDATOR.iter_errors(document), None) is not None:
        raise ValueError("catalog does not match its schema")
    identifiers = [application["id"] for application in document["applications"]]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("catalog contains duplicate application IDs")
    return document


def load_catalog(path):
    with open(path, "rb") as catalog_file:
        content = catalog_file.read(MAX_CATALOG_BYTES + 1)
    if len(content) > MAX_CATALOG_BYTES:
        raise ValueError("catalog exceeds the size limit")
    document = json.loads(
        content.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )
    return validate_catalog(document)


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Validate a local repository catalog")
    parser.add_argument("catalog_path")
    args = parser.parse_args(argv)
    try:
        load_catalog(args.catalog_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        print("catalog validation failed", file=sys.stderr)
        return 1
    print("catalog valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
