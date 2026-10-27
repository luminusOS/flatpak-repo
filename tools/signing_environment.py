import argparse
import hashlib
import hmac
import json
import os
import re


REPOSITORY = "luminusOS/flatpak-repo"
ROLES = ("issuer", "publisher")
CHANNELS = ("stable", "testing")


def validate_context(environment, role, channel):
    if role not in ROLES or channel not in CHANNELS:
        raise ValueError("role or channel is outside this repository policy")
    expected = {
        "GATE_GITHUB_REPOSITORY": REPOSITORY,
        "GATE_GITHUB_REF": "refs/heads/main",
        "GATE_GITHUB_REF_PROTECTED": "true",
        "GATE_GITHUB_EVENT_NAME": "workflow_dispatch",
        "GATE_ENVIRONMENT": f"{role}-{channel}",
    }
    if any(environment.get(key) != value for key, value in expected.items()):
        raise ValueError("workflow context is not authorized for this environment")
    return True


def validate_canary(environment):
    canary = environment.get("GATE_CANARY", "")
    expected = environment.get("GATE_CANARY_SHA256", "")
    if not canary or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("disposable canary is unavailable or malformed")
    actual = hashlib.sha256(canary.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("disposable canary does not match its environment")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("context", "check"))
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--channel", choices=CHANNELS, required=True)
    arguments = parser.parse_args()
    try:
        validate_context(os.environ, arguments.role, arguments.channel)
        if arguments.action == "check":
            validate_canary(os.environ)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"status": "authorized_context" if arguments.action == "context"
                      else "disposable_canary_verified"}))


if __name__ == "__main__":
    main()
