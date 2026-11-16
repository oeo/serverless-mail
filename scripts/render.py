#!/usr/bin/env python3
"""Writes build/relay.yml: relay.yml with src/relay.py spliced into the function's ZipFile block."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLACEHOLDER = "# RELAY_SOURCE"
# CloudFormation's limit for a template body passed directly in a request.
MAX_TEMPLATE_BYTES = 51200


def render(template, source):
    lines = template.split("\n")
    matches = [index for index, line in enumerate(lines) if line.strip() == PLACEHOLDER]
    if len(matches) != 1:
        raise ValueError(f"expected one {PLACEHOLDER} line, found {len(matches)}")
    if "\t" in source:
        raise ValueError("source contains a tab")
    indent = lines[matches[0]][: len(lines[matches[0]]) - len(lines[matches[0]].lstrip())]
    body = [indent + line if line else "" for line in source.rstrip("\n").split("\n")]
    return "\n".join(lines[: matches[0]] + body + lines[matches[0] + 1:])


def main():
    rendered = render((ROOT / "relay.yml").read_text(), (ROOT / "src" / "relay.py").read_text())
    size = len(rendered.encode())
    if size > MAX_TEMPLATE_BYTES:
        sys.exit(f"rendered template is {size} bytes, over the {MAX_TEMPLATE_BYTES} byte limit")
    target = ROOT / "build" / "relay.yml"
    target.parent.mkdir(exist_ok=True)
    target.write_text(rendered)
    print(f"{target} ({size} bytes)")


if __name__ == "__main__":
    main()
