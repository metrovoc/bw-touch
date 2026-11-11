#!/usr/bin/env python3
"""Read-only, low-disclosure access to Bitwarden through bw-touch."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import urlsplit


ITEM_TYPES = {
    1: "login",
    2: "secure-note",
    3: "card",
    4: "identity",
    5: "ssh-key",
}
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SANITIZED_ENV_KEYS = ("BW_SESSION", "BW_NOINTERACTION", "BW_TOUCH_MASTER")
LINKED_SELECTORS = {
    100: "login.username",
    101: "login.password",
    300: "card.cardholderName",
    301: "card.expMonth",
    302: "card.expYear",
    303: "card.code",
    304: "card.brand",
    305: "card.number",
    400: "identity.title",
    401: "identity.middleName",
    402: "identity.address1",
    403: "identity.address2",
    404: "identity.address3",
    405: "identity.city",
    406: "identity.state",
    407: "identity.postalCode",
    408: "identity.country",
    409: "identity.company",
    410: "identity.email",
    411: "identity.phone",
    412: "identity.ssn",
    413: "identity.username",
    414: "identity.passportNumber",
    415: "identity.licenseNumber",
    416: "identity.firstName",
    417: "identity.lastName",
}
FULL_NAME_LINKED_ID = 418


class VaultError(RuntimeError):
    pass


def clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in SANITIZED_ENV_KEYS:
        environment.pop(key, None)
    return environment


def resolve_bw_touch(override: str | None) -> str:
    candidates: list[str] = []
    if override:
        candidates.append(override)
    else:
        discovered = shutil.which("bw-touch")
        if discovered:
            candidates.append(discovered)
        candidates.append(str(Path.home() / ".local" / "bin" / "bw-touch"))

    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
    raise VaultError("bw-touch is not installed or executable")


def run_bw(binary: str, arguments: list[str]) -> bytes:
    try:
        result = subprocess.run(
            [binary, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_environment(),
            check=False,
        )
    except OSError as error:
        raise VaultError(f"unable to execute bw-touch: {error}") from error

    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()
        if not diagnostic:
            diagnostic = f"bw-touch exited with status {result.returncode}"
        raise VaultError(diagnostic)
    return result.stdout


def parse_json(payload: bytes, expected: type, operation: str) -> Any:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VaultError(f"Bitwarden returned invalid JSON for {operation}") from error
    if not isinstance(value, expected):
        raise VaultError(f"Bitwarden returned an unexpected result for {operation}")
    return value


def require_item_id(item_id: str) -> str:
    if not UUID_RE.fullmatch(item_id):
        raise VaultError("use an exact item ID returned by search")
    return item_id


def get_item(binary: str, item_id: str) -> dict[str, Any]:
    item_id = require_item_id(item_id)
    item = parse_json(run_bw(binary, ["get", "item", item_id]), dict, "get item")
    returned_id = item.get("id")
    if not isinstance(returned_id, str) or returned_id.casefold() != item_id.casefold():
        raise VaultError("Bitwarden did not return the requested exact item")
    return item


def item_type(item: dict[str, Any]) -> str:
    raw_type = item.get("type")
    return ITEM_TYPES.get(raw_type, f"unknown-{raw_type}")


def uri_origin(raw_uri: Any) -> str | None:
    if not isinstance(raw_uri, str) or not raw_uri:
        return None
    parts = urlsplit(raw_uri)
    if parts.scheme and parts.hostname:
        host = parts.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = f":{parts.port}" if parts.port is not None else ""
        except ValueError:
            port = ""
        return f"{parts.scheme}://{host}{port}"
    if parts.scheme:
        return f"{parts.scheme}:"
    return None


def summarize_item(item: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "id": item.get("id"),
        "name": item.get("name"),
        "type": item_type(item),
    }

    login = item.get("login")
    if isinstance(login, dict):
        username = login.get("username")
        if isinstance(username, str) and username:
            summary["username"] = username
        origins: list[str] = []
        for entry in login.get("uris") or []:
            if isinstance(entry, dict):
                origin = uri_origin(entry.get("uri"))
                if origin and origin not in origins:
                    origins.append(origin)
        if origins:
            summary["uri_origins"] = origins

    field_names = [
        field.get("name")
        for field in item.get("fields") or []
        if isinstance(field, dict) and isinstance(field.get("name"), str) and field.get("name")
    ]
    if field_names:
        summary["custom_fields"] = field_names
    if isinstance(item.get("notes"), str) and item["notes"]:
        summary["has_notes"] = True
    return summary


def search_items(binary: str, query: str | None, url: str | None) -> list[dict[str, Any]]:
    arguments = ["list", "items"]
    if query is not None:
        if not query.strip():
            raise VaultError("search query cannot be empty")
        arguments.extend(["--search", query])
    elif url is not None:
        if not url.strip():
            raise VaultError("URL cannot be empty")
        parts = urlsplit(url)
        if parts.username or parts.password or parts.query or parts.fragment:
            raise VaultError("use a URL without credentials, query, or fragment")
        arguments.extend(["--url", url])
    else:
        raise VaultError("provide a search query or --url")

    run_bw(binary, ["sync"])
    items = parse_json(run_bw(binary, arguments), list, "search")
    return [summarize_item(item) for item in items if isinstance(item, dict)]


def is_set(value: Any) -> bool:
    return value is not None and (not isinstance(value, str) or value != "")


def scalar_selectors(value: Any, path: str) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        selectors: list[dict[str, Any]] = []
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            selectors.extend(scalar_selectors(child, child_path))
        return selectors
    if isinstance(value, list):
        selectors = []
        for index, child in enumerate(value):
            selectors.extend(scalar_selectors(child, f"{path}[{index}]"))
        return selectors
    return [{"selector": path, "set": is_set(value)}]


def resolve_linked_value(item: dict[str, Any], linked_id: Any) -> tuple[Any, str]:
    if linked_id == FULL_NAME_LINKED_ID:
        identity = item.get("identity")
        if not isinstance(identity, dict):
            raise VaultError("linked identity value is not present")
        value = " ".join(
            part
            for part in (
                identity.get("firstName"),
                identity.get("middleName"),
                identity.get("lastName"),
            )
            if isinstance(part, str) and part
        )
        return value, "identity full name"
    selector = LINKED_SELECTORS.get(linked_id)
    if selector is None:
        raise VaultError(f"unsupported linked field ID: {linked_id}")
    return resolve_path(item, selector), selector


def inspect_item(item: dict[str, Any]) -> dict[str, Any]:
    selectors: list[dict[str, Any]] = []
    for root in ("name", "notes", "login", "secureNote", "card", "identity", "sshKey"):
        if root in item:
            selectors.extend(scalar_selectors(item[root], root))

    fields = item.get("fields") or []
    names: dict[str, int] = {}
    for field in fields:
        if isinstance(field, dict) and isinstance(field.get("name"), str):
            names[field["name"]] = names.get(field["name"], 0) + 1
    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            continue
        name = field.get("name")
        selector = (
            f"field:{name}"
            if isinstance(name, str) and name and names.get(name) == 1
            else f"fields[{index}].value"
        )
        field_value = field.get("value")
        descriptor: dict[str, Any] = {
            "selector": selector,
            "set": is_set(field_value),
            "field_type": field.get("type"),
        }
        if field.get("linkedId") is not None:
            descriptor["linked_id"] = field.get("linkedId")
            try:
                linked_value, linked_selector = resolve_linked_value(item, field.get("linkedId"))
                descriptor["set"] = is_set(linked_value)
                descriptor["linked_selector"] = linked_selector
            except VaultError:
                pass
        selectors.append(descriptor)

    if isinstance(item.get("login"), dict) and is_set(item["login"].get("totp")):
        selectors.append({"selector": "totp", "set": True, "kind": "current-code"})

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for descriptor in selectors:
        selector = descriptor["selector"]
        if selector and selector not in seen:
            seen.add(selector)
            unique.append(descriptor)
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "type": item_type(item),
        "selectors": unique,
    }


def path_tokens(selector: str) -> list[str | int]:
    if not selector:
        raise VaultError("selector cannot be empty")
    tokens: list[str | int] = []
    position = 0
    expect_component = True
    while position < len(selector):
        character = selector[position]
        if character == ".":
            if expect_component:
                raise VaultError(f"invalid selector: {selector}")
            expect_component = True
            position += 1
            continue
        if character == "[":
            end = selector.find("]", position + 1)
            if end == -1 or not selector[position + 1 : end].isdigit():
                raise VaultError(f"invalid selector: {selector}")
            tokens.append(int(selector[position + 1 : end]))
            position = end + 1
            expect_component = False
            continue
        end = position
        while end < len(selector) and selector[end] not in ".[":
            end += 1
        component = selector[position:end]
        if not component or not expect_component:
            raise VaultError(f"invalid selector: {selector}")
        tokens.append(component)
        position = end
        expect_component = False
    if expect_component:
        raise VaultError(f"invalid selector: {selector}")
    return tokens


def resolve_path(item: dict[str, Any], selector: str) -> Any:
    current: Any = item
    for token in path_tokens(selector):
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise VaultError(f"selector is not present: {selector}")
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise VaultError(f"selector is not present: {selector}")
            current = current[token]
    return current


def resolve_value(binary: str, item_id: str, selector: str) -> str:
    if selector == "totp":
        payload = run_bw(binary, ["get", "totp", require_item_id(item_id)])
        return payload.decode("utf-8").rstrip("\r\n")

    item = get_item(binary, item_id)
    if selector.startswith("field:"):
        name = selector[len("field:") :]
        matches = [
            field
            for field in item.get("fields") or []
            if isinstance(field, dict) and field.get("name") == name
        ]
        if not matches:
            raise VaultError(f"custom field is not present: {name}")
        if len(matches) != 1:
            raise VaultError(f"custom field name is ambiguous: {name}")
        field = matches[0]
        value: Any = field.get("value")
        if field.get("linkedId") is not None:
            value, _ = resolve_linked_value(item, field.get("linkedId"))
    else:
        value = resolve_path(item, selector)

    if value is None:
        raise VaultError(f"selector is empty: {selector}")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    raise VaultError(f"selector does not identify a scalar value: {selector}")


def write_json(value: Any) -> None:
    json.dump(value, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def normalize_command(arguments: list[str]) -> list[str]:
    command = arguments[1:] if arguments and arguments[0] == "--" else arguments
    if not command:
        raise VaultError("provide a child command after --")
    return command


def run_child(value: str, env_name: str | None, use_stdin: bool, arguments: list[str]) -> int:
    command = normalize_command(arguments)
    environment = clean_environment()
    standard_input: bytes | None = None
    if env_name is not None:
        if not ENV_NAME_RE.fullmatch(env_name):
            raise VaultError(f"invalid environment variable name: {env_name}")
        if "\x00" in value:
            raise VaultError("environment variables cannot contain NUL bytes")
        environment[env_name] = value
    elif use_stdin:
        standard_input = value.encode("utf-8") + b"\n"
    else:
        raise VaultError("choose --env NAME or --stdin")

    try:
        result = subprocess.run(
            command,
            input=standard_input,
            env=environment,
            check=False,
        )
    except OSError as error:
        raise VaultError(f"unable to execute child command: {error}") from error
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only, low-disclosure Bitwarden access through bw-touch."
    )
    parser.add_argument(
        "--bw-touch",
        metavar="PATH",
        help=argparse.SUPPRESS,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    search = commands.add_parser("search", help="find items and print metadata only")
    source = search.add_mutually_exclusive_group(required=True)
    source.add_argument("query", nargs="?", help="name, service, or account search")
    source.add_argument("--url", help="login URL match")

    inspect = commands.add_parser("inspect", help="list selectors without values")
    inspect.add_argument("item_id")

    read = commands.add_parser("read", help="print one explicitly requested value")
    read.add_argument("item_id")
    read.add_argument("selector")
    read.add_argument(
        "--reveal",
        action="store_true",
        help="confirm that writing the selected value to stdout is intended",
    )

    run = commands.add_parser("run", help="inject one value into one child process")
    run.add_argument("item_id")
    run.add_argument("selector")
    delivery = run.add_mutually_exclusive_group(required=True)
    delivery.add_argument("--env", metavar="NAME", help="set NAME only for the child")
    delivery.add_argument("--stdin", action="store_true", help="send value plus newline to stdin")
    run.add_argument("child", nargs=argparse.REMAINDER)

    commands.add_parser("sync", help="pull the latest vault data")
    commands.add_parser("lock", help="lock the vault and stop the bw-touch agent")
    return parser


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()
    try:
        binary = resolve_bw_touch(arguments.bw_touch)
        if arguments.command == "search":
            write_json(search_items(binary, arguments.query, arguments.url))
            return 0
        if arguments.command == "inspect":
            write_json(inspect_item(get_item(binary, arguments.item_id)))
            return 0
        if arguments.command == "read":
            if not arguments.reveal:
                raise VaultError("read requires --reveal because it writes a vault value to stdout")
            value = resolve_value(binary, arguments.item_id, arguments.selector)
            sys.stdout.write(value)
            if not value.endswith("\n"):
                sys.stdout.write("\n")
            return 0
        if arguments.command == "run":
            value = resolve_value(binary, arguments.item_id, arguments.selector)
            return run_child(value, arguments.env, arguments.stdin, arguments.child)
        if arguments.command == "sync":
            sys.stdout.buffer.write(run_bw(binary, ["sync"]))
            return 0
        if arguments.command == "lock":
            sys.stdout.buffer.write(run_bw(binary, ["lock"]))
            return 0
        parser.error("unknown command")
    except VaultError as error:
        print(f"bw-vault: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
