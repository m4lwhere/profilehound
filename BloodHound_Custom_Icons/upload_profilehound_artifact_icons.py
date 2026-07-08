#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from pathlib import Path
from urllib import error, request


DEFAULT_BLOODHOUND_URL = "http://127.0.0.1:8080"
DEFAULT_PAYLOAD_PATH = Path(__file__).with_name("ProfileHound_Artifact_Icons.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Upload ProfileHound custom artifact icons to BloodHound."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("BLOODHOUND_URL", DEFAULT_BLOODHOUND_URL),
        help=(
            "BloodHound base URL or full custom-nodes endpoint. "
            f"Default: {DEFAULT_BLOODHOUND_URL}"
        ),
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("BLOODHOUND_TOKEN"),
        help="BloodHound bearer token. Defaults to BLOODHOUND_TOKEN.",
    )
    parser.add_argument(
        "--payload",
        default=str(DEFAULT_PAYLOAD_PATH),
        help=f"Icon definition payload path. Default: {DEFAULT_PAYLOAD_PATH}",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate validation for local/self-signed HTTPS.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout in seconds. Default: 30.",
    )
    return parser


def custom_nodes_endpoint(url: str) -> str:
    clean_url = url.rstrip("/")
    if clean_url.endswith("/api/v2/custom-nodes"):
        return clean_url
    return f"{clean_url}/api/v2/custom-nodes"


def load_payload(path: str) -> dict:
    payload_path = Path(path)
    try:
        with payload_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except OSError as exc:
        raise SystemExit(f"Failed to read payload {payload_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Payload {payload_path} is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("custom_types"), dict):
        raise SystemExit("Payload must be an object with a custom_types object")
    return payload


def upload_payload(
    *,
    url: str,
    token: str,
    payload: dict,
    insecure: bool,
    timeout: float,
) -> tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        custom_nodes_endpoint(url),
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    context = None
    if insecure and req.full_url.lower().startswith("https://"):
        context = ssl._create_unverified_context()

    try:
        with request.urlopen(req, timeout=timeout, context=context) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            return response.status, response_body
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(
            f"BloodHound returned HTTP {exc.code}: {response_body or exc.reason}"
        ) from exc
    except error.URLError as exc:
        raise SystemExit(f"Failed to connect to BloodHound: {exc.reason}") from exc


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.token:
        raise SystemExit("A bearer token is required. Use --token or BLOODHOUND_TOKEN.")

    payload = load_payload(args.payload)
    status, response_body = upload_payload(
        url=args.url,
        token=args.token,
        payload=payload,
        insecure=args.insecure,
        timeout=args.timeout,
    )
    print(f"Uploaded {len(payload['custom_types'])} ProfileHound icon definitions.")
    print(f"Status Code: {status}")
    if response_body:
        print("Response Body:")
        print(response_body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
