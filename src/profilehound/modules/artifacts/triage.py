from __future__ import annotations

import re

from impacket.smb3structs import FILE_SHARE_DELETE
from impacket.smb import FILE_SHARE_READ, FILE_SHARE_WRITE

from .models import ArtifactFinding


HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
USERNAME_RE = re.compile(r"(?im)\b(?:user|username|login|account)\s*[:=]\s*([A-Za-z0-9._@\\-]{2,80})")
AWS_PROFILE_RE = re.compile(r"(?im)^\s*\[profile\s+([A-Za-z0-9_.@-]{1,80})\]\s*$")
AWS_REGION_RE = re.compile(r"(?im)^\s*region\s*=\s*([A-Za-z0-9-]{1,40})\s*$")

SECRET_PATTERNS = {
    "AWS access key pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Generic password assignment": re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]"),
    "Token assignment": re.compile(r"(?i)\b(token|secret|apikey|api_key)\s*[:=]"),
    "Private key header": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}

INTERESTING_KEYWORDS = re.compile(
    r"(?i)\b(admin|backup|jump|vpn|rdp|ssh|domain admin|prod|production|tenant|subscription|cluster)\b"
)


def _read_text_file(smb, share: str, path: str) -> str:
    chunks: list[bytes] = []

    def capture(data: bytes) -> None:
        chunks.append(data)

    getter = getattr(smb, "getFileEx", None) or smb.getFile
    try:
        getter(
            share,
            path,
            capture,
            shareAccessMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )
    except TypeError:
        getter(share, path, capture)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def _bounded_unique(values, limit: int = 10) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = str(value).strip()
        lowered = clean.lower()
        if not clean or lowered in seen:
            continue
        seen.add(lowered)
        result.append(clean)
        if len(result) >= limit:
            break
    return result


def triage_finding(
    *,
    smb,
    share: str,
    finding: ArtifactFinding,
    max_files: int,
    max_bytes: int,
) -> None:
    if not finding.triageable:
        finding.triaged = False
        finding.triagestatus = "not_supported"
        return

    summary = {
        "triagedfilecount": 0,
        "triageerrorcount": 0,
        "secretpatterncount": 0,
        "hostnamecount": 0,
        "usernamecount": 0,
        "ipaddresscount": 0,
        "cloudindicatorcount": 0,
        "privatekeyheadercount": 0,
        "interestingkeywordcount": 0,
        "topindicators": [],
    }
    hostnames: list[str] = []
    usernames: list[str] = []
    ip_addresses: list[str] = []
    top_indicators: list[str] = []

    for match in finding.matches[: max(max_files, 0)]:
        if match.targettype != "file":
            continue
        if match.size is not None and match.size > max_bytes:
            summary["triageerrorcount"] += 1
            finding.errors.append(
                {
                    "operation": "triage",
                    "sourcepath": match.sourcepath,
                    "error": "file exceeds triage max bytes",
                }
            )
            continue
        try:
            text = _read_text_file(smb, share, match.smbpath)
        except Exception as error:
            summary["triageerrorcount"] += 1
            finding.errors.append(
                {
                    "operation": "triage",
                    "sourcepath": match.sourcepath,
                    "error": str(error),
                }
            )
            continue

        summary["triagedfilecount"] += 1
        hostnames.extend(HOST_RE.findall(text))
        ip_addresses.extend(IP_RE.findall(text))
        usernames.extend(match.group(1) for match in USERNAME_RE.finditer(text))
        summary["interestingkeywordcount"] += len(INTERESTING_KEYWORDS.findall(text))

        for label, regex in SECRET_PATTERNS.items():
            count = len(regex.findall(text))
            if count:
                summary["secretpatterncount"] += count
                top_indicators.append(label)
                if label == "Private key header":
                    summary["privatekeyheadercount"] += count

        aws_profiles = _bounded_unique(AWS_PROFILE_RE.findall(text), limit=3)
        aws_regions = _bounded_unique(AWS_REGION_RE.findall(text), limit=3)
        if aws_profiles or aws_regions:
            summary["cloudindicatorcount"] += len(aws_profiles) + len(aws_regions)
            top_indicators.extend(f"AWS profile: {profile}" for profile in aws_profiles)
            top_indicators.extend(f"AWS region: {region}" for region in aws_regions)

    unique_hosts = _bounded_unique(hostnames, limit=10)
    unique_users = _bounded_unique(usernames, limit=10)
    unique_ips = _bounded_unique(ip_addresses, limit=10)
    summary["hostnamecount"] = len({host.lower() for host in hostnames})
    summary["usernamecount"] = len({user.lower() for user in usernames})
    summary["ipaddresscount"] = len(set(ip_addresses))
    summary["topindicators"] = _bounded_unique(
        top_indicators + unique_hosts + unique_ips + unique_users,
        limit=10,
    )

    finding.triaged = summary["triagedfilecount"] > 0
    if summary["triagedfilecount"] > 0 and summary["triageerrorcount"] > 0:
        finding.triagestatus = "partial"
    elif summary["triagedfilecount"] > 0:
        finding.triagestatus = "parsed"
    elif summary["triageerrorcount"] > 0:
        finding.triagestatus = "error"
    else:
        finding.triagestatus = "no_files"
    finding.triage = summary
