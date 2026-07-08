from __future__ import annotations

import fnmatch
import logging
import time

from impacket.smb3structs import FILE_ATTRIBUTE_REPARSE_POINT
from impacket.smbconnection import SessionError

from .catalog import get_effective_artifact_rules
from .models import (
    ArtifactFinding,
    ArtifactMatch,
    ArtifactOptions,
    ArtifactRule,
    TargetType,
    make_profile_artifact_finding_id,
    make_profile_artifact_id,
)


logger = logging.getLogger("profilehound")


def normalize_catalog_path(relativepath: str) -> str:
    return relativepath.replace("/", "\\").strip("\\")


def catalog_path_to_smb_path(profilefolder: str, relativepath: str) -> str:
    clean = normalize_catalog_path(relativepath)
    if clean:
        return rf"\Users\{profilefolder}\{clean}"
    return rf"\Users\{profilefolder}"


def smb_path_to_unc(target: str, share: str, smbpath: str) -> str:
    clean = smbpath.lstrip("\\")
    return rf"\\{target}\{share}\{clean}"


def _join_relative(*parts: str) -> str:
    clean_parts = [normalize_catalog_path(part) for part in parts if normalize_catalog_path(part)]
    return "\\".join(clean_parts)


def _join_smb(base: str, child: str) -> str:
    child = child.strip("\\")
    if not child:
        return base
    return base.rstrip("\\") + "\\" + child


def _entry_name(entry) -> str:
    name = entry.get_longname()
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")
    return str(name)


def _is_reparse_point(entry) -> bool:
    get_attributes = getattr(entry, "get_attributes", None)
    if get_attributes is None:
        return False
    try:
        return bool(get_attributes() & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False


def _is_missing(error: SessionError) -> bool:
    try:
        short_msg = error.getErrorString()[0]
    except Exception:
        return False
    return short_msg in {
        "STATUS_OBJECT_NAME_NOT_FOUND",
        "STATUS_NO_SUCH_FILE",
        "STATUS_OBJECT_PATH_NOT_FOUND",
        "STATUS_OBJECT_NAME_INVALID",
    }


def _entry_timestamp(entry, method: str) -> float | None:
    try:
        value = getattr(entry, method)()
    except Exception:
        return None
    return value if value and value > 0 else None


def _entry_to_match(
    entry,
    *,
    target: str,
    share: str,
    smbpath: str,
    relativepath: str,
    targettype: TargetType,
) -> ArtifactMatch:
    size = None
    if targettype == "file":
        try:
            size = int(entry.get_filesize())
        except Exception:
            size = None
    return ArtifactMatch(
        sourcepath=smb_path_to_unc(target, share, smbpath),
        relativepath=normalize_catalog_path(relativepath),
        smbpath=smbpath,
        targettype=targettype,
        size=size,
        created=_entry_timestamp(entry, "get_ctime_epoch"),
        modified=_entry_timestamp(entry, "get_wtime_epoch"),
    )


def _safe_list_path(smb, share: str, pattern: str) -> tuple[list, str | None]:
    try:
        return list(smb.listPath(share, pattern)), None
    except SessionError as error:
        if _is_missing(error):
            return [], None
        return [], str(error)
    except Exception as error:
        return [], str(error)


def get_path_metadata(smb, share: str, path: str, is_directory: bool = False) -> dict | None:
    """Return lightweight metadata for one SMB share-relative path if it exists."""
    entries, error = _safe_list_path(smb, share, path)
    if error:
        return None
    for entry in entries:
        name = _entry_name(entry)
        if name in {".", ".."}:
            continue
        if bool(entry.is_directory()) != is_directory:
            continue
        return {
            "relativepath": path,
            "exists": True,
            "isdirectory": is_directory,
            "size": None if is_directory else int(entry.get_filesize()),
            "created": _entry_timestamp(entry, "get_ctime_epoch"),
            "modified": _entry_timestamp(entry, "get_wtime_epoch"),
        }
    return None


def _expand_pattern_matches(
    smb,
    *,
    share: str,
    target: str,
    profilefolder: str,
    relative_pattern: str,
    targettype: TargetType,
) -> tuple[list[ArtifactMatch], list[dict]]:
    pattern = normalize_catalog_path(relative_pattern)
    segments = pattern.split("\\") if pattern else []
    base_smb = catalog_path_to_smb_path(profilefolder, "")
    matches: list[ArtifactMatch] = []
    errors: list[dict] = []

    def walk(index: int, current_smb: str, current_relative: str) -> None:
        if index >= len(segments):
            return

        segment = segments[index]
        list_pattern = _join_smb(current_smb, segment)
        entries, error = _safe_list_path(smb, share, list_pattern)
        if error:
            errors.append(
                {
                    "operation": "list",
                    "sourcepath": smb_path_to_unc(target, share, list_pattern),
                    "error": error,
                }
            )
            return

        is_final = index == len(segments) - 1
        for entry in entries:
            name = _entry_name(entry)
            if name in {".", ".."}:
                continue
            entry_is_dir = bool(entry.is_directory())
            entry_relative = _join_relative(current_relative, name)
            entry_smb = _join_smb(current_smb, name)

            if is_final:
                if targettype == "directory" and not entry_is_dir:
                    continue
                if targettype == "file" and entry_is_dir:
                    continue
                if entry_is_dir and _is_reparse_point(entry):
                    continue
                matches.append(
                    _entry_to_match(
                        entry,
                        target=target,
                        share=share,
                        smbpath=entry_smb,
                        relativepath=entry_relative,
                        targettype=targettype,
                    )
                )
                continue

            if entry_is_dir and not _is_reparse_point(entry):
                walk(index + 1, entry_smb, entry_relative)

    walk(0, base_smb, "")
    return matches, errors


def _root_directories(
    smb,
    *,
    share: str,
    target: str,
    profilefolder: str,
    root_pattern: str,
) -> tuple[list[ArtifactMatch], list[dict]]:
    return _expand_pattern_matches(
        smb,
        share=share,
        target=target,
        profilefolder=profilefolder,
        relative_pattern=root_pattern,
        targettype="directory",
    )


def _recursive_filename_search(
    smb,
    *,
    share: str,
    target: str,
    root: ArtifactMatch,
    filenamepatterns: list[str],
    maxdepth: int,
) -> tuple[list[ArtifactMatch], list[dict]]:
    matches: list[ArtifactMatch] = []
    errors: list[dict] = []
    lowered_patterns = [pattern.lower() for pattern in filenamepatterns]

    def walk(current_smb: str, current_relative: str, depth: int) -> None:
        entries, error = _safe_list_path(smb, share, _join_smb(current_smb, "*"))
        if error:
            errors.append(
                {
                    "operation": "list",
                    "sourcepath": smb_path_to_unc(target, share, current_smb),
                    "error": error,
                }
            )
            return
        for entry in entries:
            name = _entry_name(entry)
            if name in {".", ".."}:
                continue
            entry_smb = _join_smb(current_smb, name)
            entry_relative = _join_relative(current_relative, name)
            if entry.is_directory():
                if depth < maxdepth and not _is_reparse_point(entry):
                    walk(entry_smb, entry_relative, depth + 1)
                continue

            lowered_name = name.lower()
            if any(fnmatch.fnmatchcase(lowered_name, pattern) for pattern in lowered_patterns):
                matches.append(
                    _entry_to_match(
                        entry,
                        target=target,
                        share=share,
                        smbpath=entry_smb,
                        relativepath=entry_relative,
                        targettype="file",
                    )
                )

    walk(root.smbpath, root.relativepath, 0)
    return matches, errors


def _dedupe_matches(matches: list[ArtifactMatch]) -> list[ArtifactMatch]:
    seen: set[str] = set()
    deduped: list[ArtifactMatch] = []
    for match in matches:
        key = match.sourcepath.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    return deduped


def _collect_rule_matches(
    smb,
    *,
    share: str,
    target: str,
    profilefolder: str,
    rule: ArtifactRule,
) -> tuple[list[ArtifactMatch], list[dict]]:
    matches: list[ArtifactMatch] = []
    errors: list[dict] = []

    for relativepath in rule.relativepaths:
        path_matches, path_errors = _expand_pattern_matches(
            smb,
            share=share,
            target=target,
            profilefolder=profilefolder,
            relative_pattern=relativepath,
            targettype=rule.targettype,
        )
        matches.extend(path_matches)
        errors.extend(path_errors)

    if rule.searchroots and rule.filenamepatterns:
        for root_pattern in rule.searchroots:
            roots, root_errors = _root_directories(
                smb,
                share=share,
                target=target,
                profilefolder=profilefolder,
                root_pattern=root_pattern,
            )
            errors.extend(root_errors)
            for root in roots:
                root_matches, root_search_errors = _recursive_filename_search(
                    smb,
                    share=share,
                    target=target,
                    root=root,
                    filenamepatterns=rule.filenamepatterns,
                    maxdepth=rule.maxdepth,
                )
                matches.extend(root_matches)
                errors.extend(root_search_errors)

    return _dedupe_matches(matches), errors


def collect_profile_artifacts(
    *,
    smb,
    share: str,
    target: str,
    profile_name: str,
    profile_details: dict,
    machine: dict,
    artifact_options: ArtifactOptions,
) -> list[ArtifactFinding]:
    if not artifact_options.enabled:
        return []

    rules = get_effective_artifact_rules(artifact_options.disabled_categories)
    findings: list[ArtifactFinding] = []
    collectiontime = time.time()

    for rule in rules:
        try:
            matches, errors = _collect_rule_matches(
                smb,
                share=share,
                target=target,
                profilefolder=profile_name,
                rule=rule,
            )
        except Exception as error:
            logger.debug(
                "Artifact collection failed for %s on %s: %s",
                rule.artifacttype,
                profile_name,
                error,
            )
            continue

        if not matches:
            continue

        collectionlimited = len(matches) > artifact_options.max_matches
        capped_matches = matches[: artifact_options.max_matches]
        profilepath = profile_details["profile"]
        artifactid = make_profile_artifact_id(
            profile_details["sid"],
            rule.artifacttype,
        )
        findingid = make_profile_artifact_finding_id(
            profile_details["sid"],
            machine["sid"],
            profilepath,
            rule.artifacttype,
        )
        finding = ArtifactFinding(
            artifactid=artifactid,
            findingid=findingid,
            artifacttype=rule.artifacttype,
            category=rule.category,
            usersid=profile_details["sid"],
            machinesid=machine["sid"],
            username=profile_name,
            profilefolder=profile_name,
            computername=target,
            profilepath=profilepath,
            matches=capped_matches,
            triageable=rule.triageable,
            downloadable=rule.downloadable,
            browserprofile=rule.browserprofile,
            browser=rule.browser,
            collectiontime=collectiontime,
            collectionlimited=collectionlimited,
            collectionlimitreason="artifactmaxmatches" if collectionlimited else None,
            errors=errors,
        )
        if artifact_options.triage:
            from .triage import triage_finding

            triage_finding(
                smb=smb,
                share=share,
                finding=finding,
                max_files=artifact_options.triage_max_files,
                max_bytes=artifact_options.triage_max_bytes,
            )
        if artifact_options.download_files:
            from .downloader import download_finding

            download_finding(
                smb=smb,
                share=share,
                finding=finding,
                rule=rule,
                options=artifact_options,
            )
        findings.append(finding)

    return findings
