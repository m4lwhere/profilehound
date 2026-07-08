from __future__ import annotations

import hashlib
import time
from pathlib import Path

from impacket.smb import FILE_SHARE_READ, FILE_SHARE_WRITE
from impacket.smb3structs import FILE_SHARE_DELETE, FILE_ATTRIBUTE_REPARSE_POINT

from .collector import normalize_catalog_path, smb_path_to_unc
from .models import ArtifactFinding, ArtifactMatch, ArtifactOptions, ArtifactRule


def sanitize_component(value: str) -> str:
    cleaned = []
    for char in str(value).strip():
        if ord(char) < 32 or char in '<>:"/\\|?*':
            cleaned.append("_")
        else:
            cleaned.append(char)
    result = "".join(cleaned).strip(" .")
    return result or "unknown"


def relative_path_to_flat_filename(relativepath: str) -> str:
    clean = normalize_catalog_path(relativepath)
    return sanitize_component(clean.replace("\\", "_"))


def _source_hash(sourcepath: str) -> str:
    return hashlib.sha256(sourcepath.lower().encode("utf-8")).hexdigest()[:8]


def _append_collision_suffix(path: Path, sourcepath: str) -> Path:
    return path.with_name(f"{path.name}__{_source_hash(sourcepath)}")


def _identity_root(options: ArtifactOptions, finding: ArtifactFinding) -> Path:
    root = Path(options.download_dir or "profilehound_artifacts")
    domain = sanitize_component(options.domain or "UNKNOWN_DOMAIN")
    user = sanitize_component(finding.profilefolder or finding.username or finding.usersid)
    computer = sanitize_component(finding.computername)
    artifact = sanitize_component(finding.artifacttype)
    return root / domain / user / computer / artifact


def _copy_remote_file(smb, share: str, smbpath: str, localpath: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    bytes_written = 0
    localpath.parent.mkdir(parents=True, exist_ok=True)

    with localpath.open("wb") as handle:
        def write_chunk(data: bytes) -> None:
            nonlocal bytes_written
            handle.write(data)
            digest.update(data)
            bytes_written += len(data)

        getter = getattr(smb, "getFileEx", None) or smb.getFile
        try:
            getter(
                share,
                smbpath,
                write_chunk,
                shareAccessMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            )
        except TypeError:
            getter(share, smbpath, write_chunk)

    return bytes_written, digest.hexdigest()


def _download_normal_file(
    *,
    smb,
    share: str,
    finding: ArtifactFinding,
    match: ArtifactMatch,
    options: ArtifactOptions,
    used_paths: set[Path],
) -> None:
    max_size = options.download_max_file_size_mb * 1024 * 1024
    if match.size is not None and match.size > max_size:
        match.downloadstatus = "skipped_too_large"
        match.error = "file exceeds artifact download max file size"
        finding.skippedfilecount += 1
        finding.errors.append(
            {
                "operation": "download",
                "sourcepath": match.sourcepath,
                "error": match.error,
            }
        )
        return

    filename = relative_path_to_flat_filename(match.relativepath)
    localpath = _identity_root(options, finding) / filename
    if localpath in used_paths or localpath.exists():
        localpath = _append_collision_suffix(localpath, match.sourcepath)
    used_paths.add(localpath)

    try:
        bytes_written, digest = _copy_remote_file(smb, share, match.smbpath, localpath)
    except Exception as error:
        match.downloadstatus = "error"
        match.error = str(error)
        finding.errors.append(
            {
                "operation": "download",
                "sourcepath": match.sourcepath,
                "error": str(error),
            }
        )
        return

    match.localpath = str(localpath)
    match.downloaded = True
    match.downloadstatus = "success"
    match.downloadedat = time.time()
    match.sha256 = digest
    finding.downloadedfilecount += 1
    finding.downloadedtotalsize += bytes_written


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


def _join_smb(base: str, child: str) -> str:
    return base.rstrip("\\") + "\\" + child.strip("\\")


def _excluded(relative_dir: str, exclusions: list[str]) -> bool:
    normalized = normalize_catalog_path(relative_dir).lower()
    parts = [part.lower() for part in normalized.split("\\") if part]
    for exclusion in exclusions:
        clean = normalize_catalog_path(exclusion).lower()
        if not clean:
            continue
        if "\\" in clean:
            if normalized == clean or normalized.startswith(clean + "\\") or ("\\" + clean + "\\") in ("\\" + normalized + "\\"):
                return True
        elif clean in parts:
            return True
    return False


def _browser_profile_local_root(
    options: ArtifactOptions,
    finding: ArtifactFinding,
    match: ArtifactMatch,
    used_paths: set[Path],
) -> Path:
    profile_name = sanitize_component(match.relativepath.rstrip("\\").split("\\")[-1])
    local_root = _identity_root(options, finding) / profile_name
    if local_root in used_paths or local_root.exists():
        local_root = _append_collision_suffix(local_root, match.sourcepath)
    used_paths.add(local_root)
    return local_root


def _download_browser_profile(
    *,
    smb,
    share: str,
    finding: ArtifactFinding,
    match: ArtifactMatch,
    rule: ArtifactRule,
    options: ArtifactOptions,
    used_paths: set[Path],
) -> None:
    local_root = _browser_profile_local_root(options, finding, match, used_paths)
    if finding.localprofilepath is None:
        finding.localprofilepath = str(local_root)
    profile_downloaded_files = 0
    profile_downloaded_bytes = 0

    def walk(current_smb: str, relative_inside: str) -> None:
        nonlocal profile_downloaded_files, profile_downloaded_bytes
        if finding.downloadlimited:
            return
        try:
            entries = smb.listPath(share, _join_smb(current_smb, "*"))
        except Exception as error:
            finding.errors.append(
                {
                    "operation": "download",
                    "sourcepath": smb_path_to_unc(finding.computername, share, current_smb),
                    "error": str(error),
                }
            )
            return

        for entry in entries:
            name = _entry_name(entry)
            if name in {".", ".."}:
                continue
            child_smb = _join_smb(current_smb, name)
            child_relative = normalize_catalog_path(
                f"{relative_inside}\\{name}" if relative_inside else name
            )
            if entry.is_directory():
                if _is_reparse_point(entry) or _excluded(child_relative, rule.downloadexclusions):
                    finding.skippeddircount += 1
                    continue
                walk(child_smb, child_relative)
                continue

            try:
                size = int(entry.get_filesize())
            except Exception:
                size = 0
            if size > options.browser_skip_file_size:
                finding.skippedfilecount += 1
                continue
            if profile_downloaded_files >= options.browser_max_files_per_profile:
                finding.downloadlimited = True
                finding.downloadlimitreason = "browsermaxfilesperprofile"
                return
            if profile_downloaded_bytes + size > options.browser_max_total_bytes_per_profile:
                finding.downloadlimited = True
                finding.downloadlimitreason = "browsermaxtotalbytesperprofile"
                return

            localpath = local_root / Path(*child_relative.split("\\"))
            try:
                bytes_written, _ = _copy_remote_file(smb, share, child_smb, localpath)
            except Exception as error:
                finding.errors.append(
                    {
                        "operation": "download",
                        "sourcepath": smb_path_to_unc(finding.computername, share, child_smb),
                        "error": str(error),
                    }
                )
                continue
            profile_downloaded_files += 1
            profile_downloaded_bytes += bytes_written
            finding.downloadedfilecount += 1
            finding.downloadedtotalsize += bytes_written

    walk(match.smbpath, "")


def download_finding(
    *,
    smb,
    share: str,
    finding: ArtifactFinding,
    rule: ArtifactRule,
    options: ArtifactOptions,
) -> None:
    finding.downloadrequested = True
    if not finding.downloadable:
        finding.downloaded = False
        finding.downloadstatus = "not_supported"
        return

    used_paths: set[Path] = set()
    if finding.browserprofile:
        for match in finding.matches:
            _download_browser_profile(
                smb=smb,
                share=share,
                finding=finding,
                match=match,
                rule=rule,
                options=options,
                used_paths=used_paths,
            )
        finding.downloaded = finding.downloadedfilecount > 0
        if finding.downloadlimited or finding.errorcount > 0 or finding.skippedfilecount or finding.skippeddircount:
            finding.downloadstatus = "partial" if finding.downloaded else "error"
        else:
            finding.downloadstatus = "success" if finding.downloaded else "no_files"
        return

    for match in finding.matches:
        if match.targettype != "file":
            match.downloadstatus = "not_supported"
            continue
        _download_normal_file(
            smb=smb,
            share=share,
            finding=finding,
            match=match,
            options=options,
            used_paths=used_paths,
        )

    successes = sum(1 for match in finding.matches if match.downloaded)
    errors = sum(1 for match in finding.matches if match.downloadstatus in {"error", "skipped_too_large"})
    finding.downloaded = successes > 0
    if successes and errors:
        finding.downloadstatus = "partial"
    elif successes:
        finding.downloadstatus = "success"
    elif errors:
        finding.downloadstatus = "error"
    else:
        finding.downloadstatus = "no_files"
