from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Literal


TargetType = Literal["file", "directory"]


def _without_none_values(properties: dict) -> dict:
    return {key: value for key, value in properties.items() if value is not None}


def make_profile_artifact_id(user_sid: str, artifact_type: str) -> str:
    raw = f"profileartifact|{user_sid}|{artifact_type.lower()}"
    return "PROFILEARTIFACT-" + sha256(raw.encode("utf-8")).hexdigest()[:32]


def make_profile_artifact_finding_id(
    user_sid: str,
    machine_sid: str,
    profile_path: str,
    artifact_type: str,
) -> str:
    raw = (
        f"profileartifactfinding|{user_sid}|{machine_sid}|"
        f"{profile_path.lower()}|{artifact_type.lower()}"
    )
    return "PROFILEARTIFACTFINDING-" + sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class ArtifactRule:
    artifacttype: str
    category: str
    targettype: TargetType
    relativepaths: list[str] = field(default_factory=list)
    searchroots: list[str] = field(default_factory=list)
    filenamepatterns: list[str] = field(default_factory=list)
    recursive: bool = False
    maxdepth: int = 0
    glob: bool = False
    triageable: bool = False
    triagehandler: str | None = None
    downloadable: bool = True
    browserprofile: bool = False
    browser: str | None = None
    downloadrecursive: bool = False
    downloadexclusions: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class ArtifactOptions:
    enabled: bool = True
    triage: bool = False
    download_files: bool = False
    write_sidecar: bool = False
    download_dir: str | None = None
    disabled_categories: list[str] = field(default_factory=list)
    max_matches: int = 500
    sample_paths: int = 50
    triage_max_files: int = 25
    triage_max_bytes: int = 262144
    download_max_file_size_mb: int = 512
    browser_max_files_per_profile: int = 5000
    browser_max_total_bytes_per_profile: int = 2147483648
    browser_skip_file_size: int = 268435456
    output_path: str | None = None
    sidecar_path: str | None = None
    domain: str = ""


@dataclass
class ArtifactMatch:
    sourcepath: str
    relativepath: str
    smbpath: str
    targettype: TargetType
    size: int | None
    created: float | None
    modified: float | None
    localpath: str | None = None
    sha256: str | None = None
    downloaded: bool = False
    downloadstatus: str = "not_requested"
    downloadedat: float | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        data = {
            "sourcepath": self.sourcepath,
            "relativepath": self.relativepath,
            "size": self.size,
            "created": self.created,
            "modified": self.modified,
            "downloaded": self.downloaded,
            "downloadstatus": self.downloadstatus,
        }
        if self.localpath:
            data["localpath"] = self.localpath
        if self.downloadedat is not None:
            data["downloadedat"] = self.downloadedat
        if self.sha256:
            data["sha256"] = self.sha256
        if self.error:
            data["error"] = self.error
        return data


@dataclass
class ArtifactFinding:
    artifactid: str
    findingid: str
    artifacttype: str
    category: str
    usersid: str
    machinesid: str
    username: str
    profilefolder: str
    computername: str
    profilepath: str
    matches: list[ArtifactMatch]
    triageable: bool
    downloadable: bool
    browserprofile: bool = False
    browser: str | None = None
    collectiontime: float | None = None
    collectionlimited: bool = False
    collectionlimitreason: str | None = None
    triaged: bool = False
    triagestatus: str = "not_requested"
    triage: dict = field(default_factory=dict)
    downloadrequested: bool = False
    downloaded: bool = False
    downloadstatus: str = "not_requested"
    downloadedfilecount: int = 0
    downloadedtotalsize: int = 0
    skippedfilecount: int = 0
    skippeddircount: int = 0
    downloadlimited: bool = False
    downloadlimitreason: str | None = None
    localprofilepath: str | None = None
    errors: list[dict] = field(default_factory=list)

    @property
    def matchcount(self) -> int:
        return len(self.matches)

    @property
    def errorcount(self) -> int:
        file_errors = sum(1 for match in self.matches if match.error)
        return len(self.errors) + file_errors

    @property
    def partial(self) -> bool:
        return (
            self.errorcount > 0
            or self.collectionlimited
            or self.downloadlimited
            or self.downloadstatus == "partial"
        )

    def sample_paths(self, limit: int) -> list[str]:
        return [match.sourcepath for match in self.matches[: max(limit, 0)]]

    def browser_profiles(self) -> list[str]:
        if not self.browserprofile:
            return []
        return sorted({match.relativepath.rstrip("\\").split("\\")[-1] for match in self.matches})

    def totalsize(self) -> int:
        return sum(match.size or 0 for match in self.matches)

    def _time_bounds(self, attr: str) -> tuple[float | None, float | None]:
        values = [getattr(match, attr) for match in self.matches]
        present = [value for value in values if value is not None]
        if not present:
            return None, None
        return min(present), max(present)

    def _triage_node_properties(self) -> dict:
        return {
            key: value
            for key, value in self.triage.items()
            if isinstance(value, bool | int | float)
        }

    def to_node_properties(self, sidecar_file: str | None, sample_limit: int) -> dict:
        oldest_created, newest_created = self._time_bounds("created")
        oldest_modified, newest_modified = self._time_bounds("modified")
        samples = self.sample_paths(sample_limit)
        name_prefix = self.artifacttype
        if self.browserprofile and len(self.browser_profiles()) == 1:
            name_prefix = f"{self.artifacttype} {self.browser_profiles()[0]}"

        props = {
            "name": f"{name_prefix}: {self.username} on {self.computername}",
            "artifactid": self.artifactid,
            "artifacttype": self.artifacttype,
            "category": self.category,
            "usersid": self.usersid,
            "machinesid": self.machinesid,
            "username": self.username,
            "profilefolder": self.profilefolder,
            "computername": self.computername,
            "profilepath": self.profilepath,
            "matchcount": self.matchcount,
            "samplepaths": samples,
            "samplepathcount": len(samples),
            "totalsize": self.totalsize(),
            "oldestcreated": oldest_created,
            "newestcreated": newest_created,
            "oldestmodified": oldest_modified,
            "newestmodified": newest_modified,
            "triageable": self.triageable,
            "triaged": self.triaged,
            "triagestatus": self.triagestatus,
            "downloadable": self.downloadable,
            "downloadrequested": self.downloadrequested,
            "downloaded": self.downloaded,
            "downloadstatus": self.downloadstatus,
            "partial": self.partial,
            "errorcount": self.errorcount,
            "collectionlimited": self.collectionlimited,
            "collectionlimitreason": self.collectionlimitreason,
            "collectionmethod": "ProfileHound SMB Artifact Catalog",
            "collectiontime": self.collectiontime,
        }
        if self.browser:
            props["browser"] = self.browser
        if self.browserprofile:
            browser_profiles = self.browser_profiles()
            if len(browser_profiles) == 1:
                props["browserprofile"] = browser_profiles[0]
            elif browser_profiles:
                props["browserprofiles"] = browser_profiles
        if self.downloadrequested:
            props.update(
                {
                    "downloadedfilecount": self.downloadedfilecount,
                    "downloadedtotalsize": self.downloadedtotalsize,
                    "skippedfilecount": self.skippedfilecount,
                    "skippeddircount": self.skippeddircount,
                    "downloadlimited": self.downloadlimited,
                    "downloadlimitreason": self.downloadlimitreason,
                }
            )
        props.update(self._triage_node_properties())
        return _without_none_values(props)

    def to_sidecar_dict(self) -> dict:
        data = {
            "artifactid": self.artifactid,
            "findingid": self.findingid,
            "artifacttype": self.artifacttype,
            "category": self.category,
            "username": self.username,
            "profilefolder": self.profilefolder,
            "usersid": self.usersid,
            "computername": self.computername,
            "machinesid": self.machinesid,
            "profilepath": self.profilepath,
            "matchcount": self.matchcount,
            "collectionlimited": self.collectionlimited,
            "collectionlimitreason": self.collectionlimitreason,
            "collectiontime": self.collectiontime,
            "triage": {
                "triaged": self.triaged,
                "triagestatus": self.triagestatus,
                **self.triage,
            },
            "errors": self.errors,
            "errorcount": self.errorcount,
            "downloadrequested": self.downloadrequested,
            "downloaded": self.downloaded,
            "downloadstatus": self.downloadstatus,
            "downloadedfilecount": self.downloadedfilecount,
            "downloadedtotalsize": self.downloadedtotalsize,
            "skippedfilecount": self.skippedfilecount,
            "skippeddircount": self.skippeddircount,
            "downloadlimited": self.downloadlimited,
            "downloadlimitreason": self.downloadlimitreason,
        }
        if self.browser:
            data["browser"] = self.browser
        if self.browserprofile:
            profiles = self.browser_profiles()
            if len(profiles) == 1:
                data["browserprofile"] = profiles[0]
            elif profiles:
                data["browserprofiles"] = profiles
            data.update(
                {
                    "sourceprofilepath": self.matches[0].sourcepath if self.matches else None,
                    "localprofilepath": self.localprofilepath,
                }
            )
        else:
            data["matches"] = [match.to_dict() for match in self.matches]
        return data


@dataclass
class ArtifactCollectionSummary:
    profileschecked: int = 0
    profileswithartifacts: int = 0
    artifactnodescreated: int = 0
    artifactfindings: int = 0
    totalmatches: int = 0
    downloadedfiles: int = 0
    downloadedbrowserprofiles: int = 0
    artifacterrors: int = 0
