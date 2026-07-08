from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

from profilehound.__version__ import __version__

from .aggregation import ArtifactAggregate, aggregate_findings
from .catalog import get_effective_artifact_rules
from .models import ArtifactCollectionSummary, ArtifactFinding, ArtifactOptions


def derive_artifact_sidecar_path(output_path: str) -> str:
    path = Path(output_path)
    if path.suffix:
        return str(path.with_name(f"{path.stem}.artifacts.json"))
    return str(path.with_name(f"{path.name}.artifacts.json"))


def derive_default_download_dir(output_path: str) -> str:
    path = Path(output_path)
    if path.suffix:
        return str(path.with_name(f"{path.stem}_artifacts"))
    return str(path.with_name(f"{path.name}_artifacts"))


def iter_artifact_findings(found_profiles_by_target: dict) -> Iterable[ArtifactFinding]:
    for target_details in found_profiles_by_target.values():
        artifacts = target_details.get("artifacts", {})
        if isinstance(artifacts, dict):
            for profile_findings in artifacts.values():
                yield from profile_findings or []
        else:
            yield from artifacts or []


def summarize_artifacts(
    found_profiles_by_target: dict,
    *,
    findings: Iterable[ArtifactFinding] | None = None,
    aggregates: Iterable[ArtifactAggregate] | None = None,
) -> ArtifactCollectionSummary:
    summary = ArtifactCollectionSummary()
    profile_keys_with_artifacts: set[tuple[str, str]] = set()
    all_findings = list(findings) if findings is not None else list(
        iter_artifact_findings(found_profiles_by_target)
    )
    all_aggregates = list(aggregates) if aggregates is not None else aggregate_findings(
        all_findings
    )

    for target, target_details in found_profiles_by_target.items():
        owners = target_details.get("owners", {})
        summary.profileschecked += len(owners)
        artifacts = target_details.get("artifacts", {})
        if isinstance(artifacts, dict):
            for profile_name, profile_findings in artifacts.items():
                if profile_findings:
                    profile_keys_with_artifacts.add((target, profile_name))

    summary.artifactnodescreated = len(all_aggregates)
    summary.artifactfindings = len(all_findings)
    for finding in all_findings:
        summary.totalmatches += finding.matchcount
        summary.artifacterrors += finding.errorcount
        if finding.browserprofile:
            if finding.downloaded:
                summary.downloadedbrowserprofiles += 1
        else:
            summary.downloadedfiles += finding.downloadedfilecount

    summary.profileswithartifacts = len(profile_keys_with_artifacts)
    return summary


def _add_index(indexes: dict, index_name: str, key: str, value: str) -> None:
    bucket = indexes[index_name].setdefault(key, [])
    if value not in bucket:
        bucket.append(value)


def build_artifact_sidecar(
    found_profiles_by_target: dict,
    options: ArtifactOptions,
    *,
    collectiontime: float | None = None,
) -> dict:
    collectiontime = collectiontime or time.time()
    enabled_types = sorted(
        rule.artifacttype
        for rule in get_effective_artifact_rules(options.disabled_categories)
    )
    findings = list(iter_artifact_findings(found_profiles_by_target))
    aggregates = aggregate_findings(findings)
    summary = summarize_artifacts(
        found_profiles_by_target,
        findings=findings,
        aggregates=aggregates,
    )
    indexes = {
        "byuser": {},
        "bycomputer": {},
        "byartifacttype": {},
        "bycategory": {},
        "byfinding": {},
        "byusercomputer": {},
    }

    artifacts = {}
    for aggregate in aggregates:
        artifacts[aggregate.artifactid] = aggregate.to_sidecar_dict()
        _add_index(indexes, "byuser", aggregate.usersid, aggregate.artifactid)
        _add_index(
            indexes,
            "byartifacttype",
            aggregate.artifacttype,
            aggregate.artifactid,
        )
        for finding in aggregate.findings:
            _add_index(indexes, "bycomputer", finding.machinesid, finding.findingid)
            _add_index(indexes, "bycategory", finding.category, aggregate.artifactid)
            indexes["byfinding"][finding.findingid] = aggregate.artifactid
            _add_index(
                indexes,
                "byusercomputer",
                f"{finding.usersid}|{finding.machinesid}",
                finding.findingid,
            )

    return {
        "profilehoundversion": __version__,
        "collectiontime": collectiontime,
        "opengraphfile": options.output_path,
        "downloadroot": options.download_dir,
        "artifactcollectionenabled": options.enabled,
        "artifacttriageenabled": options.triage,
        "artifactdownloadenabled": options.download_files,
        "disabledcategories": sorted(options.disabled_categories),
        "artifactmaxmatches": options.max_matches,
        "artifactsamplepaths": options.sample_paths,
        "artifacttriagemaxfiles": options.triage_max_files,
        "artifactdownloadmaxfilesizemb": options.download_max_file_size_mb,
        "browsermaxfilesperprofile": options.browser_max_files_per_profile,
        "browsermaxtotalbytesperprofile": options.browser_max_total_bytes_per_profile,
        "enabledartifacttypes": enabled_types,
        "summary": summary.__dict__,
        "artifacts": artifacts,
        "indexes": indexes,
    }


def write_artifact_sidecar(
    found_profiles_by_target: dict,
    options: ArtifactOptions,
) -> None:
    if not options.sidecar_path:
        raise ValueError("Artifact sidecar path is required")
    sidecar = build_artifact_sidecar(found_profiles_by_target, options)
    path = Path(options.sidecar_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
