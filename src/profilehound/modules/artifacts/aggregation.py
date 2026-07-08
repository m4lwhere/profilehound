from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .models import ArtifactFinding


def _time_bounds(
    findings: Iterable[ArtifactFinding], attr: str
) -> tuple[float | None, float | None]:
    values = []
    for finding in findings:
        values.extend(getattr(match, attr) for match in finding.matches)
    present = [value for value in values if value is not None]
    if not present:
        return None, None
    return min(present), max(present)


def _without_none_values(properties: dict) -> dict:
    return {key: value for key, value in properties.items() if value is not None}


def sorted_findings(findings: Iterable[ArtifactFinding]) -> list[ArtifactFinding]:
    return sorted(findings, key=lambda item: (item.profilepath.lower(), item.findingid))


def aggregate_category(findings: Iterable[ArtifactFinding]) -> tuple[str, list[str]]:
    categories = sorted({finding.category for finding in findings})
    if not categories:
        return "", []
    return categories[0], categories


def _sample_paths(findings: Iterable[ArtifactFinding], sample_limit: int) -> list[str]:
    samples = []
    remaining = max(sample_limit, 0)
    if remaining == 0:
        return samples
    for finding in sorted_findings(findings):
        finding_samples = finding.sample_paths(remaining)
        samples.extend(finding_samples)
        remaining -= len(finding_samples)
        if remaining <= 0:
            break
    return samples


def _safety_properties(findings: Iterable[ArtifactFinding]) -> dict:
    items = tuple(findings)
    reasons = sorted(
        {
            finding.collectionlimitreason
            for finding in items
            if finding.collectionlimitreason
        }
    )
    properties = {
        "partial": any(finding.partial for finding in items),
        "errorcount": sum(finding.errorcount for finding in items),
        "collectionlimited": any(finding.collectionlimited for finding in items),
        "collectionlimitreason": reasons[0] if len(reasons) == 1 else None,
        "collectionlimitreasons": reasons if len(reasons) > 1 else None,
    }
    return _without_none_values(properties)


def _category_properties(findings: Iterable[ArtifactFinding]) -> dict:
    category, categories = aggregate_category(findings)
    properties = {"category": category}
    if len(categories) > 1:
        properties["categoryconflict"] = True
        properties["categories"] = categories
    return properties


def build_node_properties(
    aggregate: ArtifactAggregate, sample_limit: int = 50
) -> dict:
    findings = aggregate.findings
    oldest_created, newest_created = _time_bounds(findings, "created")
    oldest_modified, newest_modified = _time_bounds(findings, "modified")
    samples = _sample_paths(findings, sample_limit)
    properties = {
        "name": aggregate.artifacttype,
        "artifactid": aggregate.artifactid,
        "artifacttype": aggregate.artifacttype,
        **_category_properties(findings),
        "usersid": aggregate.usersid,
        "username": aggregate.username,
        "computercount": len({finding.machinesid for finding in findings}),
        "profilecount": len({finding.profilepath for finding in findings}),
        "findingcount": len(findings),
        "matchcount": sum(finding.matchcount for finding in findings),
        "samplepaths": samples,
        "samplepathcount": len(samples),
        "oldestcreated": oldest_created,
        "newestcreated": newest_created,
        "oldestmodified": oldest_modified,
        "newestmodified": newest_modified,
    }
    properties.update(_safety_properties(findings))
    return _without_none_values(properties)


def build_has_profile_artifact_edge_properties(aggregate: ArtifactAggregate) -> dict:
    findings = aggregate.findings
    properties = {
        "method": "ProfileHound - SMB Artifact Catalog",
        "artifacttype": aggregate.artifacttype,
        **_category_properties(findings),
        "computercount": len({finding.machinesid for finding in findings}),
        "profilecount": len({finding.profilepath for finding in findings}),
        "findingcount": len(findings),
        "matchcount": sum(finding.matchcount for finding in findings),
    }
    properties.update(_safety_properties(findings))
    return _without_none_values(properties)


def artifact_summary(aggregate: ArtifactAggregate) -> dict:
    summary = {
        "computercount": aggregate.computercount,
        "profilecount": aggregate.profilecount,
        "findingcount": aggregate.findingcount,
        "matchcount": aggregate.matchcount,
    }
    oldest_created, newest_created = aggregate.time_bounds("created")
    oldest_modified, newest_modified = aggregate.time_bounds("modified")
    summary.update(
        {
            "oldestcreated": oldest_created,
            "newestcreated": newest_created,
            "oldestmodified": oldest_modified,
            "newestmodified": newest_modified,
        }
    )
    return _without_none_values(summary)


def build_location_edge_properties(
    findings: Iterable[ArtifactFinding], sample_limit: int
) -> dict:
    items = tuple(sorted_findings(findings))
    samples = _sample_paths(items, sample_limit)
    oldest_created, newest_created = _time_bounds(items, "created")
    oldest_modified, newest_modified = _time_bounds(items, "modified")
    properties = {
        "method": "ProfileHound - SMB Artifact Catalog",
        "computername": items[0].computername if items else None,
        "profilepaths": [finding.profilepath for finding in items],
        "profilefolders": [finding.profilefolder for finding in items],
        "findingids": [finding.findingid for finding in items],
        "matchcounts": [finding.matchcount for finding in items],
        "profilecount": len({finding.profilepath for finding in items}),
        "findingcount": len(items),
        "matchcount": sum(finding.matchcount for finding in items),
        "samplepaths": samples,
        "samplepathcount": len(samples),
        "oldestcreated": oldest_created,
        "newestcreated": newest_created,
        "oldestmodified": oldest_modified,
        "newestmodified": newest_modified,
    }
    if len(items) == 1:
        properties.update(
            {
                "profilepath": items[0].profilepath,
                "profilefolder": items[0].profilefolder,
                "findingid": items[0].findingid,
            }
        )
    properties.update(_safety_properties(items))
    return _without_none_values(properties)


def build_location_aggregates(
    findings: Iterable[ArtifactFinding],
) -> list[ArtifactLocationAggregate]:
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding.machinesid].append(finding)
    aggregates = []
    for machinesid, items in sorted(grouped.items()):
        sorted_items = sorted_findings(items)
        aggregates.append(
            ArtifactLocationAggregate(
                machinesid=machinesid,
                computername=sorted_items[0].computername,
                findings=tuple(sorted_items),
            )
        )
    return aggregates


@dataclass(frozen=True)
class ArtifactLocationAggregate:
    machinesid: str
    computername: str
    findings: tuple[ArtifactFinding, ...]

    def edge_properties(self, sample_limit: int) -> dict:
        return build_location_edge_properties(self.findings, sample_limit)


@dataclass(frozen=True)
class ArtifactAggregate:
    artifactid: str
    artifacttype: str
    usersid: str
    username: str
    findings: tuple[ArtifactFinding, ...]

    @property
    def category(self) -> str:
        return aggregate_category(self.findings)[0]

    @property
    def computercount(self) -> int:
        return len({finding.machinesid for finding in self.findings})

    @property
    def profilecount(self) -> int:
        return len({finding.profilepath for finding in self.findings})

    @property
    def findingcount(self) -> int:
        return len(self.findings)

    @property
    def matchcount(self) -> int:
        return sum(finding.matchcount for finding in self.findings)

    def time_bounds(self, attr: str) -> tuple[float | None, float | None]:
        return _time_bounds(self.findings, attr)

    def node_properties(self) -> dict:
        return build_node_properties(self)

    def has_profile_artifact_edge_properties(self) -> dict:
        return build_has_profile_artifact_edge_properties(self)

    def locations(self) -> list[ArtifactLocationAggregate]:
        return build_location_aggregates(self.findings)

    def to_sidecar_dict(self) -> dict:
        data = {
            "artifactid": self.artifactid,
            "artifacttype": self.artifacttype,
            "category": self.category,
            "usersid": self.usersid,
            "username": self.username,
            "summary": artifact_summary(self),
            "findings": {
                finding.findingid: finding.to_sidecar_dict()
                for finding in self.findings
            },
        }
        category_properties = _category_properties(self.findings)
        if category_properties.get("categoryconflict"):
            data["categoryconflict"] = category_properties["categoryconflict"]
            data["categories"] = category_properties["categories"]
        return data


def aggregate_findings(findings: Iterable[ArtifactFinding]) -> list[ArtifactAggregate]:
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding.artifactid].append(finding)
    return [
        ArtifactAggregate(
            artifactid=artifactid,
            artifacttype=items[0].artifacttype,
            usersid=items[0].usersid,
            username=items[0].username,
            findings=tuple(sorted_findings(items)),
        )
        for artifactid, items in sorted(grouped.items())
    ]
