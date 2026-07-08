from __future__ import annotations

from dataclasses import dataclass


PROFILE_ARTIFACT_KIND = "ProfileArtifact"
BASE_KIND = "Base"


@dataclass(frozen=True)
class ArtifactIcon:
    category: str
    node_kind: str
    icon_name: str
    color: str

    def to_custom_type(self) -> dict:
        return {
            "icon": {
                "type": "font-awesome",
                "name": self.icon_name,
                "color": self.color,
            }
        }


FALLBACK_ARTIFACT_ICON = ArtifactIcon(
    category="profile_artifact",
    node_kind=PROFILE_ARTIFACT_KIND,
    icon_name="folder-open",
    color="#94A3B8",
)


ARTIFACT_CATEGORY_ICONS = {
    "command_history": ArtifactIcon(
        category="command_history",
        node_kind="ProfileArtifactCommandHistory",
        icon_name="terminal",
        color="#38BDF8",
    ),
    "editor_recovery": ArtifactIcon(
        category="editor_recovery",
        node_kind="ProfileArtifactEditorRecovery",
        icon_name="clock-rotate-left",
        color="#F59E0B",
    ),
    "remote_access": ArtifactIcon(
        category="remote_access",
        node_kind="ProfileArtifactRemoteAccess",
        icon_name="network-wired",
        color="#EF4444",
    ),
    "cloud_cli": ArtifactIcon(
        category="cloud_cli",
        node_kind="ProfileArtifactCloudCli",
        icon_name="cloud",
        color="#0EA5E9",
    ),
    "developer_secret": ArtifactIcon(
        category="developer_secret",
        node_kind="ProfileArtifactDeveloperSecret",
        icon_name="code",
        color="#A855F7",
    ),
    "infrastructure_as_code": ArtifactIcon(
        category="infrastructure_as_code",
        node_kind="ProfileArtifactInfrastructureAsCode",
        icon_name="diagram-project",
        color="#22C55E",
    ),
    "password_vault": ArtifactIcon(
        category="password_vault",
        node_kind="ProfileArtifactPasswordVault",
        icon_name="lock",
        color="#EAB308",
    ),
    "vpn_config": ArtifactIcon(
        category="vpn_config",
        node_kind="ProfileArtifactVpnConfig",
        icon_name="shield-halved",
        color="#14B8A6",
    ),
    "browser_store": ArtifactIcon(
        category="browser_store",
        node_kind="ProfileArtifactBrowserStore",
        icon_name="globe",
        color="#F97316",
    ),
    "dpapi_material": ArtifactIcon(
        category="dpapi_material",
        node_kind="ProfileArtifactDpapiMaterial",
        icon_name="fingerprint",
        color="#6366F1",
    ),
    "identity_material_container": ArtifactIcon(
        category="identity_material_container",
        node_kind="ProfileArtifactIdentityMaterialContainer",
        icon_name="box-archive",
        color="#64748B",
    ),
    "ai_agent": ArtifactIcon(
        category="ai_agent",
        node_kind="ProfileArtifactAiAgent",
        icon_name="robot",
        color="#D946EF",
    ),
}


def artifact_node_kinds(category: str) -> list[str]:
    category_icon = ARTIFACT_CATEGORY_ICONS.get(category)
    if category_icon is None:
        return [PROFILE_ARTIFACT_KIND, BASE_KIND]
    return [category_icon.node_kind, PROFILE_ARTIFACT_KIND, BASE_KIND]


def build_custom_icon_payload() -> dict:
    custom_types = {
        FALLBACK_ARTIFACT_ICON.node_kind: FALLBACK_ARTIFACT_ICON.to_custom_type()
    }
    for icon in ARTIFACT_CATEGORY_ICONS.values():
        custom_types[icon.node_kind] = icon.to_custom_type()
    return {"custom_types": custom_types}
