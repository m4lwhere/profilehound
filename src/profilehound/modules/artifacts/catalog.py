from __future__ import annotations

from .models import ArtifactRule


HIGH_VALUE_ROOTS = [".ssh", "Desktop", "Documents", "Downloads", "OneDrive", "OneDrive - *"]
AI_AGENT_SEARCH_ROOTS = HIGH_VALUE_ROOTS[1:]

AI_AGENT_CONFIG_PATHS = [
    r".claude\settings.json",
    r".claude\settings.local.json",
    r".codex\config.toml",
    r".codex\*.config.toml",
    r".gemini\settings.json",
    r".continue\config.yaml",
    r".continue\config.json",
    r".aider.conf.yml",
    r".aider.model.settings.yml",
    r".opencode\config.json",
    r".opencode\config.jsonc",
    r"opencode.json",
    r"opencode.jsonc",
    r".config\devin\config.json",
    r".codeium\windsurf\hooks.json",
]

AI_AGENT_CONTEXT_PATTERNS = [
    "AGENTS.md",
    "agents.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
]

AI_AGENT_CONTEXT_PATHS = [
    r".cursor\rules\*.mdc",
    r".devin\rules\*.md",
    r".windsurf\rules\*.md",
    r".gemini\GEMINI.md",
    r".claude\CLAUDE.md",
]

AI_AGENT_MCP_CONFIG_PATHS = [
    r".cursor\mcp.json",
    r".cline\mcp.json",
    r".cline\data\settings\*.json",
    r".gemini\settings.json",
    r".claude\settings.json",
    r".codex\config.toml",
    r".continue\config.yaml",
    r".continue\config.json",
    r".codeium\windsurf\mcp_config.json",
    r".codeium\mcp_config.json",
    r".config\devin\config.json",
    r".devin\config.json",
    r".devin\config.local.json",
]

AI_PROVIDER_CREDENTIAL_PATHS = [
    r".aider.conf.yml",
    r".aider.model.settings.yml",
    r".codex\config.toml",
    r".claude\settings.json",
    r".claude\settings.local.json",
    r".gemini\settings.json",
    r".continue\config.yaml",
    r".continue\config.json",
    r"opencode.json",
    r"opencode.jsonc",
]

AI_PROVIDER_CREDENTIAL_PATTERNS = [
    ".env",
    ".env.*",
    "*.env",
]

CHROMIUM_EXCLUSIONS = [
    "Cache",
    "Code Cache",
    "GPUCache",
    "GrShaderCache",
    "ShaderCache",
    "Crashpad",
    "BrowserMetrics",
    "OptimizationHints",
    "Safe Browsing",
    r"Service Worker\CacheStorage",
]

FIREFOX_EXCLUSIONS = [
    "cache2",
    "startupCache",
    "shader-cache",
    "crashes",
    "minidumps",
    "safebrowsing",
    "thumbnails",
]


def _rule(
    artifacttype: str,
    category: str,
    targettype: str,
    *,
    relativepaths: list[str] | None = None,
    searchroots: list[str] | None = None,
    filenamepatterns: list[str] | None = None,
    recursive: bool = False,
    maxdepth: int = 0,
    triageable: bool = False,
    downloadable: bool = True,
    browserprofile: bool = False,
    browser: str | None = None,
    downloadrecursive: bool = False,
    downloadexclusions: list[str] | None = None,
    description: str = "",
) -> ArtifactRule:
    paths = relativepaths or []
    patterns = filenamepatterns or []
    return ArtifactRule(
        artifacttype=artifacttype,
        category=category,
        targettype=targettype,  # type: ignore[arg-type]
        relativepaths=paths,
        searchroots=searchroots or [],
        filenamepatterns=patterns,
        recursive=recursive,
        maxdepth=maxdepth,
        glob=any("*" in path or "?" in path for path in paths + patterns),
        triageable=triageable,
        triagehandler="text_indicators" if triageable else None,
        downloadable=downloadable,
        browserprofile=browserprofile,
        browser=browser,
        downloadrecursive=downloadrecursive,
        downloadexclusions=downloadexclusions or [],
        description=description,
    )


def get_default_artifact_rules() -> list[ArtifactRule]:
    return [
        _rule(
            "powershell_history",
            "command_history",
            "file",
            relativepaths=[
                r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            ],
            triageable=True,
            description="PSReadLine history",
        ),
        _rule(
            "powershell_transcript",
            "command_history",
            "file",
            relativepaths=[
                r"Documents\PowerShell_transcript*.txt",
                r"Desktop\PowerShell_transcript*.txt",
                r"Downloads\PowerShell_transcript*.txt",
            ],
            triageable=True,
            description="PowerShell transcript files",
        ),
        _rule(
            "powershell_profile",
            "command_history",
            "file",
            relativepaths=[
                r"Documents\WindowsPowerShell\*.ps1",
                r"Documents\PowerShell\*.ps1",
            ],
            triageable=True,
            description="User PowerShell profile scripts",
        ),
        _rule(
            "notepadpp_backup",
            "editor_recovery",
            "file",
            relativepaths=[r"AppData\Roaming\Notepad++\backup\*"],
            triageable=True,
            description="Notepad++ recovery backups",
        ),
        _rule(
            "notepadpp_session",
            "editor_recovery",
            "file",
            relativepaths=[r"AppData\Roaming\Notepad++\session.xml"],
            triageable=True,
            description="Notepad++ session metadata",
        ),
        _rule(
            "ssh_private_key",
            "remote_access",
            "file",
            searchroots=HIGH_VALUE_ROOTS,
            filenamepatterns=[
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
                "id_ed25519",
                "*.pem",
                "*.key",
            ],
            recursive=True,
            maxdepth=4,
            triageable=False,
            description="SSH private key patterns",
        ),
        _rule(
            "ssh_config",
            "remote_access",
            "file",
            relativepaths=[r".ssh\config", r".ssh\known_hosts"],
            triageable=True,
            description="SSH config and known hosts",
        ),
        _rule(
            "putty_private_key",
            "remote_access",
            "file",
            searchroots=HIGH_VALUE_ROOTS,
            filenamepatterns=["*.ppk"],
            recursive=True,
            maxdepth=4,
            triageable=False,
            description="PuTTY private keys",
        ),
        _rule(
            "rdp_file",
            "remote_access",
            "file",
            relativepaths=[r"Documents\*.rdp", r"Desktop\*.rdp", r"Downloads\*.rdp"],
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=["*.rdp"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="RDP connection files",
        ),
        _rule(
            "rdcman_config",
            "remote_access",
            "file",
            relativepaths=[
                r"AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings",
                r"Documents\*.rdg",
                r"Desktop\*.rdg",
                r"Downloads\*.rdg",
            ],
            triageable=True,
            description="RDCMan settings and .rdg files",
        ),
        _rule(
            "mremoteng_config",
            "remote_access",
            "file",
            relativepaths=[r"AppData\Roaming\mRemoteNG\confCons.xml"],
            triageable=True,
            description="mRemoteNG connection config",
        ),
        _rule(
            "winscp_ini",
            "remote_access",
            "file",
            relativepaths=[r"AppData\Roaming\WinSCP.ini"],
            triageable=True,
            description="File-based WinSCP config",
        ),
        _rule(
            "filezilla_config",
            "remote_access",
            "file",
            relativepaths=[
                r"AppData\Roaming\FileZilla\sitemanager.xml",
                r"AppData\Roaming\FileZilla\recentservers.xml",
            ],
            triageable=True,
            description="FileZilla site manager files",
        ),
        _rule(
            "mobaxterm_config",
            "remote_access",
            "file",
            relativepaths=[
                r"AppData\Roaming\MobaXterm\*",
                r"Documents\MobaXterm\home\.ssh\*",
            ],
            triageable=True,
            description="MobaXterm file-based config",
        ),
        _rule(
            "superputty_config",
            "remote_access",
            "file",
            relativepaths=[r"AppData\Roaming\SuperPuTTY\sessions.xml"],
            triageable=True,
            description="SuperPuTTY sessions",
        ),
        _rule(
            "aws_credentials",
            "cloud_cli",
            "file",
            relativepaths=[r".aws\credentials"],
            triageable=True,
            description="AWS credential file",
        ),
        _rule(
            "aws_config",
            "cloud_cli",
            "file",
            relativepaths=[r".aws\config"],
            triageable=True,
            description="AWS config file",
        ),
        _rule(
            "aws_cache",
            "cloud_cli",
            "file",
            relativepaths=[r".aws\sso\cache\*.json", r".aws\cli\cache\*.json"],
            triageable=True,
            description="AWS SSO and CLI cache JSON",
        ),
        _rule(
            "azure_cli_state",
            "cloud_cli",
            "file",
            relativepaths=[
                r".azure\azureProfile.json",
                r".azure\msal_token_cache.json",
                r".azure\accessTokens.json",
                r".azure\service_principal_entries.json",
                r".azure\clouds.config",
                r".azure\config",
            ],
            triageable=True,
            description="Azure CLI state files",
        ),
        _rule(
            "azure_powershell_context",
            "cloud_cli",
            "file",
            relativepaths=[
                r".Azure\AzureRmContext.json",
                r".Azure\TokenCache.dat",
                r".Azure\ServicePrincipalSecretStore.json",
            ],
            triageable=True,
            description="Azure PowerShell (Az module) context and token cache",
        ),
        _rule(
            "msal_token_cache",
            "cloud_cli",
            "file",
            relativepaths=[
                r"AppData\Local\.IdentityService\msal.cache",
                r"AppData\Local\.IdentityService\msalV2.cache",
            ],
            triageable=False,
            description="Shared MSAL token cache (AAD refresh tokens for az/Az/VS/Office)",
        ),
        _rule(
            "gcp_cli_state",
            "cloud_cli",
            "file",
            relativepaths=[
                r"AppData\Roaming\gcloud\credentials.db",
                r"AppData\Roaming\gcloud\application_default_credentials.json",
                r"AppData\Roaming\gcloud\legacy_credentials\*\adc.json",
                r"AppData\Roaming\gcloud\legacy_credentials\*\.boto",
                r"AppData\Roaming\gcloud\configurations\*",
            ],
            triageable=True,
            description="gcloud config and credentials",
        ),
        _rule(
            "rclone_config",
            "cloud_cli",
            "file",
            relativepaths=[
                r"AppData\Roaming\rclone\rclone.conf",
                r".config\rclone\rclone.conf",
            ],
            triageable=True,
            description="rclone config (cloud storage backend tokens)",
        ),
        _rule(
            "vault_token",
            "cloud_cli",
            "file",
            relativepaths=[r".vault-token"],
            triageable=False,
            description="HashiCorp Vault token",
        ),
        _rule(
            "kubeconfig",
            "cloud_cli",
            "file",
            relativepaths=[r".kube\config"],
            triageable=True,
            description="Kubernetes config",
        ),
        _rule(
            "ai_agent_config",
            "ai_agent",
            "file",
            relativepaths=AI_AGENT_CONFIG_PATHS,
            triageable=True,
            description="AI coding agent and harness user configuration files",
        ),
        _rule(
            "ai_agent_project_context",
            "ai_agent",
            "file",
            relativepaths=AI_AGENT_CONTEXT_PATHS,
            searchroots=AI_AGENT_SEARCH_ROOTS,
            filenamepatterns=AI_AGENT_CONTEXT_PATTERNS,
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="AI coding agent project instructions, rules, and context files",
        ),
        _rule(
            "ai_agent_mcp_config",
            "ai_agent",
            "file",
            relativepaths=AI_AGENT_MCP_CONFIG_PATHS,
            triageable=True,
            description="MCP server configuration for AI coding agents and IDEs",
        ),
        _rule(
            "ai_provider_credentials",
            "ai_agent",
            "file",
            relativepaths=AI_PROVIDER_CREDENTIAL_PATHS,
            searchroots=AI_AGENT_SEARCH_ROOTS,
            filenamepatterns=AI_PROVIDER_CREDENTIAL_PATTERNS,
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="AI provider credential files and environment files",
        ),
        _rule(
            "docker_config",
            "developer_secret",
            "file",
            relativepaths=[r".docker\config.json"],
            triageable=True,
            description="Docker client config",
        ),
        _rule(
            "git_credentials",
            "developer_secret",
            "file",
            relativepaths=[r".git-credentials", r".gitconfig", r".netrc"],
            triageable=True,
            description="Git credential material",
        ),
        _rule(
            "npmrc",
            "developer_secret",
            "file",
            relativepaths=[r".npmrc"],
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=[".npmrc"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="npm config files",
        ),
        _rule(
            "pypirc",
            "developer_secret",
            "file",
            relativepaths=[r".pypirc", r"pip\pip.ini", r"AppData\Roaming\pip\pip.ini"],
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=[".pypirc", "pip.ini"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="Python package index config",
        ),
        _rule(
            "nuget_config",
            "developer_secret",
            "file",
            relativepaths=[r"AppData\Roaming\NuGet\NuGet.Config"],
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=["NuGet.Config"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="NuGet config",
        ),
        _rule(
            "maven_settings",
            "developer_secret",
            "file",
            relativepaths=[r".m2\settings.xml"],
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=["settings.xml"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="Maven settings",
        ),
        _rule(
            "gradle_properties",
            "developer_secret",
            "file",
            relativepaths=[r".gradle\gradle.properties"],
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=["gradle.properties"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="Gradle properties",
        ),
        _rule(
            "env_file",
            "developer_secret",
            "file",
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=[".env", ".env.*", "*.env"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="Environment files under high-value roots",
        ),
        _rule(
            "terraform_credentials",
            "infrastructure_as_code",
            "file",
            relativepaths=[r".terraform.d\credentials.tfrc.json", r".terraformrc"],
            triageable=True,
            description="Terraform credentials",
        ),
        _rule(
            "terraform_state",
            "infrastructure_as_code",
            "file",
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=["*.tfstate", "*.tfstate.backup"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="Terraform state files",
        ),
        _rule(
            "terraform_vars",
            "infrastructure_as_code",
            "file",
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=["*.tfvars", "*.auto.tfvars", "terraform.tfvars"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="Terraform variable files",
        ),
        _rule(
            "keepass_database",
            "password_vault",
            "file",
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=["*.kdbx"],
            recursive=True,
            maxdepth=4,
            triageable=False,
            description="KeePass databases",
        ),
        _rule(
            "vpn_config",
            "vpn_config",
            "file",
            relativepaths=[
                r"AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk",
                r"AppData\Roaming\Microsoft\Network\Connections\Pbk\*.pbk",
                r"Documents\*.ovpn",
                r"Desktop\*.ovpn",
                r"Downloads\*.ovpn",
            ],
            searchroots=HIGH_VALUE_ROOTS[1:],
            filenamepatterns=["*.ovpn", "*.pcf"],
            recursive=True,
            maxdepth=4,
            triageable=True,
            description="VPN profile files",
        ),
        _rule(
            "chrome_profile",
            "browser_store",
            "directory",
            relativepaths=[
                r"AppData\Local\Google\Chrome\User Data\Default",
                r"AppData\Local\Google\Chrome\User Data\Profile *",
            ],
            browserprofile=True,
            browser="chrome",
            downloadrecursive=True,
            downloadexclusions=CHROMIUM_EXCLUSIONS,
            description="Chrome browser profiles",
        ),
        _rule(
            "edge_profile",
            "browser_store",
            "directory",
            relativepaths=[
                r"AppData\Local\Microsoft\Edge\User Data\Default",
                r"AppData\Local\Microsoft\Edge\User Data\Profile *",
            ],
            browserprofile=True,
            browser="edge",
            downloadrecursive=True,
            downloadexclusions=CHROMIUM_EXCLUSIONS,
            description="Edge browser profiles",
        ),
        _rule(
            "firefox_profile",
            "browser_store",
            "directory",
            relativepaths=[r"AppData\Roaming\Mozilla\Firefox\Profiles\*"],
            browserprofile=True,
            browser="firefox",
            downloadrecursive=True,
            downloadexclusions=FIREFOX_EXCLUSIONS,
            description="Firefox browser profiles",
        ),
        _rule(
            "dpapi_protect_files",
            "dpapi_material",
            "file",
            relativepaths=[r"AppData\Roaming\Microsoft\Protect\*\*"],
            triageable=False,
            description="DPAPI Protect files",
        ),
        _rule(
            "windows_credential_files",
            "dpapi_material",
            "file",
            relativepaths=[
                r"AppData\Local\Microsoft\Credentials\*",
                r"AppData\Roaming\Microsoft\Credentials\*",
            ],
            triageable=False,
            description="Windows credential files",
        ),
        _rule(
            "windows_vault_files",
            "dpapi_material",
            "file",
            relativepaths=[
                r"AppData\Local\Microsoft\Vault\*\*",
                r"AppData\Roaming\Microsoft\Vault\*\*",
            ],
            triageable=False,
            description="Windows Vault files",
        ),
        _rule(
            "wsl_distribution",
            "identity_material_container",
            "file",
            relativepaths=[
                r"AppData\Local\Packages\*\LocalState\ext4.vhdx",
                r"AppData\Local\lxss\*",
            ],
            triageable=False,
            downloadable=False,
            description="WSL filesystem containers",
        ),
    ]


def filter_rules_by_disabled_categories(
    rules: list[ArtifactRule], disabled_categories: list[str] | tuple[str, ...] | set[str]
) -> list[ArtifactRule]:
    disabled = {category.lower() for category in disabled_categories}
    return [rule for rule in rules if rule.category.lower() not in disabled]


def get_effective_artifact_rules(disabled_categories: list[str] | None = None) -> list[ArtifactRule]:
    return filter_rules_by_disabled_categories(
        get_default_artifact_rules(), disabled_categories or []
    )


def print_artifact_catalog(rules: list[ArtifactRule], verbose: bool = False) -> None:
    for rule in rules:
        triage = "yes" if rule.triageable else "no"
        download = "yes" if rule.downloadable else "no"
        print(f"{rule.artifacttype:28} {rule.category:28} triage={triage} download={download}")
        if verbose:
            if rule.relativepaths:
                print(f"  paths: {', '.join(rule.relativepaths)}")
            if rule.searchroots:
                print(f"  search roots: {', '.join(rule.searchroots)}")
            if rule.filenamepatterns:
                print(f"  filename patterns: {', '.join(rule.filenamepatterns)}")
            if rule.recursive:
                print(f"  recursive: yes, maxdepth={rule.maxdepth}")
            if rule.downloadexclusions:
                print(f"  download exclusions: {', '.join(rule.downloadexclusions)}")
