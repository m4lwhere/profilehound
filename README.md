```
    ____             _____ __     __  __                      __
   / __ \_________  / __(_) /__  / / / /___  __  ______  ____/ /
  / /_/ / ___/ __ \/ /_/ / / _ \/ /_/ / __ \/ / / / __ \/ __  /
 / ____/ /  / /_/ / __/ / /  __/ __  / /_/ / /_/ / / / / /_/ /
/_/   /_/   \____/_/ /_/_/\___/_/ /_/\____/\__,_/_/ /_/\__,_/
```
# ProfileHound
ProfileHound is a post-escalation tool to help find and achieve red-teaming objectives by locating domain user profiles on machines. It uses the BloodHound OpenGraph format to build a new edge called `HasUserProfile` which determines if a user profile exists on a computer. This edge allows operators to make informed decisions about which computers to target for looting secrets.

This tool requires administrative access to the `C$` share on target machines to enumerate user profiles.

Huge thank you to Remi Gascou ([@podalirius](https://github.com/p0dalirius)) for the [ShareHound](https://github.com/p0dalirius/ShareHound) and [bhopengraph](https://github.com/p0dalirius/bhopengraph) tools. I've wanted to build a tool to collect this data for a while and using these libraries allowed me to focus on building instead of plumbing. 

> [!WARNING]
> ProfileHound is in early stages of development and does not have all collection modes implemented yet. Use with caution in production environments, you assume the risk of using this tool.

## Why?
Post-exploitation objectives in Active Directory have shifted from data stored on-site into SaaS applications and the cloud. To prove value in offsec, we need to demonstrate how access to these services can be compromised. In many cases, these services are used only by certain groups or users, such as HR, Finance, etc. In some scenarios, certain SaaS applications can only be accessed from specific machines.

BloodHound's `HasSession` edge is great, but it's only useful when a user is logged into a machine. If a user is not logged into a machine when the data is collected, it can be difficult to find which computer may contain secrets to facilitate further exploitation. User profiles may contain a significant amount of valuable intel within DPAPI, cached credentials, SSH keys, cloud keys, and more - these don't require an active user session to access.

![HasUserProfile Edge Example](/images/1.png)

ProfileHound uses BloodHound's [OpenGraph format](https://bloodhound.specterops.io/opengraph/overview) to build a new graph edge called `HasUserProfile` which determines if a user profile exists on a domain machine. This can help operators focus on machines where a high-value user or group has a profile.

The `HasUserProfile` edge contains properties for the profile’s creation date and last modified date. That information helps to determine:
- If a profile is actively used (logged in within last few days)
- If the profile has been used for years (likely to contain lots of secrets!)

![HasUserProfile Edge Properties Example](/images/2.png)


This edge also has properties for the profile creation and modification timestamps, allowing specific Cypher queries to find active or long-term user profiles on specific machines.

## Installation
Install ProfileHound using `pipx` (unless you enjoy dependency hell):

```bash
pipx install profilehound
```

To use the bleeding edge version, you can install from source:

```bash
pipx install git+https://github.com/m4lwhere/profilehound.git
```

### Docker
To use a containerized approach, build the image and run the tool with the following:

```bash
docker build -t profilehound .
docker run --rm profilehound --help
docker run --rm -v ${PWD}:/profilehound profilehound --auth-user alice --auth-password whiteRabbit --auth-domain sccm.lab --dns 192.168.57.10 --auth-dc-ip 192.168.57.10
```

## Usage



For example, to run using a Domain Admin account `sccm.lab\alice` with password `whiteRabbit`:
```
$ profilehound --auth-user alice --auth-password whiteRabbit --auth-domain sccm.lab --target 192.168.57.0/27
    ____             _____ __     __  __                      __
   / __ \_________  / __(_) /__  / / / /___  __  ______  ____/ /
  / /_/ / ___/ __ \/ /_/ / / _ \/ /_/ / __ \/ / / / __ \/ __  /
 / ____/ /  / /_/ / __/ / /  __/ __  / /_/ / /_/ / / / / /_/ /
/_/   /_/   \____/_/ /_/_/\___/_/ /_/\____/\__,_/_/ /_/\__,_/    v0.1.1
@m4lwhere

BloodHound CE OpenGraph collector for user profiles stored on domain machines.

[12/30/25 11:58:05] INFO     Loaded 32 targets
[12/30/25 11:58:08] INFO     Successful authentication on 192.168.57.10 (192.168.57.10) as sccm.lab\alice
                    INFO     Successfully connected to share \\192.168.57.10\C$ as sccm.lab\alice
                    INFO     Enumerating profiles in \\192.168.57.10\C$\Users\...
                    INFO         vagrant:    S-1-5-21-3016982856-3796307652-1246469985-1000  created:2025-11-07      modified:2025-11-07
                    INFO     Found 1 domain profile(s) for 192.168.57.10
                    INFO     Successful authentication on 192.168.57.11 (192.168.57.11) as sccm.lab\alice
[12/30/25 11:58:09] INFO     Successfully connected to share \\192.168.57.11\C$ as sccm.lab\alice
                    INFO     Enumerating profiles in \\192.168.57.11\C$\Users\...
                    INFO         administrator:      S-1-5-21-3016982856-3796307652-1246469985-500   created:2025-11-07      modified:2025-11-07
                    INFO         alice:      S-1-5-21-3016982856-3796307652-1246469985-1112  created:2025-12-28      modified:2025-11-07
                    INFO         eve:        S-1-5-21-3016982856-3796307652-1246469985-1116  created:2025-12-27      modified:2025-11-07
                    INFO     Found 3 domain profile(s) for 192.168.57.11
                    INFO     Successful authentication on 192.168.57.12 (192.168.57.12) as sccm.lab\alice
                    INFO     Successfully connected to share \\192.168.57.12\C$ as sccm.lab\alice
                    INFO     Enumerating profiles in \\192.168.57.12\C$\Users\...
                    INFO         alice:      S-1-5-21-3016982856-3796307652-1246469985-1112  created:2025-12-28      modified:2025-12-28
                    INFO         franck:     S-1-5-21-3016982856-3796307652-1246469985-1117  created:2025-12-27      modified:2025-11-07
                    INFO         sccm-sql:   S-1-5-21-3016982856-3796307652-1246469985-1121  created:2025-11-07      modified:2025-11-07
                    INFO     Found 3 domain profile(s) for 192.168.57.12
                    INFO     Successful authentication on 192.168.57.13 (192.168.57.13) as sccm.lab\alice
                    INFO     Successfully connected to share \\192.168.57.13\C$ as sccm.lab\alice
                    INFO     Enumerating profiles in \\192.168.57.13\C$\Users\...
                    INFO         alice:      S-1-5-21-3016982856-3796307652-1246469985-1112  created:2025-12-26      modified:2025-12-28
                    INFO         sccm-account-da:    S-1-5-21-3016982856-3796307652-1246469985-1119  created:2025-12-26      modified:2025-11-07
                    INFO     Found 2 domain profile(s) for 192.168.57.13
[12/30/25 11:59:27] INFO     Found 4 machines with profiles
                    INFO     Exported OpenGraph intel to profilehound_20251230-115805.json
```
This created a file called `profilehound_20251230-115805.json` in the current directory. This file can be imported directly into BHCE by dragging and dropping the file into the BloodHound UI. It will automatically be parsed and correlate nodes via SID. The new edge `HasUserProfile` will be created to show the relationship between the user and the profile.

### SMB workers and preflight

ProfileHound uses host-level SMB worker threads to speed up collection across large target sets. `--smb-workers` controls the maximum number of concurrent target collections and defaults to `4`.

Before starting the worker pool, ProfileHound runs a full preflight collection against the first target that can complete the real collection path. This preflight performs the same work as a normal target collection: resolve the target, authenticate, access `C$`, query machine SID context, enumerate profiles, and collect profile artifacts unless `--no-artifacts` is set. When the preflight succeeds, ProfileHound starts threaded collection for the remaining targets and prints a message like:

```text
SMB preflight: testing full collection on one target before starting threaded collection
SMB preflight succeeded on <target>; starting threaded SMB collection with 4 worker(s) across <n> remaining target(s)
```

Workers are scoped to hosts, not profiles or artifact rules. Each worker owns one target's SMB connection and completes that host's profile and artifact collection serially inside the connection. This avoids sharing impacket SMB connection objects across threads while still reducing wall-clock time in large environments where many hosts are offline, slow, or denied at `C$`.

If a domain authentication failure occurs after the worker pool starts, ProfileHound stops submitting new targets, cancels pending work where possible, lets already-running workers finish, and exports partial results if any profiles were already collected. At most `--smb-workers` target authentications can be in flight when this happens. Use `--smb-ignore-failed-domain-auth` only when continuing after those failures is acceptable for the engagement.

### Authentication (NTLM, pass-the-hash, Kerberos)

By default ProfileHound authenticates with NTLM using `--auth-password`. For pass-the-hash, pass `--auth-hashes LMHASH:NTHASH` (a bare NT hash without a colon is also accepted).

Kerberos is supported with `-k` / `--kerberos`. Because Kerberos service tickets are issued for `cifs/<hostname>`, **targets must be FQDNs** and `--auth-dc-ip` should point at the KDC (usually the domain controller). Three Kerberos flows are supported:

```bash
# Password -> Kerberos TGT
profilehound -k --auth-user robb.stark --auth-password sexywolfy \
  --auth-domain north.sevenkingdoms.local --auth-dc-ip 192.168.56.11 \
  --dns-server 192.168.56.11 --target winterfell.north.sevenkingdoms.local

# Overpass-the-hash (NT hash -> Kerberos TGT)
profilehound -k --auth-user robb.stark --auth-hashes :<nthash> \
  --auth-domain north.sevenkingdoms.local --auth-dc-ip 192.168.56.11 --dns-server 192.168.56.11 \
  --target winterfell.north.sevenkingdoms.local

# Pass-the-key (AES128/256)
profilehound -k --auth-user robb.stark --aes-key <hex-key> \
  --auth-domain north.sevenkingdoms.local --auth-dc-ip 192.168.56.11 --dns-server 192.168.56.11 \
  --target winterfell.north.sevenkingdoms.local

# Pass-the-ticket (existing TGT in a ccache)
export KRB5CCNAME=/path/to/robb.ccache
profilehound -k --no-pass --auth-user robb.stark \
  --auth-domain north.sevenkingdoms.local --auth-dc-ip 192.168.56.11 --dns-server 192.168.56.11 \
  --target winterfell.north.sevenkingdoms.local
```

If Kerberos fails with a clock-skew error, sync the host clock with the DC (for example `ntpdate <dc>` or run under `faketime`). A failed domain pre-authentication with a real secret stops the run to avoid account lockout, the same as an NTLM domain-auth failure; use `--smb-ignore-failed-domain-auth` to continue anyway.

Kerberos works with the same host-level SMB worker model. Credential-based Kerberos runs acquire one TGT up front and reuse it for per-host service tickets; each worker receives its own TGT dictionary copy when calling impacket. Kerberos targets should be provided as FQDNs. Raw IP or CIDR targets only work for Kerberos when reverse DNS can reliably map each IP to the correct hostname/SPN.

Artifact collection adds graph-safe artifact summary properties to the OpenGraph output. ProfileHound collapses artifact graph nodes to one `ProfileArtifact` node per user SID and artifact type. The node `name` is the artifact type, for example `dpapi_protect_files`, and its `artifactid` is stable for that `(usersid, artifacttype)` pair.

Per-computer and per-folder evidence lives on `FoundOn` edges from the collapsed artifact node to each linked computer. Those edges include folder/path fields such as `profilepath`, `profilepaths`, `profilefolder`, and `profilefolders`, plus `findingid` or `findingids` values that join to the detailed sidecar evidence.

ProfileHound does not write the detailed `.artifacts.json` evidence sidecar unless `--artifact-sidecar` is set. `--artifact-download-files` implies `--artifact-sidecar` so downloaded evidence has a paired manifest. In the sidecar, `artifacts[artifactid]` stores the collapsed artifact summary and `artifacts[artifactid]["findings"][findingid]` stores the per-computer/profile evidence, triage, and download details.

For a collection-only artifact run with detailed evidence, use `--artifact-sidecar` without `--artifact-triage`:

```bash
profilehound --auth-user alice --auth-password whiteRabbit --auth-domain sccm.lab \
  --target 192.168.57.13 --artifact-sidecar -o profilehound_collection.json
```

`--artifact-triage` is optional. It adds bounded text-derived indicators to the sidecar for triageable artifacts, but raw file contents and raw secrets are not stored in BloodHound.

The built-in artifact catalog also includes an `ai_agent` category for AI coding agents, AI coding harnesses, MCP configuration, project instruction files, and AI provider credential locations. These findings are location metadata by default; ProfileHound graphs where the files live, but does not store raw API keys or secret values in BloodHound. Downloading matched evidence still requires `--artifact-download-files`.

### Profile Artifact Custom Icons

ProfileHound emits profile artifact nodes with a category-specific primary kind, plus the generic `ProfileArtifact` kind for compatibility with existing Cypher queries. For example, a remote access finding is emitted with kinds similar to:

```json
["ProfileArtifactRemoteAccess", "ProfileArtifact", "Base"]
```

BloodHound uses the first kind as the visual node type. To make those ProfileHound artifact categories render with distinct icons, upload the bundled icon definition pack to the BloodHound custom nodes API once per BloodHound instance. This is separate from importing ProfileHound collection JSON.

The icon definition pack is [ProfileHound_Artifact_Icons.json](/BloodHound_Custom_Icons/ProfileHound_Artifact_Icons.json), and the repository includes a helper uploader at [upload_profilehound_artifact_icons.py](/BloodHound_Custom_Icons/upload_profilehound_artifact_icons.py).

The bundled pack defines node types for every built-in artifact category:

```text
ProfileArtifactCommandHistory
ProfileArtifactEditorRecovery
ProfileArtifactRemoteAccess
ProfileArtifactCloudCli
ProfileArtifactDeveloperSecret
ProfileArtifactInfrastructureAsCode
ProfileArtifactPasswordVault
ProfileArtifactVpnConfig
ProfileArtifactBrowserStore
ProfileArtifactDpapiMaterial
ProfileArtifactIdentityMaterialContainer
ProfileArtifactAiAgent
```

The generic `ProfileArtifact` icon remains in the pack as the fallback for unknown categories.

#### Upload with the bundled helper

Create a BloodHound bearer token, then run:

```bash
python BloodHound_Custom_Icons/upload_profilehound_artifact_icons.py \
  --url http://127.0.0.1:8080 \
  --token <token>
```

The helper accepts either a BloodHound base URL or the full `/api/v2/custom-nodes` endpoint. It uploads all ProfileHound artifact icon definitions in one request. A successful upload prints the number of definitions uploaded and the HTTP status code.

You can also provide the URL and token through environment variables:

```bash
BLOODHOUND_URL=http://127.0.0.1:8080 \
BLOODHOUND_TOKEN=<token> \
python BloodHound_Custom_Icons/upload_profilehound_artifact_icons.py
```

For local HTTPS with a self-signed certificate, add `--insecure`:

```bash
python BloodHound_Custom_Icons/upload_profilehound_artifact_icons.py \
  --url https://127.0.0.1:8080 \
  --token <token> \
  --insecure
```

If the icon payload is in a different location, pass it explicitly:

```bash
python BloodHound_Custom_Icons/upload_profilehound_artifact_icons.py \
  --url http://127.0.0.1:8080 \
  --token <token> \
  --payload BloodHound_Custom_Icons/ProfileHound_Artifact_Icons.json
```

#### Upload without a repository checkout

If ProfileHound is installed but the repository files are not available, generate the same icon payload with:

```bash
profilehound --print-custom-icons > profilehound_artifact_icons.json
```

Then upload it with `curl`:

```bash
curl -k -X POST http://127.0.0.1:8080/api/v2/custom-nodes \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data @profilehound_artifact_icons.json
```

You can upload the icon pack before or after importing ProfileHound OpenGraph data. Existing ProfileHound artifact nodes will use the custom icons after BloodHound has the matching custom node definitions.

ProfileHound will additionally print a small summary of statistics to the console once completed:
```
╭───────────────────────── General Summary ──────────────────────────────╮
│        ProfileHound Statistics                                         │
│  Total Targets with Profiles    4                                      │
│  Total Unique Profiles (Users)  7                                      │
│  Average Profiles per Target    2.25                                   │
╰────────────────────────────────────────────────────────────────────────╯
       Top Connected Users
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ User          ┃ Machine Count ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ alice         │ 3             │
│ vagrant       │ 1             │
│ administrator │ 1             │
│ eve           │ 1             │
│ franck        │ 1             │
└───────────────┴───────────────┘
     Top Populated Machines
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Machine       ┃ Profile Count ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ 192.168.57.11 │ 3             │
│ 192.168.57.12 │ 3             │
│ 192.168.57.13 │ 2             │
│ 192.168.57.10 │ 1             │
└───────────────┴───────────────┘
                       Oldest User Profiles
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ User            ┃ Machine         ┃ Created    ┃ Last Modified ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ vagrant         │ DC.sccm.lab     │ 2025-11-07 │ 2025-11-07    │
│ sccm-sql        │ MSSQL.sccm.lab  │ 2025-11-07 │ 2025-11-07    │
│ administrator   │ MECM.sccm.lab   │ 2025-11-07 │ 2025-11-07    │
│ sccm-account-da │ CLIENT.sccm.lab │ 2025-12-26 │ 2025-11-07    │
│ alice           │ CLIENT.sccm.lab │ 2025-12-26 │ 2025-12-28    │
└─────────────────┴─────────────────┴────────────┴───────────────┘
                Longest Lived Profiles (Created -> Modified)
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ User          ┃ Machine         ┃ Age (Days) ┃ Created    ┃ Last Modified ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ alice         │ CLIENT.sccm.lab │ 1.8        │ 2025-12-26 │ 2025-12-28    │
│ alice         │ MSSQL.sccm.lab  │ 0.0        │ 2025-12-28 │ 2025-12-28    │
│ sccm-sql      │ MSSQL.sccm.lab  │ 0.0        │ 2025-11-07 │ 2025-11-07    │
│ administrator │ MECM.sccm.lab   │ 0.0        │ 2025-11-07 │ 2025-11-07    │
│ vagrant       │ DC.sccm.lab     │ 0.0        │ 2025-11-07 │ 2025-11-07    │
└───────────────┴─────────────────┴────────────┴────────────┴───────────────┘
                     Top 5 Machines to Focus On (Hubs)
┏━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Machine         ┃ Score ┃ Reason                                         ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ MECM.sccm.lab   │ 4.5   │ Has 3 profiles, potential lateral movement hub │
│ MSSQL.sccm.lab  │ 4.5   │ Has 3 profiles, potential lateral movement hub │
│ CLIENT.sccm.lab │ 3.5   │ Has 2 profiles, potential lateral movement hub │
│ DC.sccm.lab     │ 1.0   │ Has 1 profiles, potential lateral movement hub │
└─────────────────┴───────┴────────────────────────────────────────────────┘
```


# How it Works
ProfileHound uses the `C$` share to enumerate user profiles on a domain machine at `\\<target>\C$\Users\`. It will read the user's `NTUSER.DAT` file to determine if the user is a domain account or local account by retrieving the SID from the file metadata. For example, it will gather all user directories at `\\<target>\C$\Users\` and then loop over each directory to find the `NTUSER.DAT` file at `\\<target>\C$\Users\<username>\NTUSER.DAT`. If the `NTUSER.DAT` file is owned by a well-known SID, it will try to find the user's SID by reading their DPAPI directory (e.g. `\\<target>\C$\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>`).

Additionally, ProfileHound will now search for common high-value file types for latent identity material. This covers things such as multiple browser profiles, SSH keys, cloud credentials, and many more. These are stored in `src/profilehound/modules/artifacts/catalog.py` and can be modified for further artifact types.

Because we are reaching the `C$` share, we need an administrative account to authenticate to the target machine. ProfileHound will use the credentials provided to authenticate to the target machine. If you are using a domain account, you can use the `--auth-domain` option to specify the domain. If you are using a local account, you can use the `--smb-local-auth` option.

By default, ProfileHound stops after an SMB domain authentication failure to reduce account lockout risk. If some endpoints are expected to reject domain authentication and you want to continue scanning the remaining targets, use `--smb-ignore-failed-domain-auth`.

If ProfileHound stops during SMB data collection after profiles have already been found, it will attempt to export the partial OpenGraph results before exiting.

The creation and last modified times of the `NTUSER.DAT` file are gathered and can be used to determine if the profile is active. This correlation is handled within cypher queries on the edge properties, examples are below.

It's interesting to note that if the `NTUSER.DAT` file is last modified before the creation date, it is likely that the profile was created but not used in a tangible way. This condition exists because the `NTUSER.DAT` file is copied from the `C:\Users\Default` profile when a new user profile is created, maintaining the same modified date even though the creation date is later. Because of this, we can be reasonably confident that specific profile will not contain any secrets. 

## Selecting Targets
ProfileHound uses @podalirius_ 's [ShareHound](https://github.com/p0dalirius/ShareHound) as a library to enumerate targets. If no `--target` or `--target-file` options are provided, ProfileHound will enumerate targets by connecting to LDAP to gather all machine FQDNs in the domain automatically.

For NTLM or pass-the-hash collection, targets can be IPs, FQDNs, CIDRs, or files accepted by ShareHound. For Kerberos collection, prefer FQDN target lists because Kerberos service tickets are bound to host SPNs. ShareHound sorts and deduplicates targets before collection, so the first successful preflight target is determined by the normalized target order, not necessarily the order typed on the command line.

# Fun Queries
There's a lot of powerful conclusions we can gather from this data, telling us where we should focus our attention. All of these queries can be imported into BloodHound by dragging and dropping [the ProfileHound_Cypher_Queries.zip file](/BloodHound_Queries/ProfileHound_Cypher_Queries.zip) into the BloodHound UI using the **Import** button on the **Saved Queries** page.
Here are a few examples:

### Find all User Profile Edges
This is a simple query that will find all user profiles in the graph.

```cypher
MATCH p=(u:User)-[:HasUserProfile]->(c:Computer)
RETURN p
```

### Find User Profiles by Group Name
This will find all user profiles that are members of the domain "Administrators" group.

```cypher
MATCH p=(g:Group)<-[:MemberOf*1..]-(u:User)-[:HasUserProfile]->(c:Computer)
WHERE toLower(g.samaccountname) = "administrators"
RETURN p
```

### Find User Profiles Active within last 3 Days
This will find all user profiles that have been modified within the last 3 days. This helps determine where a user profile might be a user's primary machine and have good loot.

```cypher
WITH 3 as active_days
MATCH p = (u:User)-[e:HasUserProfile]-(c:Computer)
WHERE e.profileModified > (datetime().epochSeconds - (active_days * 86400))
RETURN p
```

### Active User Profiles within a Specific Group (Powerful)
This is an extremely powerful query to locate specific user profiles used within the last 3 days for members of a specific group.

```cypher
WITH 3 as active_days, "administrators" as group_name
MATCH p = (g:Group)<-[:MemberOf*1..]-(u:User)-[e:HasUserProfile]-(c:Computer)
WHERE e.profileModified > (datetime().epochSeconds - (active_days * 86400)) AND toLower(g.samaccountname) = group_name
RETURN p
```

### Remove Unused User Profiles
This will remove any user profiles where the `NTUSER.DAT` file is modified before the creation date. This indicates that the profile was created, but not used in a tangible way. This condition exists because the `NTUSER.DAT` file is copied from the `C:\Users\Default` profile when a new user profile is created, maintaining the same modified date even though the creation date is later.

```cypher
match p = (u:User)-[e:HasUserProfile]-(c:Computer)
where e.profileCreated < e.profileModified
return p
```

# Credits
This simply wouldn't be possible without Remi Gascou's ([@podalirius](https://github.com/p0dalirius)) [ShareHound](https://github.com/p0dalirius/ShareHound) and [bhopengraph](https://github.com/p0dalirius/bhopengraph) libraries. 

# Future Improvements
The focus on this tool is determining which machines are most likely to contain secrets for specific users. Future improvements will include:

- [ ] Implement @garrettfoster13's [SCCMHunter](https://github.com/garrettfoster13/sccmhunter) as a library to improve data collection.
  - [ ] Use `get_lastlogon` function to create `HasUserProfile` edges on machines.
  - [ ] Use `get_puser` function to associate domain users as primary device owners for specific machines.
- [ ] Implement Azure AD device ownership correlation from AzureHound. 
  - [ ] This seems to be already collected as an `AZDeviceOwner` object at `.data.owners[owner.DeviceOwner.onPremisesSecurityIdentifier]`
- [ ] Use [ShareHound](https://github.com/p0dalirius/ShareHound) to spider for sensitive files in matching profiles and ingest into the graph.
- [ ] Mine the `NTUSER.DAT` file for recent programs, documents, and browser activity.
