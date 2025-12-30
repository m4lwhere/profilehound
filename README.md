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

BloodHound's `HasSession` edge is great, but it's only useful when a user is logged into a machine. If a user is not logged into a machine when the data is collected, it's much more difficult to find which computer may contain secrets to facilitate further exploitation. User profiles may contain a significant amount of valuable intel within DPAPI, cached credentials, SSH keys, cloud keys, and more - these don't require an active user session to access.

![HasUserProfile Edge Example](/images/1.png)

ProfileHound uses BloodHound's [OpenGraph format](https://bloodhound.specterops.io/opengraph/overview) to build a new graph edge called `HasUserProfile` which determines if a user profile exists on a domain machine. This can help operators focus on machines where a high-value user or group has a profile.

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
profilehound --auth-user alice --auth-password whiteRabbit --auth-domain sccm.lab --dns 192.168.57.10 --auth-dc-ip 192.168.57.10
    ____             _____ __     __  __                      __
   / __ \_________  / __(_) /__  / / / /___  __  ______  ____/ /
  / /_/ / ___/ __ \/ /_/ / / _ \/ /_/ / __ \/ / / / __ \/ __  /
 / ____/ /  / /_/ / __/ / /  __/ __  / /_/ / /_/ / / / / /_/ /
/_/   /_/   \____/_/ /_/_/\___/_/ /_/\____/\__,_/_/ /_/\__,_/    v0.1.0
@m4lwhere

BloodHound CE OpenGraph collector for user profiles stored on domain machines.

[2025-12-29 16:59:58] [INFO] Loaded 4 targets
[2025-12-29 16:59:58] [INFO] Successful authentication on CLIENT.sccm.lab (192.168.57.13) as sccm.lab\alice
[2025-12-29 16:59:59] [INFO] Successfully connected to share \\CLIENT.sccm.lab\C$ as sccm.lab\alice
[2025-12-29 16:59:59] [INFO] Enumerating profiles in \\CLIENT.sccm.lab\C$\Users\...
[2025-12-29 16:59:59] [INFO]     alice: S-1-5-21-3016982856-3796307652-1246469985-1112  created:2025-12-26      modified:2025-12-28
[2025-12-29 16:59:59] [INFO]     sccm-account-da:       S-1-5-21-3016982856-3796307652-1246469985-1119  created:2025-12-26      modified:2025-11-07
[2025-12-29 16:59:59] [INFO] Found 2 domain profile(s) for CLIENT.sccm.lab
[2025-12-29 16:59:59] [INFO] Successful authentication on DC.sccm.lab (192.168.57.10) as sccm.lab\alice
[2025-12-29 16:59:59] [INFO] Successfully connected to share \\DC.sccm.lab\C$ as sccm.lab\alice
[2025-12-29 16:59:59] [INFO] Enumerating profiles in \\DC.sccm.lab\C$\Users\...
[2025-12-29 16:59:59] [INFO] No domain profiles found for DC.sccm.lab
[2025-12-29 16:59:59] [INFO] Successful authentication on MECM.sccm.lab (192.168.57.11) as sccm.lab\alice
[2025-12-29 16:59:59] [INFO] Successfully connected to share \\MECM.sccm.lab\C$ as sccm.lab\alice
[2025-12-29 16:59:59] [INFO] Enumerating profiles in \\MECM.sccm.lab\C$\Users\...
[2025-12-29 16:59:59] [INFO]     alice: S-1-5-21-3016982856-3796307652-1246469985-1112  created:2025-12-28      modified:2025-11-07
[2025-12-29 16:59:59] [INFO]     eve:   S-1-5-21-3016982856-3796307652-1246469985-1116  created:2025-12-27      modified:2025-11-07
[2025-12-29 16:59:59] [INFO] Found 2 domain profile(s) for MECM.sccm.lab
[2025-12-29 16:59:59] [INFO] Successful authentication on MSSQL.sccm.lab (192.168.57.12) as sccm.lab\alice
[2025-12-29 16:59:59] [INFO] Successfully connected to share \\MSSQL.sccm.lab\C$ as sccm.lab\alice
[2025-12-29 16:59:59] [INFO] Enumerating profiles in \\MSSQL.sccm.lab\C$\Users\...
[2025-12-29 16:59:59] [INFO]     alice: S-1-5-21-3016982856-3796307652-1246469985-1112  created:2025-12-28      modified:2025-12-28
[2025-12-29 16:59:59] [INFO]     franck:        S-1-5-21-3016982856-3796307652-1246469985-1117  created:2025-12-27      modified:2025-11-07
[2025-12-29 16:59:59] [INFO] Found 2 domain profile(s) for MSSQL.sccm.lab
[2025-12-29 16:59:59] [INFO] Found 3 targets with profiles
[2025-12-29 16:59:59] [INFO] Exported OpenGraph intel to profilehound_20251229-165958.json
```

This created a file called `profilehound_20251229-165958.json` in the current directory. This file can be imported directly into BHCE by dragging and dropping the file into the BloodHound UI. It will automatically be parsed and correlate nodes via SID. The new edge `HasUserProfile` will be created to show the relationship between the user and the profile.

# How it Works
ProfileHound uses the `C$` share to enumerate user profiles on a domain machine at `\\<target>\C$\Users\`. It will read the user's `NTUSER.DAT` file to determine if the user is a domain account or local account by retrieving the SID from the file metadata. For example, it will gather all user directories at `\\<target>\C$\Users\` and then loop over each directory to find the `NTUSER.DAT` file at `\\<target>\C$\Users\<username>\NTUSER.DAT`. If the `NTUSER.DAT` file is owned by a well-known SID, it will try to find the user's SID by reading their DPAPI directory (e.g. `\\<target>\C$\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>`).

Because we are reaching the `C$` share, we need an administrative account to authenticate to the target machine. ProfileHound will use the credentials provided to authenticate to the target machine. If you are using a domain account, you can use the `--auth-domain` option to specify the domain. If you are using a local account, you can use the `--auth-local` option. 

The creation and last modified times of the `NTUSER.DAT` file are gathered and can be used to determine if the profile is active. This correlation is handled within cypher queries on the edge properties, examples are below.

It's interesting to note that if the `NTUSER.DAT` file is last modified before the creation date, it is likely that the profile was created but not used in a tangible way. This condition exists because the `NTUSER.DAT` file is copied from the `C:\Users\Default` profile when a new user profile is created, maintaining the same modified date even though the creation date is later. Because of this, we can be reasonably confident that specific profile will not contain any secrets. 

## Selecting Targets
ProfileHound uses @podalirius_ 's [ShareHound](https://github.com/p0dalirius/ShareHound) as a library to enumerate targets. If no `--target` or `--target-file` options are provided, ProfileHound will enumerate targets by connecting to LDAP to gather all machine FQDNs in the domain automatically.

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
WHERE e.profileModified > (datetime().epochseconds - (active_days * 86400))
RETURN p
```

### Active User Profiles within a Specific Group (Powerful)
This is an extremely powerful query to locate specific user profiles used within the last 3 days for members of a specific group.

```cypher
WITH 3 as active_days, "administrators" as group_name
MATCH p = (g:Group)<-[:MemberOf*1..]-(u:User)-[e:HasUserProfile]-(c:Computer)
WHERE e.profileModified > (datetime().epochseconds - (active_days * 86400)) AND toLower(g.samaccountname) = group_name
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