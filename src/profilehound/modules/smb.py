#!/usr/bin/env python3
"""
SMB User Profile Enumerator

Enumerates user profile directories on a remote Windows host via SMB and retrieves
the owner SID for each profile's NTUSER.DAT file. Filters to return only domain
accounts by comparing the owner SID against the local machine SID.

"""

from __future__ import annotations

import struct
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import (
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_DIRECTORY_FILE,
    FILE_OPEN,
)
from impacket.smb3structs import (
    FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE,
    FILE_NON_DIRECTORY_FILE,
    SMB2_0_INFO_SECURITY,
    SMB2_0_INFO_FILE,
    SMB2_SEC_INFO_00,
)
from impacket.ldap import ldaptypes
from impacket.dcerpc.v5 import transport, lsad, lsat
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException

# Security descriptor request flags
OWNER_SECURITY_INFORMATION = 0x00000001
POLICY_VIEW_LOCAL_INFORMATION = 0x00000001
POLICY_LOOKUP_NAMES = 0x00000800
READ_CONTROL = 0x00020000

# Well-known local/built-in SID prefixes to skip
SKIP_SID_PREFIXES = (
    "S-1-5-18",  # LOCAL SYSTEM
    "S-1-5-19",  # LOCAL SERVICE
    "S-1-5-20",  # NETWORK SERVICE
    "S-1-5-32-",  # BUILTIN domain
)

# Default profile directories to skip (system profiles)
SKIP_PROFILE_NAMES = {
    ".",
    "..",
    "Default",
    "Default User",
    "Public",
    "All Users",
}

logger = logging.getLogger("profilehound")


def get_machine_domain_sid(smb: SMBConnection, target: str) -> Optional[str]:
    """
    Query the machine's domain object SID via LSA RPC (\\pipe\\lsarpc).
    If the machine's domain object SID is the same as the local machine SID, it might be a DC.

    This returns the SID prefix for domain accounts.
    """
    try:
        # Build RPC transport over existing SMB connection
        rpctransport = transport.SMBTransport(
            smb.getRemoteHost(),
            445,
            r"\lsarpc",
            smb_connection=smb,
        )
        logger.debug(rf"Querying {target} domain SID via LSA RPC \lsarpc")
        dce = rpctransport.get_dce_rpc()
        policy_handle = None

        dce.connect()
        logger.debug("Connected to LSA RPC")

        # Impacket's own lookupsid example binds LSAT first, then calls LSAD helpers on the same DCE handle. :contentReference[oaicite:1]{index=1}
        dce.bind(lsat.MSRPC_UUID_LSAT)
        logger.debug("Bound to LSAT")

        # Need LOOKUP_NAMES so we can resolve HOSTNAME$ -> SID
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policy_handle = resp["PolicyHandle"]

        # Prefer DNS-domain info (domain joined), fall back to primary domain info.
        netbios_domain = None
        domain_sid = None
        try:
            info = lsad.hLsarQueryInformationPolicy2(
                dce,
                policy_handle,
                lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation,
            )["PolicyInformation"]["PolicyDnsDomainInfo"]
            netbios_domain = str(info["Name"])
            domain_sid = (
                info["Sid"].formatCanonical() if info["Sid"] is not None else None
            )
            # logger.debug(f"Machine's Domain SID: {domain_sid}")
        except Exception:
            info = lsad.hLsarQueryInformationPolicy2(
                dce,
                policy_handle,
                lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation,
            )["PolicyInformation"]["PolicyPrimaryDomainInfo"]
            netbios_domain = str(info["Name"])
            domain_sid = (
                info["Sid"].formatCanonical() if info["Sid"] is not None else None
            )

        if not domain_sid or domain_sid.startswith("S-1-0-0"):
            raise RuntimeError(
                "Target does not appear domain-joined (no primary domain SID returned)."
            )

        # Machine SAMAccountName in AD is HOSTNAME$
        host = (smb.getRemoteName() or "").rstrip("\x00")
        machine_sam = host if host.endswith("$") else (host + "$")

        # Try unqualified and DOMAIN\\HOSTNAME$ forms.
        candidates = [machine_sam]
        if netbios_domain:
            candidates.append(f"{netbios_domain}\\{machine_sam}")

        lookup_fn = (
            getattr(lsat, "hLsarLookupNames3", None)
            or getattr(lsat, "hLsarLookupNames2", None)
            or getattr(lsat, "hLsarLookupNames", None)
        )
        if lookup_fn is None:
            raise RuntimeError(
                "No hLsarLookupNames* helper found in your impacket lsat.py."
            )

        last_err = None
        for name in candidates:
            try:
                r = lookup_fn(dce, policy_handle, (name,))
                sid = r["TranslatedSids"]["Sids"][0]["Sid"].formatCanonical()

                # Ensure it's the AD object SID (must be under the domain SID)
                if sid.startswith(domain_sid + "-"):
                    return sid, machine_sam, netbios_domain
            except DCERPCException as e:
                if "STATUS_NONE_MAPPED" in str(e):
                    last_err = e
                    continue
                raise

        raise RuntimeError(
            f"Could not resolve domain SID for machine account {machine_sam}. "
            f"Domain={netbios_domain}, DomainSID={domain_sid}, LastError={last_err}"
        )

    finally:
        try:
            if policy_handle is not None:
                lsad.hLsarClose(dce, policy_handle)
        except Exception:
            pass
        try:
            dce.disconnect()
        except Exception:
            pass


def get_machine_local_sid(smb: SMBConnection, target: str) -> Optional[str]:
    """
    Query the local machine SID via LSA RPC (\\pipe\\lsarpc).

    This returns the SID prefix for local accounts. Domain accounts
    will have a different SID prefix (the domain SID).
    """
    try:
        # Build RPC transport over existing SMB connection
        rpctransport = transport.SMBTransport(
            smb.getRemoteHost(),
            445,
            r"\lsarpc",
            smb_connection=smb,
        )

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)

        desired = getattr(lsad, "POLICY_VIEW_LOCAL_INFORMATION", 0x00000001) | getattr(
            lsad, "POLICY_LOOKUP_NAMES", 0x00000800
        )

        try:
            policy_handle = lsad.hLsarOpenPolicy2(dce, desired)["PolicyHandle"]
        except DCERPCException:
            # Fallback that often works if the server is picky about access masks.
            policy_handle = lsad.hLsarOpenPolicy2(dce, 0x02000000)[
                "PolicyHandle"
            ]  # MAXIMUM_ALLOWED

        # Query account domain info (contains machine SID)
        resp = lsad.hLsarQueryInformationPolicy2(
            dce,
            policy_handle,
            lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation,
        )

        # Navigate the structure to get the SID
        policy_info = resp["PolicyInformation"]

        # Handle different impacket structure naming
        if "PolicyAccountDomainInfo" in policy_info.fields:
            domain_info = policy_info["PolicyAccountDomainInfo"]
        else:
            domain_info = policy_info["PolicyAccountDomainInformation"]

        domain_sid = domain_info["DomainSid"]

        # Close handle
        lsad.hLsarClose(dce, policy_handle)
        dce.disconnect()

        return domain_sid.formatCanonical()

    except (DCERPCException, SessionError, Exception) as e:
        logger.error(f"Failed to get machine SID via LSA: {e}")
        return None


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    if filetime == 0:
        return None
    # FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
    # Difference is 116444736000000000 100-ns intervals
    EPOCH_DIFF = 116444736000000000
    timestamp = (filetime - EPOCH_DIFF) / 10_000_000
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OSError, ValueError):
        return None


def get_owner_sid_for_path(
    smb: SMBConnection, share: str, path: str, is_directory: bool = False
) -> Optional[str]:
    """
    Get the owner SID for a file or directory via SMB2/3 security descriptor query.
    """
    tid = None
    fid = None

    try:
        tid = smb.connectTree(share)
        smb3 = smb._SMBConnection

        FILE_BASIC_INFORMATION = 4

        # Set creation options based on target type
        if is_directory:
            creation_options = FILE_DIRECTORY_FILE
        else:
            creation_options = FILE_NON_DIRECTORY_FILE

        fid = smb3.create(
            tid,
            path,
            desiredAccess=READ_CONTROL | FILE_READ_ATTRIBUTES,
            shareMode=FILE_SHARE_READ
            | FILE_SHARE_WRITE
            | FILE_SHARE_DELETE,  # Does this need share_delete?
            creationOptions=creation_options,
            creationDisposition=FILE_OPEN,
            fileAttributes=0,
        )

        # Two queries, same handle - protocol requires separate infoType requests for owner SID and for file attributes
        sd_resp = smb3.queryInfo(
            tid,
            fid,
            infoType=SMB2_0_INFO_SECURITY,
            fileInfoClass=SMB2_SEC_INFO_00,
            additionalInformation=OWNER_SECURITY_INFORMATION,
            flags=0,
        )
        file_resp = smb3.queryInfo(
            tid,
            fid,
            infoType=SMB2_0_INFO_FILE,
            fileInfoClass=FILE_BASIC_INFORMATION,
            additionalInformation=0,
            flags=0,
        )

        owner_sid = parse_owner_sid(sd_resp)
        created, modified = None, None
        if len(file_resp) >= 32:
            creation_time, _, last_write, _ = struct.unpack("<QQQQ", file_resp[:32])
            created = filetime_to_datetime(creation_time)
            modified = filetime_to_datetime(last_write)

        # If modified time is before created time, most likely means NTUSER.DAT was copied from C:\Users\Default
        # If this is the case, likely the user has not interacted with this profile.
        if created and modified and modified < created:
            logger.debug(
                rf"    Profile file {share}{path} was created at {created.isoformat()} and but modified at {modified.isoformat()}. It is likely this profile has not been interacted with."
            )

        return owner_sid, created, modified

    except SessionError:
        return None
    except Exception:
        return None

    finally:
        if fid is not None and tid is not None:
            try:
                smb3.close(tid, fid)
            except Exception:
                pass


def parse_owner_sid(sd_bytes: bytes) -> Optional[str]:
    """Parse a self-relative security descriptor and extract the owner SID."""
    if not sd_bytes:
        return None

    try:
        # Handle different input types
        if isinstance(sd_bytes, (bytes, bytearray)):
            data = bytes(sd_bytes)
        elif hasattr(sd_bytes, "getData"):
            data = sd_bytes.getData()
        else:
            # Try to extract buffer from response structure
            for attr in ("Buffer", "Data", "OutputBuffer"):
                if hasattr(sd_bytes, attr):
                    data = getattr(sd_bytes, attr)
                    if isinstance(data, (bytes, bytearray)):
                        break
            else:
                data = bytes(sd_bytes)

        # Parse as self-relative security descriptor
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(data)

        owner = sd["OwnerSid"]
        if owner:
            return owner.formatCanonical()
        return None

    except Exception as e:
        logger.error(f"Failed to parse security descriptor: {e}")
        return None


def enumerate_user_profiles(
    target: str,
    username: str,
    password: str,
    domain: str = "",
    lmhash: str = "",
    nthash: str = "",
    target_ip: Optional[str] = None,
    timeout: int = 3,
    include_local: bool = False,
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, str]]:
    """
    Enumerate user profiles on a remote Windows host via C$ share.
    Requires administrative access to the C$ share.

    Returns:
        machines: {machine_name: machine_sid}
        owners:  {profile_name: owner_sid} for domain accounts
        skipped: {profile_name: reason} for skipped profiles
        errors:  {profile_name: error_message} for failed queries
    """
    owners: Dict[str, str] = {}
    skipped: Dict[str, str] = {}
    errors: Dict[str, str] = {}
    machine: Dict[str, str] = {}

    # Resolve IP
    remote_host = target_ip or target

    # Connect to SMB
    logger.debug(f"Connecting to {target} ({remote_host})...")
    smb = SMBConnection(
        remoteName=target, remoteHost=remote_host, timeout=timeout, sess_port=445
    )

    # Authenticate
    try:
        if nthash or lmhash:
            logger.info("Authenticating with hashes...")
            logger.debug(f"Authenticating with hashes {lmhash}:{nthash}")
            smb.login(username, "", domain, lmhash=lmhash, nthash=nthash)
        else:
            # logger.info(
            #     rf"Attempting login on {target} ({remote_host}) with user {domain}\{username}"
            #     if domain
            #     else rf"Attempting local auth login on {target} ({remote_host}) with user {username}"
            # )
            logger.debug(
                rf"Attempting login on {target} ({remote_host}) with credentials {domain}\{username}:{password}"
                if domain
                else rf"Attempting local auth login on {target} ({remote_host}) with credentials {username}:{password}"
            )
            smb.login(username, password, domain)
    except SessionError as e:
        if domain == target:
            logger.error(
                rf"Failed to authenticate to \\{target} with local auth as {domain}\{username}"
            )
            logger.debug(f"{e}")
            raise UserWarning(
                f"Check permissions and credentials. Failed to authenticate to {target} with local auth: {e}"
            )
        else:
            logger.error(
                rf"Failed to authenticate to \\{target} with domain auth as {domain}\{username}"
            )
            logger.debug(f"{e}")
            raise SessionError(
                f"Check permissions and credentials. Failed to authenticate to {target} with domain auth: {e}"
            )

    logger.info(
        rf"Successful authentication on {target} ({remote_host}) as {domain}\{username}"
        if domain
        else rf"Successful authentication on {target} ({remote_host}) as {username}"
    )

    # Get machine SID for filtering local accounts
    machine_local_sid = None
    logger.debug(f"Querying machine SIDs via LSA on {target}...")
    try:
        machine_domain_sid, machine_sam, netbios_domain = get_machine_domain_sid(
            smb, target
        )
    except Exception as e:
        logger.error(f"Failed to query machine SIDs: {e}")
        raise RuntimeError(f"Failed to query machine SIDs: {e}")
    logger.debug(f"Machine Domain SID: {machine_domain_sid}")
    if not include_local:
        machine_local_sid = get_machine_local_sid(smb, target)
        if machine_local_sid:
            logger.debug(f"Local Machine SID:  {machine_local_sid}")
        else:
            logger.warning(
                "Could not determine machine SID - local account filtering may be incomplete"
            )
        if machine_domain_sid.startswith(machine_local_sid):
            logger.debug(
                f"Machine domain SID and local SID are the same - target {target} might be a domain controller"
            )
            include_local = True
            logger.debug(
                f"Setting include_local to True to collect accounts which match the machine SID"
            )

    # List C:\Users directory
    share = "C$"
    users_path = r"\Users\*"
    logger.debug(rf"Attempting to connect to share {share}")

    try:
        entries = smb.listPath(share, users_path)
        # logger.debug(f"Directory entries: {entries}")
        logger.info(
            rf"Successfully connected to share \\{target}\{share} as {domain}\{username}"
            if domain
            else rf"Successfully connected to share \\{target}\{share} as {username}"
        )
        logger.info(rf"Enumerating profiles in \\{target}\{share}\Users\...")
        valid_dirs_to_check = 0
        for entry in entries:
            if not entry.is_directory():
                continue
            if entry.get_longname() == "." or entry.get_longname() == "..":
                continue
            logger.debug(rf"    \\{target}\{share}\Users\{entry.get_longname()}")
            valid_dirs_to_check += 1
        logger.debug(
            rf"{valid_dirs_to_check} total directories found in \\{target}\{share}\Users\ to review for domain profiles"
        )
    except SessionError as e:
        short_msg = e.getErrorString()[0]
        if short_msg == "STATUS_ACCESS_DENIED":
            logger.debug(
                rf"Received STATUS_ACCESS_DENIED for {share} on {target} as {domain}\{username}"
                if domain
                else rf"Received STATUS_ACCESS_DENIED for {share} on {target} as {username}"
            )
            # return owners, skipped, errors, machine
            raise UserWarning(
                rf"User {domain}\{username} does not have permission to access {share} on {target}"
                if domain
                else rf"User {username} does not have permission to access {share} on {target}"
            )
        elif short_msg == "STATUS_OBJECT_NAME_NOT_FOUND":
            logger.debug(rf"Failed to list {share}\Users: {e}")
            raise UserWarning(rf"Failed to list {share}\Users: {e}")
        else:
            logger.error(f"Error: {short_msg}")
            raise RuntimeError(rf"Failed to list {share}\Users: {e}") from e

    for entry in entries:
        name = entry.get_longname()

        # Skip system/default profiles
        if name in SKIP_PROFILE_NAMES:
            logger.debug(f"Skipping {name} (system/default profile)")
            continue

        # Must be a directory
        if not entry.is_directory():
            skipped[name] = "not a directory"
            logger.debug(f"Skipping {name} (not a directory)")
            continue

        # We're parsing NTUSER.DAT since it's going to have the owner SID, it's likely local Admin is owner of domain profile directory
        ntuser_path = rf"\Users\{name}\NTUSER.DAT"

        try:
            owner_sid, created, modified = get_owner_sid_for_path(
                smb, share, ntuser_path, is_directory=False
            )

            if not owner_sid:
                skipped[name] = "could not retrieve owner SID"
                logger.warning(f"Could not retrieve owner SID for {name}")
                continue

            # Attempt fallback enumeration of DPAPI Protect Folder if well-known local/service SIDs on NTUSER.DAT
            if owner_sid.startswith(SKIP_SID_PREFIXES):
                logger.debug(
                    f"Determined {name}'s NTUSER.DAT has well-known SID as owner ({owner_sid})"
                )
                logger.debug(
                    f"Attempting fallback enumeration of DPAPI Protect Folder for {name}"
                )
                try:
                    dpapi_entries = smb.listPath(
                        share, rf"\Users\{name}\AppData\Roaming\Microsoft\Protect\*"
                    )
                    for dpapi_entry in dpapi_entries:
                        # if dpapi_entry.get_longname() == "." or dpapi_entry.get_longname() == "..":
                        if not dpapi_entry.get_longname().startswith("S-1-5-21"):
                            continue
                        logger.debug(f"DPAPI directory: {dpapi_entry.get_longname()}")
                        owner_sid = dpapi_entry.get_longname()
                        created = filetime_to_datetime(dpapi_entry.get_ctime())
                        modified = filetime_to_datetime(dpapi_entry.get_wtime())

                        if owner_sid.startswith(SKIP_SID_PREFIXES):
                            logger.debug(
                                f"Determined {name}'s DPAPI directory has well-known SID as owner ({owner_sid})"
                            )
                            logger.debug(f"Skipping enumeration of {name}")
                            skipped[name] = f"well-known SID ({owner_sid})"
                            continue

                except SessionError as e:
                    short_msg = e.getErrorString()[0]
                    if short_msg == "STATUS_ACCESS_DENIED":
                        logger.debug(
                            rf"Received STATUS_ACCESS_DENIED for {share} on {target} as {domain}\{username}"
                            if domain
                            else rf"Received STATUS_ACCESS_DENIED for {share} on {target} as {username}"
                        )
                        # return owners, skipped, errors, machine
                        raise UserWarning(
                            rf"User {domain}\{username} does not have permission to access {share} on {target}"
                            if domain
                            else rf"User {username} does not have permission to access {share} on {target}"
                        )
                    elif short_msg == "STATUS_OBJECT_NAME_NOT_FOUND":
                        logger.debug(
                            rf"DPAPI directory not found for {name}, skipping..."
                        )
                        skipped[name] = "DPAPI directory not found"
                        continue
                    else:
                        logger.error(f"Error: {short_msg}")
                        raise RuntimeError(rf"Failed to list {share}\Users: {e}") from e

            # Must be an account SID (S-1-5-21-...)
            if not owner_sid.startswith("S-1-5-21-"):
                logger.debug(f"Skipping non-account SID {name} ({owner_sid})")
                skipped[name] = f"non-account SID ({owner_sid})"
                continue

            # Filter local accounts if we have machine SID
            if machine_local_sid and owner_sid.startswith(machine_local_sid + "-"):
                if not include_local:
                    logger.debug(f"Skipping local account {name} ({owner_sid})")
                    skipped[name] = f"local account ({owner_sid})"
                    continue

            owners[name] = {
                **owners.get(name, {}),
                "sid": owner_sid,
                "created": created.timestamp(),
                "modified": modified.timestamp(),
                "target": target,
                "profile": rf"\\{target}\{share}\Users\{name}",
            }
            machine = {
                "sid": machine_domain_sid,
                "netbios_domain": netbios_domain,
                "sam": machine_sam,
            }
            logger.info(
                f"    {name}:\t{owner_sid}\tcreated:{created.strftime('%Y-%m-%d')}\tmodified:{modified.strftime('%Y-%m-%d')}"
            )

        except SessionError as e:
            errors[name] = str(e)
            logger.error(f"{name}: {e}")

    # Cleanup
    try:
        smb.logoff()
        logger.debug(f"Logged off from SMB session on {target}")
    except Exception as e:
        logger.error(f"Failed to logoff from SMB session on {target}")
        logger.debug(f"Failed to logoff from SMB session on {target}: {e}")
        pass

    return owners, skipped, errors, machine
