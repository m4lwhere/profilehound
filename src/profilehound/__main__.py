import sys
import time
import logging
import argparse
import json
import dns.resolver
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from textwrap import dedent
from impacket.smbconnection import SessionError
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)
from rich.logging import RichHandler
from rich.console import Console

from sharehound.targets import load_targets
from sharehound.core.Config import Config as SharehoundConfig
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
from profilehound.modules.smb import (
    enumerate_user_profiles,
    SKIP_PROFILE_NAMES,
    DomainAuthFailure,
)
from profilehound.__version__ import __version__
from profilehound.modules.artifacts.catalog import (
    get_effective_artifact_rules,
    print_artifact_catalog,
)
from profilehound.modules.artifacts.icons import (
    artifact_node_kinds,
    build_custom_icon_payload,
)
from profilehound.modules.artifacts.aggregation import aggregate_findings
from profilehound.modules.artifacts.models import ArtifactOptions
from profilehound.modules.artifacts.sidecar import (
    derive_artifact_sidecar_path,
    derive_default_download_dir,
    iter_artifact_findings,
    summarize_artifacts,
    write_artifact_sidecar,
)

BANNER = dedent(rf"""
    ____             _____ __     __  __                      __
   / __ \_________  / __(_) /__  / / / /___  __  ______  ____/ /
  / /_/ / ___/ __ \/ /_/ / / _ \/ /_/ / __ \/ / / / __ \/ __  /
 / ____/ /  / /_/ / __/ / /  __/ __  / /_/ / /_/ / / / / /_/ /
/_/   /_/   \____/_/ /_/_/\___/_/ /_/\____/\__,_/_/ /_/\__,_/    v{__version__}
""").strip("\n")


def banner():
    print(BANNER)
    print("@m4lwhere")
    print("")
    print(
        "BloodHound CE OpenGraph collector for user profiles stored on domain machines."
    )
    print("")


def get_args():
    parser = argparse.ArgumentParser(
        add_help=True,
        description=f"{BANNER}\n@m4lwhere\n\nProfileHound OpenGraph collector\nProfileHound is only possible due to the work of @podalirius's ShareHound and bhopengraph. Huge thanks!",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    global_args = parser.add_argument_group("Global Options")
    global_args.add_argument(
        "--auth-domain", "--domain", default="", help="Domain name"
    )
    global_args.add_argument(
        "--auth-user",
        required=False,
        help="Username for authentication (by default will be for both SMB and LDAP)",
    )
    global_args.add_argument(
        "--auth-password",
        required=False,
        help="Password for authentication (by default will be for both SMB and LDAP)",
    )
    global_args.add_argument(
        "--auth-hashes",
        required=False,
        help="LMHASH:NTHASH for authentication (by default will be for both SMB and LDAP)",
    )
    global_args.add_argument(
        "--auth-dc-ip",
        required=False,
        help="Domain controller's IP to use for authentication and LDAP queries",
    )
    global_args.add_argument(
        "-k",
        "--kerberos",
        default=False,
        action="store_true",
        help=(
            "Use Kerberos authentication. With no password/hash/AES key, uses the "
            "credential cache in KRB5CCNAME (pass-the-ticket). Kerberos targets must "
            "be FQDNs and --auth-dc-ip should point at the KDC."
        ),
    )
    global_args.add_argument(
        "--no-pass",
        default=False,
        action="store_true",
        help="Do not use a password; rely on the Kerberos ccache (KRB5CCNAME) or --aes-key",
    )
    global_args.add_argument(
        "--aes-key",
        default=None,
        help="AES128/256 key (hex) for Kerberos authentication (pass-the-key)",
    )
    global_args.add_argument(
        "--dns-server", help="DNS server to use for target resolution"
    )
    global_args.add_argument(
        "--output",
        "-o",
        default=f"profilehound_{time.strftime('%Y%m%d-%H%M%S')}.json",
        help="Output file for JSON. Default is profilehound_YYYYMMDD-HHMMSS.json",
    )
    global_args.add_argument(
        "--subnets",
        default=False,
        action="store_true",
        help="Query LDAP for all AD subnets and use them as targets",
    )
    global_args.add_argument(
        "--no-stats",
        default=False,
        action="store_true",
        help="Do not print statistics at the end",
    )
    global_args.add_argument(
        "-q", "--quiet", default=False, action="store_true", help="Do not show banner"
    )
    global_args.add_argument(
        "-v", "--verbose", default=False, action="store_true", help="Verbose logging"
    )
    global_args.add_argument(
        "-d", "--debug", default=False, action="store_true", help="Debug logging"
    )

    artifact_args = parser.add_argument_group("Artifact Collection Options")
    artifact_args.add_argument(
        "--no-artifacts",
        default=False,
        action="store_true",
        help="Disable artifact collection and keep legacy profile-only behavior",
    )
    artifact_args.add_argument(
        "--artifact-triage",
        default=False,
        action="store_true",
        help="Optionally run bounded text triage for triageable artifacts",
    )
    artifact_args.add_argument(
        "--artifact-download-files",
        default=False,
        action="store_true",
        help="Download matched downloadable artifacts up to configured caps",
    )
    artifact_args.add_argument(
        "--artifact-sidecar",
        default=False,
        action="store_true",
        help=(
            "Write paired .artifacts.json evidence sidecar. "
            "Also enabled by --artifact-download-files."
        ),
    )
    artifact_args.add_argument(
        "--artifact-download-dir",
        default=None,
        help="Directory for downloaded artifact evidence",
    )
    artifact_args.add_argument(
        "--artifact-disable-category",
        default=[],
        action="append",
        help="Disable an artifact category; can be repeated",
    )
    artifact_args.add_argument(
        "--list-artifacts",
        default=False,
        action="store_true",
        help="Print the effective built-in artifact catalog and exit",
    )
    artifact_args.add_argument(
        "--print-custom-icons",
        default=False,
        action="store_true",
        help="Print the BloodHound custom node icon payload and exit",
    )
    artifact_args.add_argument(
        "--artifact-max-matches",
        type=int,
        default=500,
        help="Max matches per artifact per profile (default: 500)",
    )
    artifact_args.add_argument(
        "--artifact-sample-paths",
        type=int,
        default=50,
        help="Sample source paths stored on artifact FoundOn edge evidence (default: 50)",
    )
    artifact_args.add_argument(
        "--artifact-triage-max-files",
        type=int,
        default=25,
        help="Max files triaged per profile-scoped artifact finding (default: 25)",
    )
    artifact_args.add_argument(
        "--artifact-download-max-file-size-mb",
        type=int,
        default=512,
        help="Max normal non-browser artifact file download size in MB (default: 512)",
    )

    smb_args = parser.add_argument_group("SMB Options")
    smb_args.add_argument(
        "--target",
        default=[],
        type=str,
        action="append",
        required=False,
        help="single target FQDN, IP, or CIDR. Omitting uses LDAP to gather all machines.",
    )
    smb_args.add_argument(
        "--targets-file",
        default=None,
        type=str,
        required=False,
        help="file path to a list of targets, one per line. Omitting uses LDAP to gather all machines.",
    )
    smb_args.add_argument(
        "--smb-timeout",
        type=int,
        default=3,
        help="SMB connection timeout in seconds (default: 3)",
    )
    smb_args.add_argument(
        "--smb-workers", type=int, default=4, help="SMB worker threads (default: 4)"
    )
    smb_args.add_argument(
        "--smb-username",
        required=False,
        help="SMB username to authenticate to SMB with.",
    )
    smb_args.add_argument(
        "--smb-password",
        required=False,
        help="SMB password to authenticate to SMB with.",
    )
    smb_args.add_argument(
        "--smb-local-auth",
        default=False,
        required=False,
        action="store_true",
        help="Use local account authentication for SMB",
    )
    smb_args.add_argument(
        "--smb-ignore-failed-domain-auth",
        default=False,
        required=False,
        action="store_true",
        help=(
            "Continue scanning remaining targets after SMB domain authentication "
            "failures instead of stopping to prevent account lockout"
        ),
    )

    ldap_args = parser.add_argument_group("LDAP Options")
    ldap_args.add_argument(
        "--ldap-dc", required=False, help="DC to be used to query LDAP for targets"
    )
    ldap_args.add_argument(
        "--ldap-username",
        required=False,
        help="LDAP username to authenticate to LDAP with.",
    )
    ldap_args.add_argument(
        "--ldap-password",
        required=False,
        help="LDAP password to authenticate to LDAP with.",
    )
    ldap_args.add_argument(
        "--ldaps",
        required=False,
        default=False,
        action="store_true",
        help="Use LDAPS for LDAP queries",
    )

    sccm_args = parser.add_argument_group("SCCM Options (NOT IMPLEMENTED YET)")
    sccm_args.add_argument("--sccm-host", help="SCCM SMS Provider hostname")
    sccm_args.add_argument("--site-code", help="SCCM site code")
    sccm_args.add_argument(
        "--sccm-user",
        help="Filter SCCM affinities to a primary user (get_puser style)",
    )

    args = parser.parse_args()
    if args.no_artifacts and args.artifact_sidecar:
        parser.error("--artifact-sidecar cannot be used with --no-artifacts")
    if args.no_artifacts and args.artifact_download_files:
        parser.error("--artifact-download-files cannot be used with --no-artifacts")
    if args.no_pass and not args.kerberos:
        parser.error("--no-pass requires --kerberos")
    if args.aes_key and not args.kerberos:
        parser.error("--aes-key requires --kerberos")
    if args.kerberos:
        if args.smb_local_auth:
            parser.error(
                "--kerberos cannot be used with --smb-local-auth (Kerberos is domain authentication)"
            )
        if not args.auth_domain:
            parser.error("--kerberos requires --auth-domain (the Kerberos realm)")
    if not args.list_artifacts and not args.print_custom_icons:
        if not args.auth_user:
            parser.error(
                "--auth-user is required unless --list-artifacts or "
                "--print-custom-icons is used"
            )
        # Kerberos allows ticket-only auth (ccache via --no-pass, or --aes-key).
        kerberos_ticket_only = args.kerberos and (args.no_pass or args.aes_key)
        if not args.auth_password and not args.auth_hashes and not kerberos_ticket_only:
            parser.error(
                "--auth-password or --auth-hashes is required (or use --kerberos with "
                "--no-pass or --aes-key) unless --list-artifacts or --print-custom-icons is used"
            )
    return args


def build_artifact_options(args) -> ArtifactOptions:
    write_sidecar = bool(
        getattr(args, "artifact_sidecar", False)
        or getattr(args, "artifact_download_files", False)
    )
    sidecar_path = derive_artifact_sidecar_path(args.output) if write_sidecar else None
    download_dir = getattr(args, "artifact_download_dir", None) or derive_default_download_dir(
        args.output
    )
    return ArtifactOptions(
        enabled=not getattr(args, "no_artifacts", True),
        triage=getattr(args, "artifact_triage", False),
        download_files=getattr(args, "artifact_download_files", False),
        write_sidecar=write_sidecar,
        download_dir=download_dir,
        disabled_categories=getattr(args, "artifact_disable_category", []) or [],
        max_matches=getattr(args, "artifact_max_matches", 500),
        sample_paths=getattr(args, "artifact_sample_paths", 50),
        triage_max_files=getattr(args, "artifact_triage_max_files", 25),
        download_max_file_size_mb=getattr(
            args, "artifact_download_max_file_size_mb", 512
        ),
        output_path=args.output,
        sidecar_path=sidecar_path,
        domain=getattr(args, "auth_domain", "") or "",
    )


def _normalize_enumeration_result(result):
    if len(result) == 5:
        return result
    owners, skipped, errors, machine = result
    return owners, {}, skipped, errors, machine


def _artifact_summary_for_node(findings, artifact_count):
    return {
        "profilehoundartifactcount": artifact_count,
        "profilehoundartifactfindingcount": len(findings),
        "profilehoundartifacttypes": sorted({finding.artifacttype for finding in findings}),
        "profilehoundartifactcategories": sorted({finding.category for finding in findings}),
    }


def _opengraph_artifact_node_properties(aggregate):
    properties = aggregate.node_properties()
    for field in (
        "machinesid",
        "computername",
        "profilefolder",
        "profilepath",
        "samplepaths",
        "samplepathcount",
    ):
        properties.pop(field, None)
    return properties


def create_opengraph(found_profiles_by_target, sidecar_file=None, sample_paths=50):
    graph = OpenGraph(source_kind="Base")

    nodes = {}
    user_profile_paths = {}
    computer_profile_paths = {}
    user_artifacts = {}
    findings_by_machine_sid = {}
    all_findings = list(iter_artifact_findings(found_profiles_by_target))
    aggregates = aggregate_findings(all_findings)

    for finding in all_findings:
        user_artifacts.setdefault(finding.usersid, []).append(finding)
        findings_by_machine_sid.setdefault(finding.machinesid, []).append(finding)

    for target, target_details in found_profiles_by_target.items():
        machine_sid = target_details["machine_sid"]
        for profile_name, profile_details in target_details["owners"].items():
            user_sid = profile_details["sid"]
            user_profile_paths.setdefault(user_sid, []).append(profile_details["profile"])
            computer_profile_paths.setdefault(machine_sid, []).append(
                profile_details["profile"]
            )

    for target, target_details in found_profiles_by_target.items():
        for profile_name, profile_details in target_details["owners"].items():
            user_sid = profile_details["sid"]
            if user_sid in nodes:
                continue
            user_findings = user_artifacts.get(user_sid, [])
            properties = {
                "HasUserProfile": sorted(set(user_profile_paths[user_sid])),
                **_artifact_summary_for_node(
                    user_findings,
                    len({finding.artifactid for finding in user_findings}),
                ),
            }
            nodes[user_sid] = Node(
                id=user_sid,
                kinds=["User", "Base"],
                properties=Properties(**properties),
            )

        machine_sid = target_details["machine_sid"]
        if machine_sid in nodes:
            continue
        nodes[machine_sid] = Node(
            id=machine_sid,
            kinds=["Computer", "Base"],
            properties=Properties(
                HasUserProfile=sorted(set(computer_profile_paths.get(machine_sid, []))),
                **_artifact_summary_for_node(
                    findings_by_machine_sid.get(machine_sid, []),
                    len(
                        {
                            (finding.usersid, finding.artifacttype)
                            for finding in findings_by_machine_sid.get(machine_sid, [])
                        }
                    ),
                ),
            ),
        )

    for aggregate in aggregates:
        nodes[aggregate.artifactid] = Node(
            id=aggregate.artifactid,
            kinds=artifact_node_kinds(aggregate.category),
            properties=Properties(**_opengraph_artifact_node_properties(aggregate)),
        )

    for node in nodes.values():
        graph.add_node(node)

    edges = []
    for target, target_details in found_profiles_by_target.items():
        for profile_name, profile_details in target_details["owners"].items():
            edges.append(
                Edge(
                    start_node=nodes[profile_details["sid"]].id,
                    end_node=nodes[target_details["machine_sid"]].id,
                    kind="HasUserProfile",
                    properties=Properties(
                        method="ProfileHound - SMB Spider",
                        path=profile_details["profile"],
                        profileCreated=profile_details["created"],
                        profileModified=profile_details["modified"],
                    ),
                )
            )
    for aggregate in aggregates:
        edges.append(
            Edge(
                start_node=nodes[aggregate.usersid].id,
                end_node=nodes[aggregate.artifactid].id,
                kind="HasProfileArtifact",
                properties=Properties(
                    **aggregate.has_profile_artifact_edge_properties()
                ),
            )
        )
        for location in aggregate.locations():
            if location.machinesid not in nodes:
                raise ValueError(
                    f"Artifact location references unknown machine SID {location.machinesid}"
                )
            properties = location.edge_properties(sample_paths)
            edges.append(
                Edge(
                    start_node=nodes[aggregate.artifactid].id,
                    end_node=nodes[location.machinesid].id,
                    kind="FoundOn",
                    properties=Properties(**properties),
                )
            )

    for edge in edges:
        graph.add_edge(edge)

    return graph


def export_results(found_profiles_by_target, args, logger, console, partial=False):
    if len(found_profiles_by_target) == 0:
        logger.debug("No collected profiles available to export")
        return False

    try:
        artifact_options = getattr(args, "artifact_options", None)
        sample_paths = 50
        if artifact_options and artifact_options.enabled:
            sample_paths = artifact_options.sample_paths
        graph = create_opengraph(found_profiles_by_target, None, sample_paths)
        graph.export_to_file(args.output)
        if (
            artifact_options
            and artifact_options.enabled
            and artifact_options.write_sidecar
        ):
            write_artifact_sidecar(found_profiles_by_target, artifact_options)
    except Exception as e:
        logger.error(f"Failed to export ProfileHound OpenGraph intel: {e}")
        return False

    if partial:
        logger.warning(f"Exported partial ProfileHound OpenGraph intel to {args.output}")
    else:
        logger.info(f"Exported ProfileHound OpenGraph intel to {args.output}")

    if not args.no_stats:
        try:
            print_statistics(found_profiles_by_target, console)
        except Exception as e:
            logger.error(f"Failed to print ProfileHound statistics: {e}")

    return True


def _reverse_lookup(resolver, ip):
    """Best-effort reverse DNS (PTR) lookup, returning an FQDN or None.

    Used under Kerberos to turn an IP target into a name for the cifs/<host> SPN.
    """
    try:
        import dns.reversename

        answer = resolver.resolve(dns.reversename.from_address(ip), "PTR")
        name = str(answer[0]).rstrip(".")
        return name or None
    except Exception:
        return None


@dataclass
class TargetCollectionResult:
    target: str
    owners: dict
    artifacts: dict
    machine: dict


def _resolve_target_for_collection(target, resolver, use_kerberos, logger):
    target_type, target_name = target
    resolved_target = target
    ip = target_name

    if target_type == "fqdn":
        try:
            logger.debug(f"Attempting DNS resolution for {target_name}")
            ip = resolver.resolve(target_name, "A")[0].address
            logger.debug(f"Resolved {target_name} to {ip}")
        except dns.resolver.NXDOMAIN:
            logger.info(
                f"Target {target_name} does not exist, received NXDOMAIN from DNS server {resolver.nameservers}"
            )
            return None
        except Exception as e:
            logger.error(f"Failed to resolve target {target_name}: {e}")
            return None
    elif "ip" in target_type:
        ip = target_name
        if use_kerberos:
            # Kerberos service tickets are for cifs/<hostname>, so an IP
            # target has no valid SPN. Try reverse DNS to recover a name.
            fqdn = _reverse_lookup(resolver, ip)
            if not fqdn:
                logger.warning(
                    f"Skipping {ip}: Kerberos requires an FQDN target and no "
                    f"PTR record was found. Use FQDN targets or --targets-file."
                )
                return None
            logger.debug(f"Kerberos: resolved {ip} -> {fqdn} for SPN")
            resolved_target = (target_type, fqdn)

    return resolved_target, ip


def _collect_target_profiles(
    target,
    *,
    args,
    resolver,
    logger,
    artifact_options,
    auth_lmhash,
    auth_nthash,
    use_kerberos,
    aes_key,
    kdc_host,
    use_cache,
    kerberos_tgt,
):
    resolved = _resolve_target_for_collection(target, resolver, use_kerberos, logger)
    if resolved is None:
        return None

    target, ip = resolved
    auth_domain = target[1] if args.smb_local_auth else args.auth_domain
    if args.smb_local_auth:
        logger.debug(f"Using local machine authentication for user {args.auth_user}")

    try:
        result = enumerate_user_profiles(
            target=target[1],
            username=args.auth_user,
            password=args.auth_password,
            domain=auth_domain,
            lmhash=auth_lmhash,
            nthash=auth_nthash,
            timeout=args.smb_timeout,
            target_ip=ip,
            artifact_options=artifact_options,
            use_kerberos=use_kerberos,
            aes_key=aes_key,
            kdc_host=kdc_host,
            use_cache=use_cache,
            kerberos_tgt=kerberos_tgt.copy() if kerberos_tgt else None,
        )
        owners, artifacts, _skipped, _errors, machine = _normalize_enumeration_result(
            result
        )
    except OSError as e:
        logger.debug(f"Failed to connect to {target[1]} ({ip}): {e}")
        return None
    except UserWarning as e:
        logger.warning(f"{e}")
        logger.warning(f"Continuing attempts for all remaining targets")
        return None
    except (DomainAuthFailure, SessionError) as e:
        logger.info(
            rf"Failed to authenticate to {target[1]} with domain auth as {auth_domain}\{args.auth_user}"
        )
        logger.debug(f"{e}")
        if args.smb_ignore_failed_domain_auth:
            logger.warning(
                "Ignoring SMB domain authentication failure because "
                "--smb-ignore-failed-domain-auth was set"
            )
            logger.warning("Continuing attempts for all remaining targets")
            return None
        raise
    except RuntimeError as e:
        logger.error(f"Failed to get profile enumeration for {target[1]}: {e}")
        return None
    except Exception as e:
        logger.error(
            f"Something really went wrong with {target[1]}, attempting to continue: {e}"
        )
        return None

    if len(owners) == 0:
        logger.info(f"No domain profiles found for {target[1]}")
    else:
        logger.info(f"Found {len(owners)} domain profile(s) for {target[1]}")

    return TargetCollectionResult(
        target=target[1],
        owners=owners,
        artifacts=artifacts,
        machine=machine,
    )


def _store_collection_result(found_profiles_by_target, result):
    if result is None or len(result.owners) == 0:
        return
    found_profiles_by_target[result.target] = {
        "owners": result.owners,
        "artifacts": result.artifacts,
        "machine_sid": result.machine["sid"],
    }


def _log_domain_auth_stop(logger):
    logger.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    logger.error("!!!!! Stopping for all targets to prevent domain account lockout !!!!!")
    logger.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")


def _run_threaded_target_collection(
    targets,
    *,
    worker_count,
    progress,
    task_id,
    found_profiles_by_target,
    args,
    resolver,
    logger,
    artifact_options,
    auth_lmhash,
    auth_nthash,
    use_kerberos,
    aes_key,
    kdc_host,
    use_cache,
    kerberos_tgt,
):
    if not targets:
        return None

    target_iter = iter(targets)
    futures = {}
    fatal_error = None

    with ThreadPoolExecutor(max_workers=worker_count) as executor:

        def submit_next():
            try:
                next_target = next(target_iter)
            except StopIteration:
                return False
            future = executor.submit(
                _collect_target_profiles,
                next_target,
                args=args,
                resolver=resolver,
                logger=logger,
                artifact_options=artifact_options,
                auth_lmhash=auth_lmhash,
                auth_nthash=auth_nthash,
                use_kerberos=use_kerberos,
                aes_key=aes_key,
                kdc_host=kdc_host,
                use_cache=use_cache,
                kerberos_tgt=kerberos_tgt,
            )
            futures[future] = next_target
            return True

        for _ in range(min(worker_count, len(targets))):
            submit_next()

        while futures and fatal_error is None:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            completed_count = len(done)
            for future in done:
                target = futures.pop(future)
                progress.update(task_id, advance=1)
                try:
                    result = future.result()
                except KeyboardInterrupt:
                    raise
                except (DomainAuthFailure, SessionError) as e:
                    fatal_error = e
                except Exception as e:
                    logger.error(
                        f"Something really went wrong with {target[1]}, attempting to continue: {e}"
                    )
                else:
                    _store_collection_result(found_profiles_by_target, result)

            if fatal_error is None:
                for _ in range(completed_count):
                    if not submit_next():
                        break

        if fatal_error is not None:
            for future in futures:
                future.cancel()

            while futures:
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    target = futures.pop(future)
                    progress.update(task_id, advance=1)
                    if future.cancelled():
                        continue
                    try:
                        result = future.result()
                    except KeyboardInterrupt:
                        raise
                    except (DomainAuthFailure, SessionError) as e:
                        logger.debug(
                            f"Additional SMB domain authentication failure after stop request on {target[1]}: {e}"
                        )
                    except Exception as e:
                        logger.error(
                            f"Something really went wrong with {target[1]}, attempting to continue: {e}"
                        )
                    else:
                        _store_collection_result(found_profiles_by_target, result)

    return fatal_error


def main() -> int:
    args = get_args()
    if getattr(args, "print_custom_icons", False):
        print(json.dumps(build_custom_icon_payload(), indent=2))
        return 0

    if not args.quiet:
        banner()

    logger = logging.getLogger("profilehound")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    console = Console(stderr=True)
    handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_path=False,
        show_time=True,
        show_level=True,
        markup=True,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    if not logger.handlers:
        logger.addHandler(handler)

    artifact_options = build_artifact_options(args)
    args.artifact_options = artifact_options
    if getattr(args, "list_artifacts", False):
        rules = get_effective_artifact_rules(
            getattr(args, "artifact_disable_category", []) or []
        )
        print_artifact_catalog(rules, verbose=args.verbose or args.debug)
        return 0

    if (
        artifact_options.enabled
        and artifact_options.triage
        and not artifact_options.write_sidecar
    ):
        logger.warning(
            "Artifact triage is enabled without --artifact-sidecar; detailed "
            "triage indicators will not be written to output."
        )

    if artifact_options.download_files:
        logger.warning("Artifact file download enabled.")
        logger.warning(
            "Matched downloadable artifacts will be copied locally up to configured caps."
        )
        logger.warning(
            "Browser profiles will be recursively copied with cache and bulk-data exclusions."
        )
        logger.warning("WSL artifacts are existence-only and will not be downloaded.")

    config = SharehoundConfig()
    config.verbose = args.verbose
    config.debug = args.debug

    # Use the sharehound load_targets function.
    # This will check if targets file was provided, if not, then query LDAP for all machines
    logger.debug("Starting profilehound target collection")
    targets = []
    if args.targets_file is not None:
        logger.debug(f"Loading targets from {args.targets_file}")
    elif len(args.target) > 0:
        logger.debug(f"Loading target {args.target}")
    else:
        logger.debug("No targets provided, attempting to gather machines from LDAP")
    try:
        targets = load_targets(args, config, logger)
    except Exception as e:
        logger.error(f"Failed to load targets: {e}")
        sys.exit(1)
    if len(targets) == 0:
        logger.error(
            "No targets found, check that you have the correct DNS and SMB permissions and try again"
        )
        raise Exception(
            "No targets found in targets file or LDAP. Check your permissions and try again. Perhaps use --auth-dc-ip to specify a DC to query?"
        )
    logger.info(f"Loaded {len(targets)} targets")

    # Initialize DNS resolver
    resolver = dns.resolver.Resolver()
    if args.dns_server:
        resolver.nameservers = [args.dns_server]
        logger.debug(f"Using custom DNS server: {args.dns_server}")
    else:
        logger.debug(f"Using default DNS server of {resolver.nameservers}")

    # Initialize dict to store good results. We want found users, targets with their locations
    found_profiles_by_target = {}

    # For each target, run the SMB collection for the C$ share to gather \\target\C$\Users
    # Each directory in there needs to be checked for a domain user profile
    logger.debug(f"Targeting {len(targets)} hosts")
    logger.debug(f"Skipping profiles {SKIP_PROFILE_NAMES}")

    # --auth-hashes is documented as LMHASH:NTHASH. Split into the two hex halves
    # so pass-the-hash works; accept a bare NT hash without a colon as well.
    auth_lmhash, auth_nthash = "", ""
    if args.auth_hashes:
        if ":" in args.auth_hashes:
            auth_lmhash, auth_nthash = args.auth_hashes.split(":", 1)
        else:
            auth_nthash = args.auth_hashes

    # Kerberos settings. Use the ccache (KRB5CCNAME) only when no explicit secret
    # is supplied (pure pass-the-ticket); otherwise request a fresh TGT from the
    # provided password / NT hash (overpass-the-hash) / AES key (pass-the-key).
    use_kerberos = args.kerberos
    aes_key = args.aes_key or ""
    kdc_host = args.auth_dc_ip
    use_cache = bool(
        use_kerberos
        and (args.no_pass or not (args.auth_password or args.auth_hashes or aes_key))
    )
    if use_kerberos:
        logger.debug(
            "Kerberos auth enabled (kdcHost=%s, useCache=%s, aesKey=%s)"
            % (kdc_host, use_cache, "set" if aes_key else "none")
        )
        if kdc_host is None:
            logger.warning(
                "Kerberos is enabled without --auth-dc-ip; ticket requests will rely "
                "on DNS SRV discovery of the KDC and may fail in offsec networks."
            )

    # Acquire a single Kerberos TGT and reuse it for every host, so credential-based
    # runs cost one AS-REQ total instead of one per host (quieter to the KDC and
    # faster). Ticket-only runs (--no-pass) already reuse the ccache TGT, and a bad
    # secret fails here once, up front, before any host is touched.
    kerberos_tgt = None
    if use_kerberos and not use_cache:
        from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants as krb5_constants

        principal = Principal(
            args.auth_user, type=krb5_constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        try:
            tgt, cipher, _old_session_key, session_key = getKerberosTGT(
                principal,
                args.auth_password or "",
                args.auth_domain,
                auth_lmhash,
                auth_nthash,
                aes_key,
                kdc_host,
            )
            kerberos_tgt = {"KDC_REP": tgt, "cipher": cipher, "sessionKey": session_key}
            logger.info("Acquired one Kerberos TGT; reusing it for all targets")
        except KerberosError as e:
            logger.error(f"Failed to acquire Kerberos TGT: {e}")
            if e.getErrorCode() == krb5_constants.ErrorCodes.KRB_AP_ERR_SKEW.value:
                logger.error(
                    f"Clock skew too great; sync the host clock with the KDC "
                    f"({kdc_host}) (e.g. 'ntpdate {kdc_host}' or faketime) and retry."
                )
            return 1
        except Exception as e:
            logger.error(f"Failed to acquire Kerberos TGT: {e}")
            return 1
    try:
        with Progress(
            SpinnerColumn("bouncingBall", style="magenta"),
            TextColumn("[bold cyan]{task.description}", justify="right"),
            BarColumn(
                bar_width=None,
                style="black",
                complete_style="magenta",
                finished_style="green",
            ),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            transient=True,
            console=console,
        ) as progress:
            task_id = progress.add_task(
                "[bold magenta]Hunting Profiles...", total=len(targets)
            )
            remaining_targets = []
            worker_count = max(1, int(getattr(args, "smb_workers", 1)))
            preflight_complete = False

            preflight_message = (
                "SMB preflight: testing full collection on one target before "
                "starting threaded collection"
            )
            logger.info(preflight_message)
            progress.update(
                task_id,
                description=f"[bold magenta]{preflight_message}...",
            )

            for index, target in enumerate(targets):
                progress.update(task_id, advance=1)
                try:
                    result = _collect_target_profiles(
                        target,
                        args=args,
                        resolver=resolver,
                        logger=logger,
                        artifact_options=artifact_options,
                        auth_lmhash=auth_lmhash,
                        auth_nthash=auth_nthash,
                        use_kerberos=use_kerberos,
                        aes_key=aes_key,
                        kdc_host=kdc_host,
                        use_cache=use_cache,
                        kerberos_tgt=kerberos_tgt,
                    )
                except (DomainAuthFailure, SessionError) as e:
                    logger.debug(f"{e}")
                    _log_domain_auth_stop(logger)
                    export_results(
                        found_profiles_by_target, args, logger, console, partial=True
                    )
                    return 1

                if result is None:
                    continue

                _store_collection_result(found_profiles_by_target, result)
                preflight_complete = True
                remaining_targets = targets[index + 1 :]
                if remaining_targets:
                    logger.info(
                        f"SMB preflight succeeded on {result.target}; starting "
                        f"threaded SMB collection with {worker_count} worker(s) "
                        f"across {len(remaining_targets)} remaining target(s)"
                    )
                    progress.update(
                        task_id,
                        description=(
                            f"[bold magenta]Hunting Profiles with {worker_count} "
                            "SMB worker(s)..."
                        ),
                    )
                else:
                    logger.info(
                        f"SMB preflight succeeded on {result.target}; no remaining "
                        "targets for threaded collection"
                    )
                break

            if preflight_complete:
                fatal_error = _run_threaded_target_collection(
                    remaining_targets,
                    worker_count=worker_count,
                    progress=progress,
                    task_id=task_id,
                    found_profiles_by_target=found_profiles_by_target,
                    args=args,
                    resolver=resolver,
                    logger=logger,
                    artifact_options=artifact_options,
                    auth_lmhash=auth_lmhash,
                    auth_nthash=auth_nthash,
                    use_kerberos=use_kerberos,
                    aes_key=aes_key,
                    kdc_host=kdc_host,
                    use_cache=use_cache,
                    kerberos_tgt=kerberos_tgt,
                )
                if fatal_error is not None:
                    logger.debug(f"{fatal_error}")
                    _log_domain_auth_stop(logger)
                    export_results(
                        found_profiles_by_target, args, logger, console, partial=True
                    )
                    return 1
    except KeyboardInterrupt:
        logger.warning("Interrupted during profile collection")
        export_results(found_profiles_by_target, args, logger, console, partial=True)
        return 130
    except Exception as e:
        logger.error(f"Profile collection failed before completion: {e}")
        export_results(found_profiles_by_target, args, logger, console, partial=True)
        return 1
    logger.info(f"Found {len(found_profiles_by_target)} machines with profiles")

    if len(found_profiles_by_target) == 0:
        logger.warning(
            "No profiles found, check that you have the correct DNS and SMB permissions and try again"
        )
        if args.auth_dc_ip is None:
            logger.warning(
                "Perhaps use --auth-dc-ip to specify the domain controller IP?"
            )
        return 1

    if not export_results(found_profiles_by_target, args, logger, console):
        return 1


def print_statistics(found_profiles_by_target, console):
    from rich.table import Table
    from rich.panel import Panel
    from datetime import datetime

    table = Table(title="ProfileHound Statistics", show_header=False, box=None)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    total_targets = len(found_profiles_by_target)

    unique_users = set()
    total_profiles = 0
    machine_counts = []

    user_counts = {}
    profile_dates = []

    for target, details in found_profiles_by_target.items():
        owners = details["owners"]
        count = len(owners)
        total_profiles += count
        machine_counts.append((target, count))

        for user, user_details in owners.items():
            unique_users.add(user)
            user_counts[user] = user_counts.get(user, 0) + 1

            created = user_details.get("created") or 0
            modified = user_details.get("modified") or 0
            if created and modified:
                profile_dates.append(
                    {
                        "user": user,
                        "target": target,
                        "created": created,
                        "modified": modified,
                        "duration": modified - created,
                    }
                )

    avg_profiles = total_profiles / total_targets if total_targets > 0 else 0

    table.add_row("Total Targets with Profiles", str(total_targets))
    table.add_row("Total Unique Profiles (Users)", str(len(unique_users)))
    table.add_row("Average Profiles per Target", f"{avg_profiles:.2f}")

    console.print(Panel(table, title="General Summary"))

    if any("artifacts" in details for details in found_profiles_by_target.values()):
        all_findings = list(iter_artifact_findings(found_profiles_by_target))
        aggregates = aggregate_findings(all_findings)
        artifact_summary = summarize_artifacts(
            found_profiles_by_target,
            findings=all_findings,
            aggregates=aggregates,
        )
        artifact_table = Table(title="Artifact Summary", show_header=False, box=None)
        artifact_table.add_column("Metric", style="cyan")
        artifact_table.add_column("Value", style="magenta")
        artifact_table.add_row("Profiles checked", str(artifact_summary.profileschecked))
        artifact_table.add_row(
            "Profiles with artifacts", str(artifact_summary.profileswithartifacts)
        )
        artifact_table.add_row(
            "Artifact nodes created", str(artifact_summary.artifactnodescreated)
        )
        artifact_table.add_row(
            "Artifact findings", str(artifact_summary.artifactfindings)
        )
        artifact_table.add_row(
            "Total artifact matches", str(artifact_summary.totalmatches)
        )
        artifact_table.add_row("Downloaded files", str(artifact_summary.downloadedfiles))
        artifact_table.add_row(
            "Browser profiles downloaded",
            str(artifact_summary.downloadedbrowserprofiles),
        )
        artifact_table.add_row("Artifact errors", str(artifact_summary.artifacterrors))
        console.print(Panel(artifact_table, title="Artifact Collection"))

        artifact_type_counts = {}
        artifact_category_counts = {}
        for aggregate in aggregates:
            type_counts = artifact_type_counts.setdefault(
                aggregate.artifacttype,
                {"nodes": 0, "findings": 0, "matches": 0},
            )
            type_counts["nodes"] += 1
            for category in {finding.category for finding in aggregate.findings}:
                category_counts = artifact_category_counts.setdefault(
                    category,
                    {"nodes": 0, "findings": 0},
                )
                category_counts["nodes"] += 1
        for finding in all_findings:
            type_counts = artifact_type_counts.setdefault(
                finding.artifacttype,
                {"nodes": 0, "findings": 0, "matches": 0},
            )
            type_counts["findings"] += 1
            type_counts["matches"] += finding.matchcount
            category_counts = artifact_category_counts.setdefault(
                finding.category,
                {"nodes": 0, "findings": 0},
            )
            category_counts["findings"] += 1

        if artifact_type_counts:
            type_table = Table(title="Top Artifact Types")
            type_table.add_column("Artifact Type", style="green")
            type_table.add_column("Artifact Nodes", style="yellow")
            type_table.add_column("Findings", style="cyan")
            type_table.add_column("Matches", style="magenta")
            for artifacttype, counts in sorted(
                artifact_type_counts.items(),
                key=lambda item: item[1]["matches"],
                reverse=True,
            )[:5]:
                type_table.add_row(
                    artifacttype,
                    str(counts["nodes"]),
                    str(counts["findings"]),
                    str(counts["matches"]),
                )
            console.print(type_table)

            category_table = Table(title="Top Artifact Categories")
            category_table.add_column("Category", style="green")
            category_table.add_column("Artifact Nodes", style="yellow")
            category_table.add_column("Findings", style="cyan")
            for category, counts in sorted(
                artifact_category_counts.items(),
                key=lambda item: item[1]["findings"],
                reverse=True,
            )[:5]:
                category_table.add_row(
                    category, str(counts["nodes"]), str(counts["findings"])
                )
            console.print(category_table)

    # Top connected users
    sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    user_table = Table(title="Users with most profiles")
    user_table.add_column("User", style="green")
    user_table.add_column("Machine Count", style="yellow")
    for user, count in sorted_users:
        user_table.add_row(user, str(count))
    console.print(user_table)

    # Top populated machines
    sorted_machines = sorted(machine_counts, key=lambda x: x[1], reverse=True)[:5]
    machine_table = Table(title="Top Populated Machines")
    machine_table.add_column("Machine", style="blue")
    machine_table.add_column("Profile Count", style="yellow")
    for machine, count in sorted_machines:
        machine_table.add_row(machine, str(count))
    console.print(machine_table)

    # Oldest Profiles
    sorted_by_date = sorted(profile_dates, key=lambda x: x["created"])[:5]
    oldest_table = Table(title="Oldest User Profiles")
    oldest_table.add_column("User", style="green")
    oldest_table.add_column("Machine", style="blue")
    oldest_table.add_column("Created", style="cyan")
    oldest_table.add_column("Last Modified", style="yellow")
    for p in sorted_by_date:
        created_str = datetime.fromtimestamp(p["created"]).strftime("%Y-%m-%d")
        modified_str = datetime.fromtimestamp(p["modified"]).strftime("%Y-%m-%d")
        oldest_table.add_row(p["user"], p["target"], created_str, modified_str)
    console.print(oldest_table)

    # Longest Duration
    sorted_by_duration = sorted(
        profile_dates, key=lambda x: x["duration"], reverse=True
    )[:5]
    duration_table = Table(title="Longest Lived Profiles (Created -> Modified)")
    duration_table.add_column("User", style="green")
    duration_table.add_column("Machine", style="blue")
    duration_table.add_column("Age (Days)", style="magenta")
    duration_table.add_column("Created", style="cyan")
    duration_table.add_column("Last Modified", style="yellow")
    for p in sorted_by_duration:
        days = p["duration"] / 86400
        duration_table.add_row(
            p["user"],
            p["target"],
            f"{days:.1f}",
            datetime.fromtimestamp(p["created"]).strftime("%Y-%m-%d"),
            datetime.fromtimestamp(p["modified"]).strftime("%Y-%m-%d"),
        )
    console.print(duration_table)

    # Top 5 Focus Machines
    machine_scores = []
    for target, details in found_profiles_by_target.items():
        score = 0
        owners = details["owners"]
        profile_count = len(owners)

        # Base score is profile count
        score += profile_count * 1.0

        # Bonus for having "connector" users (users present on many machines)
        connector_bonus = 0
        for user in owners:
            if user_counts[user] > 1:
                connector_bonus += user_counts[
                    user
                ]  # Add the number of machines this user is on

        score += connector_bonus * 0.5
        machine_scores.append((target, score, profile_count))

    sorted_focus = sorted(machine_scores, key=lambda x: x[1], reverse=True)[:5]

    focus_table = Table(title="Top 5 Machines to Focus On (Hubs)")
    focus_table.add_column("Machine", style="red bold")
    focus_table.add_column("Score", style="yellow")
    focus_table.add_column("Reason", style="white")

    for machine, score, count in sorted_focus:
        focus_table.add_row(
            machine,
            f"{score:.1f}",
            f"Has {count} profiles, potential lateral movement hub",
        )

    console.print(focus_table)


if __name__ == "__main__":
    main()
