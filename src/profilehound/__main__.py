import sys
import time
import logging
import argparse
import dns.resolver
from textwrap import dedent
from impacket.smbconnection import SessionError
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.logging import RichHandler
from rich.console import Console

from sharehound.targets import load_targets
from sharehound.core.Config import Config as SharehoundConfig
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
from profilehound.modules.smb import enumerate_user_profiles, SKIP_PROFILE_NAMES
from profilehound.__version__ import __version__

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
        required=True,
        help="Username for authentication (by default will be for both SMB and LDAP)",
    )
    global_args.add_argument(
        "--auth-password",
        required=True,
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
        "-q", "--quiet", default=False, action="store_true", help="Do not show banner"
    )
    global_args.add_argument(
        "-v", "--verbose", default=True, action="store_true", help="Verbose logging"
    )
    global_args.add_argument(
        "-d", "--debug", default=False, action="store_true", help="Debug logging"
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
        "--smb-timeout", type=int, default=3, help="SMB connection timeout in seconds (default: 3)"
    )
    smb_args.add_argument(
        "--smb-workers", type=int, default=8, help="SMB worker threads"
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
    return args


def create_opengraph(found_profiles_by_target):
    graph = OpenGraph(source_kind="Base")

    nodes = {}
    for target, target_details in found_profiles_by_target.items():
        profile_paths = []
        for profile_name, profile_details in target_details["owners"].items():
            nodes[profile_name] = Node(
                id=profile_details["sid"],
                kinds=["User", "Base"],
                properties=Properties(
                    HasUserProfile=[
                        profile_details["profile"],
                    ]
                ),
            )
            profile_paths.append(profile_details["profile"])

        nodes[target] = Node(
            id=target_details["machine_sid"],  # Need Machine SID here
            kinds=["Computer", "Base"],
            properties=Properties(HasUserProfile=profile_paths),
        )

    for node in nodes.values():
        graph.add_node(node)

    edges = []
    for target, target_details in found_profiles_by_target.items():
        for profile_name, profile_details in target_details["owners"].items():
            edges.append(
                Edge(
                    start_node=nodes[profile_name].id,
                    end_node=nodes[target].id,
                    kind="HasUserProfile",
                    properties=Properties(
                        method="ProfileHound - SMB Spider",
                        path=profile_details["profile"],
                        profileCreated=profile_details["created"],
                        profileModified=profile_details["modified"],
                    ),
                )
            )

    for edge in edges:
        graph.add_edge(edge)

    return graph


def main() -> int:
    args = get_args()
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
    handler = RichHandler(console=console, rich_tracebacks=True, show_path=False, show_time=True, show_level=True, markup=True)
    handler.setFormatter(logging.Formatter("%(message)s"))
    if not logger.handlers:
        logger.addHandler(handler)

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
    with Progress(
        SpinnerColumn("bouncingBall", style="magenta"),
        TextColumn("[bold cyan]{task.description}", justify="right"),
        BarColumn(bar_width=None, style="black", complete_style="magenta", finished_style="green"),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        transient=True,
        console=console,
    ) as progress:
        task_id = progress.add_task("[bold magenta]Hunting Profiles...", total=len(targets))
        for target in targets:
            progress.update(task_id, advance=1)
            if args.smb_local_auth:
                logger.debug(
                    f"Using local machine authentication for user {args.auth_user}"
                )
                args.auth_domain = target[1]
            if target[0] == "fqdn":
                try:
                    logger.debug(f"Attempting DNS resolution for {target[1]}")
                    ip = resolver.resolve(target[1], "A")[0].address
                    logger.debug(f"Resolved {target[1]} to {ip}")
                except dns.resolver.NXDOMAIN:
                    logger.info(
                        f"Target {target[1]} does not exist, received NXDOMAIN from DNS server {resolver.nameservers}"
                    )
                    continue
                except Exception as e:
                    logger.error(f"Failed to resolve target {target[1]}: {e}")
                    continue
            elif "ip" in target[0]:
                ip = target[1]
            try:
                owners, skipped, errors, machine = enumerate_user_profiles(
                    target=target[1],
                    username=args.auth_user,
                    password=args.auth_password,
                    domain=args.auth_domain,
                    lmhash=args.auth_hashes,
                    nthash=args.auth_hashes,
                    timeout=args.smb_timeout,
                    target_ip=ip,
                )
            except OSError as e:
                logger.debug(f"Failed to connect to {target[1]} ({ip}): {e}")
                continue
            except UserWarning as e:
                logger.warning(f"{e}")
                logger.warning(f"Continuing attempts for all remaining targets")
                continue
            except SessionError as e:
                logger.info(
                    rf"Failed to authenticate to {target[1]} with domain auth as {args.auth_domain}\{args.auth_user}"
                )
                logger.error(
                    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                )
                logger.error(
                    "!!!!! Stopping for all targets to prevent domain account lockout !!!!!"
                )
                logger.error(
                    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                )
                return 1
            except RuntimeError as e:
                logger.error(f"Failed to get profile enumeration for {target[1]}: {e}")
                continue
            except Exception as e:
                logger.error(f"Something really went wrong with {target[1]}, attempting to continue: {e}")
                continue

            if len(owners) == 0:
                logger.info(f"No domain profiles found for {target[1]}")
                continue
            found_profiles_by_target[target[1]] = {
                "owners": owners,
                "machine_sid": machine["sid"],
            }
            logger.info(f"Found {len(owners)} domain profile(s) for {target[1]}")
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

    # Now we have a dict of targets with their profiles, time to create the OpenGraph
    graph = create_opengraph(found_profiles_by_target)
    graph.export_to_file(args.output)
    logger.info(f"Exported OpenGraph intel to {args.output}")


if __name__ == "__main__":
    main()
