import logging
import sys
import types
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch


class FakeSessionError(Exception):
    pass


def install_module(name, **attrs):
    module = types.ModuleType(name)
    for attr_name, attr_value in attrs.items():
        setattr(module, attr_name, attr_value)
    sys.modules[name] = module
    return module


class DummyRichHandler(logging.Handler):
    def __init__(self, *args, **kwargs):
        super().__init__()

    def emit(self, record):
        pass


class DummyColumn:
    def __init__(self, *args, **kwargs):
        pass


class DummyConsole:
    def __init__(self, *args, **kwargs):
        pass


class DummyResolver:
    nameservers = ["127.0.0.1"]


class DummyConfig:
    pass


class DummyOpenGraph:
    def __init__(self, *args, **kwargs):
        pass

    def add_node(self, *args, **kwargs):
        pass

    def add_edge(self, *args, **kwargs):
        pass

    def export_to_file(self, *args, **kwargs):
        pass


class DummyGraphObject:
    def __init__(self, *args, **kwargs):
        self.id = kwargs.get("id")


dns_resolver_module = install_module(
    "dns.resolver", Resolver=DummyResolver, NXDOMAIN=type("NXDOMAIN", (Exception,), {})
)
install_module("dns", resolver=dns_resolver_module)
install_module("impacket")
install_module("impacket.smbconnection", SessionError=FakeSessionError)
install_module("rich")
install_module(
    "rich.progress",
    Progress=None,
    SpinnerColumn=DummyColumn,
    TextColumn=DummyColumn,
    BarColumn=DummyColumn,
    TaskProgressColumn=DummyColumn,
    TimeRemainingColumn=DummyColumn,
)
install_module("rich.logging", RichHandler=DummyRichHandler)
install_module("rich.console", Console=DummyConsole)
install_module("sharehound")
install_module("sharehound.targets", load_targets=lambda *args, **kwargs: [])
install_module("sharehound.core")
install_module("sharehound.core.Config", Config=DummyConfig)
install_module("bhopengraph")
install_module("bhopengraph.OpenGraph", OpenGraph=DummyOpenGraph)
install_module("bhopengraph.Node", Node=DummyGraphObject)
install_module("bhopengraph.Edge", Edge=DummyGraphObject)
install_module("bhopengraph.Properties", Properties=DummyGraphObject)
install_module(
    "profilehound.modules.smb",
    enumerate_user_profiles=lambda *args, **kwargs: ({}, {}, {}, {}),
    SKIP_PROFILE_NAMES=set(),
)

import profilehound.__main__ as profilehound_main


class DummyProgress:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def add_task(self, *args, **kwargs):
        return 1

    def update(self, *args, **kwargs):
        pass


def make_args(ignore_failed_domain_auth=False):
    return SimpleNamespace(
        quiet=True,
        debug=False,
        verbose=False,
        targets_file=None,
        target=["10.0.0.1", "10.0.0.2"],
        dns_server=None,
        smb_local_auth=False,
        auth_user="alice",
        auth_password="password",
        auth_domain="example.local",
        auth_hashes=None,
        smb_timeout=3,
        smb_ignore_failed_domain_auth=ignore_failed_domain_auth,
        auth_dc_ip="10.0.0.10",
        no_stats=True,
        output="profilehound.json",
    )


class MainSmbDomainAuthFailureTests(TestCase):
    def test_domain_auth_failure_stops_remaining_targets_by_default(self):
        with (
            patch.object(profilehound_main, "get_args", return_value=make_args()),
            patch.object(
                profilehound_main,
                "load_targets",
                return_value=[("ip", "10.0.0.1"), ("ip", "10.0.0.2")],
            ),
            patch.object(profilehound_main, "Progress", DummyProgress),
            patch.object(profilehound_main, "SessionError", FakeSessionError),
            patch.object(
                profilehound_main,
                "enumerate_user_profiles",
                side_effect=FakeSessionError("domain auth failed"),
            ) as enumerate_user_profiles,
        ):
            result = profilehound_main.main()

        self.assertEqual(result, 1)
        self.assertEqual(enumerate_user_profiles.call_count, 1)

    def test_ignore_failed_domain_auth_continues_remaining_targets(self):
        with (
            patch.object(
                profilehound_main,
                "get_args",
                return_value=make_args(ignore_failed_domain_auth=True),
            ),
            patch.object(
                profilehound_main,
                "load_targets",
                return_value=[("ip", "10.0.0.1"), ("ip", "10.0.0.2")],
            ),
            patch.object(profilehound_main, "Progress", DummyProgress),
            patch.object(profilehound_main, "SessionError", FakeSessionError),
            patch.object(
                profilehound_main,
                "enumerate_user_profiles",
                side_effect=[
                    FakeSessionError("domain auth failed"),
                    ({}, {}, {}, {}),
                ],
            ) as enumerate_user_profiles,
        ):
            result = profilehound_main.main()

        self.assertEqual(result, 1)
        self.assertEqual(enumerate_user_profiles.call_count, 2)
