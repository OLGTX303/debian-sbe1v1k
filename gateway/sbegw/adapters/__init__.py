"""Adapter layer.

Product code (netd/wifid/api) must depend only on these interfaces, never on a
QSDK or distro command line directly (wifi spec §52). Each adapter reports its
own availability so a missing tool degrades a capability instead of raising.
"""
from . import ethtool, hostapd, nft, nl80211, platform, rtnl  # noqa: F401

__all__ = ["ethtool", "hostapd", "nft", "nl80211", "platform", "rtnl"]
