"""Network utilities for private/public IP checking and network entity grouping."""

import ipaddress
from typing import Any, Dict, Optional


def is_non_private_ip(ip_str: Optional[str]) -> bool:
    """Returns True if the IP is a valid public/non-private IPv4 or IPv6 address."""
    if not ip_str:
        return False
    ip_clean = str(ip_str).strip()
    if ip_clean in ("127.0.0.1", "::1", "localhost", "-", "::"):
        return False
    try:
        ip = ipaddress.ip_address(ip_clean)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
    except ValueError:
        return False


def get_network_group_key(ip_str: Optional[str], raw: Optional[Dict[str, Any]] = None) -> str:
    """
    Groups network activity by Gateway MAC, DHCP Server, FQDN or IP Subnet (/24 or /64)
    instead of raw ephemeral DHCP IP.
    """
    raw_dict = raw or {}
    # 1. Prefer hardware / infrastructure identifiers if provided
    gateway_mac = raw_dict.get("GatewayMac") or raw_dict.get("SourceMac")
    if gateway_mac:
        return f"mac:{gateway_mac.lower()}"

    dhcp_server = raw_dict.get("DhcpServer")
    if dhcp_server:
        return f"dhcp:{dhcp_server}"

    hostname = raw_dict.get("SourceHostname") or raw_dict.get("DestinationHostname")
    if hostname and hostname not in ("localhost", "-"):
        return f"host:{hostname.lower()}"

    if not ip_str:
        return "unknown_net"

    clean_ip = str(ip_str).strip()
    try:
        ip = ipaddress.ip_address(clean_ip)
        if ip.version == 4:
            # Group IPv4 by /24 subnet
            net = ipaddress.IPv4Network(f"{clean_ip}/24", strict=False)
            return f"subnet:{net.network_address}/24"
        else:
            # Group IPv6 by /64 subnet
            net6 = ipaddress.IPv6Network(f"{clean_ip}/64", strict=False)
            return f"subnet:{net6.network_address}/64"
    except ValueError:
        return f"ip:{clean_ip}"
