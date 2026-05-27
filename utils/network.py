import socket
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    """
    Checks if a URL is safe to request.
    Prevents SSRF by blocking private, loopback, and reserved IP addresses.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        return is_safe_hostname(hostname)
    except Exception:
        return False

def is_safe_hostname(hostname):
    """
    Checks if a hostname resolves to a safe IP address.
    """
    try:
        # Resolve all IP addresses for the hostname
        # Using getaddrinfo to handle both IPv4 and IPv6
        addr_info = socket.getaddrinfo(hostname, None)
        for addr in addr_info:
            ip_str = addr[4][0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
        return True
    except Exception:
        # If it doesn't resolve, we might still want to block it if it looks like an IP
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
        except ValueError:
            pass
        return False
