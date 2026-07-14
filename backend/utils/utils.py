import ipaddress
import logging
import socket
import urllib.parse
from typing import (
    Sequence,
    Union,
)
import aiohttp
import aiohttp.resolver
import validators
from config import settings
from constants import ERROR_MESSAGES
from utils.misc import is_host_allowed


ENABLE_LOCAL_WEB_FETCH = False
WEB_FETCH_FILTER_LIST = [
    '!169.254.169.254',
    '!fd00:ec2::254',
    '!metadata.google.internal',
    '!metadata.azure.com',
    '!100.100.100.200',
]

log = logging.getLogger(__name__)


def resolve_hostname(hostname):
    # Get address information
    addr_info = socket.getaddrinfo(hostname, None)

    # Extract IP addresses from address information
    ipv4_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET]
    ipv6_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET6]

    return ipv4_addresses, ipv6_addresses


def validate_url(url: Union[str, Sequence[str]]):
    if isinstance(url, str):
        if isinstance(validators.url(url), validators.ValidationError):
            raise ValueError(ERROR_MESSAGES.INVALID_URL)

        # Reject parser-confusing chars: urlparse and requests/aiohttp split
        # on these differently, e.g. http://127.0.0.1\@1.1.1.1 → urlparse
        # extracts 1.1.1.1 (public, passes filter) while requests connects
        # to 127.0.0.1 (internal). Same shape with tab/CR/LF.
        if any(ch in url for ch in ('\\', '\t', '\n', '\r')):
            log.warning(f'Blocked URL with parser-confusing char: {url!r}')
            raise ValueError(ERROR_MESSAGES.INVALID_URL)

        parsed_url = urllib.parse.urlparse(url)

        # Protocol validation - only allow http/https
        if parsed_url.scheme not in ['http', 'https']:
            log.warning(f'Blocked non-HTTP(S) protocol: {parsed_url.scheme} in URL: {url}')
            raise ValueError(ERROR_MESSAGES.INVALID_URL)

        # Blocklist check using unified filtering logic
        if WEB_FETCH_FILTER_LIST:
            # Match on the parsed hostname, not the full URL: a path component would
            # otherwise let any URL slip past a hostname-based block/allow entry.
            if not is_host_allowed(parsed_url.hostname, WEB_FETCH_FILTER_LIST):
                log.warning(f'URL blocked by filter list: {url}')
                raise ValueError(ERROR_MESSAGES.INVALID_URL)

        if not ENABLE_LOCAL_WEB_FETCH:
            # Local web fetch is disabled, filter out URLs that resolve to non-global IP addresses.
            parsed_url = urllib.parse.urlparse(url)
            # Get IPv4 and IPv6 addresses
            ipv4_addresses, ipv6_addresses = resolve_hostname(parsed_url.hostname)
            # Check if any of the resolved addresses are private
            # DNS rebinding is mitigated at the connection layer; see _SSRFSafeResolver / _SSRFSafeAdapter
            for ip in ipv4_addresses + ipv6_addresses:
                addr = ipaddress.ip_address(ip)
                if not addr.is_global:
                    raise ValueError(ERROR_MESSAGES.INVALID_URL)
        return True
    elif isinstance(url, Sequence):
        return all(validate_url(u) for u in url)
    else:
        return False


class _SSRFSafeResolver(aiohttp.resolver.DefaultResolver):
    """aiohttp resolver that rejects non-global IPs unless local fetch is on."""

    async def resolve(self, host, port=0, family=socket.AF_INET):
        results = await super().resolve(host, port, family)
        if not ENABLE_LOCAL_WEB_FETCH:
            for entry in results:
                if not ipaddress.ip_address(entry['host']).is_global:
                    raise ValueError(ERROR_MESSAGES.INVALID_URL)
        return results


def get_ssrf_safe_session() -> aiohttp.ClientSession:
    """A one-off aiohttp session that re-validates the connect-time IP via _SSRFSafeResolver,
    defeating DNS rebinding. Use for validate_url-gated fetches of user-supplied URLs that must
    not use the shared (rebinding-vulnerable) pool. Use as a context manager so it is closed:
    ``async with get_ssrf_safe_session() as session: ...``.
    """
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(resolver=_SSRFSafeResolver()),
        timeout=aiohttp.ClientTimeout(total=settings.AIOHTTP.CLIENT_TIMEOUT),
        trust_env=True,
    )
