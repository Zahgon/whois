# -*- coding: utf-8 -*-

import logging
import os
import re
import socket
import subprocess
import sys
from typing import Any, Optional, Pattern

from .exceptions import WhoisError
from .parser import WhoisEntry
from .whois import NICClient

logger = logging.getLogger(__name__)

# thanks to https://www.regextester.com/104038
IPV4_OR_V6: Pattern[str] = re.compile(
    r"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))"  # noqa: E501
)


def whois(
    url: str,
    command: bool = False,
    flags: int = 0,
    executable: str = "whois",
    executable_opts: Optional[list[str]] = None,
    inc_raw: bool = False,
    quiet: bool = False,
    ignore_socket_errors: bool = True,
    convert_punycode: bool = True,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    url: the URL to search whois
    command: whether to use the native whois command (default False)
    executable: executable to use for native whois command (default 'whois')
    flags: flags to pass to the whois client (default 0)
    inc_raw: whether to include the raw text from whois in the result (default False)
    quiet: whether to avoid printing output (default False)
    ignore_socket_errors: whether to ignore socket errors (default True)
    convert_punycode: whether to convert the given URL punycode (default True)
    timeout: timeout for WHOIS request (default 10 seconds)
    """
    pass


suffixes: Optional[set] = None


def extract_domain(url: str) -> str:
    """Extract the domain from the given URL

    >>> logger.info(extract_domain('http://www.google.com.au/tos.html'))
    google.com.au
    >>> logger.info(extract_domain('abc.def.com'))
    def.com
    >>> logger.info(extract_domain(u'www.å…¬å�¸.hk'))
    å…¬å�¸.hk
    >>> logger.info(extract_domain('chambagri.fr'))
    chambagri.fr
    >>> logger.info(extract_domain('www.webscraping.com'))
    webscraping.com
    >>> logger.info(extract_domain('198.252.206.140'))
    stackoverflow.com
    >>> logger.info(extract_domain('102.112.2O7.net'))
    2o7.net
    >>> logger.info(extract_domain('globoesporte.globo.com'))
    globo.com
    >>> logger.info(extract_domain('1-0-1-1-1-0-1-1-1-1-1-1-1-.0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info'))
    0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info
    >>> logger.info(extract_domain('2607:f8b0:4006:802::200e'))
    1e100.net
    >>> logger.info(extract_domain('172.217.3.110'))
    1e100.net
    """
    pass


if __name__ == "__main__":
    try:
        url = sys.argv[1]
    except IndexError:
        logger.error("Usage: %s url" % sys.argv[0])
    else:
        logger.info(whois(url))
