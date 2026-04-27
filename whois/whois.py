# -*- coding: utf-8 -*-

"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2010 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
from __future__ import annotations
import logging
import optparse
import os
import re
import socket
import sys
from typing import Optional, Pattern

logger = logging.getLogger(__name__)


class NICClient:
    ABUSEHOST = "whois.abuse.net"
    AI_HOST = "whois.nic.ai"
    ANICHOST = "whois.arin.net"
    APP_HOST = "whois.nic.google"
    AR_HOST = "whois.nic.ar"
    BNICHOST = "whois.registro.br"
    BW_HOST = "whois.nic.net.bw"
    BY_HOST = "whois.cctld.by"
    CA_HOST = "whois.ca.fury.ca"
    CHAT_HOST = "whois.nic.chat"
    CL_HOST = "whois.nic.cl"
    CM_HOST = "whois.netcom.cm"
    CR_HOST = "whois.nic.cr"
    DEFAULT_PORT = "nicname"
    DENICHOST = "whois.denic.de"
    DEV_HOST = "whois.nic.google"
    DE_HOST = "whois.denic.de"
    DK_HOST = "whois.dk-hostmaster.dk"
    DNICHOST = "whois.nic.mil"
    DO_HOST = "whois.nic.do"
    GAMES_HOST = "whois.nic.games"
    GNICHOST = "whois.nic.gov"
    GOOGLE_HOST = "whois.nic.google"
    GROUP_HOST = "whois.namecheap.com"
    HK_HOST = "whois.hkirc.hk"
    HN_HOST = "whois.nic.hn"
    HR_HOST = "whois.dns.hr"
    IANAHOST = "whois.iana.org"
    INICHOST = "whois.networksolutions.com"
    IST_HOST = "whois.afilias-srs.net"
    JOBS_HOST = "whois.nic.jobs"
    JP_HOST = "whois.jprs.jp"
    KZ_HOST = "whois.nic.kz"
    LAT_HOST = "whois.nic.lat"
    LI_HOST = "whois.nic.li"
    LIVE_HOST = "whois.nic.live"
    LNICHOST = "whois.lacnic.net"
    LT_HOST = "whois.domreg.lt"
    MARKET_HOST = "whois.nic.market"
    MNICHOST = "whois.ra.net"
    MONEY_HOST = "whois.nic.money"
    MX_HOST = "whois.mx"
    NICHOST = "whois.crsnic.net"
    NL_HOST = "whois.domain-registry.nl"
    NORIDHOST = "whois.norid.no"
    ONLINE_HOST = "whois.nic.online"
    OOO_HOST = "whois.nic.ooo"
    PAGE_HOST = "whois.nic.page"
    PANDIHOST = "whois.pandi.or.id"
    PE_HOST = "kero.yachay.pe"
    PNICHOST = "whois.apnic.net"
    QNICHOST_TAIL = ".whois-servers.net"
    QNICHOST_HEAD = "whois.nic."
    RNICHOST = "whois.ripe.net"
    SNICHOST = "whois.6bone.net"
    WEBSITE_HOST = "whois.nic.website"
    ZA_HOST = "whois.registry.net.za"
    RU_HOST = "whois.tcinet.ru"
    IDS_HOST = "whois.identitydigital.services"
    GDD_HOST = "whois.dnrs.godaddy"
    SHOP_HOST = "whois.nic.shop"
    SG_HOST = "whois.sgnic.sg"
    STORE_HOST = "whois.centralnic.com"
    STUDIO_HOST = "whois.nic.studio"
    DETI_HOST = "whois.nic.xn--d1acj3b"
    MOSKVA_HOST = "whois.registry.nic.xn--80adxhks"
    RF_HOST = "whois.registry.tcinet.ru"
    PIR_HOST = "whois.publicinterestregistry.org"
    NG_HOST = "whois.nic.net.ng"
    PPUA_HOST = "whois.pp.ua"
    UKR_HOST = "whois.dotukr.com"
    TN_HOST = "whois.ati.tn"
    SBS_HOST = "whois.nic.sbs"
    GA_HOST = "whois.nic.ga"
    XYZ_HOST = "whois.nic.xyz"

    SITE_HOST = "whois.nic.site"
    DESIGN_HOST = "whois.nic.design"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois: list[str] = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

    def __init__(self, prefer_ipv6: bool = False):
        self.use_qnichost: bool = False
        self.prefer_ipv6 = prefer_ipv6

    @staticmethod
    def findwhois_server(buf: str, hostname: str, query: str) -> Optional[str]:
        """Search the initial TLD lookup results for the regional-specific
        whois server for getting contact details.
        """
        pass

    @staticmethod
    def get_socks_socket():
        pass

    def _connect(self, hostname: str, timeout: int) -> socket.socket:
        """Resolve WHOIS IP address and connect to its TCP 43 port."""
        pass

    def findwhois_iana(self, tld: str, timeout: int = 10) -> Optional[str]:
        pass

    def whois(
        self,
        query: str,
        hostname: str,
        flags: int,
        many_results: bool = False,
        quiet: bool = False,
        timeout: int = 10,
        ignore_socket_errors: bool = True
    ) -> str:
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specific whois server and do a lookup
        there for contact details.  If `quiet` is `True`, will
        not send a message to logger when a socket error
        is encountered. Uses `timeout` as a number of seconds
        to set as a timeout on the socket. If `ignore_socket_errors`
        is `False`, will raise an exception instead of returning
        a string containing the error.
        """
        pass

    def choose_server(self, domain: str, timeout: int = 10) -> Optional[str]:
        """Choose initial lookup NIC host"""
        pass
            # server = tld + NICClient.QNICHOST_TAIL
            # try:
            #    socket.gethostbyname(server)
            # except socket.gaierror:
            #    server = NICClient.QNICHOST_HEAD + tld
            # return server

    def whois_lookup(
        self, options: Optional[dict], query_arg: str, flags: int, quiet: bool = False, ignore_socket_errors: bool = True, timeout: int = 10
    ) -> str:
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records.  If `quiet` is `True`, no message
        will be printed to STDOUT when a socket error is encountered.
        If `ignore_socket_errors` is `False`, will raise an exception
        instead of returning a string containing the error."""
        pass


def parse_command_line(argv: list[str]) -> tuple[optparse.Values, list[str]]:
    """Options handling mostly follows the UNIX whois(1) man page, except
    long-form options can also be used.
    """
    pass


if __name__ == "__main__":
    flags = 0
    options, args = parse_command_line(sys.argv)
    nic_client = NICClient(prefer_ipv6=options.prefer_ipv6)
    if options.b_quicklookup:
        flags = flags | NICClient.WHOIS_QUICK
    logger.debug(nic_client.whois_lookup(options.__dict__, args[1], flags))
