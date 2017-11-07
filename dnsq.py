"""
High-level DNS library built on top of dnspython.
Only two functions matter here:

    - query_dns()    : runs an arbitrary DNS query
    - mx_hosts_for() : returns a list of MX hosts for a given domain
"""
import logging
import socket
import threading
from collections import deque
from itertools import groupby
from random import shuffle

import dns
import dns.exception
import dns.resolver
import dns.reversename
from expiringdict import ExpiringDict

_log = logging.getLogger(__name__)

_DNS_CACHE_LIFE_SECONDS = 240.0
_DNS_TIMEOUT_SECONDS = 3.0  # timeout per DNS server
_DNS_LIFETIME_TIMEOUT_SECONDS = 5.2  # total timeout per DNS request
_PTR_CACHE_LEN = 512

# This cache is used to store PTR records for IP addresses
_ptr_cache = ExpiringDict(max_len=_PTR_CACHE_LEN,
                          max_age_seconds=_DNS_CACHE_LIFE_SECONDS)

_thread_local = threading.local()
_thread_local.resolver = None


def get_primary_nameserver(hostname):
    """
    Query DNS for the primary nameserver (SOA) for the given hostname.
    """
    dq = deque(hostname.split('.'))
    while len(dq) > 1:
        soa = query_dns('.'.join(dq), 'SOA')
        if soa:
            return soa[0].split(" ")[0].strip(".")
        dq.popleft()


def mx_hosts_for(hostname):
    """
    Returns a list of MX hostnames for a given domain name, sorted by their priority + randomization
    Note that if no MX records are found it falls back to default

    >>> mx_hosts_for('gmail.com')
    ['alt1.gmail-smtp-in.l.google.com', 'alt2.gmail-smtp-in.l.google.com']

    Raises ecxeptions for network errors.
    """
    retval = []
    try:
        answers = sorted(_exec_query(hostname, 'MX'))
        for mx_pref, grouper in groupby(answers,
                                        lambda entry: entry.preference):
            group = [entry.exchange.to_text() for entry in grouper]
            shuffle(group)
            retval += group

    # timeout, raise an exception - let them retry
    except dns.exception.Timeout:
        raise Exception("DNS failure for " + str(hostname))

    # no MX record:
    except dns.resolver.NoAnswer:
        retval = [hostname]

    # invalid domain
    except dns.resolver.NXDOMAIN:
        retval = []

    # empty label (ex: domain..com)
    except dns.name.EmptyLabel:
        retval = []

    # filter out invalid queries (tld does not exist)
    dns_attention_string = ''.join(
        ['your-dns-needs-immediate-attention.', hostname.rstrip('.'), '.'])
    retval = [s for s in retval if s != dns_attention_string]

    # strip ending . and filter None
    retval = [h.strip('.') for h in retval]
    return filter(lambda x: x, retval)


def ptr_record_for(ipaddress):
    """
    Performs reverse DNS lookup on a given IP address.
    This is a replacement for socket.gethostbyaddr(), but with the following
    differences:
        - Returns None instead of throwing exceptions
        - It is fast: it will not block for 5+ seconds for IPs without PTRs
        - It is caching: it will be instant nearly all the time

        >>> ptr_record_for('127.0.0.1')
        "localhost"
        >>> ptr_record_for('74.125.224.123')
        "nuq04s08-in-f27.1e100.net"
        >>> ptr_record_for('74.125.224.1')
        None
    """
    if ipaddress == '127.0.0.1':
        return 'localhost'

    MISSING = "unknown"
    retval = None

    # see if we have it cached:
    cached_value = _ptr_cache.get(ipaddress)
    if cached_value:
        return cached_value if cached_value != MISSING else None

    try:
        # get the in_addr.arpa name, like 142.224.125.74.in-addr.arpa.
        inaddr_arpa_name = dns.reversename.from_address(ipaddress).to_text()

        # now use ARPA name to query for PTR:
        hosts = query_dns(inaddr_arpa_name, "PTR")
        if hosts:
            retval = hosts[0].strip('.')
            _ptr_cache[ipaddress] = retval
            # success: found the PTR record:
            return retval
    except:
        pass

    # no suitable PTR:
    _ptr_cache[ipaddress] = MISSING
    return None


def spf_record_for(hostname, bypass_cache=True):
    """Retrieves SPF record for a given hostname.

    According to the standard, domain must not have multiple SPF records, so
    if it's the case then an empty string is returned.
    """
    try:
        primary_ns = None
        if bypass_cache:
            primary_ns = get_primary_nameserver(hostname)

        txt_records = query_dns(hostname, 'txt', primary_ns)
        spf_records = [r for r in txt_records if r.strip().startswith('v=spf')]

        if len(spf_records) == 1:
            return spf_records[0]

    except Exception as e:
        _log.exception(e)

    return ''


def query_dns(hostname, record_type, name_srv=None, tcp=True):
    """
    Runs simple DNS queries, like:
        >>> query_dns('mailgun.net', 'txt')
        ['v=spf1 include:_spf.mailgun.org ~all']
    """
    try:
        # if nameserver was specified, convert it into IP:
        name_srv_ip = None
        if name_srv:
            ips = query_dns(name_srv, 'A')
            if ips:
                name_srv_ip = ips[0]

        records = _exec_query(hostname, record_type, name_srv_ip, tcp=tcp)
        if record_type.lower() == 'txt':
            return [record.to_text().strip("\"").replace('" "', '') for record
                    in records]
        else:
            return [record.to_text() for record in records]

    # no entry?
    except (
            dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []


def _exec_query(hostname, record_type, name_srv_ip=None, tcp=True):
    """
    Execute a DNS query against a given name source.
    """
    try:
        # if nameserver specified then try it first.
        if name_srv_ip:
            resolver = _new_resolver(name_srv_ip)
            try:
                return resolver.query(hostname, record_type, tcp=tcp)
            except dns.exception.Timeout:
                pass

        # if it's not specified or timed out then use default nameserver
        return _get_default_resolver().query(hostname, record_type, tcp=tcp)

    except (dns.exception.Timeout,
            dns.resolver.NoNameservers,
            socket.error):
        return []


def _get_default_resolver():
    """
    Returns DNS resolver instance for the calling thread.
    """
    resolver = getattr(_thread_local, 'resolver', None)
    if resolver:
        return resolver

    _thread_local.resolver = _new_resolver()
    return _thread_local.resolver


def _new_resolver(name_srv_ip=None):
    resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT_SECONDS
    resolver.lifetime = _DNS_LIFETIME_TIMEOUT_SECONDS
    if name_srv_ip:
        resolver.nameservers = [name_srv_ip]
    return resolver
