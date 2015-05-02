# -*- coding: utf-8 -*-

"""
Set of usefull functions to retrieve data from SNMP.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from django.conf import settings
from pysnmp.entity.rfc3413.oneliner import cmdgen



SNMP_COMMUNITIES = getattr(settings, 'SNMP_PLUGIN_COMMUNITIES', ['public'])
SNMP_V3_AUTH = (
    settings.SNMP_V3_USER,
    settings.SNMP_V3_AUTH_KEY,
    settings.SNMP_V3_PRIV_KEY,
)
if not all(SNMP_V3_AUTH):
    SNMP_V3_AUTH = None
PRIV_PROTOCOLS = (
    cmdgen.usmDESPrivProtocol,
    cmdgen.usmAesCfb128Protocol,
    cmdgen.usmAesCfb192Protocol,
    cmdgen.usmAesCfb256Protocol,
)


def _snmp(
    ip, community, oid, attempts=2, timeout=3, snmp_version='2c',
    priv_protocol=cmdgen.usmDESPrivProtocol
):
    result = snmp_command(
        str(ip), community, oid, attempts=attempts, timeout=timeout,
        snmp_version=snmp_version, priv_protocol=priv_protocol,
    )
    if result is None:
        message = None
    else:
        message = unicode(result[0][1])
    return message


def get_snmp(ipaddress):
    community = ipaddress.snmp_community
    version = ipaddress.snmp_version or '2c'
    oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)  # sysDesc
    http_family = ipaddress.http_family
    message = None
    # Windows hosts always say that the port is closed, even when it's open
    if http_family not in ('Microsoft-IIS', 'Unspecified', 'RomPager'):
        if not check_snmp_port(ipaddress.address):
            return None, None, None
    if http_family == 'HP':
        version = '1'
        oid = (1, 3, 6, 1, 4, 1, 2, 3, 51, 2, 2, 21, 1, 1, 5, 0)
        # bladeCenterManufacturingId
    if http_family == 'RomPager':
        version = '1'
    if version != '3':
        # Don't try SNMP v2 if v3 worked on this host.
        communities = list(SNMP_COMMUNITIES)
        if community:
            if community in communities:
                communities.remove(community)
            communities.insert(0, community)
        for community in communities:
            message = _snmp(
                ipaddress.address,
                community,
                oid,
                attempts=2,
                timeout=0.2,
                snmp_version=version,
            )
            if message == '' and version != '1':
                # prevent empty response for some communities.
                version = '1'
                message = _snmp(
                    ipaddress.address,
                    community,
                    oid,
                    attempts=2,
                    timeout=0.2,
                    snmp_version=version,
                )
            if message:
                return message, community, version
    if SNMP_V3_AUTH:
        version = '3'
        for priv_protocol in PRIV_PROTOCOLS:
            message = _snmp(
                ipaddress.address,
                SNMP_V3_AUTH,
                oid,
                attempts=2,
                timeout=2,  # SNMP v3 usually needs more time
                snmp_version=version,
                priv_protocol=priv_protocol,
            )
            if message:
                return message, community, version
    if not message:
        return None, None, None
    return message, community, version



from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1902 import OctetString


def check_snmp_port(ip, port=161, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(b'0:\x02\x01\x030\x0f\x02\x02Ji\x02\x03\x00\xff\xe3\x04\x01'
                  b'\x04\x02\x01\x03\x04\x100\x0e\x04\x00\x02\x01\x00\x02\x01'
                  b'\x00\x04\x00\x04\x00\x04\x000\x12\x04\x00\x04\x00\xa0\x0c'
                  b'\x02\x027\xf0\x02\x01\x00\x02\x01\x000\x00')
        reply = s.recv(255)
    except socket.error:
        return False
    finally:
        s.close()
    return bool(reply)


def user_data(auth, snmp_version, priv_protocol=cmdgen.usmDESPrivProtocol):
    if snmp_version == '2c':
        community = auth
        data = cmdgen.CommunityData('ralph', community, 1)
    elif snmp_version in ('3', 3):
        # For snmpv3, auth is a tuple of user, password and encryption key
        snmp_v3_user, snmp_v3_auth, snmp_v3_priv = auth
        data = cmdgen.UsmUserData(
            snmp_v3_user,
            snmp_v3_auth,
            snmp_v3_priv,
            authProtocol=cmdgen.usmHMACSHAAuthProtocol,
            privProtocol=priv_protocol,
        )
    else:
        community = auth
        data = cmdgen.CommunityData('ralph', community, 0)
    return data


def snmp_command(
    hostname, community, oid, snmp_version='2c', timeout=1, attempts=3,
    priv_protocol=cmdgen.usmDESPrivProtocol
):
    transport = cmdgen.UdpTransportTarget((hostname, 161), attempts, timeout)
    data = user_data(community, snmp_version, priv_protocol=priv_protocol)
    gen = cmdgen.CommandGenerator()
    error, status, index, vars = gen.getCmd(data, transport, oid)
    if error:
        return None
    else:
        return vars


def snmp_walk(
    hostname, community, oid, snmp_version='2c', timeout=1, attempts=3,
    priv_protocol=cmdgen.usmDESPrivProtocol
):
    transport = cmdgen.UdpTransportTarget((hostname, 161), attempts, timeout)
    data = user_data(community, snmp_version, priv_protocol=priv_protocol)
    gen = cmdgen.CommandGenerator()
    error, status, index, values = gen.nextCmd(data, transport, oid)
    if not error:
        return values


def snmp_bulk(
    hostname, community, oid, snmp_version='2c', timeout=1, attempts=3
):
    transport = cmdgen.UdpTransportTarget((hostname, 161), attempts, timeout)
    data = user_data(community, snmp_version)
    gen = cmdgen.CommandGenerator()
    if snmp_version in ('2c', '3', 3):
        error, status, index, vars = gen.bulkCmd(data, transport, 0, 25, oid)
    else:
        error, status, index, vars = gen.nextCmd(data, transport, oid)
    if error:
        return {}
    return dict(i for i, in vars)


def snmp_macs(
    hostname, community, oid, snmp_version='2c', timeout=1, attempts=3
):
    for oid, value in snmp_bulk(hostname, community, oid, snmp_version,
                                timeout, attempts).iteritems():
        if isinstance(value, OctetString):
            mac = ''.join('%02x' % ord(c) for c in value).upper()
            if len(mac) == 12:
                yield mac
