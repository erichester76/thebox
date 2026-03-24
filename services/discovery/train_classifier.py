"""Train the TheBox RF device-type classifier and save it to MODEL_PATH.

This script can be run:

1. **At Docker build time** (baked into the image): the Dockerfile copies this
   file and calls ``python train_classifier.py`` so the model is available
   the moment the container starts.

2. **With a Fingerbank API key** (recommended for highest accuracy)::

       python train_classifier.py --fingerbank-api-key <YOUR_API_KEY>

   This pulls labelled DHCP fingerprint data directly from the Fingerbank REST
   API (paginating ``/devices`` and ``/dhcp_fingerprints``).  Register for a
   free key at https://fingerbank.org/users/register.  The ``FINGERBANK_API_KEY``
   environment variable is also accepted automatically.

3. **Manually with the fingerbank JSON dataset**::

       python train_classifier.py --fingerbank-json /path/to/fingerprints_and_devices.json

   The fingerbank Open Source Database (CC-licensed) is available at:
   https://github.com/fingerbank/open-source-database

4. **Manually with the fingerbank SQLite database**::

       python train_classifier.py --fingerbank-db /path/to/fingerbank.db

   The ``fingerbank.db`` file can be downloaded from the Fingerbank API::

       curl -k -o fingerbank.db "https://api.fingerbank.org/api/v2/download/db?key=<YOUR_API_KEY>"

   .. note::
       Many standard DB downloads have an empty ``combination`` table and
       ``mac_vendor.device_id`` always set to 0, which yields no training
       samples.  Prefer option 2 (``--fingerbank-api-key``) in that case.

5. **Interactively** to inspect feature importances or cross-validation scores::

       python train_classifier.py --cv --verbose

The trained model is a sklearn RandomForestClassifier serialised with joblib.
Expected size: ~50–150 KB.  Loaded by ``device_classifier.py`` at runtime.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

# Allow importing device_classifier from the same directory when called as a
# standalone script (not installed as a package).
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from device_classifier import (  # noqa: E402
    DEVICE_TYPES,
    FEATURE_COUNT,
    MODEL_PATH,
    extract_features,
)

# ── Synthetic training dataset ────────────────────────────────────────────────
# Each sample is a dict with keys matching the extract_features() signature
# plus a "label" key (one of DEVICE_TYPES).
#
# Rationale: a small but representative set of canonical device profiles gives
# the RF model a strong prior that generalises well to home/SMB networks.
# The model is then refined when the operator provides the fingerbank dataset.


def _p(*ports: int) -> list[dict]:
    """Helper: build an open_ports list from a sequence of port numbers."""
    return [{"port": p, "state": "open", "service": ""} for p in ports]


def _m(*stypes: str) -> dict:
    """Helper: build an extra_info dict with mDNS service types."""
    return {"mdns_services": [{"service_type": s} for s in stypes]}


def _h(server: str, **extra: object) -> dict:
    """Helper: build an extra_info dict with an HTTP server banner."""
    d = {"http_server": server}
    d.update(extra)
    return d


def _mh(*stypes: str, **extra: object) -> dict:
    """Helper: extra_info with both mDNS and optional extra keys."""
    d: dict = {"mdns_services": [{"service_type": s} for s in stypes]}
    d.update(extra)
    return d


# fmt: off
_SYNTHETIC_DATA: list[dict] = [

    # ── IoT ───────────────────────────────────────────────────────────────────
    # Espressif-based smart plugs / bulbs (BusyBox udhcpc fingerprint)
    {"label": "iot", "vendor": "Espressif Inc.",     "open_ports": _p(80),          "extra_info": _h("uhttpd"),             "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "vendor": "Espressif Inc.",     "open_ports": _p(80, 443),     "extra_info": _h("uhttpd"),             "dhcp_fingerprint": "1,3,6,12,15,28,42"},
    {"label": "iot", "vendor": "Shenzhen Tuya",      "open_ports": _p(80),          "extra_info": _h("busybox"),            "dhcp_fingerprint": "1,3,6,12,15,28"},
    {"label": "iot", "vendor": "Tuya Global Inc.",   "open_ports": _p(80, 443),     "extra_info": {},                       "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "vendor": "Belkin International","open_ports": _p(80, 49152),  "extra_info": _h("mini_httpd"),         "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "iot", "vendor": "WeMo Device",        "open_ports": _p(49152, 49153),"extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Google Chromecast / Cast devices
    {"label": "iot", "vendor": "Google LLC",         "open_ports": _p(8008, 8009),  "extra_info": _m("_googlecast._tcp"),   "dhcp_fingerprint": "1,3,6,15,119,252"},
    {"label": "iot", "vendor": "Google LLC",         "open_ports": _p(8009),        "extra_info": _m("_cast._tcp"),         "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "iot", "vendor": "Google LLC",         "open_ports": _p(80, 8008),    "extra_info": _m("_googlecast._tcp", "_spotify-connect._tcp"), "dhcp_fingerprint": "1,3,6,15,119"},
    # Amazon Echo / Ring
    {"label": "iot", "vendor": "Amazon Technologies","open_ports": _p(443, 55443),  "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,119,252"},
    {"label": "iot", "vendor": "Amazon Technologies","open_ports": _p(80, 443),     "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "iot", "vendor": "Ring LLC",           "open_ports": _p(80, 443),     "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Philips Hue bridge
    {"label": "iot", "vendor": "Philips Lighting BV","open_ports": _p(80, 443),     "extra_info": _h("nginx"),              "dhcp_fingerprint": "1,3,6,15,28,42,100,101"},
    {"label": "iot", "vendor": "Signify Netherlands","open_ports": _p(80),          "extra_info": _h("mini_httpd"),         "dhcp_fingerprint": "1,3,6,12,15,28"},
    # Nest / smart home
    {"label": "iot", "vendor": "Nest Labs Inc.",     "open_ports": _p(443),         "extra_info": _m("_matter._tcp"),       "dhcp_fingerprint": "1,3,6,15,119,252"},
    {"label": "iot", "vendor": "Nest Labs Inc.",     "open_ports": _p(443, 9543),   "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,119"},
    # IP cameras (RTSP)
    {"label": "iot", "vendor": "Hikvision Digital",  "open_ports": _p(80, 443, 554),"extra_info": _h("hikvision"),          "dhcp_fingerprint": "1,3,6,12,15,28"},
    {"label": "iot", "vendor": "Dahua Technology",   "open_ports": _p(80, 554),     "extra_info": {},                       "dhcp_fingerprint": "1,3,6,12,15,28,42"},
    {"label": "iot", "vendor": "Axis Communications","open_ports": _p(80, 443, 554),"extra_info": _h("axis"),               "dhcp_fingerprint": "1,3,6,12,15,28"},
    # MQTT-connected devices
    {"label": "iot", "vendor": "Espressif Inc.",     "open_ports": _p(1883),        "extra_info": _m("_mqtt._tcp"),         "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "vendor": "Shelly (Allterco)",  "open_ports": _p(80, 1883),    "extra_info": _h("boa"),                "dhcp_fingerprint": "1,3,6,12,15,28"},
    {"label": "iot", "vendor": "Shenzhen LILIN",     "open_ports": _p(8883),        "extra_info": {},                       "dhcp_fingerprint": "1,3,6,12,15,28,42"},
    # Smart TV
    {"label": "iot", "vendor": "Samsung Electronics","open_ports": _p(8001, 8080),  "extra_info": _m("_cast._tcp"),         "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "iot", "vendor": "LG Electronics",     "open_ports": _p(3000, 8080),  "extra_info": _m("_googlecast._tcp"),   "dhcp_fingerprint": "1,3,6,15,28,51"},
    # HomeKit accessories
    {"label": "iot", "vendor": "Eve Systems GmbH",   "open_ports": _p(80),          "extra_info": _m("_homekit._tcp"),      "dhcp_fingerprint": "1,3,6,15,119,252"},
    {"label": "iot", "vendor": "iRobot Corp.",        "open_ports": _p(8883),        "extra_info": _m("_hap._tcp"),          "dhcp_fingerprint": "1,3,6,15,119,252"},
    # Generic BusyBox IoT (no vendor match)
    {"label": "iot", "vendor": None,                 "open_ports": _p(80),          "extra_info": _h("uhttpd"),             "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "vendor": None,                 "open_ports": _p(80, 8080),    "extra_info": _h("boa"),                "dhcp_fingerprint": "1,3,6,12,15,28"},
    {"label": "iot", "vendor": None,                 "open_ports": _p(1883, 8883),  "extra_info": {},                       "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "vendor": "Blink Indoor",       "open_ports": _p(443),         "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,119,252"},

    # ── Desktop / workstation ─────────────────────────────────────────────────
    # Windows 10/11
    {"label": "desktop", "vendor": "Intel Corporate",    "open_ports": _p(445, 3389, 80),"extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "vendor": "Realtek Semi.",      "open_ports": _p(445, 3389),    "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "vendor": "Dell Inc.",          "open_ports": _p(445),          "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "vendor": "Lenovo",             "open_ports": _p(445, 139),     "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "vendor": "ASUS",               "open_ports": _p(445),          "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "vendor": "Hewlett Packard",    "open_ports": _p(445, 3389),    "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    # macOS
    {"label": "desktop", "vendor": "Apple Inc.",         "open_ports": _p(5900, 22),     "extra_info": _m("_workstation._tcp", "_afpovertcp._tcp"), "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "desktop", "vendor": "Apple Inc.",         "open_ports": _p(445),          "extra_info": _m("_smb._tcp", "_workstation._tcp"),        "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "desktop", "vendor": "Apple Inc.",         "open_ports": _p(88, 445, 5900),"extra_info": _m("_workstation._tcp"),                    "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    # Linux desktop
    {"label": "desktop", "vendor": "Intel Corporate",    "open_ports": _p(22),           "extra_info": _m("_workstation._tcp"),                    "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "desktop", "vendor": "Realtek Semi.",      "open_ports": _p(22),           "extra_info": _m("_workstation._tcp"),                    "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "desktop", "vendor": "Broadcom Inc.",      "open_ports": _p(22, 5900),     "extra_info": _m("_workstation._tcp"),                    "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    # Windows workstation without RDP (typical corporate)
    {"label": "desktop", "vendor": "Intel Corporate",    "open_ports": _p(445, 139),     "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,43,44,46,47,119,252"},
    {"label": "desktop", "vendor": "Dell Inc.",          "open_ports": _p(445, 139, 22), "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,43,44,46,47,119,252"},
    # No ports (fresh discovery — only vendor/DHCP signals)
    {"label": "desktop", "vendor": "Lenovo",             "open_ports": [],               "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "vendor": "ASUS",               "open_ports": [],               "extra_info": {},                  "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},

    # ── Server ────────────────────────────────────────────────────────────────
    # Linux web/app server
    {"label": "server", "vendor": "Intel Corporate",    "open_ports": _p(22, 80, 443),     "extra_info": _h("nginx"),    "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "vendor": "Intel Corporate",    "open_ports": _p(22, 80, 443, 3306),"extra_info": _h("apache"),  "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "vendor": "Supermicro",         "open_ports": _p(22, 80, 443),     "extra_info": _h("nginx"),    "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "vendor": "Broadcom Inc.",      "open_ports": _p(22, 80, 443, 8080),"extra_info": _h("tomcat"),  "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "vendor": "Intel Corporate",    "open_ports": _p(22, 443, 5432),   "extra_info": _h("nginx"),    "dhcp_fingerprint": None},
    {"label": "server", "vendor": "Intel Corporate",    "open_ports": _p(22, 25, 443, 993, 995),"extra_info": _h("nginx"), "dhcp_fingerprint": None},
    # NAS
    {"label": "server", "vendor": "Synology Inc.",      "open_ports": _p(22, 80, 443, 445),"extra_info": _mh("_smb._tcp", http_server="lighttpd"), "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "vendor": "QNAP Systems",       "open_ports": _p(22, 80, 443, 445),"extra_info": _mh("_smb._tcp"), "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "vendor": "Western Digital",    "open_ports": _p(80, 443, 445),    "extra_info": _mh("_smb._tcp"), "dhcp_fingerprint": "1,3,6,12,15,17,23,28"},
    # Mail server
    {"label": "server", "vendor": "Intel Corporate",    "open_ports": _p(22, 25, 110, 143), "extra_info": _h("iis"),     "dhcp_fingerprint": None},
    # Database-only server
    {"label": "server", "vendor": "Supermicro",         "open_ports": _p(22, 3306),        "extra_info": {},              "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "vendor": "Supermicro",         "open_ports": _p(22, 5432),        "extra_info": {},              "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    # Windows Server (IIS)
    {"label": "server", "vendor": "Intel Corporate",    "open_ports": _p(80, 443, 445, 3389),"extra_info": _h("microsoft-iis"), "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "server", "vendor": "Dell Inc.",          "open_ports": _p(80, 443, 25, 445), "extra_info": _h("iis"),      "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    # Virtualisation host
    {"label": "server", "vendor": "Broadcom Inc.",      "open_ports": _p(22, 80, 443, 5900),"extra_info": _h("nginx"),    "dhcp_fingerprint": None},

    # ── Mobile ────────────────────────────────────────────────────────────────
    # iPhone / iPad
    {"label": "mobile", "vendor": "Apple Inc.",         "open_ports": [],               "extra_info": _m("_companion-link._tcp"),                 "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "mobile", "vendor": "Apple Inc.",         "open_ports": [],               "extra_info": {},                                          "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "mobile", "vendor": "Apple Inc.",         "open_ports": _p(62078),        "extra_info": _m("_airplay._tcp"),                        "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    # Android phone
    {"label": "mobile", "vendor": "Samsung Electronics","open_ports": [],               "extra_info": {},                                          "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "vendor": "Qualcomm Inc.",      "open_ports": [],               "extra_info": {},                                          "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "vendor": "MediaTek Inc.",      "open_ports": [],               "extra_info": {},                                          "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "vendor": "Xiaomi",             "open_ports": [],               "extra_info": {},                                          "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "vendor": "Huawei Device",      "open_ports": [],               "extra_info": {},                                          "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Tablet
    {"label": "mobile", "vendor": "Samsung Electronics","open_ports": _p(5900),         "extra_info": {},                                          "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "vendor": "Apple Inc.",         "open_ports": [],               "extra_info": _m("_raop._tcp"),                            "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    # Random/private MAC (MAC address randomisation) — no vendor match
    {"label": "mobile", "vendor": None,                 "open_ports": [],               "extra_info": {},                                          "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "vendor": None,                 "open_ports": [],               "extra_info": {},                                          "dhcp_fingerprint": "1,121,3,6,15,119,252"},

    # ── Printer ───────────────────────────────────────────────────────────────
    # HP JetDirect / LaserJet
    {"label": "printer", "vendor": "Hewlett Packard",   "open_ports": _p(9100, 515, 631, 80), "extra_info": _mh("_ipp._tcp", "_printer._tcp", http_server="jetdirect"), "dhcp_fingerprint": "1,3,6,15,44,46,47,31,33,121,249,43,252,12"},
    {"label": "printer", "vendor": "Hewlett Packard",   "open_ports": _p(9100, 631, 80),       "extra_info": _mh("_ipp._tcp", http_server="hp laserjet"),                "dhcp_fingerprint": "1,3,6,15,44,46,47,31,33,121,249,43,252,12"},
    {"label": "printer", "vendor": "Hewlett Packard",   "open_ports": _p(9100, 443, 631),      "extra_info": _mh("_ipps._tcp", "_ipp._tcp"),                             "dhcp_fingerprint": "1,3,6,15,44,46,47,31,33,121,249,43,252,12"},
    # Epson
    {"label": "printer", "vendor": "Seiko Epson Corp.", "open_ports": _p(9100, 631, 80),       "extra_info": _m("_ipp._tcp", "_printer._tcp"),                           "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "printer", "vendor": "Seiko Epson Corp.", "open_ports": _p(631, 443),            "extra_info": _m("_ipps._tcp"),                                           "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Canon
    {"label": "printer", "vendor": "Canon Inc.",        "open_ports": _p(9100, 515, 631),      "extra_info": _m("_ipp._tcp"),                                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "printer", "vendor": "Canon Inc.",        "open_ports": _p(9100, 80),            "extra_info": _m("_printer._tcp"),                                        "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Brother
    {"label": "printer", "vendor": "Brother Industries","open_ports": _p(9100, 515, 80),       "extra_info": _m("_ipp._tcp", "_printer._tcp"),                           "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Lexmark
    {"label": "printer", "vendor": "Lexmark Intl Inc.", "open_ports": _p(9100, 631, 80),       "extra_info": _m("_ipp._tcp"),                                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Xerox
    {"label": "printer", "vendor": "Xerox Corporation", "open_ports": _p(9100, 443, 515),      "extra_info": _m("_ipps._tcp"),                                           "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Network-connected label printer
    {"label": "printer", "vendor": "Brother Industries","open_ports": _p(9100),                "extra_info": {},                                                          "dhcp_fingerprint": "1,3,6,15,28,51"},
    {"label": "printer", "vendor": None,                "open_ports": _p(9100, 515, 631),      "extra_info": _h("printer"),                                              "dhcp_fingerprint": None},

    # ── Network device ────────────────────────────────────────────────────────
    # Cisco router/switch
    {"label": "network_device", "vendor": "Cisco Systems", "open_ports": _p(22, 23, 80, 443, 161), "extra_info": {},  "dhcp_fingerprint": "1,3,6,15,9"},
    {"label": "network_device", "vendor": "Cisco Systems", "open_ports": _p(22, 80, 443, 161),     "extra_info": {},  "dhcp_fingerprint": "1,3,6,15,9"},
    {"label": "network_device", "vendor": "Cisco-Meraki",  "open_ports": _p(22, 80, 443),          "extra_info": _h("nginx"), "dhcp_fingerprint": "1,3,6,15,9"},
    # Ubiquiti UniFi
    {"label": "network_device", "vendor": "Ubiquiti Inc.", "open_ports": _p(22, 80, 443, 8080, 8443),"extra_info": _h("ubiquiti"), "dhcp_fingerprint": "1,3,6,15,28,51"},
    {"label": "network_device", "vendor": "Ubiquiti Inc.", "open_ports": _p(22, 443, 8443),           "extra_info": {},             "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Netgear
    {"label": "network_device", "vendor": "Netgear Inc.",  "open_ports": _p(80, 443, 23),             "extra_info": _h("netgear"),  "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "network_device", "vendor": "Netgear Inc.",  "open_ports": _p(80, 443),                 "extra_info": {},             "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # TP-Link / Archer
    {"label": "network_device", "vendor": "TP-Link Tech.", "open_ports": _p(80, 443, 22),             "extra_info": _h("zyxel"),    "dhcp_fingerprint": "1,3,6,15,28,51"},
    {"label": "network_device", "vendor": "TP-Link Tech.", "open_ports": _p(80, 443),                 "extra_info": {},             "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Aruba / HP wireless
    {"label": "network_device", "vendor": "Aruba Networks","open_ports": _p(22, 80, 443, 8443),       "extra_info": {},             "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Juniper
    {"label": "network_device", "vendor": "Juniper Networks","open_ports": _p(22, 80, 443, 161),      "extra_info": {},             "dhcp_fingerprint": "1,3,6,15,28,51"},
    # MikroTik
    {"label": "network_device", "vendor": "Mikrotik SIA",  "open_ports": _p(22, 80, 8291, 443),      "extra_info": {},             "dhcp_fingerprint": None},
    # ZyXEL DSL router
    {"label": "network_device", "vendor": "ZyXEL Comm.",   "open_ports": _p(22, 80, 443, 23),        "extra_info": _h("zyxel"),    "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Generic router (TR-069 management)
    {"label": "network_device", "vendor": None,             "open_ports": _p(7547, 80, 443),           "extra_info": {},             "dhcp_fingerprint": None},
    # Fortinet firewall
    {"label": "network_device", "vendor": "Fortinet Inc.",  "open_ports": _p(22, 80, 443, 8443),      "extra_info": {},             "dhcp_fingerprint": None},
    # ISP-provisioned cable modem (DOCSIS)
    {"label": "network_device", "vendor": None,             "open_ports": _p(80, 443, 161),            "extra_info": {},             "dhcp_fingerprint": "54,51,58,59,1,28,121,33,3,12,119,15,6,40,41,42,26,17,82,255"},
]
# fmt: on


def _build_samples_from_synthetic() -> tuple[list[list[float]], list[str]]:
    """Convert _SYNTHETIC_DATA into (X, y) arrays."""
    X: list[list[float]] = []
    y: list[str] = []
    for sample in _SYNTHETIC_DATA:
        feats = extract_features(
            vendor=sample.get("vendor"),
            open_ports=sample.get("open_ports", []),
            extra_info=sample.get("extra_info"),
            dhcp_fingerprint=sample.get("dhcp_fingerprint"),
        )
        X.append(feats)
        y.append(sample["label"])
    return X, y


def _build_samples_from_fingerbank_json(path: str) -> tuple[list[list[float]], list[str]]:
    """Parse a fingerbank ``fingerprints_and_devices.json`` export.

    The Open Source Fingerbank database (CC-BY-4.0) is available at:
    https://github.com/fingerbank/open-source-database

    This function extracts DHCP option-55 fingerprint strings and the
    ``device.name`` / ``device.parent_id`` hierarchy to map to our labels.
    Only samples whose root parent maps to a known :data:`DEVICE_TYPES` label
    are included.
    """
    # Rough top-level Fingerbank category name → our label mapping.
    _FB_CATEGORY_MAP = {
        "mobile device": "mobile",
        "smartphone": "mobile",
        "tablet": "mobile",
        "ios device": "mobile",
        "android": "mobile",
        "iot": "iot",
        "smart tv": "iot",
        "streaming": "iot",
        "game console": "iot",
        "printer": "printer",
        "network device": "network_device",
        "router": "network_device",
        "switch": "network_device",
        "access point": "network_device",
        "nas": "server",
        "workstation": "desktop",
        "desktop": "desktop",
        "laptop": "desktop",
        "computer": "desktop",
        "server": "server",
        "virtual machine": "server",
    }

    log.info("fingerbank_load_start path=%s", path)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    # Build a device-id → root category name index.
    devices: dict = {}
    for device in data.get("devices", []):
        did = device.get("id")
        name = (device.get("name") or "").lower()
        parent = device.get("parent_id")
        devices[did] = {"name": name, "parent": parent}

    def _root_category(did: int | None) -> str | None:
        seen: set = set()
        while did is not None and did not in seen:
            seen.add(did)
            node = devices.get(did, {})
            name = node.get("name", "")
            if name in _FB_CATEGORY_MAP:
                return _FB_CATEGORY_MAP[name]
            parent = node.get("parent")
            # Guard against non-integer parent IDs in malformed data.
            if not isinstance(parent, int):
                break
            did = parent
        return None

    X: list[list[float]] = []
    y: list[str] = []
    skipped = 0
    for fp in data.get("fingerprints", []):
        dhcp_fp: str = fp.get("value") or fp.get("fingerprint") or ""
        if not dhcp_fp:
            skipped += 1
            continue
        device_id = fp.get("device_id")
        label = _root_category(device_id) if device_id else None
        if label is None:
            skipped += 1
            continue
        feats = extract_features(
            vendor=None,
            open_ports=[],
            extra_info=None,
            dhcp_fingerprint=dhcp_fp,
        )
        X.append(feats)
        y.append(label)

    log.info("fingerbank_load_done loaded=%d skipped=%d", len(y), skipped)
    return X, y


def _build_samples_from_fingerbank_db(path: str) -> tuple[list[list[float]], list[str]]:
    """Parse a ``fingerbank.db`` SQLite database exported from the Fingerbank API.

    The database can be downloaded from::

        curl -k -o fingerbank.db "https://api.fingerbank.org/api/v2/download/db?key=<YOUR_API_KEY>"

    Actual schema used:

    * ``device``           – ``id``, ``name``, ``parent_id`` (device-type hierarchy)
    * ``dhcp_fingerprint`` – ``id``, ``value``, ``ignored``  (DHCP opt-55 strings)
    * ``combination``      – ``dhcp_fingerprint_id``, ``mac_vendor_id``, ``device_id``
                             (links fingerprints + vendor to a classified device)

    .. note::
        In many DB snapshots downloaded from the Fingerbank API the
        ``combination`` table is **empty** and ``mac_vendor.device_id`` is
        always ``0``.  If that is your situation, use the
        ``--fingerbank-api-key`` option instead to pull labelled data
        directly from the Fingerbank REST API.
    """
    # Rough top-level Fingerbank category name → our label mapping.
    _FB_CATEGORY_MAP = {
        "mobile device": "mobile",
        "smartphone": "mobile",
        "tablet": "mobile",
        "ios device": "mobile",
        "android": "mobile",
        "iot": "iot",
        "smart tv": "iot",
        "streaming": "iot",
        "game console": "iot",
        "printer": "printer",
        "network device": "network_device",
        "router": "network_device",
        "switch": "network_device",
        "access point": "network_device",
        "nas": "server",
        "workstation": "desktop",
        "desktop": "desktop",
        "laptop": "desktop",
        "computer": "desktop",
        "server": "server",
        "virtual machine": "server",
    }

    log.info("fingerbank_db_load_start path=%s", path)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row

    # Build device-id → {name, parent_id} index.
    devices: dict[int, dict] = {}
    try:
        for row in con.execute("SELECT id, name, parent_id FROM device"):
            devices[row["id"]] = {
                "name": (row["name"] or "").lower(),
                "parent": row["parent_id"],
            }
    except sqlite3.OperationalError as exc:
        log.error("fingerbank_db_device_error error=%s", exc)
        con.close()
        return [], []

    def _root_category(did: int | None) -> str | None:
        seen: set[int] = set()
        while did is not None and did not in seen:
            seen.add(did)
            node = devices.get(did, {})
            name = node.get("name", "")
            if name in _FB_CATEGORY_MAP:
                return _FB_CATEGORY_MAP[name]
            parent = node.get("parent")
            if not isinstance(parent, int):
                break
            did = parent
        return None

    # Join combination → dhcp_fingerprint (for the opt-55 string) and
    # mac_vendor (for the OUI vendor name).  Rows with ignored fingerprints
    # or no device_id are excluded by the WHERE clause.
    _COMBO_QUERY = """
        SELECT
            df.value  AS dhcp_fp,
            mv.name   AS vendor_name,
            c.device_id
        FROM combination c
        LEFT JOIN dhcp_fingerprint df ON df.id = c.dhcp_fingerprint_id
        LEFT JOIN mac_vendor        mv ON mv.id = c.mac_vendor_id
        WHERE c.device_id IS NOT NULL
          AND (df.ignored IS NULL OR df.ignored = 0)
    """

    X: list[list[float]] = []
    y: list[str] = []
    skipped = 0
    seen_samples: set[tuple] = set()
    try:
        for row in con.execute(_COMBO_QUERY):
            dhcp_fp: str = row["dhcp_fp"] or ""
            vendor: str | None = row["vendor_name"] or None
            device_id: int = row["device_id"]

            # Skip combinations that carry no useful signal at all.
            if not dhcp_fp and vendor is None:
                skipped += 1
                continue

            label = _root_category(device_id)
            if label is None:
                skipped += 1
                continue

            # Deduplicate identical (dhcp_fp, vendor, device_id) tuples.
            key = (dhcp_fp, vendor, device_id)
            if key in seen_samples:
                skipped += 1
                continue
            seen_samples.add(key)

            feats = extract_features(
                vendor=vendor,
                open_ports=[],
                extra_info=None,
                dhcp_fingerprint=dhcp_fp if dhcp_fp else None,
            )
            X.append(feats)
            y.append(label)
    except sqlite3.OperationalError as exc:
        log.error("fingerbank_db_combination_error error=%s", exc)
    finally:
        con.close()

    if not y:
        log.warning(
            "fingerbank_db_no_samples: combination table appears empty or "
            "mac_vendor.device_id is 0; consider using --fingerbank-api-key instead"
        )
    log.info("fingerbank_db_load_done loaded=%d skipped=%d", len(y), skipped)
    return X, y



def _build_samples_from_fingerbank_api(
    api_key: str,
    base_url: str = "https://api.fingerbank.org/api/v2",
) -> tuple[list[list[float]], list[str]]:
    """Pull labelled DHCP fingerprint data directly from the Fingerbank REST API.

    This is the recommended approach when the local ``fingerbank.db`` SQLite
    file has an empty ``combination`` table (or ``mac_vendor.device_id`` is
    always 0), which is common with the standard API download.

    Two paginated endpoints are used:

    * ``GET /api/v2/devices``           – full device-type hierarchy
    * ``GET /api/v2/dhcp_fingerprints`` – DHCP opt-55 strings with ``device_id``

    The API key can be obtained for free at https://fingerbank.org/users/register
    (also exposed as the ``FINGERBANK_API_KEY`` env var used by the discovery
    service at runtime).

    Parameters
    ----------
    api_key:
        Fingerbank API key.
    base_url:
        Base URL for the Fingerbank API (default: ``https://api.fingerbank.org/api/v2``).
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    # Rough top-level Fingerbank category name → our label mapping.
    _FB_CATEGORY_MAP = {
        "mobile device": "mobile",
        "smartphone": "mobile",
        "tablet": "mobile",
        "ios device": "mobile",
        "android": "mobile",
        "iot": "iot",
        "smart tv": "iot",
        "streaming": "iot",
        "game console": "iot",
        "printer": "printer",
        "network device": "network_device",
        "router": "network_device",
        "switch": "network_device",
        "access point": "network_device",
        "nas": "server",
        "workstation": "desktop",
        "desktop": "desktop",
        "laptop": "desktop",
        "computer": "desktop",
        "server": "server",
        "virtual machine": "server",
    }

    def _get_pages(endpoint: str) -> list[dict]:
        """Fetch all pages from a paginated Fingerbank list endpoint."""
        results: list[dict] = []
        page = 1
        per_page = 100
        while True:
            params = urllib.parse.urlencode(
                {"key": api_key, "page": page, "per_page": per_page}
            )
            url = f"{base_url}/{endpoint}?{params}"
            try:
                with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
                    data = json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                log.error("fingerbank_api_http_error endpoint=%s page=%d status=%d", endpoint, page, exc.code)
                break
            except Exception as exc:
                log.error("fingerbank_api_error endpoint=%s page=%d error=%s", endpoint, page, exc)
                break

            # The API may return a bare list or a dict with a matching key.
            if isinstance(data, list):
                page_items = data
            elif isinstance(data, dict):
                # Try the endpoint name as the key (e.g. "dhcp_fingerprints").
                page_items = data.get(endpoint) or data.get(endpoint.rstrip("s")) or []
            else:
                break

            if not page_items:
                break
            results.extend(page_items)
            log.info("fingerbank_api_page endpoint=%s page=%d fetched=%d total=%d", endpoint, page, len(page_items), len(results))
            if len(page_items) < per_page:
                # Last page.
                break
            page += 1
        return results

    log.info("fingerbank_api_load_start base_url=%s", base_url)

    # ── 1. Load device hierarchy ──────────────────────────────────────────────
    devices: dict[int, dict] = {}
    for dev in _get_pages("devices"):
        did = dev.get("id")
        if did is None:
            continue
        devices[int(did)] = {
            "name": (dev.get("name") or "").lower(),
            "parent": dev.get("parent_id"),
        }
    log.info("fingerbank_api_devices_loaded count=%d", len(devices))

    def _root_category(did: int | None) -> str | None:
        seen: set[int] = set()
        while did is not None and did not in seen:
            seen.add(did)
            node = devices.get(did, {})
            name = node.get("name", "")
            if name in _FB_CATEGORY_MAP:
                return _FB_CATEGORY_MAP[name]
            parent = node.get("parent")
            if not isinstance(parent, int):
                break
            did = parent
        return None

    # ── 2. Load DHCP fingerprints ─────────────────────────────────────────────
    X: list[list[float]] = []
    y: list[str] = []
    skipped = 0
    seen_samples: set[tuple] = set()

    for fp in _get_pages("dhcp_fingerprints"):
        # Skip ignored fingerprints.
        if fp.get("ignored"):
            skipped += 1
            continue

        dhcp_fp: str = (fp.get("value") or "").strip()
        if not dhcp_fp:
            skipped += 1
            continue

        device_id = fp.get("device_id")
        if not device_id:
            skipped += 1
            continue

        label = _root_category(int(device_id))
        if label is None:
            skipped += 1
            continue

        key = (dhcp_fp, device_id)
        if key in seen_samples:
            skipped += 1
            continue
        seen_samples.add(key)

        feats = extract_features(
            vendor=None,
            open_ports=[],
            extra_info=None,
            dhcp_fingerprint=dhcp_fp,
        )
        X.append(feats)
        y.append(label)

    log.info("fingerbank_api_load_done loaded=%d skipped=%d", len(y), skipped)
    return X, y


def train(
    extra_X: list[list[float]] | None = None,
    extra_y: list[str] | None = None,
    n_estimators: int = 100,
    max_depth: int = 8,
    run_cv: bool = False,
    verbose: bool = False,
) -> object:
    """Train and return a RandomForestClassifier.

    Parameters
    ----------
    extra_X, extra_y:
        Optional additional training samples (e.g. from the fingerbank dataset)
        to augment the embedded synthetic set.
    n_estimators:
        Number of trees in the forest.  100 gives a good size/accuracy tradeoff.
    max_depth:
        Maximum depth of each tree.  8 keeps the model compact (~100 KB).
    run_cv:
        When ``True``, print 5-fold cross-validation accuracy to stdout.
    verbose:
        When ``True``, print feature importances.
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score

    X_syn, y_syn = _build_samples_from_synthetic()
    X_all = X_syn.copy()
    y_all = y_syn.copy()

    if extra_X and extra_y:
        X_all.extend(extra_X)
        y_all.extend(extra_y)

    X_np = np.array(X_all, dtype=np.float32)
    y_np = np.array(y_all)

    log.info("training_start samples=%d features=%d", len(y_all), X_np.shape[1])

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_np, y_np)
    log.info("training_done classes=%s", list(clf.classes_))

    if run_cv:
        scores = cross_val_score(clf, X_np, y_np, cv=5, scoring="accuracy", n_jobs=-1)
        print(
            f"5-fold CV accuracy: {scores.mean():.3f} ± {scores.std():.3f}  "
            f"[{', '.join(f'{s:.3f}' for s in scores)}]"
        )

    if verbose:
        from device_classifier import (  # noqa: PLC0415
            DHCP_OPTIONS,
            FEATURE_PORTS,
            HTTP_SERVER_KEYWORDS,
            MDNS_SERVICE_TYPES,
            VENDOR_KEYWORDS,
        )

        feature_names: list[str] = (
            [f"dhcp_opt_{o}" for o in DHCP_OPTIONS]
            + [f"port_{p}" for p in FEATURE_PORTS]
            + [f"vendor_{k}" for k in VENDOR_KEYWORDS]
            + [f"mdns_{s}" for s in MDNS_SERVICE_TYPES]
            + [f"http_{k}" for k in HTTP_SERVER_KEYWORDS]
        )
        importances = clf.feature_importances_
        top_n = sorted(enumerate(importances), key=lambda x: -x[1])[:20]
        print("\nTop-20 feature importances:")
        for idx, imp in top_n:
            print(f"  {feature_names[idx]:<35s}  {imp:.4f}")

    return clf


def save(clf: object, path: str = MODEL_PATH) -> None:
    """Serialise *clf* to *path* using joblib."""
    import joblib  # noqa: PLC0415

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(clf, path, compress=3)
    size_kb = os.path.getsize(path) / 1024
    log.info("model_saved path=%s size_kb=%.1f", path, size_kb)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the TheBox RF device-type classifier.",
    )
    parser.add_argument(
        "--fingerbank-json",
        metavar="PATH",
        help=(
            "Path to fingerbank open-source fingerprints_and_devices.json for augmentation. "
            "Available at https://github.com/fingerbank/open-source-database"
        ),
    )
    parser.add_argument(
        "--fingerbank-db",
        metavar="PATH",
        help=(
            "Path to fingerbank.db SQLite database for augmentation. "
            "Download with: curl -k -o fingerbank.db "
            "\"https://api.fingerbank.org/api/v2/download/db?key=<YOUR_API_KEY>\". "
            "NOTE: the standard downloaded DB often has an empty combination table "
            "and device_id=0 in mac_vendor; use --fingerbank-api-key instead."
        ),
    )
    parser.add_argument(
        "--fingerbank-api-key",
        metavar="KEY",
        default=os.environ.get("FINGERBANK_API_KEY", ""),
        help=(
            "Fingerbank API key for pulling labelled data directly from the "
            "Fingerbank REST API (recommended over --fingerbank-db). "
            "Defaults to the FINGERBANK_API_KEY environment variable. "
            "Register for a free key at https://fingerbank.org/users/register"
        ),
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        default=MODEL_PATH,
        help=f"Destination path for the model file (default: {MODEL_PATH}).",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of RF trees (default: 100).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=8,
        help="Maximum tree depth (default: 8).",
    )
    parser.add_argument("--cv", action="store_true", help="Run 5-fold cross-validation.")
    parser.add_argument("--verbose", action="store_true", help="Print feature importances.")
    args = parser.parse_args()

    extra_X: list[list[float]] | None = None
    extra_y: list[str] | None = None
    if args.fingerbank_api_key:
        extra_X, extra_y = _build_samples_from_fingerbank_api(args.fingerbank_api_key)
    elif args.fingerbank_db:
        extra_X, extra_y = _build_samples_from_fingerbank_db(args.fingerbank_db)
    elif args.fingerbank_json:
        extra_X, extra_y = _build_samples_from_fingerbank_json(args.fingerbank_json)

    clf = train(
        extra_X=extra_X,
        extra_y=extra_y,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        run_cv=args.cv,
        verbose=args.verbose,
    )
    save(clf, path=args.output)


if __name__ == "__main__":
    main()
