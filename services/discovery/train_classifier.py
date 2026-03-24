"""Train the TheBox RF device-type and OS-family classifiers.

This script can be run:

1. **At Docker build time** (baked into the image): the Dockerfile copies this
   file and calls ``python train_classifier.py`` so the models are available
   the moment the container starts.

2. **With a Fingerbank API key** (augments the device_type classifier)::

       python train_classifier.py --fingerbank-api-key <YOUR_API_KEY>

   This pulls labelled DHCP fingerprint data directly from the Fingerbank REST
   API (paginating ``/devices`` and ``/dhcp_fingerprints``).  Register for a
   free key at https://fingerbank.org/users/register.  The ``FINGERBANK_API_KEY``
   environment variable is also accepted automatically.

3. **Interactively** to inspect feature importances or cross-validation scores::

       python train_classifier.py --cv --verbose

The trained models are saved as a ``(clf_device_type, clf_os_family)`` tuple
serialised with joblib.  Both classifiers use the same 142-dimension feature
vector defined in ``device_classifier.py``.  ``clf_device_type`` is trained on
the full dataset (synthetic + optional Fingerbank API data); ``clf_os_family``
is trained on the synthetic dataset only because Fingerbank data provides only
DHCP fingerprints without port or OS signals.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
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
    OS_FAMILIES,
    extract_features,
)

# ── Synthetic training dataset ────────────────────────────────────────────────
# Each sample is a dict with keys matching the extract_features() signature
# plus a "label" key (one of DEVICE_TYPES).
#
# Rationale: a small but representative set of canonical device profiles gives
# the RF model a strong prior that generalises well to home/SMB networks.
# The model is then refined when the operator provides the fingerbank dataset.


# ── Synthetic training dataset ────────────────────────────────────────────────
# Each sample is a dict with keys matching the extract_features() signature
# plus "label" (device_type) and "os_family" keys.
#
# Design principles:
#   1. Only include verifiable, high-confidence signal combinations.
#   2. Cover ALL discovery paths: DHCP-based, port-scan-only, vendor-only,
#      mDNS-only, and mixed non-DHCP.  Many real-world devices are found via
#      ARP scan or passive mDNS and will never send a DHCP request (static IP,
#      already-leased, or randomised MAC suppresses DHCP fingerprinting).
#   3. The "embedded" os_family covers all firmware devices: IoT, IP cameras,
#      network equipment, and printers.


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
    # os_family="embedded" for all IoT — these run closed firmware stacks.

    # Espressif-based smart plugs / bulbs (BusyBox udhcpc fingerprint)
    {"label": "iot", "os_family": "embedded", "vendor": "Espressif Inc.",      "open_ports": _p(80),           "extra_info": _h("uhttpd"),             "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "os_family": "embedded", "vendor": "Espressif Inc.",      "open_ports": _p(80, 443),      "extra_info": _h("uhttpd"),             "dhcp_fingerprint": "1,3,6,12,15,28,42"},
    {"label": "iot", "os_family": "embedded", "vendor": "Shenzhen Tuya",       "open_ports": _p(80),           "extra_info": _h("busybox"),            "dhcp_fingerprint": "1,3,6,12,15,28"},
    {"label": "iot", "os_family": "embedded", "vendor": "Tuya Global Inc.",    "open_ports": _p(80, 443),      "extra_info": {},                       "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "os_family": "embedded", "vendor": "Belkin International","open_ports": _p(80, 49152),    "extra_info": _h("mini_httpd"),         "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "iot", "os_family": "embedded", "vendor": "WeMo Device",         "open_ports": _p(49152, 49153), "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Google Chromecast / Cast devices
    {"label": "iot", "os_family": "embedded", "vendor": "Google LLC",          "open_ports": _p(8008, 8009),   "extra_info": _m("_googlecast._tcp"),   "dhcp_fingerprint": "1,3,6,15,119,252"},
    {"label": "iot", "os_family": "embedded", "vendor": "Google LLC",          "open_ports": _p(8009),         "extra_info": _m("_cast._tcp"),         "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "iot", "os_family": "embedded", "vendor": "Google LLC",          "open_ports": _p(80, 8008),     "extra_info": _m("_googlecast._tcp", "_spotify-connect._tcp"), "dhcp_fingerprint": "1,3,6,15,119"},
    # Amazon Echo / Ring
    {"label": "iot", "os_family": "embedded", "vendor": "Amazon Technologies", "open_ports": _p(443, 55443),   "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,119,252"},
    {"label": "iot", "os_family": "embedded", "vendor": "Amazon Technologies", "open_ports": _p(80, 443),      "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "iot", "os_family": "embedded", "vendor": "Ring LLC",            "open_ports": _p(80, 443),      "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Philips Hue bridge
    {"label": "iot", "os_family": "embedded", "vendor": "Philips Lighting BV", "open_ports": _p(80, 443),      "extra_info": _h("nginx"),              "dhcp_fingerprint": "1,3,6,15,28,42,100,101"},
    {"label": "iot", "os_family": "embedded", "vendor": "Signify Netherlands", "open_ports": _p(80),           "extra_info": _h("mini_httpd"),         "dhcp_fingerprint": "1,3,6,12,15,28"},
    # Nest / smart home
    {"label": "iot", "os_family": "embedded", "vendor": "Nest Labs Inc.",      "open_ports": _p(443),          "extra_info": _m("_matter._tcp"),       "dhcp_fingerprint": "1,3,6,15,119,252"},
    {"label": "iot", "os_family": "embedded", "vendor": "Nest Labs Inc.",      "open_ports": _p(443, 9543),    "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,119"},
    # IP cameras (RTSP)
    {"label": "iot", "os_family": "embedded", "vendor": "Hikvision Digital",   "open_ports": _p(80, 443, 554), "extra_info": _h("hikvision"),          "dhcp_fingerprint": "1,3,6,12,15,28"},
    {"label": "iot", "os_family": "embedded", "vendor": "Dahua Technology",    "open_ports": _p(80, 554),      "extra_info": {},                       "dhcp_fingerprint": "1,3,6,12,15,28,42"},
    {"label": "iot", "os_family": "embedded", "vendor": "Axis Communications", "open_ports": _p(80, 443, 554), "extra_info": _h("axis"),               "dhcp_fingerprint": "1,3,6,12,15,28"},
    # MQTT-connected devices
    {"label": "iot", "os_family": "embedded", "vendor": "Espressif Inc.",      "open_ports": _p(1883),         "extra_info": _m("_mqtt._tcp"),         "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "os_family": "embedded", "vendor": "Shelly (Allterco)",   "open_ports": _p(80, 1883),     "extra_info": _h("boa"),                "dhcp_fingerprint": "1,3,6,12,15,28"},
    {"label": "iot", "os_family": "embedded", "vendor": "Shenzhen LILIN",      "open_ports": _p(8883),         "extra_info": {},                       "dhcp_fingerprint": "1,3,6,12,15,28,42"},
    # Smart TV
    {"label": "iot", "os_family": "embedded", "vendor": "Samsung Electronics", "open_ports": _p(8001, 8080),   "extra_info": _m("_cast._tcp"),         "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "iot", "os_family": "embedded", "vendor": "LG Electronics",      "open_ports": _p(3000, 8080),   "extra_info": _m("_googlecast._tcp"),   "dhcp_fingerprint": "1,3,6,15,28,51"},
    # HomeKit accessories
    {"label": "iot", "os_family": "embedded", "vendor": "Eve Systems GmbH",    "open_ports": _p(80),           "extra_info": _m("_homekit._tcp"),      "dhcp_fingerprint": "1,3,6,15,119,252"},
    {"label": "iot", "os_family": "embedded", "vendor": "iRobot Corp.",         "open_ports": _p(8883),         "extra_info": _m("_hap._tcp"),          "dhcp_fingerprint": "1,3,6,15,119,252"},
    # Generic BusyBox IoT (no vendor match — discovered via scan only)
    {"label": "iot", "os_family": "embedded", "vendor": None,                  "open_ports": _p(80),           "extra_info": _h("uhttpd"),             "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "os_family": "embedded", "vendor": None,                  "open_ports": _p(80, 8080),     "extra_info": _h("boa"),                "dhcp_fingerprint": "1,3,6,12,15,28"},
    {"label": "iot", "os_family": "embedded", "vendor": None,                  "open_ports": _p(1883, 8883),   "extra_info": {},                       "dhcp_fingerprint": "1,3,6,12,15,28,42,100,101"},
    {"label": "iot", "os_family": "embedded", "vendor": "Blink Indoor",        "open_ports": _p(443),          "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,119,252"},

    # ── Desktop / workstation ─────────────────────────────────────────────────
    # Windows 10/11 — DHCP options 44,46,47 (NetBIOS) are Windows-specific
    {"label": "desktop", "os_family": "windows", "vendor": "Intel Corporate",  "open_ports": _p(445, 3389, 80),"extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "os_family": "windows", "vendor": "Realtek Semi.",    "open_ports": _p(445, 3389),    "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "os_family": "windows", "vendor": "Dell Inc.",        "open_ports": _p(445),          "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "os_family": "windows", "vendor": "Lenovo",           "open_ports": _p(445, 139),     "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "os_family": "windows", "vendor": "ASUS",             "open_ports": _p(445),          "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "os_family": "windows", "vendor": "Hewlett Packard",  "open_ports": _p(445, 3389),    "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    # macOS — option 121 (classless static route) + mDNS workstation/_afp
    {"label": "desktop", "os_family": "macos",   "vendor": "Apple Inc.",       "open_ports": _p(5900, 22),     "extra_info": _m("_workstation._tcp", "_afpovertcp._tcp"), "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "desktop", "os_family": "macos",   "vendor": "Apple Inc.",       "open_ports": _p(445),          "extra_info": _m("_smb._tcp", "_workstation._tcp"),        "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "desktop", "os_family": "macos",   "vendor": "Apple Inc.",       "open_ports": _p(88, 445, 5900),"extra_info": _m("_workstation._tcp"),                     "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    # Linux desktop — Linux dhclient option set + _workstation._tcp mDNS
    {"label": "desktop", "os_family": "linux",   "vendor": "Intel Corporate",  "open_ports": _p(22),           "extra_info": _m("_workstation._tcp"),                     "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "desktop", "os_family": "linux",   "vendor": "Realtek Semi.",    "open_ports": _p(22),           "extra_info": _m("_workstation._tcp"),                     "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "desktop", "os_family": "linux",   "vendor": "Broadcom Inc.",    "open_ports": _p(22, 5900),     "extra_info": _m("_workstation._tcp"),                     "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    # Windows workstation without RDP (typical corporate firewall)
    {"label": "desktop", "os_family": "windows", "vendor": "Intel Corporate",  "open_ports": _p(445, 139),     "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,43,44,46,47,119,252"},
    {"label": "desktop", "os_family": "windows", "vendor": "Dell Inc.",        "open_ports": _p(445, 139, 22), "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,43,44,46,47,119,252"},
    # No ports open (fresh ARP discovery — only vendor/DHCP signals)
    {"label": "desktop", "os_family": "windows", "vendor": "Lenovo",           "open_ports": [],               "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "desktop", "os_family": "windows", "vendor": "ASUS",             "open_ports": [],               "extra_info": {},                       "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},

    # ── Server ────────────────────────────────────────────────────────────────
    # Linux web/app server — nginx/apache + SSH are strong Linux signals
    {"label": "server", "os_family": "linux",   "vendor": "Intel Corporate",   "open_ports": _p(22, 80, 443),      "extra_info": _h("nginx"),          "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "os_family": "linux",   "vendor": "Intel Corporate",   "open_ports": _p(22, 80, 443, 3306),"extra_info": _h("apache"),         "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "os_family": "linux",   "vendor": "Supermicro",        "open_ports": _p(22, 80, 443),      "extra_info": _h("nginx"),          "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "os_family": "linux",   "vendor": "Broadcom Inc.",     "open_ports": _p(22, 80, 443, 8080),"extra_info": _h("tomcat"),         "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "os_family": "linux",   "vendor": "Intel Corporate",   "open_ports": _p(22, 443, 5432),    "extra_info": _h("nginx"),          "dhcp_fingerprint": None},
    {"label": "server", "os_family": "linux",   "vendor": "Intel Corporate",   "open_ports": _p(22, 25, 443, 993, 995), "extra_info": _h("nginx"),     "dhcp_fingerprint": None},
    # NAS — Synology DSM and QNAP QTS both run Linux
    {"label": "server", "os_family": "linux",   "vendor": "Synology Inc.",     "open_ports": _p(22, 80, 443, 445), "extra_info": _mh("_smb._tcp", http_server="lighttpd"), "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "os_family": "linux",   "vendor": "QNAP Systems",      "open_ports": _p(22, 80, 443, 445), "extra_info": _mh("_smb._tcp"),     "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "os_family": "linux",   "vendor": "Western Digital",   "open_ports": _p(80, 443, 445),     "extra_info": _mh("_smb._tcp"),     "dhcp_fingerprint": "1,3,6,12,15,17,23,28"},
    # Mail server: Linux with postfix/dovecot (nginx front-end, port 22+25+110+143)
    {"label": "server", "os_family": "linux",   "vendor": "Intel Corporate",   "open_ports": _p(22, 25, 110, 143), "extra_info": _h("nginx"),          "dhcp_fingerprint": None},
    # Database-only server (Linux — PostgreSQL/MySQL nearly always Linux)
    {"label": "server", "os_family": "linux",   "vendor": "Supermicro",        "open_ports": _p(22, 3306),         "extra_info": {},                   "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    {"label": "server", "os_family": "linux",   "vendor": "Supermicro",        "open_ports": _p(22, 5432),         "extra_info": {},                   "dhcp_fingerprint": "1,3,6,12,15,17,23,28,29,31,33,40,41,42"},
    # Windows Server (IIS) — IIS is exclusively Windows
    {"label": "server", "os_family": "windows", "vendor": "Intel Corporate",   "open_ports": _p(80, 443, 445, 3389), "extra_info": _h("microsoft-iis"), "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    {"label": "server", "os_family": "windows", "vendor": "Dell Inc.",         "open_ports": _p(80, 443, 25, 445),   "extra_info": _h("iis"),           "dhcp_fingerprint": "1,3,6,15,31,33,43,44,46,47,119,121,249,252"},
    # Virtualisation host (KVM/VMware/Proxmox — Linux hypervisors)
    {"label": "server", "os_family": "linux",   "vendor": "Broadcom Inc.",     "open_ports": _p(22, 80, 443, 5900), "extra_info": _h("nginx"),          "dhcp_fingerprint": None},

    # ── Mobile ────────────────────────────────────────────────────────────────
    # iPhone / iPad — Apple vendor + DHCP opt-121 + companion-link or airplay mDNS
    {"label": "mobile", "os_family": "ios",     "vendor": "Apple Inc.",        "open_ports": [],               "extra_info": _m("_companion-link._tcp"),    "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "mobile", "os_family": "ios",     "vendor": "Apple Inc.",        "open_ports": [],               "extra_info": {},                            "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    {"label": "mobile", "os_family": "ios",     "vendor": "Apple Inc.",        "open_ports": _p(62078),        "extra_info": _m("_airplay._tcp"),           "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    # Android phone — Samsung/Qualcomm/MediaTek/Xiaomi with Android DHCP pattern
    {"label": "mobile", "os_family": "android", "vendor": "Samsung Electronics","open_ports": [],              "extra_info": {},                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "os_family": "android", "vendor": "Qualcomm Inc.",     "open_ports": [],               "extra_info": {},                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "os_family": "android", "vendor": "MediaTek Inc.",     "open_ports": [],               "extra_info": {},                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "os_family": "android", "vendor": "Xiaomi",            "open_ports": [],               "extra_info": {},                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "os_family": "android", "vendor": "Huawei Device",     "open_ports": [],               "extra_info": {},                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Tablet
    {"label": "mobile", "os_family": "android", "vendor": "Samsung Electronics","open_ports": _p(5900),        "extra_info": {},                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "os_family": "ios",     "vendor": "Apple Inc.",        "open_ports": [],               "extra_info": _m("_raop._tcp"),              "dhcp_fingerprint": "1,121,3,6,15,119,252"},
    # Random/private MAC (MAC address randomisation) — differentiate by DHCP
    {"label": "mobile", "os_family": "android", "vendor": None,               "open_ports": [],               "extra_info": {},                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "mobile", "os_family": "ios",     "vendor": None,               "open_ports": [],               "extra_info": {},                            "dhcp_fingerprint": "1,121,3,6,15,119,252"},

    # ── Printer ───────────────────────────────────────────────────────────────
    # Printers run embedded firmware regardless of vendor.
    # HP JetDirect / LaserJet — port 9100 (JetDirect) is a definitive printer signal
    {"label": "printer", "os_family": "embedded", "vendor": "Hewlett Packard",  "open_ports": _p(9100, 515, 631, 80),  "extra_info": _mh("_ipp._tcp", "_printer._tcp", http_server="jetdirect"), "dhcp_fingerprint": "1,3,6,15,44,46,47,31,33,121,249,43,252,12"},
    {"label": "printer", "os_family": "embedded", "vendor": "Hewlett Packard",  "open_ports": _p(9100, 631, 80),       "extra_info": _mh("_ipp._tcp", http_server="hp laserjet"),                "dhcp_fingerprint": "1,3,6,15,44,46,47,31,33,121,249,43,252,12"},
    {"label": "printer", "os_family": "embedded", "vendor": "Hewlett Packard",  "open_ports": _p(9100, 443, 631),      "extra_info": _mh("_ipps._tcp", "_ipp._tcp"),                             "dhcp_fingerprint": "1,3,6,15,44,46,47,31,33,121,249,43,252,12"},
    # Epson
    {"label": "printer", "os_family": "embedded", "vendor": "Seiko Epson Corp.","open_ports": _p(9100, 631, 80),       "extra_info": _m("_ipp._tcp", "_printer._tcp"),                           "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "printer", "os_family": "embedded", "vendor": "Seiko Epson Corp.","open_ports": _p(631, 443),            "extra_info": _m("_ipps._tcp"),                                           "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Canon
    {"label": "printer", "os_family": "embedded", "vendor": "Canon Inc.",       "open_ports": _p(9100, 515, 631),      "extra_info": _m("_ipp._tcp"),                                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "printer", "os_family": "embedded", "vendor": "Canon Inc.",       "open_ports": _p(9100, 80),            "extra_info": _m("_printer._tcp"),                                        "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Brother
    {"label": "printer", "os_family": "embedded", "vendor": "Brother Industries","open_ports": _p(9100, 515, 80),      "extra_info": _m("_ipp._tcp", "_printer._tcp"),                           "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Lexmark
    {"label": "printer", "os_family": "embedded", "vendor": "Lexmark Intl Inc.","open_ports": _p(9100, 631, 80),       "extra_info": _m("_ipp._tcp"),                                            "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Xerox
    {"label": "printer", "os_family": "embedded", "vendor": "Xerox Corporation","open_ports": _p(9100, 443, 515),      "extra_info": _m("_ipps._tcp"),                                           "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # Network-connected label printer
    {"label": "printer", "os_family": "embedded", "vendor": "Brother Industries","open_ports": _p(9100),               "extra_info": {},                                                          "dhcp_fingerprint": "1,3,6,15,28,51"},
    {"label": "printer", "os_family": "embedded", "vendor": None,               "open_ports": _p(9100, 515, 631),      "extra_info": _h("printer"),                                              "dhcp_fingerprint": None},

    # ── Network device ────────────────────────────────────────────────────────
    # All network equipment runs proprietary embedded firmware.
    # Cisco router/switch — port 161 (SNMP) + 23 (Telnet) are strong signals
    {"label": "network_device", "os_family": "embedded", "vendor": "Cisco Systems",  "open_ports": _p(22, 23, 80, 443, 161), "extra_info": {},              "dhcp_fingerprint": "1,3,6,15,9"},
    {"label": "network_device", "os_family": "embedded", "vendor": "Cisco Systems",  "open_ports": _p(22, 80, 443, 161),     "extra_info": {},              "dhcp_fingerprint": "1,3,6,15,9"},
    {"label": "network_device", "os_family": "embedded", "vendor": "Cisco-Meraki",   "open_ports": _p(22, 80, 443),          "extra_info": _h("nginx"),     "dhcp_fingerprint": "1,3,6,15,9"},
    # Ubiquiti UniFi — port 8443 (UniFi controller) is a strong Ubiquiti signal
    {"label": "network_device", "os_family": "embedded", "vendor": "Ubiquiti Inc.",  "open_ports": _p(22, 80, 443, 8080, 8443), "extra_info": _h("ubiquiti"), "dhcp_fingerprint": "1,3,6,15,28,51"},
    {"label": "network_device", "os_family": "embedded", "vendor": "Ubiquiti Inc.",  "open_ports": _p(22, 443, 8443),           "extra_info": {},            "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Netgear
    {"label": "network_device", "os_family": "embedded", "vendor": "Netgear Inc.",   "open_ports": _p(80, 443, 23),          "extra_info": _h("netgear"),   "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    {"label": "network_device", "os_family": "embedded", "vendor": "Netgear Inc.",   "open_ports": _p(80, 443),              "extra_info": {},              "dhcp_fingerprint": "1,3,6,15,28,51,58,59"},
    # TP-Link / Archer
    {"label": "network_device", "os_family": "embedded", "vendor": "TP-Link Tech.",  "open_ports": _p(80, 443, 22),          "extra_info": _h("zyxel"),     "dhcp_fingerprint": "1,3,6,15,28,51"},
    {"label": "network_device", "os_family": "embedded", "vendor": "TP-Link Tech.",  "open_ports": _p(80, 443),              "extra_info": {},              "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Aruba / HP wireless
    {"label": "network_device", "os_family": "embedded", "vendor": "Aruba Networks", "open_ports": _p(22, 80, 443, 8443),    "extra_info": {},              "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Juniper
    {"label": "network_device", "os_family": "embedded", "vendor": "Juniper Networks","open_ports": _p(22, 80, 443, 161),    "extra_info": {},              "dhcp_fingerprint": "1,3,6,15,28,51"},
    # MikroTik — port 8291 (Winbox) is MikroTik-specific
    {"label": "network_device", "os_family": "embedded", "vendor": "Mikrotik SIA",   "open_ports": _p(22, 80, 8291, 443),    "extra_info": {},              "dhcp_fingerprint": None},
    # ZyXEL DSL router
    {"label": "network_device", "os_family": "embedded", "vendor": "ZyXEL Comm.",    "open_ports": _p(22, 80, 443, 23),      "extra_info": _h("zyxel"),     "dhcp_fingerprint": "1,3,6,15,28,51"},
    # Generic router (TR-069 management port 7547 is ISP CPE)
    {"label": "network_device", "os_family": "embedded", "vendor": None,             "open_ports": _p(7547, 80, 443),        "extra_info": {},              "dhcp_fingerprint": None},
    # Fortinet firewall
    {"label": "network_device", "os_family": "embedded", "vendor": "Fortinet Inc.",  "open_ports": _p(22, 80, 443, 8443),    "extra_info": {},              "dhcp_fingerprint": None},
    # ISP-provisioned cable modem (DOCSIS) — distinctive DHCP option set
    {"label": "network_device", "os_family": "embedded", "vendor": None,             "open_ports": _p(80, 443, 161),         "extra_info": {},              "dhcp_fingerprint": "54,51,58,59,1,28,121,33,3,12,119,15,6,40,41,42,26,17,82,255"},

    # =========================================================================
    # NON-DHCP SAMPLES
    # The following samples have dhcp_fingerprint=None.  They represent devices
    # discovered via ARP scan, passive mDNS, nmap port scan, or banner grab —
    # the most common paths for static-IP and already-leased devices.
    # =========================================================================

    # ── Port-signature-only (no vendor, no DHCP) ─────────────────────────────
    # These are the most important non-DHCP samples because they cover devices
    # found exclusively by an nmap port scan.

    # Windows: SMB (445) + RDP (3389) is an unambiguous Windows signature
    {"label": "desktop",        "os_family": "windows",  "vendor": None, "open_ports": _p(445, 3389),           "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "desktop",        "os_family": "windows",  "vendor": None, "open_ports": _p(445, 3389, 80),       "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "desktop",        "os_family": "windows",  "vendor": None, "open_ports": _p(445, 139, 3389),      "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "desktop",        "os_family": "windows",  "vendor": None, "open_ports": _p(445, 139),            "extra_info": {},          "dhcp_fingerprint": None},
    # Windows server: IIS header makes it unambiguous
    {"label": "server",         "os_family": "windows",  "vendor": None, "open_ports": _p(80, 443, 445, 3389),  "extra_info": _h("iis"),   "dhcp_fingerprint": None},
    {"label": "server",         "os_family": "windows",  "vendor": None, "open_ports": _p(80, 443, 445),        "extra_info": _h("microsoft-iis"), "dhcp_fingerprint": None},
    # Linux server: SSH + web stack (nginx/apache) is a very strong Linux signal
    {"label": "server",         "os_family": "linux",    "vendor": None, "open_ports": _p(22, 80, 443),         "extra_info": _h("nginx"), "dhcp_fingerprint": None},
    {"label": "server",         "os_family": "linux",    "vendor": None, "open_ports": _p(22, 80, 443),         "extra_info": _h("apache"),"dhcp_fingerprint": None},
    {"label": "server",         "os_family": "linux",    "vendor": None, "open_ports": _p(22, 80, 443, 8080),   "extra_info": _h("nginx"), "dhcp_fingerprint": None},
    {"label": "server",         "os_family": "linux",    "vendor": None, "open_ports": _p(22, 80, 443, 3306),   "extra_info": _h("apache"),"dhcp_fingerprint": None},
    {"label": "server",         "os_family": "linux",    "vendor": None, "open_ports": _p(22, 443, 5432),       "extra_info": _h("nginx"), "dhcp_fingerprint": None},
    {"label": "server",         "os_family": "linux",    "vendor": None, "open_ports": _p(22, 25, 443, 993),    "extra_info": _h("nginx"), "dhcp_fingerprint": None},
    # SSH alone: could be Linux desktop or server; use "server" as the more
    # likely classification (desktops rarely have inbound SSH exposed)
    {"label": "server",         "os_family": "linux",    "vendor": None, "open_ports": _p(22),                  "extra_info": {},          "dhcp_fingerprint": None},
    # NAS port signature: SSH + HTTP/S + SMB
    {"label": "server",         "os_family": "linux",    "vendor": None, "open_ports": _p(22, 80, 443, 445),    "extra_info": _mh("_smb._tcp"), "dhcp_fingerprint": None},
    # Printer: port 9100 (JetDirect raw print) alone is definitive
    {"label": "printer",        "os_family": "embedded", "vendor": None, "open_ports": _p(9100),                "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "printer",        "os_family": "embedded", "vendor": None, "open_ports": _p(9100, 515),           "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "printer",        "os_family": "embedded", "vendor": None, "open_ports": _p(9100, 631),           "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "printer",        "os_family": "embedded", "vendor": None, "open_ports": _p(515, 631),            "extra_info": {},          "dhcp_fingerprint": None},
    # IP camera: RTSP (554) is a very strong camera signal
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(554),                 "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(80, 554),             "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(80, 443, 554),        "extra_info": {},          "dhcp_fingerprint": None},
    # MQTT broker/device: port 1883 or 8883 is strong IoT indicator
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(1883),                "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(8883),                "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(1883, 8883),          "extra_info": {},          "dhcp_fingerprint": None},
    # IoT web-only (BusyBox HTTP server header, no DHCP)
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(80),                  "extra_info": _h("uhttpd"),"dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(80),                  "extra_info": _h("boa"),   "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(80),                  "extra_info": _h("busybox"),"dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": None, "open_ports": _p(80),                  "extra_info": _h("mini_httpd"), "dhcp_fingerprint": None},
    # Network device: SNMP (161) + management web = router/switch
    {"label": "network_device", "os_family": "embedded", "vendor": None, "open_ports": _p(22, 80, 443, 161),    "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": None, "open_ports": _p(80, 443, 161),        "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": None, "open_ports": _p(22, 23, 80, 161),     "extra_info": {},          "dhcp_fingerprint": None},
    # TR-069 (7547) = ISP CPE router
    {"label": "network_device", "os_family": "embedded", "vendor": None, "open_ports": _p(7547),                "extra_info": {},          "dhcp_fingerprint": None},
    # Winbox port 8291 = MikroTik router (extremely specific)
    {"label": "network_device", "os_family": "embedded", "vendor": None, "open_ports": _p(8291),                "extra_info": {},          "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": None, "open_ports": _p(22, 8291, 80),        "extra_info": {},          "dhcp_fingerprint": None},

    # ── Vendor-only (no DHCP, no open ports) ─────────────────────────────────
    # ARP-discovered devices where only the MAC OUI vendor is known.

    # Unambiguous IoT vendors
    {"label": "iot",            "os_family": "embedded", "vendor": "Espressif Inc.",      "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Tuya Global Inc.",    "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Shenzhen Tuya",       "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Hikvision Digital",   "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Dahua Technology",    "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Axis Communications", "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Amazon Technologies", "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Nest Labs Inc.",      "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Ring LLC",            "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    # Unambiguous network device vendors
    {"label": "network_device", "os_family": "embedded", "vendor": "Cisco Systems",       "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": "Ubiquiti Inc.",        "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": "Aruba Networks",       "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": "Fortinet Inc.",        "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": "Juniper Networks",     "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": "Mikrotik SIA",         "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    # Unambiguous printer vendors (Epson/Canon/Brother are predominantly printers
    # on home/SMB networks; HP and Xerox are excluded due to PC ambiguity)
    {"label": "printer",        "os_family": "embedded", "vendor": "Seiko Epson Corp.",    "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "printer",        "os_family": "embedded", "vendor": "Canon Inc.",           "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "printer",        "os_family": "embedded", "vendor": "Brother Industries",   "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    # NAS vendors
    {"label": "server",         "os_family": "linux",    "vendor": "Synology Inc.",        "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},
    {"label": "server",         "os_family": "linux",    "vendor": "QNAP Systems",         "open_ports": [], "extra_info": {}, "dhcp_fingerprint": None},

    # ── mDNS-only (no DHCP, no open ports, vendor optional) ──────────────────
    # Devices discovered via passive mDNS / DNS-SD browsing.  These service
    # types are standardised and unambiguous.

    # _googlecast._tcp = Chromecast / Android TV / Google Nest Hub
    {"label": "iot",     "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_googlecast._tcp"),             "dhcp_fingerprint": None},
    # _cast._tcp = Google Cast (older Chromecasts and Samsung TVs with Cast)
    {"label": "iot",     "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_cast._tcp"),                   "dhcp_fingerprint": None},
    # _airplay._tcp = Apple TV, HomePod, AirPort Express
    {"label": "iot",     "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_airplay._tcp"),                 "dhcp_fingerprint": None},
    {"label": "iot",     "os_family": "embedded", "vendor": "Apple Inc.", "open_ports": [], "extra_info": _m("_airplay._tcp"),                 "dhcp_fingerprint": None},
    # _homekit._tcp / _hap._tcp = HomeKit accessory (always embedded)
    {"label": "iot",     "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_homekit._tcp"),                 "dhcp_fingerprint": None},
    {"label": "iot",     "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_hap._tcp"),                    "dhcp_fingerprint": None},
    # _matter._tcp = Matter/Thread IoT accessory
    {"label": "iot",     "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_matter._tcp"),                  "dhcp_fingerprint": None},
    # _spotify-connect._tcp = Spotify-enabled speaker/TV
    {"label": "iot",     "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_spotify-connect._tcp"),         "dhcp_fingerprint": None},
    # _mqtt._tcp = MQTT broker or IoT gateway
    {"label": "iot",     "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_mqtt._tcp"),                    "dhcp_fingerprint": None},
    # _ipp._tcp + _printer._tcp = IPP printer (universally a printer)
    {"label": "printer", "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_ipp._tcp", "_printer._tcp"),    "dhcp_fingerprint": None},
    {"label": "printer", "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_ipp._tcp"),                    "dhcp_fingerprint": None},
    {"label": "printer", "os_family": "embedded", "vendor": None,         "open_ports": [], "extra_info": _m("_ipps._tcp"),                   "dhcp_fingerprint": None},
    # _workstation._tcp + _afpovertcp._tcp = macOS desktop (AFP is Apple-only)
    {"label": "desktop", "os_family": "macos",    "vendor": None,         "open_ports": [], "extra_info": _m("_workstation._tcp", "_afpovertcp._tcp"), "dhcp_fingerprint": None},
    {"label": "desktop", "os_family": "macos",    "vendor": "Apple Inc.", "open_ports": [], "extra_info": _m("_workstation._tcp", "_afpovertcp._tcp"), "dhcp_fingerprint": None},
    # _workstation._tcp + _smb._tcp (no AFP) = Linux desktop running Avahi + Samba
    {"label": "desktop", "os_family": "linux",    "vendor": None,         "open_ports": [], "extra_info": _m("_workstation._tcp", "_smb._tcp"), "dhcp_fingerprint": None},
    # _ssh._tcp = SSH-advertised server or desktop (treat as server — more common)
    {"label": "server",  "os_family": "linux",    "vendor": None,         "open_ports": [], "extra_info": _m("_ssh._tcp"),                     "dhcp_fingerprint": None},

    # ── Combined non-DHCP (vendor + ports, no DHCP) ───────────────────────────
    # Strong multi-signal combinations without DHCP data.  These are the most
    # common real-world non-DHCP cases: static-IP servers and appliances.

    # Ubiquiti + port 8443 = UniFi AP/switch with static management IP
    {"label": "network_device", "os_family": "embedded", "vendor": "Ubiquiti Inc.", "open_ports": _p(22, 8443),        "extra_info": {},              "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": "Ubiquiti Inc.", "open_ports": _p(22, 80, 8443),    "extra_info": _h("ubiquiti"),  "dhcp_fingerprint": None},
    # Cisco + SNMP on static IP
    {"label": "network_device", "os_family": "embedded", "vendor": "Cisco Systems", "open_ports": _p(22, 80, 161),     "extra_info": {},              "dhcp_fingerprint": None},
    {"label": "network_device", "os_family": "embedded", "vendor": "Cisco Systems", "open_ports": _p(22, 443, 161),    "extra_info": {},              "dhcp_fingerprint": None},
    # Linux server identified by vendor + service stack (static IP, no DHCP)
    {"label": "server",         "os_family": "linux",    "vendor": "Supermicro",    "open_ports": _p(22, 80, 443),     "extra_info": _h("nginx"),    "dhcp_fingerprint": None},
    {"label": "server",         "os_family": "linux",    "vendor": "Intel Corporate","open_ports": _p(22, 80, 443),    "extra_info": _h("apache"),   "dhcp_fingerprint": None},
    # NAS on static IP
    {"label": "server",         "os_family": "linux",    "vendor": "Synology Inc.", "open_ports": _p(22, 80, 443, 445),"extra_info": _mh("_smb._tcp"), "dhcp_fingerprint": None},
    {"label": "server",         "os_family": "linux",    "vendor": "QNAP Systems",  "open_ports": _p(22, 80, 443, 445),"extra_info": {},              "dhcp_fingerprint": None},
    # Windows desktop on static IP (e.g. admin workstation)
    {"label": "desktop",        "os_family": "windows",  "vendor": "Intel Corporate","open_ports": _p(445, 3389),      "extra_info": {},              "dhcp_fingerprint": None},
    {"label": "desktop",        "os_family": "windows",  "vendor": "Dell Inc.",      "open_ports": _p(445, 3389),      "extra_info": {},              "dhcp_fingerprint": None},
    {"label": "desktop",        "os_family": "windows",  "vendor": "Lenovo",         "open_ports": _p(445, 139),       "extra_info": {},              "dhcp_fingerprint": None},
    # macOS desktop on static IP
    {"label": "desktop",        "os_family": "macos",    "vendor": "Apple Inc.",     "open_ports": _p(445, 5900),      "extra_info": _m("_workstation._tcp"), "dhcp_fingerprint": None},
    {"label": "desktop",        "os_family": "macos",    "vendor": "Apple Inc.",     "open_ports": _p(22, 445),        "extra_info": _m("_afpovertcp._tcp"),  "dhcp_fingerprint": None},
    # Linux desktop on static IP
    {"label": "desktop",        "os_family": "linux",    "vendor": "Intel Corporate","open_ports": _p(22),             "extra_info": _m("_workstation._tcp"), "dhcp_fingerprint": None},
    {"label": "desktop",        "os_family": "linux",    "vendor": "Realtek Semi.",  "open_ports": _p(22),             "extra_info": _m("_workstation._tcp"), "dhcp_fingerprint": None},
    # IP camera: vendor + RTSP on static IP
    {"label": "iot",            "os_family": "embedded", "vendor": "Hikvision Digital", "open_ports": _p(80, 554),     "extra_info": _h("hikvision"), "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Dahua Technology",  "open_ports": _p(80, 554),     "extra_info": {},              "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Axis Communications","open_ports": _p(80, 443, 554),"extra_info": {},             "dhcp_fingerprint": None},
    # Espressif + uhttpd on static IP (e.g. Shelly relay with static config)
    {"label": "iot",            "os_family": "embedded", "vendor": "Espressif Inc.", "open_ports": _p(80),             "extra_info": _h("boa"),       "dhcp_fingerprint": None},
    {"label": "iot",            "os_family": "embedded", "vendor": "Espressif Inc.", "open_ports": _p(80, 1883),       "extra_info": {},              "dhcp_fingerprint": None},
    # Printer on static IP (vendor + printing ports)
    {"label": "printer",        "os_family": "embedded", "vendor": "Hewlett Packard", "open_ports": _p(9100, 631),    "extra_info": _m("_ipp._tcp"), "dhcp_fingerprint": None},
    {"label": "printer",        "os_family": "embedded", "vendor": "Seiko Epson Corp.","open_ports": _p(9100, 631),   "extra_info": _m("_ipp._tcp"), "dhcp_fingerprint": None},
    {"label": "printer",        "os_family": "embedded", "vendor": "Canon Inc.",       "open_ports": _p(9100),        "extra_info": {},              "dhcp_fingerprint": None},
]
# fmt: on


def _build_samples_from_synthetic() -> tuple[list[list[float]], list[str], list[str]]:
    """Convert _SYNTHETIC_DATA into (X, y_device_type, y_os_family) arrays."""
    X: list[list[float]] = []
    y_dt: list[str] = []
    y_os: list[str] = []
    for sample in _SYNTHETIC_DATA:
        feats = extract_features(
            vendor=sample.get("vendor"),
            open_ports=sample.get("open_ports", []),
            extra_info=sample.get("extra_info"),
            dhcp_fingerprint=sample.get("dhcp_fingerprint"),
        )
        X.append(feats)
        y_dt.append(sample["label"])
        y_os.append(sample["os_family"])
    return X, y_dt, y_os


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
    extra_y_dt: list[str] | None = None,
    n_estimators: int = 100,
    max_depth: int = 8,
    run_cv: bool = False,
    verbose: bool = False,
) -> tuple[object, object]:
    """Train device_type and os_family classifiers and return them as a tuple.

    Parameters
    ----------
    extra_X, extra_y_dt:
        Optional additional training samples for the *device_type* classifier
        only (e.g. DHCP fingerprints from the Fingerbank API that carry a
        device_type label but no os_family).  These are NOT used to train the
        os_family classifier.
    n_estimators:
        Number of trees in the forest.  100 gives a good size/accuracy tradeoff.
    max_depth:
        Maximum depth of each tree.  8 keeps the model compact (~100 KB).
    run_cv:
        When ``True``, print 5-fold cross-validation accuracy to stdout for
        both classifiers.
    verbose:
        When ``True``, print the top-20 feature importances for the device_type
        classifier.

    Returns
    -------
    tuple[clf_device_type, clf_os_family]
        Both classifiers sharing the same 142-dimension feature vector.
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score

    X_syn, y_dt_syn, y_os_syn = _build_samples_from_synthetic()

    # ── device_type classifier (synthetic + optional Fingerbank augmentation) ─
    X_dt = X_syn.copy()
    y_dt = y_dt_syn.copy()
    if extra_X and extra_y_dt:
        X_dt.extend(extra_X)
        y_dt.extend(extra_y_dt)

    X_dt_np = np.array(X_dt, dtype=np.float32)
    y_dt_np = np.array(y_dt)

    log.info(
        "training_device_type_start samples=%d features=%d",
        len(y_dt), X_dt_np.shape[1],
    )
    clf_dt = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf_dt.fit(X_dt_np, y_dt_np)
    log.info("training_device_type_done classes=%s", list(clf_dt.classes_))

    # ── os_family classifier (synthetic only — Fingerbank has no OS labels) ───
    X_os_np = np.array(X_syn, dtype=np.float32)
    y_os_np = np.array(y_os_syn)

    log.info(
        "training_os_family_start samples=%d features=%d",
        len(y_os_syn), X_os_np.shape[1],
    )
    clf_os = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf_os.fit(X_os_np, y_os_np)
    log.info("training_os_family_done classes=%s", list(clf_os.classes_))

    if run_cv:
        for label, clf, X_np, y_np in [
            ("device_type", clf_dt, X_dt_np, y_dt_np),
            ("os_family",   clf_os, X_os_np, y_os_np),
        ]:
            # Need at least 2 samples per class for CV; skip if not enough data.
            from collections import Counter  # noqa: PLC0415
            min_count = min(Counter(y_np).values())
            if min_count < 2:
                print(f"[{label}] Skipping CV — too few samples in some classes.")
                continue
            scores = cross_val_score(
                clf, X_np, y_np,
                cv=min(5, min_count),
                scoring="accuracy",
                n_jobs=-1,
            )
            print(
                f"[{label}] 5-fold CV accuracy: {scores.mean():.3f} ± {scores.std():.3f}  "
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
        for label, clf in [("device_type", clf_dt), ("os_family", clf_os)]:
            importances = clf.feature_importances_
            top_n = sorted(enumerate(importances), key=lambda x: -x[1])[:20]
            print(f"\nTop-20 feature importances [{label}]:")
            for idx, imp in top_n:
                print(f"  {feature_names[idx]:<35s}  {imp:.4f}")

    return clf_dt, clf_os


def save(models: tuple[object, object], path: str = MODEL_PATH) -> None:
    """Serialise the ``(clf_device_type, clf_os_family)`` tuple to *path* using joblib."""
    import joblib  # noqa: PLC0415

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(models, path, compress=3)
    size_kb = os.path.getsize(path) / 1024
    log.info("model_saved path=%s size_kb=%.1f", path, size_kb)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Train the TheBox RF device-type and OS-family classifiers. "
            "The output file contains a (clf_device_type, clf_os_family) tuple."
        ),
    )
    parser.add_argument(
        "--fingerbank-api-key",
        metavar="KEY",
        default=os.environ.get("FINGERBANK_API_KEY", ""),
        help=(
            "Fingerbank API key for pulling additional labelled DHCP fingerprints "
            "to augment the device_type classifier. "
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
    extra_y_dt: list[str] | None = None
    if args.fingerbank_api_key:
        extra_X, extra_y_dt = _build_samples_from_fingerbank_api(args.fingerbank_api_key)

    models = train(
        extra_X=extra_X,
        extra_y_dt=extra_y_dt,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        run_cv=args.cv,
        verbose=args.verbose,
    )
    save(models, path=args.output)


if __name__ == "__main__":
    main()
