"""Train the TheBox RF device-type and OS-family classifiers.

This script can be run:

1. **At Docker build time** (baked into the image): the Dockerfile copies this
   file and calls ``python train_classifier.py`` so the models are available
   the moment the container starts.

2. **Interactively** to inspect feature importances or cross-validation scores::

       python train_classifier.py --cv --verbose

The trained models are saved as a ``(clf_device_type, clf_os_family)`` tuple
serialised with joblib.  Both classifiers use the feature vector defined in
``device_classifier.py`` (vendor OUI keywords, open TCP ports, mDNS service
types, HTTP server header keywords).  DHCP option-55 fingerprints are excluded
because the vast majority of devices are discovered via ARP scan, passive
mDNS/SSDP, or nmap — not DHCP snooping.

Training data is derived from the domain knowledge that was previously encoded
as runtime heuristics in app.py (vendor keyword tables, port signals, mDNS
service types, HTTP server banners, SNMP sysDescr keywords, UPnP manufacturer
strings).  Converting those hints into training samples gives the classifier
richer, denser coverage than was achievable with a rule engine.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

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

# ── Sample-building helpers ───────────────────────────────────────────────────

def _p(*ports: int) -> list[dict]:
    """Build an open_ports list from port numbers."""
    return [{"port": p, "state": "open", "service": ""} for p in ports]


def _m(*stypes: str) -> dict:
    """Build an extra_info dict with mDNS service types."""
    return {"mdns_services": [{"service_type": s} for s in stypes]}


def _h(server: str, **extra: object) -> dict:
    """Build an extra_info dict with an HTTP server banner."""
    d: dict = {"http_server": server}
    d.update(extra)
    return d


def _mh(*stypes: str, **extra: object) -> dict:
    """Build an extra_info dict with mDNS service types plus additional keys."""
    d: dict = {"mdns_services": [{"service_type": s} for s in stypes]}
    d.update(extra)
    return d


# ── Canonical vendor / keyword tables ────────────────────────────────────────
# These tables encode the domain knowledge that was previously used as
# runtime heuristics in app.py.  They are used here only at train time to
# generate training samples — they are not loaded at service startup.

# IoT hardware vendors (OUI registry canonical names or close approximations)
_CANONICAL_IOT_VENDORS: list[str] = [
    # Microcontroller / embedded SoC
    "Espressif Inc.",
    "Nordic Semiconductor ASA",
    "Microchip Technology Inc.",
    "Texas Instruments",
    "NXP Semiconductors",
    "Bouffalo Lab",
    # Smart home automation hubs / protocols
    "Lutron Electronics",
    "Leviton Manufacturing",
    "Aeotec Ltd.",
    "Fibaro Group",
    "HomeSeer Technologies",
    "Hubitat Inc.",
    "SmartThings Inc.",
    # Smart lighting
    "Signify Netherlands BV",        # Philips Hue
    "LIFX Technologies",
    "Nanoleaf Inc.",
    "Govee Home",
    "Sengled Optoelectronics",
    "Innr Lighting BV",
    "Yeelight Technology",
    "IKEA of Sweden",
    "FEIT Electric Company",
    # Smart plugs / switches / relays
    "Tuya Global Inc.",
    "Shenzhen Tuya Smart",
    "eWeLink (CoolKit Technologies)",
    "Shelly Group",
    "Sonoff (ITEAD Intelligent Systems)",
    "Meross Technology",
    "Gosund Technology",
    "SwitchBot Inc.",
    "Broadlink Co. Ltd.",
    "Belkin International",
    "Kasa Smart (TP-Link)",
    # Thermostats / HVAC
    "ecobee Inc.",
    "Honeywell International",
    "Tado GmbH",
    "Nest Labs Inc.",
    "Johnson Controls",
    # IP cameras / video doorbells
    "Ring LLC",
    "Arlo Technologies",
    "Blink (Amazon)",
    "Eufy Security (Anker)",
    "Wyze Labs Inc.",
    "Amcrest Technologies",
    "Reolink Digital Technology",
    "Foscam Digital Technologies",
    "Hikvision Digital Technology",
    "Dahua Technology",
    "Axis Communications",
    "Hanwha Vision",
    "VIVOTEK Inc.",
    "DoorBird (Bird Home Automation)",
    "August Home Inc.",
    # Smart speakers / streaming devices
    "Amazon Technologies Inc.",
    "Google LLC",
    "Sonos Inc.",
    "Roku Inc.",
    "Samsung Electronics",           # smart TVs / Cast devices
    "TCL King Electrical",
    "Hisense International",
    "Vizio Inc.",
    "LG Electronics",
    # Robot vacuums / smart appliances
    "iRobot Corporation",
    "Ecovacs Robotics",
    "Roborock Technology",
    "Neato Robotics",
    # Smart locks / garage / blinds
    "Chamberlain Group",
    "Allegion plc",
    "Somfy Systems",
    # Health / environment sensors
    "Withings SA",
    "Netatmo SA",
    "Eve Systems GmbH",
    # General IoT / accessories
    "Anker Innovations",
    "Xiaomi Communications",
    "Aqara (Lumi United Technology)",
    "Elgato Systems",
    # OUI chip-maker placeholders (commodity IoT hardware)
    "Smart Innovation LLC",
    "Hui Zhou Gaoshengda Technology Co.,LTD",
    "Shenzhen Bilian Electronic",
    "Shenzhen Aisens Technology",
]

_CANONICAL_NETWORK_VENDORS: list[str] = [
    "Cisco Systems Inc.",
    "Cisco-Meraki LLC",
    "Ubiquiti Inc.",
    "Ubiquiti Networks",
    "Aruba Networks",
    "Juniper Networks",
    "Mikrotik SIA",
    "ZyXEL Communications",
    "TP-Link Technologies",
    "Fortinet Inc.",
    "Ruckus Networks",
    "Aerohive Networks",
    "Sophos Ltd.",
    "Palo Alto Networks",
    "WatchGuard Technologies",
    "SonicWall Inc.",
    "Barracuda Networks",
    "Cambium Networks",
    "CradlePoint Inc.",
    "Extreme Networks",
    "Netgear Inc.",
    "HP Enterprise (network)",       # HP switches / APs
]

_CANONICAL_NAS_VENDORS: list[str] = [
    "Synology Inc.",
    "QNAP Systems, Inc.",
    "Western Digital Technologies",
    "Seagate Technology",
    "Buffalo Inc.",
    "Drobo Inc.",
    "Asustor Inc.",
    "Promise Technology",
    "Overland-Tandberg",
]

_CANONICAL_PRINTER_VENDORS: list[str] = [
    "Hewlett Packard",
    "Seiko Epson Corp.",
    "Canon Inc.",
    "Brother Industries",
    "Lexmark International",
    "Xerox Corporation",
    "Konica Minolta",
    "Kyocera Document Solutions",
    "Ricoh Company",
]

# Embedded HTTP server banners → IoT / network device
_IOT_HTTP_SERVER_BANNERS: list[str] = [
    "uhttpd", "boa", "mini_httpd", "goahead", "lwip", "mongoose",
    "micropython", "esp-idf", "shelly", "tasmota", "openwrt", "dd-wrt",
    "thttpd", "micro_httpd",
    # IP camera / NVR branded servers
    "hikvision", "dnvrs-webs", "dahua", "axis", "vivotek",
    "amcrest", "reolink", "foscam", "netwave",
    # Smart home branded servers
    "ewelink", "wemo", "homeseer",
]

# SNMP sysDescr keywords → network_device
_SNMP_NETWORK_DEVICE_KEYWORDS: list[str] = [
    "cisco ios", "cisco nx-os", "ios-xe", "ios xr",
    "junos", "routeros", "mikrotik", "edgeos", "edgerouter",
    "arubaos", "fortios", "fortigate", "panos", "pan-os",
    "procurve", "opnsense", "pfsense",
]

# SNMP sysDescr keywords → printer
_SNMP_PRINTER_KEYWORDS: list[str] = [
    "jetdirect", "laserjet", "officejet", "brother", "bizhub",
    "konica", "kyocera", "xerox", "lexmark", "ricoh", "epson", "printer",
]

# SNMP sysDescr keywords → IoT / embedded
_SNMP_IOT_KEYWORDS: list[str] = [
    "esp-idf", "freertos", "lwip", "shelly", "tasmota",
    "hikvision", "dahua", "axis",
]

# UPnP manufacturer strings → IoT
_IOT_UPNP_MANUFACTURERS: list[str] = [
    "tuya", "espressif", "shelly", "philips", "sonos", "ring", "nest",
    "ecobee", "amazon", "google", "ikea", "govee", "irobot", "ecovacs",
    "roborock", "withings", "netatmo", "fibaro", "aeotec", "belkin",
    "wemo", "kasa", "switchbot", "broadlink", "hikvision", "dahua",
    "axis", "amcrest", "reolink", "foscam", "wyze", "eufy", "blink",
    "arlo", "august", "chamberlain", "liftmaster",
    "roku", "tcl", "hisense", "vizio", "tivo", "directv", "samsung",
    "lg electronics", "lg", "sony", "sharp", "panasonic",
]


# ── Training sample generation ────────────────────────────────────────────────

def _build_synthetic_samples() -> list[dict]:  # noqa: C901
    """Build the full training dataset from vendor tables and signal patterns.

    Returns a list of sample dicts, each with keys:
      ``label`` (device_type), ``os_family``, ``vendor``, ``open_ports``,
      ``extra_info``.
    """
    samples: list[dict] = []

    def _iot(vendor=None, ports=None, extra=None):
        samples.append({"label": "iot",            "os_family": "embedded",
                         "vendor": vendor, "open_ports": ports or [],
                         "extra_info": extra or {}})

    def _net(vendor=None, ports=None, extra=None):
        samples.append({"label": "network_device", "os_family": "embedded",
                         "vendor": vendor, "open_ports": ports or [],
                         "extra_info": extra or {}})

    def _srv(vendor=None, ports=None, extra=None, os_family="linux"):
        samples.append({"label": "server",         "os_family": os_family,
                         "vendor": vendor, "open_ports": ports or [],
                         "extra_info": extra or {}})

    def _desk(vendor=None, ports=None, extra=None, os_family="windows"):
        samples.append({"label": "desktop",        "os_family": os_family,
                         "vendor": vendor, "open_ports": ports or [],
                         "extra_info": extra or {}})

    def _mob(vendor=None, ports=None, extra=None, os_family="android"):
        samples.append({"label": "mobile",         "os_family": os_family,
                         "vendor": vendor, "open_ports": ports or [],
                         "extra_info": extra or {}})

    def _prt(vendor=None, ports=None, extra=None):
        samples.append({"label": "printer",        "os_family": "embedded",
                         "vendor": vendor, "open_ports": ports or [],
                         "extra_info": extra or {}})

    # =========================================================================
    # IoT devices
    # =========================================================================

    # 1. Vendor-only (ARP-discovered; only MAC OUI known)
    for v in _CANONICAL_IOT_VENDORS:
        _iot(vendor=v)

    # 2. IoT vendor + characteristic port / banner combinations
    _iot("Espressif Inc.",              _p(80),           _h("uhttpd"))
    _iot("Espressif Inc.",              _p(80, 443),      _h("uhttpd"))
    _iot("Espressif Inc.",              _p(80, 1883),     {})
    _iot("Espressif Inc.",              _p(1883),         _m("_mqtt._tcp"))
    _iot("Shenzhen Tuya Smart",         _p(80),           _h("busybox"))
    _iot("Tuya Global Inc.",            _p(80, 443),      {})
    _iot("Shelly Group",                _p(80),           _h("shelly"))
    _iot("Shelly Group",                _p(80, 1883),     {})
    _iot("Shelly Group",                _p(80, 443),      _h("mongoose"))
    _iot("Sonoff (ITEAD Intelligent Systems)", _p(80),   _h("ewelink"))
    _iot("Govee Home",                  _p(80),           _h("goahead"))
    _iot("LIFX Technologies",           _p(80),           {})
    _iot("Signify Netherlands BV",      _p(80, 443),      _h("mini_httpd"))
    _iot("Signify Netherlands BV",      _p(80),           _h("nginx"))
    _iot("Ring LLC",                    _p(443),          {})
    _iot("Ring LLC",                    _p(80, 443),      {})
    _iot("Arlo Technologies",           _p(443),          {})
    _iot("Blink (Amazon)",              _p(443),          {})
    _iot("Hikvision Digital Technology",_p(80, 443, 554), _h("hikvision"))
    _iot("Hikvision Digital Technology",_p(80, 554),      {})
    _iot("Dahua Technology",            _p(80, 554),      _h("dahua"))
    _iot("Dahua Technology",            _p(80, 554),      _h("dnvrs-webs"))
    _iot("Axis Communications",         _p(80, 443, 554), _h("axis"))
    _iot("Axis Communications",         _p(80, 443, 554), {})
    _iot("Reolink Digital Technology",  _p(80, 554),      _h("reolink"))
    _iot("Amcrest Technologies",        _p(80, 554),      _h("amcrest"))
    _iot("Foscam Digital Technologies", _p(80, 554),      _h("foscam"))
    _iot("VIVOTEK Inc.",                _p(80, 554),      _h("vivotek"))
    _iot("iRobot Corporation",          _p(443),          _m("_hap._tcp"))
    _iot("Ecovacs Robotics",            _p(443),          {})
    _iot("Roborock Technology",         _p(443),          {})
    _iot("ecobee Inc.",                 _p(443),          _m("_hap._tcp"))
    _iot("Nest Labs Inc.",              _p(443),          _m("_matter._tcp"))
    _iot("Nest Labs Inc.",              _p(443),          {})
    _iot("Honeywell International",     _p(80, 443),      {})
    _iot("Tado GmbH",                   _p(443),          _m("_hap._tcp"))
    _iot("Sonos Inc.",                  _p(80, 443, 1400),_m("_spotify-connect._tcp"))
    _iot("Sonos Inc.",                  _p(80),           {})
    _iot("Roku Inc.",                   _p(8060),         _m("_spotify-connect._tcp"))
    _iot("Roku Inc.",                   _p(8060, 8080),   {})
    _iot("TCL King Electrical",         _p(8060, 8080),   _m("_googlecast._tcp"))
    _iot("Hisense International",       _p(8080),         _m("_cast._tcp"))
    _iot("Vizio Inc.",                  _p(8080),         _m("_cast._tcp"))
    _iot("LG Electronics",              _p(3000, 8080),   _m("_googlecast._tcp"))
    _iot("Samsung Electronics",         _p(8001, 8080),   _m("_cast._tcp"))
    _iot("Google LLC",                  _p(8008, 8009),   _m("_googlecast._tcp"))
    _iot("Google LLC",                  _p(8009),         _m("_cast._tcp"))
    _iot("Google LLC",                  _p(80, 8008),     _m("_googlecast._tcp", "_spotify-connect._tcp"))
    _iot("Amazon Technologies Inc.",    _p(443),          {})
    _iot("Amazon Technologies Inc.",    _p(443, 55443),   {})
    _iot("Kasa Smart (TP-Link)",        _p(80, 9999),     _h("uhttpd"))
    _iot("Broadlink Co. Ltd.",          _p(80),           _h("goahead"))
    _iot("Meross Technology",           _p(80, 443),      {})
    _iot("SwitchBot Inc.",              _p(443),          _m("_homekit._tcp"))
    _iot("Aqara (Lumi United Technology)", _p(80),        _m("_homekit._tcp"))
    _iot("Eve Systems GmbH",            _p(80),           _m("_homekit._tcp"))
    _iot("Chamberlain Group",           _p(443),          _m("_matter._tcp"))
    _iot("August Home Inc.",            _p(443),          _m("_hap._tcp"))
    _iot("Hui Zhou Gaoshengda Technology Co.,LTD", _p(80),
         _mh("_googlecast._tcp", upnp_manufacturer="Roku"))
    _iot("Hui Zhou Gaoshengda Technology Co.,LTD", [],
         {"upnp_manufacturer": "TCL"})
    _iot("Smart Innovation LLC",        _p(80),           {})
    _iot("Smart Innovation LLC",        [],               {})
    _iot("Shenzhen Bilian Electronic",  _p(80),           _h("uhttpd"))
    _iot("Belkin International",        _p(80, 49152),    _h("mini_httpd"))

    # 3. Port-signal-only (no vendor, no banner; pure port fingerprint)
    for ports in [
        (554,), (80, 554), (443, 554), (80, 443, 554),       # RTSP
        (8554,), (80, 8554),                                   # RTSP alt
        (1883,), (8883,), (1883, 8883), (80, 1883),           # MQTT
        (5683,), (5683, 5684),                                 # CoAP
        (502,), (502, 80),                                     # Modbus
        (8008,), (8009,), (8008, 8009), (80, 8008, 8009),     # Cast
        (8008, 8009, 443),                                     # Cast with TLS
        (47808,),                                              # BACnet
        (9999,),                                               # Kasa
        (49153,), (80, 49152, 49153),                         # WeMo
    ]:
        _iot(ports=_p(*ports))

    # 4. HTTP server banner only (IoT embedded web servers)
    for banner in _IOT_HTTP_SERVER_BANNERS:
        _iot(ports=_p(80), extra=_h(banner))
    for banner in ["uhttpd", "goahead", "mini_httpd", "boa", "shelly", "openwrt", "mongoose"]:
        _iot(ports=_p(80, 443), extra=_h(banner))

    # 5. mDNS IoT service types (each individually and in key combinations)
    for svc in ("_googlecast._tcp", "_cast._tcp", "_airplay._tcp", "_homekit._tcp",
                "_hap._tcp", "_matter._tcp", "_spotify-connect._tcp",
                "_mqtt._tcp", "_raop._tcp"):
        _iot(extra=_m(svc))
        _iot(vendor="Apple Inc.", extra=_m(svc))    # Apple TV / HomePod
    _iot(extra=_m("_googlecast._tcp", "_spotify-connect._tcp"))
    _iot(ports=_p(8009), extra=_m("_googlecast._tcp"))
    _iot(extra=_m("_homekit._tcp", "_hap._tcp"))
    _iot(extra=_m("_matter._tcp", "_hap._tcp"))
    _iot(ports=_p(1883), extra=_m("_mqtt._tcp"))

    # 6. UPnP manufacturer signals
    for mfr in _IOT_UPNP_MANUFACTURERS:
        _iot(extra={"upnp_manufacturer": mfr})
    _iot(extra={"upnp_device_type": "urn:schemas-upnp-org:device:MediaRenderer:1"})
    _iot(extra={"upnp_device_type": "urn:schemas-upnp-org:device:MediaServer:1"})

    # 7. SNMP sysDescr IoT keywords
    for kw in _SNMP_IOT_KEYWORDS:
        _iot(ports=_p(80, 161),
             extra={"snmp_sysdescr": f"Device running {kw} firmware"})

    # =========================================================================
    # Network devices
    # =========================================================================

    # 1. Vendor-only
    for v in _CANONICAL_NETWORK_VENDORS:
        _net(vendor=v)

    # 2. Vendor + port combinations
    _net("Cisco Systems Inc.",      _p(22, 23, 80, 161),    {})
    _net("Cisco Systems Inc.",      _p(22, 80, 443, 161),   {})
    _net("Cisco Systems Inc.",      _p(22, 443, 161),       {})
    _net("Cisco-Meraki LLC",        _p(22, 80, 443),        _h("nginx"))
    _net("Ubiquiti Inc.",           _p(22, 80, 443, 8443),  _h("ubiquiti"))
    _net("Ubiquiti Inc.",           _p(22, 443, 8443),      {})
    _net("Ubiquiti Inc.",           _p(22, 80, 8443),       {})
    _net("Ubiquiti Inc.",           _p(80),                 {})
    _net("Ubiquiti Networks",       _p(22, 80, 8443),       {})
    _net("Aruba Networks",          _p(22, 80, 443, 8443),  {})
    _net("Juniper Networks",        _p(22, 80, 443, 161),   {})
    _net("Mikrotik SIA",            _p(22, 80, 8291, 443),  {})
    _net("Mikrotik SIA",            _p(8291,),               {})
    _net("Mikrotik SIA",            _p(22, 8291),            {})
    _net("ZyXEL Communications",    _p(22, 80, 443, 23),    _h("zyxel"))
    _net("TP-Link Technologies",    _p(80, 443, 22),        {})
    _net("Fortinet Inc.",           _p(22, 80, 443, 8443),  {})
    _net("Ruckus Networks",         _p(22, 80, 443),        {})
    _net("Sophos Ltd.",             _p(22, 80, 443),        {})
    _net("Palo Alto Networks",      _p(22, 80, 443),        {})
    _net("WatchGuard Technologies", _p(22, 80, 443, 8080),  {})
    _net("SonicWall Inc.",          _p(22, 80, 443),        {})
    _net("Netgear Inc.",            _p(80, 443, 23),        _h("netgear"))
    _net("Netgear Inc.",            _p(80, 443),            {})

    # 3. Port-only (no vendor)
    for ports in [
        (22, 23, 80, 161),   # SSH+Telnet+HTTP+SNMP = classic router/switch
        (80, 443, 161),      # HTTP+HTTPS+SNMP = managed switch
        (22, 80, 443, 161),  # SSH+web+SNMP
        (22, 80, 161),
        (80, 161),
        (7547,),             # TR-069 = ISP CPE (very specific to routers/modems)
        (7547, 80),
        (7547, 80, 443),
        (7547, 443),
        (8291,),             # Winbox = MikroTik (extremely specific)
        (22, 8291),
        (22, 8291, 80),
        (8291, 80),          # Winbox + HTTP = MikroTik with web UI
        (22, 80, 8443),      # Ubiquiti-style management
        (22, 443, 8443),
        (23, 80),            # Telnet + HTTP = legacy managed device
        (23, 80, 161),
    ]:
        _net(ports=_p(*ports))

    # 4. SNMP sysDescr keywords → network device
    for kw in _SNMP_NETWORK_DEVICE_KEYWORDS:
        _net(ports=_p(22, 80, 161),
             extra={"snmp_sysdescr": f"Software: {kw} Version 15.1"})

    # 5. SNMP sysName patterns → network device
    for name in ("rtr-01", "router-core", "sw-01", "switch-access",
                 "fw-01", "ap-floor1", "gw-main"):
        _net(ports=_p(22, 161), extra={"snmp_sysname": name})

    # 6. HTTP title → network device
    for title in ("router", "gateway", "routeros", "edgerouter", "unifi",
                  "ubiquiti", "meraki", "fortigate", "opnsense", "pfsense",
                  "arubaos", "sophos xg"):
        _net(ports=_p(80, 443), extra={"http_title": title})

    # 7. UPnP device type → network device
    _net(extra={"upnp_device_type": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"})
    _net(extra={"upnp_device_type": "urn:schemas-upnp-org:device:WANDevice:1"})
    _net(extra={"upnp_device_type": "urn:schemas-upnp-org:device:WLANAccessPoint:1"})

    # =========================================================================
    # Servers (Linux + NAS + Windows Server)
    # =========================================================================

    # 1. NAS vendor-only
    for v in _CANONICAL_NAS_VENDORS:
        _srv(vendor=v)

    # 2. NAS vendor + port combos
    _srv("Synology Inc.",                _p(22, 80, 443, 445),
         _mh("_smb._tcp", http_server="lighttpd"))
    _srv("Synology Inc.",                _p(22, 80, 443),    _h("nginx"))
    _srv("Synology Inc.",                _p(22, 80, 443, 445), {})
    _srv("QNAP Systems, Inc.",           _p(22, 80, 443, 445), _mh("_smb._tcp"))
    _srv("QNAP Systems, Inc.",           _p(80, 443),        _h("nginx"))
    _srv("Western Digital Technologies", _p(80, 443, 445),   _mh("_smb._tcp"))
    _srv("Seagate Technology",           _p(80, 443, 445),   {})
    _srv("Buffalo Inc.",                 _p(22, 80, 443, 445), {})

    # 3. Linux server: SSH + web stack (definitive Linux server signature)
    _linux_server_patterns = [
        (_p(22, 80, 443),         _h("nginx")),
        (_p(22, 80, 443),         _h("apache")),
        (_p(22, 80, 443),         _h("lighttpd")),
        (_p(22, 80, 443),         _h("caddy")),
        (_p(22, 80, 443, 3306),   _h("apache")),
        (_p(22, 80, 443, 3306),   _h("nginx")),
        (_p(22, 80, 443, 5432),   _h("nginx")),
        (_p(22, 80, 443, 8080),   _h("nginx")),
        (_p(22, 80, 443, 8080),   _h("tomcat")),
        (_p(22, 25, 443, 993),    _h("nginx")),
        (_p(22, 25, 110, 143),    _h("nginx")),
        (_p(22, 3306),            {}),
        (_p(22, 5432),            {}),
        (_p(22,),                 {}),
        (_p(22, 80, 443, 445),    _mh("_smb._tcp")),
        (_p(22, 80, 443),         _mh("_ssh._tcp")),
    ]
    for ports, extra in _linux_server_patterns:
        _srv(ports=ports, extra=extra)
        # Repeat with common server hardware vendors
        for v in ("Intel Corporate", "Supermicro Computer", "Broadcom Inc."):
            _srv(vendor=v, ports=ports, extra=extra)

    # mDNS _ssh._tcp alone = SSH-advertised device = server
    _srv(extra=_m("_ssh._tcp"))

    # NAS mDNS-only
    _srv(extra=_mh("_smb._tcp"))
    _srv(extra=_mh("_smb._tcp", "_ssh._tcp"))

    # 4. Windows Server: IIS header = exclusively Windows
    for v in (None, "Intel Corporate", "Dell Inc.", "Hewlett Packard Enterprise"):
        for kw in ("iis", "microsoft-iis"):
            _srv(vendor=v, ports=_p(80, 443, 445, 3389), extra=_h(kw),
                 os_family="windows")
            _srv(vendor=v, ports=_p(80, 443, 445),       extra=_h(kw),
                 os_family="windows")

    # 5. SNMP sysDescr "linux" + SSH
    _srv(ports=_p(22, 80),
         extra={"snmp_sysdescr": "Linux server 5.15.0 #1 SMP x86_64"})
    _srv(ports=_p(22),
         extra={"snmp_sysdescr": "Linux ubuntu 6.1.0 aarch64"})

    # =========================================================================
    # Desktop workstations (Windows, macOS, Linux)
    # =========================================================================

    # Windows: SMB + RDP is unambiguous
    for ports in [
        _p(445, 3389), _p(445, 3389, 80), _p(445, 139, 3389),
        _p(445, 139),  _p(445,),          _p(139,),
    ]:
        _desk(ports=ports)
    # Windows + hardware vendor
    for v in ("Intel Corporate", "Realtek Semiconductor", "Dell Inc.",
              "Lenovo", "ASUS", "Hewlett Packard", "HP Inc.", "Acer", "MSI"):
        _desk(vendor=v, ports=_p(445, 3389))
        _desk(vendor=v, ports=_p(445, 139))
        _desk(vendor=v)

    # macOS: _workstation._tcp + AFP / SMB mDNS, AirPlay/RAOP
    for vendor in ("Apple Inc.", None):
        _desk(vendor=vendor, extra=_m("_workstation._tcp", "_afpovertcp._tcp"),
              os_family="macos")
        _desk(vendor=vendor, extra=_m("_workstation._tcp", "_smb._tcp", "_afpovertcp._tcp"),
              os_family="macos")
        _desk(vendor=vendor, ports=_p(22, 445),
              extra=_m("_workstation._tcp", "_afpovertcp._tcp"), os_family="macos")
        _desk(vendor=vendor, ports=_p(5900, 22),
              extra=_m("_workstation._tcp"), os_family="macos")
        _desk(vendor=vendor, extra=_m("_airplay._tcp", "_raop._tcp", "_ssh._tcp"),
              os_family="macos")
        _desk(vendor=vendor,
              extra=_m("_airplay._tcp", "_raop._tcp", "_companion-link._tcp", "_ssh._tcp"),
              os_family="macos")
        _desk(vendor=vendor, ports=_p(22, 445),
              extra=_m("_afpovertcp._tcp"), os_family="macos")

    # Linux desktop: Avahi publishes _workstation._tcp
    for vendor in (None, "Intel Corporate", "Realtek Semiconductor", "Broadcom Inc.",
                   "AMD Inc."):
        _desk(vendor=vendor, ports=_p(22),  extra=_m("_workstation._tcp"),
              os_family="linux")
        _desk(vendor=vendor, ports=_p(22, 5900),
              extra=_m("_workstation._tcp"), os_family="linux")
        _desk(vendor=vendor, extra=_m("_workstation._tcp", "_smb._tcp"),
              os_family="linux")

    # Desktop SNMP sysDescr hint
    _desk(ports=_p(445),
          extra={"snmp_sysdescr":
                 "Hardware: Intel64 Family 6, Software: Windows Version 10.0"})

    # =========================================================================
    # Mobile phones and tablets
    # =========================================================================

    # iOS: _companion-link._tcp without desktop mDNS = iPhone/iPad
    # Apple vendor OUI + various port/mDNS combinations
    for vendor in ("Apple Inc.", None):
        _mob(vendor=vendor, extra=_m("_companion-link._tcp"), os_family="ios")
        _mob(vendor=vendor, os_family="ios")
        _mob(vendor=vendor, extra=_m("_airplay._tcp"), os_family="ios")
        _mob(vendor=vendor, extra=_m("_raop._tcp"),    os_family="ios")
        _mob(vendor=vendor, ports=_p(62078), extra=_m("_companion-link._tcp"),
             os_family="ios")
        _mob(vendor=vendor, ports=_p(62078), os_family="ios")

    # iPad-specific (same signals as iPhone but tablet form factor)
    _mob(vendor="Apple Inc.", extra=_m("_companion-link._tcp", "_airplay._tcp"),
         os_family="ios")
    _mob(vendor="Apple Inc.", extra=_m("_companion-link._tcp"), os_family="ios")

    # mDNS TXT record Apple model identifiers
    for model in ("iPhone14,2", "iPhone15,3", "iPad13,4", "iPod9,1"):
        _mob(vendor="Apple Inc.", extra={"mdns_txt_model": model}, os_family="ios")
        _mob(vendor=None,         extra={"mdns_txt_model": model}, os_family="ios")

    # Android: major phone OEM vendors, no ports open (phones block inbound)
    for v in ("Samsung Electronics", "Qualcomm Inc.", "MediaTek Inc.",
              "Xiaomi Communications", "Huawei Device Co.", "Motorola Mobility",
              "OnePlus Technology", "OPPO Electronics", "Vivo Mobile",
              "Realme Mobile", "Google Inc.",        # Pixel phones
              "Nothing Technology"):
        _mob(vendor=v, os_family="android")
        # Some Android phones with Cast/AirPlay receiver apps
    _mob(vendor="Samsung Electronics", ports=_p(8008), os_family="android")
    _mob(vendor="Qualcomm Inc.",        ports=_p(8008), os_family="android")

    # Locally-administered MAC (random) + no vendor = modern phone (MAC rotation)
    _mob(vendor=None, os_family="ios")
    _mob(vendor=None, os_family="android")
    _mob(vendor=None, ports=_p(62078), os_family="ios")

    # Android tablet: Samsung + 5900 (VNC/remote access app) is a tablet signal
    _mob(vendor="Samsung Electronics", ports=_p(5900), os_family="android")

    # =========================================================================
    # Printers
    # =========================================================================

    # Vendor-only
    for v in _CANONICAL_PRINTER_VENDORS:
        _prt(vendor=v)

    # Vendor + port + mDNS
    _prt("Hewlett Packard",
         _p(9100, 515, 631, 80),
         _mh("_ipp._tcp", "_printer._tcp", http_server="jetdirect"))
    _prt("Hewlett Packard",   _p(9100, 631),      _mh("_ipp._tcp", http_server="jetdirect"))
    _prt("Hewlett Packard",   _p(9100, 443, 631),  _m("_ipps._tcp"))
    _prt("Seiko Epson Corp.", _p(9100, 631, 80),   _m("_ipp._tcp", "_printer._tcp"))
    _prt("Seiko Epson Corp.", _p(631, 443),         _m("_ipps._tcp"))
    _prt("Canon Inc.",        _p(9100, 515, 631),   _m("_ipp._tcp"))
    _prt("Canon Inc.",        _p(9100, 80),          _m("_printer._tcp"))
    _prt("Brother Industries",_p(9100, 515, 80),    _m("_ipp._tcp", "_printer._tcp"))
    _prt("Lexmark International", _p(9100, 631, 80), _m("_ipp._tcp"))
    _prt("Xerox Corporation", _p(9100, 443, 515),   _m("_ipps._tcp"))
    _prt("Konica Minolta",    _p(9100, 631),         _m("_ipp._tcp"))
    _prt("Kyocera Document Solutions", _p(9100, 515, 631), _m("_ipp._tcp"))
    _prt("Ricoh Company",     _p(9100, 631, 80),     _m("_ipp._tcp"))

    # Port-only printer patterns (9100 = JetDirect raw print = definitive)
    for ports in [
        (9100,), (9100, 515), (9100, 631), (515, 631),
        (9100, 515, 631), (9100, 80), (9100, 443),
    ]:
        _prt(ports=_p(*ports))

    # mDNS-only printer
    for svc_combo in [
        ("_ipp._tcp",), ("_ipps._tcp",),
        ("_ipp._tcp", "_printer._tcp"), ("_printer._tcp",),
        ("_ipp._tcp", "_smb._tcp"),     # printer with SMB scan share
    ]:
        _prt(extra=_m(*svc_combo))
    # mDNS printer with vendor — strongest signal
    for v in _CANONICAL_PRINTER_VENDORS:
        _prt(vendor=v, extra=_m("_ipp._tcp"))

    # SNMP sysDescr → printer
    for kw in _SNMP_PRINTER_KEYWORDS:
        _prt(ports=_p(9100, 161),
             extra={"snmp_sysdescr": f"HP {kw} Series"})

    # HTTP title → printer
    for title in ("HP LaserJet", "HP OfficeJet", "Brother Printer",
                  "Canon PRINT", "Epson Printer", "Xerox Printer",
                  "KYOCERA", "Konica Minolta", "Ricoh"):
        _prt(ports=_p(80, 9100), extra={"http_title": title})

    # HTTP banner printer
    _prt(ports=_p(9100, 80), extra=_h("jetdirect"))
    _prt(ports=_p(9100, 80), extra=_h("printer"))

    # UPnP device type → printer
    _prt(extra={"upnp_device_type": "urn:schemas-upnp-org:device:Printer:1"})

    return samples


# ── Public interface ──────────────────────────────────────────────────────────

def _build_samples_from_synthetic() -> tuple[list[list[float]], list[str], list[str]]:
    """Convert synthetic samples into (X, y_device_type, y_os_family) arrays."""
    X: list[list[float]] = []
    y_dt: list[str] = []
    y_os: list[str] = []
    for sample in _build_synthetic_samples():
        feats = extract_features(
            vendor=sample.get("vendor"),
            open_ports=sample.get("open_ports", []),
            extra_info=sample.get("extra_info"),
        )
        X.append(feats)
        y_dt.append(sample["label"])
        y_os.append(sample["os_family"])
    return X, y_dt, y_os


def train(
    n_estimators: int = 200,
    max_depth: int = 10,
    run_cv: bool = False,
    verbose: bool = False,
) -> tuple[object, object]:
    """Train device_type and os_family classifiers and return them as a tuple.

    Parameters
    ----------
    n_estimators:
        Number of trees in the forest.  200 gives a good accuracy/size tradeoff
        with the expanded training set.
    max_depth:
        Maximum depth of each tree.
    run_cv:
        When ``True``, print 5-fold cross-validation accuracy to stdout.
    verbose:
        When ``True``, print the top-20 feature importances.

    Returns
    -------
    tuple[clf_device_type, clf_os_family]
        Both classifiers sharing the same feature vector.
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score

    X_syn, y_dt_syn, y_os_syn = _build_samples_from_synthetic()

    log.info(
        "training_start samples=%d features=%d device_type_classes=%s",
        len(y_dt_syn), FEATURE_COUNT,
        sorted(set(y_dt_syn)),
    )

    X_np = np.array(X_syn, dtype=np.float32)
    y_dt_np = np.array(y_dt_syn)
    y_os_np = np.array(y_os_syn)

    clf_dt = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf_dt.fit(X_np, y_dt_np)
    log.info("training_device_type_done classes=%s", list(clf_dt.classes_))

    clf_os = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf_os.fit(X_np, y_os_np)
    log.info("training_os_family_done classes=%s", list(clf_os.classes_))

    if run_cv:
        for label, clf, y_np in [
            ("device_type", clf_dt, y_dt_np),
            ("os_family",   clf_os, y_os_np),
        ]:
            from collections import Counter  # noqa: PLC0415
            counts = Counter(y_np)
            min_count = min(counts.values()) if counts else 0
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
                f"[{label}] CV accuracy: {scores.mean():.3f} ± {scores.std():.3f}  "
                f"[{', '.join(f'{s:.3f}' for s in scores)}]"
            )

    if verbose:
        from device_classifier import (  # noqa: PLC0415
            FEATURE_PORTS,
            HTTP_SERVER_KEYWORDS,
            MDNS_SERVICE_TYPES,
            VENDOR_KEYWORDS,
        )
        feature_names: list[str] = (
            [f"port_{p}" for p in FEATURE_PORTS]
            + [f"vendor_{k}" for k in VENDOR_KEYWORDS]
            + [f"mdns_{s}" for s in MDNS_SERVICE_TYPES]
            + [f"http_{k}" for k in HTTP_SERVER_KEYWORDS]
        )
        for label, clf in [("device_type", clf_dt), ("os_family", clf_os)]:
            importances = clf.feature_importances_
            top_n = sorted(enumerate(importances), key=lambda x: -x[1])[:20]
            print(f"\nTop-20 feature importances [{label}]:")
            for idx, imp in top_n:
                print(f"  {feature_names[idx]:<40s}  {imp:.4f}")

    return clf_dt, clf_os


def save(models: tuple[object, object], path: str = MODEL_PATH) -> None:
    """Serialise the ``(clf_device_type, clf_os_family)`` tuple to *path*."""
    import joblib  # noqa: PLC0415

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(models, path, compress=3)
    size_kb = os.path.getsize(path) / 1024
    log.info("model_saved path=%s size_kb=%.1f", path, size_kb)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Train the TheBox RF device-type and OS-family classifiers. "
            "Output: a (clf_device_type, clf_os_family) tuple saved with joblib."
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
        default=200,
        help="Number of RF trees (default: 200).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum tree depth (default: 10).",
    )
    parser.add_argument("--cv",      action="store_true", help="Run cross-validation.")
    parser.add_argument("--verbose", action="store_true", help="Print feature importances.")
    args = parser.parse_args()

    models = train(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        run_cv=args.cv,
        verbose=args.verbose,
    )
    save(models, path=args.output)


if __name__ == "__main__":
    main()
