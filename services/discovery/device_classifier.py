"""RandomForest device-type classifier for TheBox discovery service.

Provides fast, in-process device classification using a pre-trained
sklearn RandomForestClassifier (~100 KB on disk).  The model is trained
by ``train_classifier.py`` (run during Docker image build) and loaded once
at service startup.

Feature vector (142 dimensions total):
  - DHCP option-55 individual option-code flags     (30 flags)
  - Open port multi-hot vector                      (30 flags)
  - OUI vendor name keyword bag-of-words            (42 flags)
  - mDNS service-type presence/absence flags        (18 flags)
  - HTTP Server header keyword flags                (22 flags)

The classifier returns one of the canonical device-type labels:
  ``iot``, ``desktop``, ``server``, ``mobile``, ``printer``, ``network_device``

When the model is not found or confidence is below *RF_MIN_CONFIDENCE*
(default 0.50) the caller falls back to the existing rule-based
``guess_device_type()`` heuristic in ``app.py``.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

# Path to the serialised joblib model.  Can be overridden at runtime.
MODEL_PATH: str = os.environ.get(
    "RF_MODEL_PATH", "/app/models/device_classifier.pkl"
)

# Minimum predicted-class probability to accept the RF label instead of
# falling back to the heuristic.  Higher values = more conservative / fewer
# overrides of the heuristic.
RF_MIN_CONFIDENCE: float = float(os.environ.get("RF_MIN_CONFIDENCE", "0.50"))

# Master on/off switch — set RF_CLASSIFIER_ENABLED=false to disable entirely.
RF_CLASSIFIER_ENABLED: bool = (
    os.environ.get("RF_CLASSIFIER_ENABLED", "true").lower() == "true"
)

# ── Feature definitions ───────────────────────────────────────────────────────

# Individual DHCP option codes whose *presence* in the option-55 Parameter
# Request List is used as a binary feature.  These 30 codes cover the most
# discriminative options across Windows, macOS, iOS, Android, Linux and
# embedded/IoT firmware DHCP stacks.
DHCP_OPTIONS: list[int] = [
    1,   # Subnet Mask
    2,   # Time Offset
    3,   # Router
    4,   # Time Server
    6,   # DNS Server
    7,   # Log Server
    12,  # Hostname
    15,  # Domain Name
    17,  # Root Path
    23,  # Default IP TTL
    28,  # Broadcast Address
    31,  # Perform Router Discovery
    33,  # Static Route
    40,  # NIS Domain
    41,  # NIS Server
    42,  # NTP Server
    43,  # Vendor Specific
    44,  # NetBIOS Name Server
    46,  # NetBIOS Node Type
    47,  # NetBIOS Scope
    51,  # Lease Time
    54,  # Server Identifier
    58,  # Renewal Time
    59,  # Rebinding Time
    95,  # LDAP
    100, # Timezone (POSIX-TZ)
    101, # Timezone (TZ-Database)
    119, # Domain Search
    121, # Classless Static Route
    252, # Private / Proxy Autodiscovery
]

# Ports whose open/closed state is used as a binary feature.
FEATURE_PORTS: list[int] = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    139,   # NetBIOS Session
    143,   # IMAP
    161,   # SNMP
    443,   # HTTPS
    445,   # SMB/CIFS
    515,   # LPR / LPD
    554,   # RTSP (IP cameras)
    631,   # IPP (printing)
    993,   # IMAPS
    995,   # POP3S
    1883,  # MQTT (IoT)
    3306,  # MySQL
    3389,  # RDP
    5353,  # mDNS
    5432,  # PostgreSQL
    5900,  # VNC
    7547,  # TR-069 (CPE/ISP device management)
    8080,  # HTTP alt
    8443,  # HTTPS alt
    8883,  # MQTT TLS (IoT)
    9100,  # RAW print / JetDirect
    49152, # UPnP / dynamic
    5000,  # UPnP / custom IoT
]

# OUI vendor name keywords — case-insensitive substring match.
VENDOR_KEYWORDS: list[str] = [
    # Mobile / phones / tablets
    "apple", "samsung", "qualcomm", "mediatek", "xiaomi", "huawei",
    # IoT manufacturers
    "espressif", "shenzhen", "tuya", "amazon", "google", "philips",
    "belkin", "ring", "nest", "blink", "wemo", "lifx",
    # Network equipment
    "cisco", "ubiquiti", "netgear", "tp-link", "aruba",
    "juniper", "mikrotik", "zyxel", "fortinet", "meraki",
    # Printers
    "hewlett", "epson", "canon", "brother", "lexmark", "xerox",
    # Workstations / PCs
    "intel", "realtek", "broadcom", "dell", "lenovo",
    # NAS / storage
    "supermicro", "synology", "qnap",
]

# mDNS / DNS-SD service types — presence is used as a binary feature.
MDNS_SERVICE_TYPES: list[str] = [
    "_googlecast._tcp",
    "_cast._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_homekit._tcp",
    "_hap._tcp",
    "_ipp._tcp",
    "_ipps._tcp",
    "_printer._tcp",
    "_workstation._tcp",
    "_smb._tcp",
    "_afpovertcp._tcp",
    "_ssh._tcp",
    "_http._tcp",
    "_https._tcp",
    "_mqtt._tcp",
    "_matter._tcp",
    "_spotify-connect._tcp",
]

# HTTP Server header keyword flags — case-insensitive substring match.
HTTP_SERVER_KEYWORDS: list[str] = [
    # Traditional web servers
    "apache", "nginx", "iis", "lighttpd", "jetty", "tomcat",
    # Embedded / IoT HTTP stacks
    "mini_httpd", "boa", "thttpd", "uhttpd", "busybox", "micro_httpd",
    # Printers
    "jetdirect", "printer",
    # Network equipment
    "linksys", "zyxel", "dlink", "netgear", "ubiquiti", "hikvision",
    # Mobile / smart device platform indicators
    "gws", "android",
]

# Total feature vector length (used by train_classifier.py too).
FEATURE_COUNT: int = (
    len(DHCP_OPTIONS)
    + len(FEATURE_PORTS)
    + len(VENDOR_KEYWORDS)
    + len(MDNS_SERVICE_TYPES)
    + len(HTTP_SERVER_KEYWORDS)
)

# Canonical device-type labels (must match training labels in train_classifier.py).
DEVICE_TYPES: list[str] = [
    "iot",
    "desktop",
    "server",
    "mobile",
    "printer",
    "network_device",
]


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(
    vendor: str | None,
    open_ports: list[dict],
    extra_info: dict | None,
    dhcp_fingerprint: str | None = None,
) -> list[float]:
    """Return a fixed-length feature vector (list of 0.0 / 1.0 floats).

    Parameters
    ----------
    vendor:
        OUI vendor name string (e.g. ``"Espressif Inc."``).
    open_ports:
        List of port dicts with at least a ``"port"`` key
        (e.g. ``[{"port": 80, "state": "open", "service": "http"}]``).
    extra_info:
        The ``extra_info`` dict stored on the device record, which may
        contain ``mdns_services``, ``http_server``, etc.
    dhcp_fingerprint:
        Comma-separated DHCP option-55 Parameter Request List string
        (e.g. ``"1,3,6,15,119,252"``).  ``None`` when unknown.

    Returns
    -------
    list of float
        Binary feature vector of length :data:`FEATURE_COUNT`.
    """
    features: list[float] = []
    extra: dict = extra_info or {}
    vendor_l: str = (vendor or "").lower()
    ports: set[int] = {p["port"] for p in (open_ports or [])}

    # ── DHCP option-55 flags ──────────────────────────────────────────────────
    # Parse the fingerprint string into a set of integer option codes.
    fp_opts: set[int] = set()
    if dhcp_fingerprint:
        try:
            fp_opts = {int(c.strip()) for c in dhcp_fingerprint.split(",") if c.strip()}
        except (ValueError, AttributeError):
            pass
    for opt in DHCP_OPTIONS:
        features.append(1.0 if opt in fp_opts else 0.0)

    # ── Open-port multi-hot ───────────────────────────────────────────────────
    for port in FEATURE_PORTS:
        features.append(1.0 if port in ports else 0.0)

    # ── Vendor keyword bag-of-words ───────────────────────────────────────────
    for kw in VENDOR_KEYWORDS:
        features.append(1.0 if kw in vendor_l else 0.0)

    # ── mDNS service-type flags ───────────────────────────────────────────────
    mdns_types: set[str] = set()
    for svc in extra.get("mdns_services", []):
        stype = (svc.get("service_type") or "").lower()
        if stype:
            mdns_types.add(stype)
    for stype in MDNS_SERVICE_TYPES:
        features.append(1.0 if stype in mdns_types else 0.0)

    # ── HTTP Server keyword flags ─────────────────────────────────────────────
    http_server_l: str = (extra.get("http_server") or "").lower()
    for kw in HTTP_SERVER_KEYWORDS:
        features.append(1.0 if kw in http_server_l else 0.0)

    return features


# ── Model I/O ─────────────────────────────────────────────────────────────────

# Module-level loaded classifier instance (None = not yet loaded / unavailable).
_clf = None


def load_classifier() -> bool:
    """Load the pre-trained RF model from *MODEL_PATH*.

    Returns ``True`` on success, ``False`` when the model file is missing or
    cannot be loaded (e.g. incompatible sklearn version).  A warning is logged
    in the failure case so the operator knows to rebuild the image.
    """
    global _clf  # noqa: PLW0603

    if not RF_CLASSIFIER_ENABLED:
        log.info("rf_classifier_disabled")
        return False

    try:
        import joblib  # noqa: PLC0415 (import inside function for graceful missing-dep)
        _clf = joblib.load(MODEL_PATH)
        n_classes = len(_clf.classes_) if hasattr(_clf, "classes_") else None
        n_trees = _clf.n_estimators if hasattr(_clf, "n_estimators") else None
        log.info(
            "rf_classifier_loaded",
            path=MODEL_PATH,
            classes=n_classes,
            estimators=n_trees,
            feature_count=FEATURE_COUNT,
        )
        return True
    except FileNotFoundError:
        log.warning("rf_model_not_found", path=MODEL_PATH)
    except Exception as exc:
        log.warning("rf_classifier_load_error", path=MODEL_PATH, error=str(exc))
    return False


def classify_device(
    vendor: str | None,
    open_ports: list[dict],
    extra_info: dict | None,
    dhcp_fingerprint: str | None = None,
    min_confidence: float | None = None,
) -> tuple[str, float]:
    """Classify a device using the loaded RF model.

    Parameters
    ----------
    vendor, open_ports, extra_info, dhcp_fingerprint:
        Same semantics as :func:`extract_features`.
    min_confidence:
        Override the module-level *RF_MIN_CONFIDENCE* threshold for this call.
        Defaults to the module-level constant when ``None``.

    Returns
    -------
    tuple[str, float]
        ``(device_type, confidence)`` where *device_type* is one of the
        canonical labels defined in :data:`DEVICE_TYPES` and *confidence* is
        the highest predicted class probability in [0, 1].

        Returns ``("unknown", 0.0)`` when:

        * the model is not loaded (file missing or disabled);
        * feature extraction raises an unexpected exception;
        * the highest class probability is below *min_confidence*.
    """
    if _clf is None:
        return "unknown", 0.0

    threshold = RF_MIN_CONFIDENCE if min_confidence is None else min_confidence

    try:
        import numpy as np  # noqa: PLC0415

        features = extract_features(vendor, open_ports, extra_info, dhcp_fingerprint)
        X = np.array([features], dtype=np.float32)
        proba = _clf.predict_proba(X)[0]
        max_idx = int(np.argmax(proba))
        confidence = float(proba[max_idx])

        if confidence < threshold:
            return "unknown", confidence

        label = str(_clf.classes_[max_idx])
        log.debug(
            "rf_classify",
            label=label,
            confidence=round(confidence, 3),
            vendor=vendor,
        )
        return label, confidence

    except Exception as exc:
        log.debug("rf_classify_error", error=str(exc))
        return "unknown", 0.0
