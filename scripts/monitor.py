#!/usr/bin/env python3
"""
SSL & Domain Expiration Monitor for Sysadmins
Scans domains from data/domains.json, writes results to data/results.json,
and sends HTML email notifications via Corporate Groupware SMTP / Gmail SMTP.
Supports direct lookup from VNNIC (https://vnnic.vn/whois-information/) with automatic CAPTCHA OCR.
"""

import argparse
import concurrent.futures
import datetime
import html as pyhtml
import io
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional third-party imports with graceful fallback
try:
    import requests as pyrequests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import whois as pywhois
    HAS_PYWHOIS = True
except ImportError:
    HAS_PYWHOIS = False

try:
    from PIL import Image, ImageOps
    if not hasattr(Image, "ANTIALIAS"):
        Image.ANTIALIAS = Image.LANCZOS  # Compatibility shim for ddddocr on Pillow 10+
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import ddddocr
    HAS_DDDDOCR = True
except ImportError:
    HAS_DDDDOCR = False

try:
    import pytesseract
    HAS_TESSERACT = True
except ImportError:
    HAS_TESSERACT = False


BASE_DIR = Path(__file__).resolve().parent.parent
DOMAINS_FILE = BASE_DIR / "data" / "domains.json"
RESULTS_FILE = BASE_DIR / "data" / "results.json"

DEFAULT_BKNS_DEMO_KEY = "bkns_dmo_2376da23bd44858c8390aeeb93065404d21ede1ba2c5d59c0cffc33d6e83c2dd"
_BKNS_LOCK = threading.Lock()
_OCR_LOCK = threading.Lock()
_DDDDOCR_INSTANCE: Any = None

MULTI_PART_TLDS = {
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "int.vn", "ac.vn",
    "biz.vn", "info.vn", "name.vn", "pro.vn", "health.vn", "io.vn", "ai.vn",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "com.sg", "edu.sg", "gov.sg", "com.my",
    "co.kr", "or.kr", "com.tw", "org.tw", "com.hk", "co.id", "or.id",
    "co.th", "in.th", "com.ph", "co.nz", "com.br", "co.in", "net.in",
}


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def clean_hostname(raw: str) -> str:
    """Strip scheme, path, and port from a domain/URL string."""
    h = raw.strip().lower()
    h = re.sub(r"^https?://", "", h)
    h = h.split("/")[0].split("?")[0].split("#")[0]
    if ":" in h:
        h = h.split(":")[0]
    return h.strip(".")


def extract_root_domain(hostname: str) -> str:
    """Extract registrable root domain (e.g., mail.corp.example.com.vn -> example.com.vn)."""
    host = clean_hostname(hostname)
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_any_date(val: Any) -> Optional[datetime.datetime]:
    """Parse datetime from various formats (datetime object, list, timestamp, ISO string, VN WHOIS strings)."""
    if val is None:
        return None
    if isinstance(val, list):
        for item in val:
            parsed = parse_any_date(item)
            if parsed:
                return parsed
        return None
    if isinstance(val, (int, float)):
        try:
            ts = float(val)
            if ts > 1e11:  # milliseconds
                ts = ts / 1000.0
            if ts > 0:
                return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        except Exception:
            return None
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=datetime.timezone.utc)
        return val.astimezone(datetime.timezone.utc)
    if isinstance(val, datetime.date):
        return datetime.datetime(val.year, val.month, val.day, tzinfo=datetime.timezone.utc)
    if isinstance(val, str):
        s = pyhtml.unescape(val).replace("\xa0", " ").strip()
        if not s:
            return None
        if s.isdigit() and len(s) >= 10:
            return parse_any_date(int(s))
        s_clean = re.sub(r"\s+\([A-Z]+\)$", "", s)
        if s_clean.endswith("Z"):
            s_clean = s_clean[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)
        except ValueError:
            pass

        formats = [
            "%d-%m-%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%d-%m-%Y",
            "%d/%m/%Y",
            "%Y-%m-%d",
            "%Y/%m/%d",
            "%d-%b-%Y",
            "%d.%m.%Y",
            "%Y.%m.%d",
            "%b %d %H:%M:%S %Y %Z",
            "%Y%m%d%H%M%SZ",
            "%d-%b-%Y %H:%M:%S UTC",
        ]
        for fmt in formats:
            try:
                dt = datetime.datetime.strptime(s[:25].strip(), fmt)
                return dt.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                continue

        m_dmy = re.search(r"\b(\d{1,2})[-/.](\d{1,2})[-/.](20\d{2}|19\d{2})\b", s)
        if m_dmy:
            try:
                d, m, y = int(m_dmy.group(1)), int(m_dmy.group(2)), int(m_dmy.group(3))
                return datetime.datetime(y, m, d, tzinfo=datetime.timezone.utc)
            except ValueError:
                pass
        m_ymd = re.search(r"\b(20\d{2}|19\d{2})[-/.](\d{1,2})[-/.](\d{1,2})\b", s)
        if m_ymd:
            try:
                y, m, d = int(m_ymd.group(1)), int(m_ymd.group(2)), int(m_ymd.group(3))
                return datetime.datetime(y, m, d, tzinfo=datetime.timezone.utc)
            except ValueError:
                pass
    return None


def normalize_registrar_name(registrar: Optional[str], nameservers: Optional[List[str]] = None) -> Optional[str]:
    """Normalize Vietnamese & International registrar names (especially Mắt Bão & Tenten)."""
    reg = (registrar or "").strip()
    ns_str = " ".join(nameservers or []).lower()

    reg_lower = reg.lower()
    if "mắt bão" in reg_lower or "mat bao" in reg_lower or "matbao" in reg_lower:
        return f"Mắt Bão ({reg})" if "mắt bão" not in reg_lower else reg
    if "gmo-z.com" in reg_lower or "runsystem" in reg_lower or "tenten" in reg_lower:
        return "Tenten.vn (GMO-Z.com RUNSYSTEM)"
    if "p.a việt nam" in reg_lower or "p.a viet nam" in reg_lower or "pavietnam" in reg_lower:
        return "P.A Việt Nam"
    if "nhân hòa" in reg_lower or "nhan hoa" in reg_lower or "nhanhoa" in reg_lower:
        return "Nhân Hòa"

    if not reg:
        if "matbao" in ns_str:
            return "Mắt Bão (Theo Nameserver)"
        if "tenten" in ns_str or "z.com" in ns_str:
            return "Tenten.vn (Theo Nameserver)"
        if "pavietnam" in ns_str:
            return "P.A Việt Nam (Theo Nameserver)"
        if "nhanhoa" in ns_str:
            return "Nhân Hòa (Theo Nameserver)"
    return reg or None


def http_get_text(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 8) -> Optional[str]:
    """Fetch URL text using requests (if available) or urllib."""
    hdrs = headers or {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
    }
    if HAS_REQUESTS:
        try:
            r = pyrequests.get(url, headers=hdrs, timeout=timeout)
            if r.status_code == 200 and r.text:
                return r.text
        except Exception:
            pass
    try:
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def query_doh_nameservers(root_domain: str, timeout: int = 6) -> List[str]:
    """Fetch NS records for root_domain via Cloudflare DNS-over-HTTPS."""
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(root_domain)}&type=NS"
        txt = http_get_text(url, headers={"Accept": "application/dns-json"}, timeout=timeout)
        if txt:
            data = json.loads(txt)
            ns_list = [
                str(ans.get("data", "")).lower().rstrip(".")
                for ans in (data.get("Answer") or [])
                if ans.get("type") == 2 and ans.get("data")
            ]
            return list(dict.fromkeys(ns_list))[:6]
    except Exception:
        pass
    return []


def classify_status(days_left: Optional[int], warn_days: int, crit_days: int, has_error: bool = False) -> str:
    if has_error or days_left is None:
        return "error"
    if days_left < 0:
        return "expired"
    if days_left <= crit_days:
        return "critical"
    if days_left <= warn_days:
        return "warning"
    return "ok"


def check_ssl_certificate(
    hostname: str,
    port: int = 443,
    warn_days: int = 30,
    crit_days: int = 7,
    timeout: int = 10,
) -> Dict[str, Any]:
    """Connects to hostname:port via TLS and extracts certificate metadata."""
    result: Dict[str, Any] = {
        "ssl_checked": True,
        "ssl_status": "error",
        "ssl_days_left": None,
        "ssl_valid_from": None,
        "ssl_valid_to": None,
        "ssl_issuer": None,
        "ssl_subject": None,
        "ssl_sans": [],
        "ssl_serial": None,
        "ssl_protocol": None,
        "ssl_cipher": None,
        "ssl_ip": None,
        "ssl_trusted": False,
        "ssl_trust_warning": None,
        "ssl_latency_ms": None,
        "ssl_error": None,
    }

    start_time = time.perf_counter()
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if addr_info:
            result["ssl_ip"] = addr_info[0][4][0]
    except Exception as exc:
        result["ssl_error"] = f"DNS Resolution failed: {exc}"
        return result

    der_cert: Optional[bytes] = None
    peer_cert_dict: Optional[Dict[str, Any]] = None

    verified_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with verified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["ssl_latency_ms"] = round((time.perf_counter() - start_time) * 1000)
                result["ssl_trusted"] = True
                result["ssl_protocol"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["ssl_cipher"] = cipher_info[0]
                peer_cert_dict = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as verify_err:
        result["ssl_trusted"] = False
        result["ssl_trust_warning"] = str(verify_err.verify_message or verify_err)
    except Exception as conn_err:
        result["ssl_error"] = f"TLS Connection failed: {conn_err}"
        return result

    if der_cert is None:
        unverified_ctx = ssl.create_default_context()
        unverified_ctx.check_hostname = False
        unverified_ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["ssl_latency_ms"] = round((time.perf_counter() - start_time) * 1000)
                    result["ssl_protocol"] = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result["ssl_cipher"] = cipher_info[0]
                    der_cert = ssock.getpeercert(binary_form=True)
        except Exception as conn_err:
            result["ssl_error"] = f"TLS Handshake failed: {conn_err}"
            return result

    valid_from: Optional[datetime.datetime] = None
    valid_to: Optional[datetime.datetime] = None

    if der_cert and HAS_CRYPTOGRAPHY:
        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            valid_from = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            valid_to = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

            issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer_parts = []
            if issuer_org:
                issuer_parts.append(str(issuer_org[0].value))
            if issuer_cn:
                cn_val = str(issuer_cn[0].value)
                if cn_val not in issuer_parts:
                    issuer_parts.append(cn_val)
            result["ssl_issuer"] = " - ".join(issuer_parts) if issuer_parts else cert.issuer.rfc4514_string()

            subj_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            result["ssl_subject"] = str(subj_cn[0].value) if subj_cn else cert.subject.rfc4514_string()
            result["ssl_serial"] = format(cert.serial_number, "X")

            try:
                ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = ext.value.get_values_for_type(x509.DNSName)
                result["ssl_sans"] = list(sans)[:15]
            except x509.ExtensionNotFound:
                result["ssl_sans"] = []
        except Exception as parse_err:
            result["ssl_error"] = f"Cert parse error: {parse_err}"

    if valid_to is None and peer_cert_dict:
        valid_from = parse_any_date(peer_cert_dict.get("notBefore"))
        valid_to = parse_any_date(peer_cert_dict.get("notAfter"))
        issuer_tuples = peer_cert_dict.get("issuer", ())
        issuer_map = {k: v for t in issuer_tuples for k, v in t}
        result["ssl_issuer"] = issuer_map.get("organizationName") or issuer_map.get("commonName") or "Unknown Issuer"
        subj_tuples = peer_cert_dict.get("subject", ())
        subj_map = {k: v for t in subj_tuples for k, v in t}
        result["ssl_subject"] = subj_map.get("commonName") or hostname
        result["ssl_serial"] = peer_cert_dict.get("serialNumber")
        san_list = peer_cert_dict.get("subjectAltName", ())
        result["ssl_sans"] = [v for k, v in san_list if k == "DNS"][:15]

    if valid_to is not None:
        now = now_utc()
        delta = valid_to - now
        days_left = int(delta.total_seconds() // 86400)
        result["ssl_days_left"] = days_left
        result["ssl_valid_from"] = valid_from.strftime("%Y-%m-%d %H:%M UTC") if valid_from else None
        result["ssl_valid_to"] = valid_to.strftime("%Y-%m-%d %H:%M UTC")
        result["ssl_status"] = classify_status(days_left, warn_days, crit_days, has_error=False)
        if not result["ssl_trusted"] and result["ssl_status"] == "ok":
            result["ssl_status"] = "warning"
    else:
        result["ssl_status"] = "error"
        if not result["ssl_error"]:
            result["ssl_error"] = result["ssl_trust_warning"] or "Unable to parse SSL expiration date"

    return result


def query_rdap_domain(root_domain: str, timeout: int = 8) -> Optional[Dict[str, Any]]:
    """Query RDAP (IANA/rdap.org or VNNIC RDAP) for structured domain registration data."""
    urls = [f"https://rdap.org/domain/{root_domain}"]
    if root_domain.endswith(".vn"):
        urls.insert(0, f"https://rdap.vnnic.vn/domain/{root_domain}")

    for url in urls:
        try:
            txt = http_get_text(
                url,
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": "SysadminSSLMonitor/1.0 (+https://duongnvd.github.io)",
                },
                timeout=timeout,
            )
            if not txt:
                continue
            data = json.loads(txt)
            events = data.get("events", [])
            exp_date = None
            reg_date = None
            for ev in events:
                action = (ev.get("eventAction") or "").lower()
                ev_date = parse_any_date(ev.get("eventDate"))
                if "expir" in action and ev_date:
                    exp_date = ev_date
                elif "registr" in action and ev_date:
                    reg_date = ev_date

            registrar = None
            for ent in data.get("entities", []):
                roles = [r.lower() for r in ent.get("roles", [])]
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org"):
                                registrar = str(item[3])
                                break
                    if not registrar and ent.get("handle"):
                        registrar = str(ent.get("handle"))

            nameservers = []
            for ns in data.get("nameservers", []):
                ldh = ns.get("ldhName")
                if ldh:
                    nameservers.append(ldh.lower())

            if exp_date:
                return {
                    "expiry_date": exp_date,
                    "creation_date": reg_date,
                    "registrar": registrar,
                    "nameservers": nameservers[:6],
                    "source": "RDAP",
                }
        except Exception:
            continue
    return None


def query_raw_whois_socket(root_domain: str, timeout: int = 8) -> Optional[Dict[str, Any]]:
    """Fallback raw socket port 43 WHOIS lookup."""
    try:
        tld = root_domain.split(".")[-1]
        whois_server = "whois.vnnic.vn" if root_domain.endswith(".vn") else None
        if not whois_server:
            with socket.create_connection(("whois.iana.org", 43), timeout=timeout) as s:
                s.sendall(f"{tld}\r\n".encode("utf-8"))
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            text_iana = resp.decode("utf-8", errors="replace")
            m_srv = re.search(r"^whois:\s*(\S+)", text_iana, re.IGNORECASE | re.MULTILINE)
            if m_srv:
                whois_server = m_srv.group(1).strip()

        if not whois_server:
            return None

        with socket.create_connection((whois_server, 43), timeout=timeout) as s:
            s.sendall(f"{root_domain}\r\n".encode("utf-8"))
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        raw_text = resp.decode("utf-8", errors="replace")

        exp_patterns = [
            r"Registry Expiry Date:\s*(.+)",
            r"Registrar Registration Expiration Date:\s*(.+)",
            r"Expiration Date:\s*(.+)",
            r"Expiry Date:\s*(.+)",
            r"Expire Date:\s*(.+)",
            r"Ngày hết hạn:\s*(.+)",
            r"paid-till:\s*(.+)",
            r"Valid Until:\s*(.+)",
            r"Expiration Time:\s*(.+)",
        ]
        exp_date = None
        for pat in exp_patterns:
            m = re.search(pat, raw_text, re.IGNORECASE)
            if m:
                exp_date = parse_any_date(m.group(1).strip())
                if exp_date:
                    break

        reg_patterns = [
            r"Creation Date:\s*(.+)",
            r"Created On:\s*(.+)",
            r"Registered On:\s*(.+)",
            r"Issue Date:\s*(.+)",
            r"Ngày đăng ký:\s*(.+)",
            r"Registration Time:\s*(.+)",
        ]
        reg_date = None
        for pat in reg_patterns:
            m = re.search(pat, raw_text, re.IGNORECASE)
            if m:
                reg_date = parse_any_date(m.group(1).strip())
                if reg_date:
                    break

        registrar = None
        m_reg = re.search(r"(?:Registrar|Nhà đăng ký):\s*(.+)", raw_text, re.IGNORECASE)
        if m_reg:
            registrar = m_reg.group(1).strip()

        nameservers = re.findall(r"Name Server:\s*(\S+)", raw_text, re.IGNORECASE)
        nameservers = list(dict.fromkeys([ns.lower().rstrip(".") for ns in nameservers]))[:6]

        if exp_date:
            return {
                "expiry_date": exp_date,
                "creation_date": reg_date,
                "registrar": registrar,
                "nameservers": nameservers,
                "source": f"WHOIS ({whois_server})",
            }
    except Exception:
        pass
    return None


def parse_vn_whois_payload(raw_payload: str) -> Optional[Dict[str, Any]]:
    """
    Parse JSON or HTML/text from VNNIC (https://vnnic.vn/whois-information/),
    Mắt Bão (whois.net.vn), BKNS, iNET, or P.A Việt Nam.
    """
    if not raw_payload or not raw_payload.strip():
        return None

    # 1. Try JSON format first
    try:
        data = json.loads(raw_payload)
        if isinstance(data, dict) and isinstance(data.get("contents"), str):
            data = json.loads(data["contents"])
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data["data"]
        if isinstance(data, dict) and isinstance(data.get("whois_data"), dict):
            data = {**data, **data["whois_data"]}
        if isinstance(data, dict):
            reg_obj = data.get("registration") if isinstance(data.get("registration"), dict) else {}
            exp_raw = (
                data.get("expiryDate")
                or data.get("expirationDate")
                or data.get("expireDate")
                or data.get("expiration_date")
                or data.get("expiry_date")
                or data.get("registryExpiryDate")
                or data.get("expiredDate")
                or data.get("expiresAt")
                or data.get("expires_at")
                or data.get("ngày_hết_hạn")
                or data.get("ngay_het_han")
                or reg_obj.get("expires_at")
            )
            reg_raw = (
                data.get("creationDate")
                or data.get("createDate")
                or data.get("creation_date")
                or data.get("createdDate")
                or data.get("issueDate")
                or data.get("registeredAt")
                or data.get("registeredDate")
                or data.get("ngày_đăng_ký")
                or data.get("ngay_dang_ky")
                or reg_obj.get("created_at")
            )
            exp_date = parse_any_date(exp_raw)
            reg_date = parse_any_date(reg_raw)
            registrar = (
                (data.get("registrar", {}).get("name") if isinstance(data.get("registrar"), dict) else data.get("registrar"))
                or data.get("registrarName")
                or data.get("nhà_đăng_ký_quản_lý")
                or reg_obj.get("registrar")
            )
            registrant = (
                data.get("registrant")
                or data.get("registrantName")
                or data.get("owner")
                or data.get("subcriber")
                or data.get("tên_chủ_thể_đăng_ký_sử_dụng")
            )

            raw_ns = (
                data.get("nameServers")
                or data.get("nameServer")
                or data.get("nameservers")
                or data.get("name_servers")
                or data.get("DNS")
                or []
            )
            if isinstance(raw_ns, str):
                raw_ns = [x.strip() for x in re.split(r"[,;\s]+", raw_ns) if x.strip()]
            nameservers = [str(ns).lower().rstrip(".") for ns in raw_ns if ns][:6]

            raw_text = str(data.get("rawtext") or data.get("rawText") or data.get("raw") or "")
            if not exp_date and raw_text:
                m = re.search(
                    r"(?:Expiration Date|Expiry Date|Expired Date|Ngày hết hạn|paid-till)[\s:\-]*(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4})",
                    raw_text,
                    re.IGNORECASE,
                )
                if m:
                    exp_date = parse_any_date(m.group(1).strip())
            if not reg_date and raw_text:
                m = re.search(
                    r"(?:Creation Date|Created On|Issue Date|Ngày đăng ký|Ngày cấp)[\s:\-]*(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4})",
                    raw_text,
                    re.IGNORECASE,
                )
                if m:
                    reg_date = parse_any_date(m.group(1).strip())
            if not registrar and raw_text:
                m = re.search(
                    r"(?:Registrar|Nhà đăng ký quản lý|Nhà đăng ký)[\s:\-]*([^\r\n]+)",
                    raw_text,
                    re.IGNORECASE,
                )
                if m:
                    registrar = m.group(1).strip()

            if exp_date:
                return {
                    "expiry_date": exp_date,
                    "creation_date": reg_date,
                    "registrar": normalize_registrar_name(str(registrar) if registrar else None, nameservers),
                    "registrant": str(registrant).strip() if registrant else None,
                    "nameservers": nameservers,
                    "source": "VNNIC / VN-WHOIS",
                }
    except Exception:
        pass

    # 2. Parse HTML / Table / Plain text (such as https://vnnic.vn/whois-information/ or whois.net.vn)
    cleaned_html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw_payload, flags=re.IGNORECASE | re.DOTALL)
    unescaped = pyhtml.unescape(cleaned_html).replace("\xa0", " ").replace("&nbsp;", " ")
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in re.sub(r"<[^>]+>", "\n", unescaped).splitlines()]
    clean_txt = "\n".join(ln for ln in lines if ln)

    exp_date = None
    m_exp = re.search(
        r"(?:Ngày hết hạn|Expiration Date|Expiry Date|Expired Date|paid-till)[\s:\-]*(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4})",
        clean_txt,
        re.IGNORECASE,
    )
    if m_exp:
        exp_date = parse_any_date(m_exp.group(1).strip())
    if not exp_date:
        return None

    reg_date = None
    m_reg_dt = re.search(
        r"(?:Ngày đăng ký|Ngày cấp|Creation Date|Created On|Issue Date)[\s:\-]*(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4})",
        clean_txt,
        re.IGNORECASE,
    )
    if m_reg_dt:
        reg_date = parse_any_date(m_reg_dt.group(1).strip())

    registrar = None
    m_registrar = re.search(
        r"(?:Nhà đăng ký quản lý|Nhà đăng ký|Registrar Name|Registrar)[\s:\-]*([^\r\n]+)",
        clean_txt,
        re.IGNORECASE,
    )
    if m_registrar:
        registrar = m_registrar.group(1).strip()

    registrant = None
    m_registrant = re.search(
        r"(?:Tên chủ thể đăng ký sử dụng|Chủ thể đăng ký|Chủ sở hữu|Registrant Organization|Registrant Name|Registrant)[\s:\-]*([^\r\n]+)",
        clean_txt,
        re.IGNORECASE,
    )
    if m_registrant:
        registrant = m_registrant.group(1).strip()

    nameservers: List[str] = []
    m_dns = re.search(
        r"(?:Máy chủ DNS chuyển giao|Name Server|Nameservers|DNS)[\s:\-]*(.+?)(?:DNSSEC|Trạng thái|Status|Từ khóa tìm kiếm|$)",
        clean_txt,
        re.IGNORECASE | re.DOTALL,
    )
    if m_dns:
        ns_candidates = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", m_dns.group(1).lower())
        nameservers = list(dict.fromkeys([ns.rstrip(".") for ns in ns_candidates]))[:6]

    return {
        "expiry_date": exp_date,
        "creation_date": reg_date,
        "registrar": normalize_registrar_name(registrar, nameservers),
        "registrant": registrant,
        "nameservers": nameservers,
        "source": "VNNIC (vnnic.vn/whois-information)",
    }


class _VnnicFormParser(HTMLParser):
    """Extracts Drupal WHOIS search form, hidden tokens, and CAPTCHA image URL from vnnic.vn/whois-information."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "post").lower(),
                "id": attr_dict.get("id", ""),
                "inputs": [],
                "images": [],
            }
            self.forms.append(self._current_form)
        elif self._current_form is not None:
            if t in ("input", "button"):
                self._current_form["inputs"].append(attr_dict)
            elif t == "img" and attr_dict.get("src"):
                self._current_form["images"].append(attr_dict["src"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


def solve_vnnic_captcha(img_bytes: bytes, prefer_tesseract: bool = False) -> str:
    """
    Solves the 3-character simple image CAPTCHA on https://vnnic.vn/whois-information/
    using ddddocr and/or pytesseract.
    """
    global _DDDDOCR_INSTANCE
    if not img_bytes:
        return ""

    # 1. Try ddddocr (deep learning OCR specialized for simple CAPTCHAs)
    if HAS_DDDDOCR and not prefer_tesseract:
        with _OCR_LOCK:
            try:
                if _DDDDOCR_INSTANCE is None:
                    _DDDDOCR_INSTANCE = ddddocr.DdddOcr(show_ad=False)
                raw_code = _DDDDOCR_INSTANCE.classification(img_bytes)
                code = re.sub(r"[^A-Za-z0-9]", "", str(raw_code or ""))
                if 2 <= len(code) <= 6:
                    return code
            except Exception:
                pass

    # 2. Try pytesseract with Pillow preprocessing (3x upscale + binary threshold)
    if HAS_PIL and HAS_TESSERACT:
        try:
            img = Image.open(io.BytesIO(img_bytes)).convert("L")
            img = ImageOps.expand(img, border=16, fill=255)
            w, h = img.size
            img = img.resize((w * 3, h * 3), Image.LANCZOS)
            img = ImageOps.autocontrast(img)
            bw = img.point(lambda p: 0 if p < 155 else 255, "1")
            for psm in ("8", "7"):
                cfg = f"--psm {psm} -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                txt = pytesseract.image_to_string(bw, config=cfg)
                code = re.sub(r"[^A-Za-z0-9]", "", txt or "")
                if 2 <= len(code) <= 6:
                    return code
        except Exception:
            pass

    return ""


def query_vnnic_portal_whois(root_domain: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    Directly queries https://vnnic.vn/whois-information/ (Trung tâm Internet Việt Nam - VNNIC),
    automatically solving its 3-character image CAPTCHA and parsing the official Vietnamese WHOIS table.
    """
    if not HAS_REQUESTS:
        return None

    portal_urls = [
        "https://vnnic.vn/whois-information",
        "https://vnnic.vn/vi/whois-information",
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
    }

    session = pyrequests.Session()
    session.headers.update(headers)

    for base_url in portal_urls:
        try:
            resp = session.get(base_url, timeout=timeout)
            if resp.status_code != 200 or not resp.text:
                continue

            current_html = resp.text
            current_url = resp.url or base_url

            # Check if result is already present without CAPTCHA
            direct_parsed = parse_vn_whois_payload(current_html)
            if direct_parsed and direct_parsed.get("expiry_date"):
                return direct_parsed

            # Attempt up to 5 times to solve the 3-character CAPTCHA and submit the form
            for attempt in range(5):
                parser = _VnnicFormParser()
                parser.feed(current_html)

                target_form = None
                for frm in parser.forms:
                    has_captcha = any("captcha" in (inp.get("name") or "").lower() for inp in frm["inputs"]) or any(
                        "captcha" in src.lower() for src in frm["images"]
                    )
                    if has_captcha or "whois" in frm.get("id", "").lower() or "whois" in frm.get("action", "").lower():
                        target_form = frm
                        break

                if not target_form:
                    break

                form_data: Dict[str, str] = {}
                domain_field_name: Optional[str] = None
                captcha_field_name: str = "captcha_response"
                submit_added = False

                for inp in target_form["inputs"]:
                    itype = (inp.get("type") or "text").lower()
                    iname = inp.get("name") or ""
                    ival = inp.get("value") or ""
                    if not iname:
                        continue
                    if itype == "hidden":
                        form_data[iname] = ival
                    elif itype == "submit":
                        if not submit_added:
                            form_data[iname] = ival or "Tìm kiếm"
                            submit_added = True
                    elif itype in ("text", "search", ""):
                        if "captcha" in iname.lower():
                            captcha_field_name = iname
                        elif domain_field_name is None:
                            domain_field_name = iname

                if not domain_field_name:
                    domain_field_name = "key"

                form_data[domain_field_name] = root_domain

                captcha_img_src = None
                for src in target_form["images"]:
                    if "captcha" in src.lower():
                        captcha_img_src = src
                        break
                if not captcha_img_src and target_form["images"]:
                    captcha_img_src = target_form["images"][0]

                if captcha_img_src:
                    captcha_url = urllib.parse.urljoin(current_url, captcha_img_src)
                    img_resp = session.get(captcha_url, headers={"Referer": current_url}, timeout=timeout)
                    if img_resp.status_code == 200 and img_resp.content:
                        code = solve_vnnic_captcha(img_resp.content, prefer_tesseract=(attempt % 2 == 1))
                        if not code:
                            continue
                        form_data[captcha_field_name] = code

                action_url = urllib.parse.urljoin(current_url, target_form["action"] or current_url)
                if target_form["method"] == "get":
                    post_resp = session.get(action_url, params=form_data, headers={"Referer": current_url}, timeout=timeout)
                else:
                    post_resp = session.post(action_url, data=form_data, headers={"Referer": current_url}, timeout=timeout)

                if post_resp.status_code != 200 or not post_resp.text:
                    break

                parsed = parse_vn_whois_payload(post_resp.text)
                if parsed and parsed.get("expiry_date"):
                    parsed["source"] = "VNNIC (vnnic.vn/whois-information)"
                    return parsed

                # Use the reloaded form & fresh CAPTCHA from post_resp.text for the next retry
                current_html = post_resp.text
                current_url = post_resp.url or action_url
        except Exception:
            continue

    return None


def query_bkns_vn_whois(root_domain: str, timeout: int = 8) -> Optional[Dict[str, Any]]:
    """
    Query BKNS Official VNNIC REST API (/api/v1/whois).
    Handles the demo key rate limit (2 req/min) gracefully with a thread lock and retry.
    """
    api_key = os.environ.get("BKNS_API_KEY", "").strip() or DEFAULT_BKNS_DEMO_KEY
    url = f"https://whois.bkns.vn/api/v1/whois?domain={urllib.parse.quote(root_domain)}"
    headers = {
        "X-API-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "SysadminSSLMonitor/1.0",
    }

    with _BKNS_LOCK:
        for attempt in range(2):
            if HAS_REQUESTS:
                try:
                    resp = pyrequests.get(url, headers=headers, timeout=timeout)
                    if resp.status_code == 200 and resp.text:
                        parsed = parse_vn_whois_payload(resp.text)
                        if parsed and parsed.get("expiry_date"):
                            parsed["source"] = "VNNIC (BKNS API)"
                            return parsed
                    elif resp.status_code == 429 and attempt == 0:
                        retry_after = int(resp.headers.get("Retry-After", "31") or "31")
                        wait_s = min(max(retry_after, 15), 35)
                        print(f"    [VNNIC Rate-Limit] Đợi {wait_s}s để lấy tiếp hạn tên miền {root_domain}...")
                        time.sleep(wait_s)
                        continue
                except Exception:
                    pass
            else:
                txt = http_get_text(url, headers=headers, timeout=timeout)
                if txt:
                    parsed = parse_vn_whois_payload(txt)
                    if parsed and parsed.get("expiry_date"):
                        parsed["source"] = "VNNIC (BKNS API)"
                        return parsed
            break
    return None


def query_vn_registrar_whois(root_domain: str, timeout: int = 8) -> Optional[Dict[str, Any]]:
    """
    Query VNNIC (https://vnnic.vn/whois-information/) first, followed by Mắt Bão (whois.net.vn),
    BKNS VNNIC API, iNET, and P.A Việt Nam.
    """
    # 1. Try Official VNNIC Portal (https://vnnic.vn/whois-information/) with automatic CAPTCHA OCR
    vnnic_res = query_vnnic_portal_whois(root_domain, timeout=timeout)
    if vnnic_res and vnnic_res.get("expiry_date"):
        return vnnic_res

    # 2. Try Mắt Bão (whois.net.vn), iNET, and PA Vietnam gateways
    matbao_url = f"http://www.whois.net.vn/whois.php?domain={urllib.parse.quote(root_domain)}&act=getwhois"
    inet_url = f"https://whois.inet.vn/api/whois/domainspecify/{urllib.parse.quote(root_domain)}"
    pa_url = f"https://whois.pavietnam.vn/whois.php?domain={urllib.parse.quote(root_domain)}&cmd=get_whois"

    candidate_urls = [
        matbao_url,
        f"https://api.allorigins.win/raw?url={urllib.parse.quote(matbao_url, safe='')}",
        f"https://api.codetabs.com/v1/proxy?quest={matbao_url}",
        inet_url,
        f"https://api.allorigins.win/raw?url={urllib.parse.quote(inet_url, safe='')}",
        f"https://api.codetabs.com/v1/proxy?quest={inet_url}",
        pa_url,
        f"https://api.allorigins.win/raw?url={urllib.parse.quote(pa_url, safe='')}",
    ]

    headers = {
        "Accept": "application/json, text/html, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    }

    for url in candidate_urls:
        txt = http_get_text(url, headers=headers, timeout=timeout)
        if not txt:
            continue
        parsed = parse_vn_whois_payload(txt)
        if parsed and parsed.get("expiry_date"):
            return parsed

    # 3. Try BKNS Official VNNIC REST API
    bkns_res = query_bkns_vn_whois(root_domain, timeout=timeout)
    if bkns_res and bkns_res.get("expiry_date"):
        return bkns_res

    return None


def check_domain_registration(
    hostname: str,
    custom_expiry: str = "",
    warn_days: int = 30,
    crit_days: int = 14,
    cached_info: Optional[Dict[str, Any]] = None,
    prev_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Checks domain WHOIS / RDAP expiration date, registrar, registrant, creation date, and nameservers.
    Supports .vn domains (VNNIC, Mắt Bão, Tenten, PA, Nhân Hòa, iNET) and international TLDs.
    """
    root_domain = extract_root_domain(hostname)
    result: Dict[str, Any] = {
        "domain_checked": True,
        "domain_root": root_domain,
        "domain_status": "unknown",
        "domain_days_left": None,
        "domain_expiry_date": None,
        "domain_creation_date": None,
        "domain_registrar": None,
        "domain_registrant": None,
        "domain_nameservers": [],
        "domain_source": None,
        "domain_error": None,
    }

    exp_dt: Optional[datetime.datetime] = None
    reg_dt: Optional[datetime.datetime] = None
    registrar: Optional[str] = None
    registrant: Optional[str] = None
    nameservers: List[str] = query_doh_nameservers(root_domain)
    source: Optional[str] = None

    # Check if we already have a verified expiry date from previous results (> 45 days left)
    if root_domain.endswith(".vn") and prev_result and prev_result.get("domain_expiry_date"):
        prev_exp = parse_any_date(prev_result.get("domain_expiry_date"))
        if prev_exp and (prev_exp - now_utc()).days > 45:
            exp_dt = prev_exp
            reg_dt = parse_any_date(prev_result.get("domain_creation_date"))
            registrar = prev_result.get("domain_registrar")
            registrant = prev_result.get("domain_registrant")
            source = prev_result.get("domain_source") or "VNNIC (vnnic.vn/whois-information)"

    # 1. For .vn domains, query VNNIC (https://vnnic.vn/whois-information/) & Vietnamese Registrar WHOIS
    if exp_dt is None and root_domain.endswith(".vn"):
        vn_info = query_vn_registrar_whois(root_domain)
        if vn_info and vn_info.get("expiry_date"):
            exp_dt = vn_info["expiry_date"]
            reg_dt = vn_info.get("creation_date")
            registrar = vn_info.get("registrar")
            registrant = vn_info.get("registrant")
            if vn_info.get("nameservers"):
                nameservers = vn_info["nameservers"]
            source = vn_info.get("source", "VNNIC (vnnic.vn/whois-information)")

    # 2. Try RDAP (fast, structured for .com, .net, .org, .io, .dev, etc.)
    if exp_dt is None:
        rdap_info = query_rdap_domain(root_domain)
        if rdap_info and rdap_info.get("expiry_date"):
            exp_dt = rdap_info["expiry_date"]
            reg_dt = rdap_info.get("creation_date")
            registrar = rdap_info.get("registrar")
            if rdap_info.get("nameservers"):
                nameservers = rdap_info["nameservers"]
            source = rdap_info.get("source", "RDAP")

    # 3. Try Vietnamese Registrar WHOIS API as universal fallback for international domains
    if exp_dt is None and not root_domain.endswith(".vn"):
        vn_fallback = query_vn_registrar_whois(root_domain)
        if vn_fallback and vn_fallback.get("expiry_date"):
            exp_dt = vn_fallback["expiry_date"]
            reg_dt = vn_fallback.get("creation_date")
            registrar = vn_fallback.get("registrar")
            registrant = vn_fallback.get("registrant")
            if vn_fallback.get("nameservers"):
                nameservers = vn_fallback["nameservers"]
            source = vn_fallback.get("source", "VN-WHOIS")

    # 4. Fallback to python-whois
    if exp_dt is None and HAS_PYWHOIS and not root_domain.endswith(".vn"):
        try:
            w = pywhois.whois(root_domain)
            exp_dt = parse_any_date(getattr(w, "expiration_date", None) or w.get("expiration_date"))
            reg_dt = parse_any_date(getattr(w, "creation_date", None) or w.get("creation_date"))
            raw_reg = getattr(w, "registrar", None) or w.get("registrar")
            if isinstance(raw_reg, list):
                registrar = str(raw_reg[0]) if raw_reg else None
            elif raw_reg:
                registrar = str(raw_reg)
            raw_ns = getattr(w, "name_servers", None) or w.get("name_servers") or []
            if isinstance(raw_ns, str):
                raw_ns = [raw_ns]
            if raw_ns:
                nameservers = list(dict.fromkeys([str(ns).lower().rstrip(".") for ns in raw_ns if ns]))[:6]
            if exp_dt:
                source = "WHOIS"
        except Exception as exc:
            result["domain_error"] = f"WHOIS lookup warning: {exc}"

    # 5. Fallback to raw socket WHOIS
    if exp_dt is None:
        raw_info = query_raw_whois_socket(root_domain)
        if raw_info and raw_info.get("expiry_date"):
            exp_dt = raw_info["expiry_date"]
            reg_dt = raw_info.get("creation_date") or reg_dt
            registrar = raw_info.get("registrar") or registrar
            if raw_info.get("nameservers"):
                nameservers = raw_info["nameservers"]
            source = raw_info.get("source", "Raw WHOIS")

    # 6. Fallback to cached WHOIS info synced from Browser or previous result
    if exp_dt is None and cached_info:
        c_exp = parse_any_date(cached_info.get("cached_domain_expiry"))
        if c_exp:
            exp_dt = c_exp
            reg_dt = parse_any_date(cached_info.get("cached_creation_date")) or reg_dt
            registrar = cached_info.get("cached_registrar") or registrar
            registrant = cached_info.get("cached_registrant") or registrant
            source = "VNNIC (vnnic.vn/whois-information)"

    if exp_dt is None and prev_result and prev_result.get("domain_expiry_date"):
        p_exp = parse_any_date(prev_result.get("domain_expiry_date"))
        if p_exp:
            exp_dt = p_exp
            reg_dt = parse_any_date(prev_result.get("domain_creation_date")) or reg_dt
            registrar = prev_result.get("domain_registrar") or registrar
            registrant = prev_result.get("domain_registrant") or registrant
            source = prev_result.get("domain_source") or "Cached"

    # 7. Manual override (`custom_domain_expiry` in domains.json)
    if custom_expiry and custom_expiry.strip():
        manual_dt = parse_any_date(custom_expiry.strip())
        if manual_dt:
            exp_dt = manual_dt
            source = "Manual Config" if not source else f"{source} + Manual"

    registrar = normalize_registrar_name(registrar, nameservers)
    result["domain_registrar"] = registrar or "—"
    result["domain_registrant"] = registrant
    result["domain_nameservers"] = nameservers

    if exp_dt is not None:
        now = now_utc()
        days_left = int((exp_dt - now).total_seconds() // 86400)
        result["domain_days_left"] = days_left
        result["domain_expiry_date"] = exp_dt.strftime("%Y-%m-%d")
        result["domain_creation_date"] = reg_dt.strftime("%Y-%m-%d") if reg_dt else None
        result["domain_registrar"] = registrar or "Unknown Registrar"
        result["domain_source"] = source
        result["domain_status"] = classify_status(days_left, warn_days, crit_days, has_error=False)
        result["domain_error"] = None
    else:
        result["domain_status"] = "unknown"
        if not result["domain_error"]:
            result["domain_error"] = (
                "Không lấy được ngày hết hạn tự động từ Registry (có thể điền ngày hết hạn thủ công trên giao diện)"
            )

    return result


def scan_single_entry(
    entry: Dict[str, Any],
    settings: Dict[str, Any],
    prev_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Scan both SSL and Domain expiry for a single domain entry."""
    raw_domain = entry.get("domain", "")
    hostname = clean_hostname(raw_domain)
    port = int(entry.get("port", 443) or 443)
    check_ssl = bool(entry.get("check_ssl", True))
    check_domain = bool(entry.get("check_domain", True))
    custom_expiry = str(entry.get("custom_domain_expiry", "") or "")

    warn_ssl = int(entry.get("alert_days_ssl") or settings.get("alert_days_ssl", 30))
    crit_ssl = int(entry.get("critical_days_ssl") or settings.get("critical_days_ssl", 7))
    warn_dom = int(entry.get("alert_days_domain") or settings.get("alert_days_domain", 30))
    crit_dom = int(entry.get("critical_days_domain") or settings.get("critical_days_domain", 14))

    item: Dict[str, Any] = {
        "id": entry.get("id") or f"dom-{hostname}",
        "domain": hostname,
        "port": port,
        "group": entry.get("group") or "Default",
        "notes": entry.get("notes") or "",
        "notify_emails": entry.get("notify_emails") or [],
        "custom_domain_expiry": custom_expiry,
        "checked_at": now_utc().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    if check_ssl:
        ssl_res = check_ssl_certificate(hostname, port=port, warn_days=warn_ssl, crit_days=crit_ssl)
        item.update(ssl_res)
    else:
        item.update({
            "ssl_checked": False,
            "ssl_status": "skipped",
            "ssl_days_left": None,
        })

    if check_domain:
        dom_res = check_domain_registration(
            hostname,
            custom_expiry=custom_expiry,
            warn_days=warn_dom,
            crit_days=crit_dom,
            cached_info=entry,
            prev_result=prev_result,
        )
        item.update(dom_res)
    else:
        item.update({
            "domain_checked": False,
            "domain_root": extract_root_domain(hostname),
            "domain_status": "skipped",
            "domain_days_left": None,
        })

    statuses = [item.get("ssl_status"), item.get("domain_status")]
    priority = ["expired", "error", "critical", "warning", "ok", "unknown", "skipped"]
    overall = "ok"
    for p in priority:
        if p in statuses:
            overall = p
            break
    item["overall_status"] = overall
    return item


def build_email_html(
    items: List[Dict[str, Any]],
    alert_items: List[Dict[str, Any]],
    settings: Dict[str, Any],
    is_test: bool = False,
) -> Tuple[str, str]:
    """Generate email Subject and responsive HTML body suitable for Groupware / Outlook / Gmail."""
    dashboard_url = settings.get("dashboard_url") or "https://duongnvd.github.io/ssl-monitor/"
    now_str = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    if is_test:
        subject = f"[TEST] Hệ thống theo dõi SSL & Domain - Kết nối SMTP thành công ({now_str})"
    elif alert_items:
        crit_count = sum(1 for x in alert_items if x.get("overall_status") in ("expired", "critical", "error"))
        warn_count = len(alert_items) - crit_count
        subject = f"[CẢNH BÁO SSL/DOMAIN] {len(alert_items)} tên miền cần chú ý ({crit_count} khẩn cấp, {warn_count} sắp hết hạn)"
    else:
        subject = f"[Báo cáo SSL/Domain] Tất cả {len(items)} tên miền đều hoạt động tốt ({now_str})"

    def badge_html(status: str, days: Optional[int]) -> str:
        colors = {
            "ok": ("#065f46", "#d1fae5", "An toàn"),
            "warning": ("#92400e", "#fef3c7", "Sắp hết hạn"),
            "critical": ("#991b1b", "#fee2e2", "Khẩn cấp"),
            "expired": ("#ffffff", "#dc2626", "ĐÃ HẾT HẠN"),
            "error": ("#991b1b", "#fee2e2", "Lỗi kiểm tra"),
            "unknown": ("#374151", "#f3f4f6", "Chưa rõ"),
            "skipped": ("#6b7280", "#f3f4f6", "Bỏ qua"),
        }
        fg, bg, label = colors.get(status, ("#374151", "#f3f4f6", status))
        days_text = f"{days} ngày" if days is not None else label
        return (
            f'<span style="display:inline-block;padding:4px 10px;border-radius:12px;'
            f'font-size:12px;font-weight:bold;color:{fg};background-color:{bg};">'
            f"{days_text}</span>"
        )

    rows_html = ""
    target_list = items if (is_test or not alert_items) else alert_items
    for it in target_list:
        ssl_badge = badge_html(it.get("ssl_status", "unknown"), it.get("ssl_days_left"))
        dom_badge = badge_html(it.get("domain_status", "unknown"), it.get("domain_days_left"))
        ssl_exp = it.get("ssl_valid_to") or (it.get("ssl_error") or "—")
        dom_exp = it.get("domain_expiry_date") or "—"
        issuer = it.get("ssl_issuer") or "—"
        registrar = it.get("domain_registrar") or "—"

        rows_html += f"""
        <tr style="border-bottom:1px solid #e5e7eb;">
          <td style="padding:12px 10px;font-weight:bold;color:#111827;">
            {it['domain']}:{it.get('port', 443)}
            <div style="font-size:11px;color:#6b7280;font-weight:normal;">Nhóm: {it.get('group', 'Default')} {('• ' + it['notes']) if it.get('notes') else ''}</div>
          </td>
          <td style="padding:12px 10px;text-align:center;">{ssl_badge}</td>
          <td style="padding:12px 10px;font-size:12px;color:#374151;">
            <div><strong>Hết hạn:</strong> {ssl_exp}</div>
            <div style="color:#6b7280;">CA: {issuer}</div>
          </td>
          <td style="padding:12px 10px;text-align:center;">{dom_badge}</td>
          <td style="padding:12px 10px;font-size:12px;color:#374151;">
            <div><strong>Hết hạn:</strong> {dom_exp}</div>
            <div style="color:#6b7280;">Registrar: {registrar}</div>
          </td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,Roboto,Arial,sans-serif;background-color:#f3f4f6;margin:0;padding:24px;">
  <div style="max-width:860px;margin:0 auto;background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
    <div style="background:#0f172a;color:#ffffff;padding:20px 24px;">
      <h2 style="margin:0;font-size:20px;">🛡️ Hệ thống Giám sát SSL &amp; Domain</h2>
      <p style="margin:6px 0 0;color:#94a3b8;font-size:13px;">Thời gian quét: {now_str} | Tổng số theo dõi: {len(items)} domain</p>
    </div>
    <div style="padding:24px;">
      <p style="margin-top:0;color:#334155;font-size:14px;">
        {"Đây là email kiểm tra kết nối SMTP (Groupware / Mail Server) từ hệ thống giám sát SSL & Domain." if is_test else f"Hệ thống phát hiện <strong>{len(alert_items)}</strong> tên miền/chứng chỉ SSL sắp đến hạn hoặc cần kiểm tra:"}
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:12px;">
        <thead>
          <tr style="background:#f8fafc;border-bottom:2px solid #cbd5e1;text-align:left;color:#475569;">
            <th style="padding:10px;">Tên miền</th>
            <th style="padding:10px;text-align:center;">Trạng thái SSL</th>
            <th style="padding:10px;">Chi tiết SSL</th>
            <th style="padding:10px;text-align:center;">Trạng thái Domain</th>
            <th style="padding:10px;">Chi tiết Domain</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
      <div style="margin-top:24px;text-align:center;">
        <a href="{dashboard_url}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;padding:10px 22px;border-radius:6px;font-weight:bold;font-size:14px;">
          Mở Bảng điều khiển: {dashboard_url}
        </a>
      </div>
    </div>
    <div style="background:#f8fafc;padding:14px 24px;font-size:12px;color:#64748b;border-top:1px solid #e2e8f0;">
      Email tự động gửi từ hệ thống <strong>SSL &amp; Domain Monitor</strong> trên GitHub Actions.
    </div>
  </div>
</body>
</html>"""
    return subject, html


def send_smtp_email(
    subject: str,
    html_body: str,
    recipients: List[str],
) -> bool:
    """Sends HTML email via Corporate Groupware SMTP or Gmail SMTP."""
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587").strip() or "587")
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_pass = os.environ.get("SMTP_PASS", "").strip()
    smtp_from = os.environ.get("SMTP_FROM", "").strip() or smtp_user or f"ssl-monitor@{socket.getfqdn()}"
    smtp_security = os.environ.get("SMTP_SECURITY", "auto").strip().lower()
    skip_verify = os.environ.get("SMTP_SKIP_TLS_VERIFY", "false").strip().lower() in ("true", "1", "yes")

    clean_recipients = [r.strip() for r in recipients if r and "@" in r and r.strip() != "admin@example.com"]
    if not smtp_host:
        print("[INFO] SMTP_HOST chưa được cấu hình trong biến môi trường / GitHub Secrets. Bỏ qua gửi email.")
        return False
    if not clean_recipients:
        print("[INFO] Chưa có địa chỉ email người nhận hợp lệ (SMTP_TO hoặc default_recipients). Bỏ qua gửi email.")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = ", ".join(clean_recipients)
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    tls_ctx = ssl.create_default_context()
    if skip_verify:
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE

    try:
        use_ssl = smtp_security == "ssl" or (smtp_security == "auto" and smtp_port == 465)
        use_starttls = smtp_security == "starttls" or (smtp_security == "auto" and smtp_port in (587, 2525, 25))

        if use_ssl:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20, context=tls_ctx)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)

        with server:
            server.ehlo()
            if not use_ssl and use_starttls and server.has_extn("STARTTLS"):
                server.starttls(context=tls_ctx)
                server.ehlo()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, clean_recipients, msg.as_string())

        print(f"[OK] Đã gửi email thông báo tới: {', '.join(clean_recipients)} qua {smtp_host}:{smtp_port}")
        return True
    except Exception as exc:
        print(f"[ERROR] Gửi email qua {smtp_host}:{smtp_port} thất bại: {exc}", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="SSL & Domain Expiration Monitor")
    parser.add_argument("--config", default=str(DOMAINS_FILE), help="Path to domains.json")
    parser.add_argument("--output", default=str(RESULTS_FILE), help="Path to results.json")
    parser.add_argument("--force-email", action="store_true", help="Send email report even if all domains are OK")
    parser.add_argument("--test-email", action="store_true", help="Send a test email to verify Groupware SMTP")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[ERROR] Không tìm thấy file cấu hình: {config_path}", file=sys.stderr)
        return 1

    with open(config_path, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    settings = config_data.get("settings", {})
    domains_list = config_data.get("domains", [])

    # Load previous results to preserve already-known .vn expiry dates if rate-limited
    output_path = Path(args.output)
    prev_map: Dict[str, Dict[str, Any]] = {}
    if output_path.exists():
        try:
            with open(output_path, "r", encoding="utf-8") as pf:
                prev_data = json.load(pf)
                for p_item in prev_data.get("items", []):
                    if p_item.get("domain"):
                        prev_map[clean_hostname(p_item["domain"])] = p_item
        except Exception:
            pass

    print(f"[*] Bắt đầu kiểm tra {len(domains_list)} tên miền...")
    items: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {
            executor.submit(
                scan_single_entry,
                entry,
                settings,
                prev_map.get(clean_hostname(entry.get("domain", ""))),
            ): entry
            for entry in domains_list
            if entry.get("domain")
        }
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            items.append(res)
            print(
                f"  - {res['domain']}:{res['port']} -> "
                f"SSL: {res.get('ssl_status')} ({res.get('ssl_days_left')}d) | "
                f"Domain: {res.get('domain_status')} ({res.get('domain_days_left')}d, Exp: {res.get('domain_expiry_date')}, Reg: {res.get('domain_registrar')})"
            )

    def sort_key(x: Dict[str, Any]) -> Tuple[int, int, str]:
        status_order = {"expired": 0, "error": 1, "critical": 2, "warning": 3, "ok": 4, "unknown": 5, "skipped": 6}
        s_ord = status_order.get(x.get("overall_status", "ok"), 9)
        ssl_d = x.get("ssl_days_left") if x.get("ssl_days_left") is not None else 99999
        dom_d = x.get("domain_days_left") if x.get("domain_days_left") is not None else 99999
        return (s_ord, min(ssl_d, dom_d), x.get("domain", ""))

    items.sort(key=sort_key)

    summary = {
        "total": len(items),
        "healthy": sum(1 for x in items if x.get("overall_status") == "ok"),
        "warning": sum(1 for x in items if x.get("overall_status") == "warning"),
        "critical": sum(1 for x in items if x.get("overall_status") in ("critical", "expired", "error")),
        "ssl_expiring": sum(1 for x in items if x.get("ssl_status") in ("warning", "critical", "expired", "error")),
        "domain_expiring": sum(1 for x in items if x.get("domain_status") in ("warning", "critical", "expired")),
    }

    output_payload = {
        "last_updated": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary,
        "settings": {
            "alert_days_ssl": settings.get("alert_days_ssl", 30),
            "critical_days_ssl": settings.get("critical_days_ssl", 7),
            "alert_days_domain": settings.get("alert_days_domain", 30),
            "critical_days_domain": settings.get("critical_days_domain", 14),
            "notify_mode": settings.get("notify_mode", "alert_only"),
        },
        "items": items,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, ensure_ascii=False, indent=2)

    print(f"[+] Đã lưu kết quả tại: {output_path}")

    alert_items = [
        x for x in items if x.get("overall_status") in ("expired", "error", "critical", "warning")
    ]

    env_to = [e.strip() for e in os.environ.get("SMTP_TO", "").split(",") if e.strip()]
    cfg_to = settings.get("default_recipients") or []
    global_recipients = list(dict.fromkeys(env_to + cfg_to))

    notify_mode = settings.get("notify_mode", "alert_only")
    should_send = (
        args.test_email
        or args.force_email
        or notify_mode == "daily_digest"
        or (len(alert_items) > 0)
    )

    if should_send:
        subject, html_body = build_email_html(items, alert_items, settings, is_test=args.test_email)
        send_smtp_email(subject, html_body, global_recipients)

        per_recipient_items: Dict[str, List[Dict[str, Any]]] = {}
        for it in alert_items:
            for extra_email in it.get("notify_emails") or []:
                extra_email = extra_email.strip()
                if extra_email and extra_email not in global_recipients:
                    per_recipient_items.setdefault(extra_email, []).append(it)

        for rcpt, rcpt_items in per_recipient_items.items():
            sub_custom, html_custom = build_email_html(rcpt_items, rcpt_items, settings, is_test=False)
            send_smtp_email(sub_custom, html_custom, [rcpt])

    return 0


if __name__ == "__main__":
    sys.exit(main())
