#!/usr/bin/env python3
"""
SSL & Domain Expiration Monitor for Sysadmins
Scans domains from data/domains.json, writes results to data/results.json,
and sends HTML email notifications via Corporate Groupware SMTP / Gmail SMTP.
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional third-party imports with graceful fallback
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


BASE_DIR = Path(__file__).resolve().parent.parent
DOMAINS_FILE = BASE_DIR / "data" / "domains.json"
RESULTS_FILE = BASE_DIR / "data" / "results.json"

# Common multi-level Second-Level Domains (especially .vn and international)
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
    """Parse datetime from various formats (datetime object, list, ISO string, common WHOIS strings)."""
    if val is None:
        return None
    if isinstance(val, list):
        for item in val:
            parsed = parse_any_date(item)
            if parsed:
                return parsed
        return None
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=datetime.timezone.utc)
        return val.astimezone(datetime.timezone.utc)
    if isinstance(val, datetime.date):
        return datetime.datetime(val.year, val.month, val.day, tzinfo=datetime.timezone.utc)
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        # Handle trailing Z or timezone offsets
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
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
            "%d-%m-%Y",
            "%d/%m/%Y",
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
    return None


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
    """
    Connects to hostname:port via TLS, verifies certificate chain, and extracts
    expiration date, issuer, subject, SANs, protocol, cipher, and IP.
    Even if the certificate is expired or self-signed, extracts certificate metadata.
    """
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

    # Step 1: Try verified connection first
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

    # Step 2: If verification failed, fetch binary DER certificate with CERT_NONE to still get expiry/issuer
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

    # Step 3: Parse DER certificate via cryptography (preferred) or standard peer_cert_dict
    valid_from: Optional[datetime.datetime] = None
    valid_to: Optional[datetime.datetime] = None

    if der_cert and HAS_CRYPTOGRAPHY:
        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            valid_from = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            valid_to = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

            # Extract Issuer Organization / CN
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

            # Extract Subject CN
            subj_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            result["ssl_subject"] = str(subj_cn[0].value) if subj_cn else cert.subject.rfc4514_string()

            # Serial number
            result["ssl_serial"] = format(cert.serial_number, "X")

            # Subject Alternative Names (SANs)
            try:
                ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = ext.value.get_values_for_type(x509.DNSName)
                result["ssl_sans"] = list(sans)[:15]
            except x509.ExtensionNotFound:
                result["ssl_sans"] = []
        except Exception as parse_err:
            result["ssl_error"] = f"Cert parse error: {parse_err}"

    # Fallback to peer_cert_dict from standard library if cryptography wasn't available
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
        # If cert is untrusted (e.g. self-signed or wrong hostname) and not already expired, mark warning/critical
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
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": "SysadminSSLMonitor/1.0 (+https://duongnvd.github.io)",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    continue
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
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
    """Fallback raw socket port 43 WHOIS lookup using IANA referral."""
    try:
        tld = root_domain.split(".")[-1]
        # Query IANA for TLD whois server
        whois_server = None
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
        m_reg = re.search(r"Registrar:\s*(.+)", raw_text, re.IGNORECASE)
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


def check_domain_registration(
    hostname: str,
    custom_expiry: str = "",
    warn_days: int = 30,
    crit_days: int = 14,
) -> Dict[str, Any]:
    """
    Checks domain WHOIS / RDAP expiration date, registrar, creation date, and nameservers.
    Supports manual override via custom_expiry (YYYY-MM-DD) for private/restricted TLDs.
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
        "domain_nameservers": [],
        "domain_source": None,
        "domain_error": None,
    }

    exp_dt: Optional[datetime.datetime] = None
    reg_dt: Optional[datetime.datetime] = None
    registrar: Optional[str] = None
    nameservers: List[str] = []
    source: Optional[str] = None

    # 1. Try RDAP first (fast, structured, no rate-limit parsing issues)
    rdap_info = query_rdap_domain(root_domain)
    if rdap_info and rdap_info.get("expiry_date"):
        exp_dt = rdap_info["expiry_date"]
        reg_dt = rdap_info.get("creation_date")
        registrar = rdap_info.get("registrar")
        nameservers = rdap_info.get("nameservers") or []
        source = rdap_info.get("source", "RDAP")

    # 2. Fallback to python-whois
    if exp_dt is None and HAS_PYWHOIS:
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
            nameservers = list(dict.fromkeys([str(ns).lower().rstrip(".") for ns in raw_ns if ns]))[:6]
            if exp_dt:
                source = "WHOIS"
        except Exception as exc:
            result["domain_error"] = f"WHOIS lookup warning: {exc}"

    # 3. Fallback to raw socket WHOIS
    if exp_dt is None:
        raw_info = query_raw_whois_socket(root_domain)
        if raw_info and raw_info.get("expiry_date"):
            exp_dt = raw_info["expiry_date"]
            reg_dt = raw_info.get("creation_date") or reg_dt
            registrar = raw_info.get("registrar") or registrar
            nameservers = raw_info.get("nameservers") or nameservers
            source = raw_info.get("source", "Raw WHOIS")

    # 4. Manual override (`custom_domain_expiry` in domains.json)
    if custom_expiry and custom_expiry.strip():
        manual_dt = parse_any_date(custom_expiry.strip())
        if manual_dt:
            exp_dt = manual_dt
            source = "Manual Config" if not source else f"{source} + Manual"

    if exp_dt is not None:
        now = now_utc()
        days_left = int((exp_dt - now).total_seconds() // 86400)
        result["domain_days_left"] = days_left
        result["domain_expiry_date"] = exp_dt.strftime("%Y-%m-%d")
        result["domain_creation_date"] = reg_dt.strftime("%Y-%m-%d") if reg_dt else None
        result["domain_registrar"] = registrar or "Unknown Registrar"
        result["domain_nameservers"] = nameservers
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


def scan_single_entry(entry: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
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
            hostname, custom_expiry=custom_expiry, warn_days=warn_dom, crit_days=crit_dom
        )
        item.update(dom_res)
    else:
        item.update({
            "domain_checked": False,
            "domain_root": extract_root_domain(hostname),
            "domain_status": "skipped",
            "domain_days_left": None,
        })

    # Compute overall status for sorting and filtering
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
    """
    Sends HTML email via Corporate Groupware SMTP or Gmail SMTP.
    Environment variables supported:
      SMTP_HOST       - e.g., mail.company.com or smtp.gmail.com
      SMTP_PORT       - e.g., 587 (STARTTLS), 465 (SSL), or 25 (Relay/Plain/STARTTLS)
      SMTP_USER       - optional if internal relay on port 25, or username/email
      SMTP_PASS       - SMTP password / App password
      SMTP_FROM       - Sender address, e.g. "Sysadmin Monitor <monitor@company.com>"
      SMTP_SECURITY   - "auto" (default), "starttls", "ssl", "none"
      SMTP_SKIP_TLS_VERIFY - "true" if internal groupware uses self-signed certificate
    """
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

    print(f"[*] Bắt đầu kiểm tra {len(domains_list)} tên miền...")
    items: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {
            executor.submit(scan_single_entry, entry, settings): entry
            for entry in domains_list
            if entry.get("domain")
        }
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            items.append(res)
            print(
                f"  - {res['domain']}:{res['port']} -> "
                f"SSL: {res.get('ssl_status')} ({res.get('ssl_days_left')}d) | "
                f"Domain: {res.get('domain_status')} ({res.get('domain_days_left')}d)"
            )

    # Sort items by lowest days left (most urgent first)
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

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, ensure_ascii=False, indent=2)

    print(f"[+] Đã lưu kết quả tại: {output_path}")

    # Determine whether to send email alerts
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

        # Also check if any alerting domain has specific per-domain notify_emails
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
