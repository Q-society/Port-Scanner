#!/usr/bin/env python3
"""
QSOC-SCANNER :: Enterprise Port Reconnaissance Console
=======================================================
Standalone GUI application for authorized TCP/UDP port scanning across
IPv4 and IPv6 targets, with lightweight banner-based service detection
and risk scoring.

LEGAL NOTICE
------------
Use ONLY on systems you own or have explicit written authorization to
test. Unauthorized scanning of third-party systems may be illegal under
laws such as the U.S. CFAA, UK Computer Misuse Act, or local equivalents.
"""

import sys
import socket
import threading
import queue
import time
import re
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QTextEdit, QFrame,
    QComboBox, QSpinBox, QCheckBox, QGroupBox, QGridLayout, QMessageBox,
    QStatusBar, QSizePolicy, QTabWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor

# ----------------------------------------------------------------------------
# THEME — neutral slate / graphite SOC console
# ----------------------------------------------------------------------------
BG_APP        = "#0d1117"   # window background
BG_PANEL      = "#141a23"   # card/panel background
BG_PANEL_ALT  = "#1a212c"   # input fields, table alt rows
BG_HEADER     = "#10151d"   # top bar
BORDER        = "#262e3a"
BORDER_LIGHT  = "#323c4a"

TEXT_PRIMARY  = "#e6e9ef"
TEXT_SECOND   = "#9aa5b1"
TEXT_MUTED    = "#5b6573"

ACCENT_BLUE   = "#4c8dff"   # primary accent
ACCENT_BLUE_D = "#2f5fb8"
SUCCESS       = "#2bb673"   # open / low risk
WARNING       = "#e0a23b"   # medium
HIGH          = "#e0793b"   # high
CRITICAL      = "#e0526a"   # critical

RISK_COLOR = {
    "LOW": SUCCESS,
    "MEDIUM": WARNING,
    "HIGH": HIGH,
    "CRITICAL": CRITICAL,
    "INFO": ACCENT_BLUE,
    "UNKNOWN": TEXT_MUTED,
}

UI_FONT_FAMILY   = "'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
MONO_FONT_FAMILY = "'Cascadia Mono', Consolas, 'Courier New', monospace"

APP_LOGO = r"""
 ██████╗ ███████╗ ██████╗  ██████╗
██╔═══██╗██╔════╝██╔═══██╗██╔════╝
██║   ██║███████╗██║   ██║██║
██║▄▄ ██║╚════██║██║   ██║██║
╚██████╔╝███████║╚██████╔╝╚██████╗
 ╚══▀▀═╝ ╚══════╝ ╚═════╝  ╚═════╝
"""

# ----------------------------------------------------------------------------
# PORT INTELLIGENCE — baseline reference, used when banner grab is inconclusive
# port -> (service, risk, note)
# ----------------------------------------------------------------------------
PORT_INTEL = {
    7: ("Echo", "LOW", "Rarely needed; disable if unused."),
    20: ("FTP-DATA", "MEDIUM", "Unencrypted file transfer channel."),
    21: ("FTP", "HIGH", "Cleartext credentials; prefer SFTP/FTPS."),
    22: ("SSH", "LOW", "Secure if key-auth and rate limiting are configured."),
    23: ("Telnet", "CRITICAL", "Cleartext remote shell. Disable immediately."),
    25: ("SMTP", "MEDIUM", "Check for open relay misconfiguration."),
    53: ("DNS", "MEDIUM", "Check for zone transfer / cache poisoning exposure."),
    67: ("DHCP", "INFO", "Expected on local network segments."),
    69: ("TFTP", "HIGH", "No auth, no encryption. Often device configs."),
    80: ("HTTP", "MEDIUM", "Unencrypted web traffic; check for HTTPS redirect."),
    110: ("POP3", "MEDIUM", "Cleartext mail retrieval unless TLS-wrapped."),
    111: ("RPCBind", "HIGH", "Often leveraged for service enumeration / DDoS reflection."),
    123: ("NTP", "MEDIUM", "Can be abused for amplification attacks."),
    135: ("MS-RPC", "HIGH", "Common Windows lateral-movement vector."),
    137: ("NetBIOS-NS", "MEDIUM", "Legacy name service; info disclosure risk."),
    139: ("NetBIOS-SSN", "HIGH", "Legacy SMB; relay/enum risk."),
    143: ("IMAP", "MEDIUM", "Cleartext mail unless TLS-wrapped."),
    161: ("SNMP", "HIGH", "Default 'public' community strings are common."),
    389: ("LDAP", "MEDIUM", "Check for anonymous bind."),
    443: ("HTTPS", "LOW", "Verify certificate validity and TLS version."),
    445: ("SMB", "CRITICAL", "EternalBlue-class exploit surface. Patch & segment."),
    512: ("rexec", "HIGH", "Cleartext remote execution protocol."),
    513: ("rlogin", "HIGH", "Cleartext remote login protocol."),
    514: ("rsh / syslog", "HIGH", "Legacy remote shell or unauthenticated logging."),
    993: ("IMAPS", "LOW", "Encrypted; verify TLS configuration."),
    995: ("POP3S", "LOW", "Encrypted; verify TLS configuration."),
    1433: ("MSSQL", "HIGH", "Database exposed directly to network; restrict source IPs."),
    1521: ("Oracle DB", "HIGH", "Database exposed directly to network; restrict source IPs."),
    1900: ("SSDP/UPnP", "MEDIUM", "Common amplification / device enumeration vector."),
    2049: ("NFS", "HIGH", "Misconfigured exports can leak filesystem access."),
    3306: ("MySQL", "HIGH", "Database exposed directly to network; restrict source IPs."),
    3389: ("RDP", "CRITICAL", "Top ransomware entry vector. VPN/MFA-gate it."),
    5353: ("mDNS", "INFO", "Expected on local network segments."),
    5432: ("PostgreSQL", "HIGH", "Database exposed directly to network; restrict source IPs."),
    5900: ("VNC", "CRITICAL", "Often weak/no auth; full remote desktop access."),
    6379: ("Redis", "CRITICAL", "Frequently unauthenticated; full data + RCE risk."),
    8080: ("HTTP-ALT", "MEDIUM", "Common admin/proxy panel; verify auth."),
    8443: ("HTTPS-ALT", "LOW", "Verify certificate validity and TLS version."),
    9200: ("Elasticsearch", "CRITICAL", "Frequently unauthenticated; mass data exposure risk."),
    27017: ("MongoDB", "CRITICAL", "Frequently unauthenticated; mass data exposure risk."),
}

# Banner substring -> (service label override, risk override or None to keep baseline)
BANNER_SIGNATURES = [
    (re.compile(rb"SSH-\d\.\d-OpenSSH[_-]?([\w\.]+)", re.I), "OpenSSH {0}", "LOW"),
    (re.compile(rb"SSH-\d\.\d-([\w\.\-]+)", re.I), "SSH ({0})", "LOW"),
    (re.compile(rb"220.*ProFTPD", re.I), "ProFTPD", "HIGH"),
    (re.compile(rb"220.*vsFTPd\s*([\d\.]+)?", re.I), "vsFTPd {0}", "HIGH"),
    (re.compile(rb"220.*FileZilla", re.I), "FileZilla Server", "HIGH"),
    (re.compile(rb"HTTP/1\.[01].*Server:\s*nginx[/ ]?([\d\.]+)?", re.I | re.S), "nginx {0}", "MEDIUM"),
    (re.compile(rb"Server:\s*Apache[/ ]?([\d\.]+)?", re.I), "Apache httpd {0}", "MEDIUM"),
    (re.compile(rb"Server:\s*Microsoft-IIS[/ ]?([\d\.]+)?", re.I), "Microsoft IIS {0}", "MEDIUM"),
    (re.compile(rb"Server:\s*([\w\-/\.]+)", re.I), "HTTP server ({0})", "MEDIUM"),
    (re.compile(rb"^220[ -].*SMTP", re.I), "SMTP service", "MEDIUM"),
    (re.compile(rb"^\+OK.*POP3", re.I), "POP3 service", "MEDIUM"),
    (re.compile(rb"\* OK.*IMAP", re.I), "IMAP service", "MEDIUM"),
    (re.compile(rb"^E\s*\x00\x00\x00.*mysql_native_password|mysql", re.I), "MySQL", "HIGH"),
    (re.compile(rb"^.\x00\x00\x00\x0a", re.I), "MySQL-compatible DB", "HIGH"),
    (re.compile(rb"REDIS|^-NOAUTH|^-ERR", re.I), "Redis", "CRITICAL"),
    (re.compile(rb"RFB 0\d\d\.\d\d\d"), "VNC (RFB)", "CRITICAL"),
    (re.compile(rb"MongoDB|ismaster", re.I), "MongoDB", "CRITICAL"),
]


def fingerprint_banner(banner_bytes):
    """Try to identify a service/version from a raw banner. Returns (label, risk) or (None, None)."""
    if not banner_bytes:
        return None, None
    for pattern, label_fmt, risk in BANNER_SIGNATURES:
        m = pattern.search(banner_bytes)
        if m:
            try:
                groups = [g.decode(errors="ignore") if isinstance(g, bytes) else (g or "") for g in m.groups()]
            except Exception:
                groups = []
            try:
                label = label_fmt.format(*groups) if groups else label_fmt.format("")
            except Exception:
                label = label_fmt.format("")
            return label.strip(), risk
    return None, None


def classify_port(port: int, protocol: str = "tcp"):
    if port in PORT_INTEL:
        return PORT_INTEL[port]
    if port < 1024:
        return ("Well-known port", "MEDIUM", "Unidentified well-known service; investigate manually.")
    return ("Unregistered / custom", "UNKNOWN", "Non-standard service; manual fingerprinting advised.")


def grab_tcp_banner(sock):
    try:
        sock.settimeout(0.8)
        data = sock.recv(256)
        return data
    except Exception:
        return b""


def clean_banner_text(raw_bytes):
    if not raw_bytes:
        return ""
    text = raw_bytes.decode(errors="ignore").strip()
    text = text.replace("\r", " ").replace("\n", " | ")
    return text[:90]


# ----------------------------------------------------------------------------
# SCAN WORKER THREAD
# ----------------------------------------------------------------------------
class ScanWorker(QThread):
    progress = pyqtSignal(int, int)
    port_found = pyqtSignal(str, int, str, str, str, str)  # protocol, port, service, risk, note, banner
    log_line = pyqtSignal(str, str)  # text, level (info/warn/error/open)
    finished_scan = pyqtSignal(float, int)

    def __init__(self, target, start_port, end_port, mode="tcp", threads=200, timeout=0.5, force_ipv6=False):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.mode = mode  # "tcp", "udp", "both"
        self.thread_count = threads
        self.timeout = timeout
        self.force_ipv6 = force_ipv6
        self._stop_flag = threading.Event()
        self._lock = threading.Lock()
        self._done_count = 0
        self._open_count = 0

    def stop(self):
        self._stop_flag.set()

    def run(self):
        start_time = time.time()

        family, resolved_ip = self._resolve_target()
        if resolved_ip is None:
            self.log_line.emit(f"Could not resolve host: {self.target}", "error")
            self.finished_scan.emit(0.0, 0)
            return

        ip_version = "IPv6" if family == socket.AF_INET6 else "IPv4"
        self.log_line.emit(f"Resolved {self.target} -> {resolved_ip} ({ip_version})", "info")

        protocols = []
        if self.mode in ("tcp", "both"):
            protocols.append("tcp")
        if self.mode in ("udp", "both"):
            protocols.append("udp")

        total_ports = self.end_port - self.start_port + 1
        total_jobs = total_ports * len(protocols)
        self.log_line.emit(
            f"Scanning ports {self.start_port}-{self.end_port} "
            f"[{'/'.join(p.upper() for p in protocols)}] with {self.thread_count} workers...",
            "info"
        )

        job_q = queue.Queue()
        for proto in protocols:
            for p in range(self.start_port, self.end_port + 1):
                job_q.put((proto, p))

        def worker():
            while not self._stop_flag.is_set():
                try:
                    proto, port = job_q.get_nowait()
                except queue.Empty:
                    return
                if proto == "tcp":
                    self._scan_tcp(family, resolved_ip, port)
                else:
                    self._scan_udp(family, resolved_ip, port)
                with self._lock:
                    self._done_count += 1
                    self.progress.emit(self._done_count, total_jobs)
                job_q.task_done()

        threads = []
        for _ in range(min(self.thread_count, max(total_jobs, 1))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        elapsed = time.time() - start_time
        self.log_line.emit(f"Scan complete in {elapsed:.2f}s.", "info")
        self.finished_scan.emit(elapsed, self._open_count)

    def _resolve_target(self):
        """Resolve target, respecting force_ipv6 preference. Returns (family, ip_str) or (None, None)."""
        try:
            if self.force_ipv6:
                infos = socket.getaddrinfo(self.target, None, socket.AF_INET6)
            else:
                infos = socket.getaddrinfo(self.target, None)
            family, _, _, _, sockaddr = infos[0]
            return family, sockaddr[0]
        except socket.gaierror:
            if not self.force_ipv6:
                try:
                    infos = socket.getaddrinfo(self.target, None, socket.AF_INET6)
                    family, _, _, _, sockaddr = infos[0]
                    return family, sockaddr[0]
                except socket.gaierror:
                    pass
            return None, None

    def _scan_tcp(self, family, ip, port):
        if self._stop_flag.is_set():
            return
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                addr = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
                result = s.connect_ex(addr)
                if result == 0:
                    raw_banner = grab_tcp_banner(s)
                    banner_text = clean_banner_text(raw_banner)
                    fp_label, fp_risk = fingerprint_banner(raw_banner)
                    base_service, base_risk, note = classify_port(port, "tcp")
                    service = fp_label if fp_label else base_service
                    risk = fp_risk if fp_risk else base_risk
                    with self._lock:
                        self._open_count += 1
                    self.port_found.emit("TCP", port, service, risk, note, banner_text)
                    self.log_line.emit(f"OPEN  tcp/{port}  ->  {service}  [{risk}]", "open")
        except Exception:
            pass

    def _scan_udp(self, family, ip, port):
        """UDP has no handshake; we send a probe and treat 'no ICMP unreachable' as open|filtered."""
        if self._stop_flag.is_set():
            return
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                addr = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
                try:
                    s.sendto(b"\x00", addr)
                    data, _ = s.recvfrom(256)
                    banner_text = clean_banner_text(data)
                    base_service, base_risk, note = classify_port(port, "udp")
                    with self._lock:
                        self._open_count += 1
                    self.port_found.emit("UDP", port, base_service, base_risk, note, banner_text)
                    self.log_line.emit(f"OPEN  udp/{port}  ->  {base_service}  [{base_risk}]", "open")
                except socket.timeout:
                    # No response = open|filtered for well-known UDP services; report cautiously
                    if port in PORT_INTEL:
                        base_service, base_risk, note = classify_port(port, "udp")
                        with self._lock:
                            self._open_count += 1
                        self.port_found.emit(
                            "UDP", port, base_service, base_risk,
                            note + " (no response — open|filtered, unconfirmed)", ""
                        )
                        self.log_line.emit(f"OPEN|FILTERED  udp/{port}  ->  {base_service}", "open")
                except ConnectionResetError:
                    pass  # ICMP port unreachable -> closed
        except Exception:
            pass


# ----------------------------------------------------------------------------
# SPLASH SCREEN — clean, minimal, professional
# ----------------------------------------------------------------------------
class SplashScreen(QWidget):
    finished = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(620, 360)
        self._progress_val = 0
        self._build_ui()
        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(28)

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_PANEL};
                border: 1px solid {BORDER_LIGHT};
                border-radius: 6px;
            }}
        """)
        inner = QVBoxLayout(card)
        inner.setContentsMargins(40, 36, 40, 36)
        inner.setSpacing(8)

        logo = QLabel(APP_LOGO)
        logo.setStyleSheet(f"color: {ACCENT_BLUE}; background: transparent;")
        logo.setFont(QFont(MONO_FONT_FAMILY.split(",")[0].strip("'"), 9, QFont.Bold))
        logo.setAlignment(Qt.AlignCenter)
        inner.addWidget(logo)

        name = QLabel("QSOC-SCANNER")
        name.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent; letter-spacing: 4px;")
        name.setFont(QFont(UI_FONT_FAMILY.split(",")[0].strip("'"), 17, QFont.Bold))
        name.setAlignment(Qt.AlignCenter)
        inner.addWidget(name)

        subtitle = QLabel("Enterprise Port Reconnaissance Console")
        subtitle.setStyleSheet(f"color: {TEXT_SECOND}; background: transparent;")
        subtitle.setFont(QFont(UI_FONT_FAMILY.split(",")[0].strip("'"), 10))
        subtitle.setAlignment(Qt.AlignCenter)
        inner.addWidget(subtitle)

        inner.addSpacing(20)

        self.status_label = QLabel("Initializing scan engine...")
        self.status_label.setStyleSheet(f"color: {TEXT_MUTED}; background: transparent;")
        self.status_label.setFont(QFont(UI_FONT_FAMILY.split(",")[0].strip("'"), 9))
        self.status_label.setAlignment(Qt.AlignCenter)
        inner.addWidget(self.status_label)

        bar_wrap = QFrame()
        bar_wrap.setFixedHeight(6)
        bar_wrap.setStyleSheet(f"background-color: {BG_PANEL_ALT}; border-radius: 3px;")
        bar_layout = QHBoxLayout(bar_wrap)
        bar_layout.setContentsMargins(0, 0, 0, 0)
        self.bar_fill = QFrame()
        self.bar_fill.setStyleSheet(f"background-color: {ACCENT_BLUE}; border-radius: 3px;")
        bar_layout.addWidget(self.bar_fill)
        bar_layout.addStretch()
        inner.addSpacing(10)
        inner.addWidget(bar_wrap)
        self._bar_wrap_width = 540 - 80

        outer.addWidget(card)

    def resizeEvent(self, event):
        super().resizeEvent(event)

    def _tick(self):
        self._progress_val += 3
        stages = [
            (0, "Initializing scan engine..."),
            (25, "Loading service signature database..."),
            (55, "Calibrating thread pool..."),
            (80, "Preparing IPv4 / IPv6 resolvers..."),
            (95, "Ready."),
        ]
        for threshold, text in reversed(stages):
            if self._progress_val >= threshold:
                self.status_label.setText(text)
                break
        pct = min(self._progress_val, 100)
        self.bar_fill.setFixedWidth(int(self._bar_wrap_width * pct / 100))
        if self._progress_val >= 100:
            self._timer.stop()
            self.finished.emit()


# ----------------------------------------------------------------------------
# MAIN WINDOW
# ----------------------------------------------------------------------------
class QSocScannerMain(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.setWindowTitle("QSOC-Scanner — Enterprise Port Reconnaissance Console")
        self.resize(1240, 780)
        self._apply_global_style()
        self._build_ui()

    # ---------------- styling ----------------
    def _apply_global_style(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {BG_APP};
                color: {TEXT_PRIMARY};
                font-family: {UI_FONT_FAMILY};
                font-size: 13px;
            }}
            QLabel {{ background: transparent; }}
            QGroupBox {{
                background-color: {BG_PANEL};
                border: 1px solid {BORDER};
                border-radius: 6px;
                margin-top: 16px;
                padding-top: 10px;
                font-weight: 600;
                color: {TEXT_SECOND};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                color: {TEXT_SECOND};
                font-size: 11px;
                letter-spacing: 1px;
            }}
            QLineEdit, QSpinBox, QComboBox {{
                background-color: {BG_PANEL_ALT};
                border: 1px solid {BORDER};
                border-radius: 4px;
                padding: 7px 10px;
                color: {TEXT_PRIMARY};
                selection-background-color: {ACCENT_BLUE_D};
            }}
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
                border: 1px solid {ACCENT_BLUE};
            }}
            QComboBox::drop-down {{ border: none; width: 22px; }}
            QComboBox QAbstractItemView {{
                background-color: {BG_PANEL_ALT};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER_LIGHT};
                selection-background-color: {ACCENT_BLUE_D};
            }}
            QPushButton {{
                background-color: {BG_PANEL_ALT};
                border: 1px solid {BORDER_LIGHT};
                border-radius: 4px;
                padding: 9px 20px;
                color: {TEXT_PRIMARY};
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {BORDER_LIGHT};
            }}
            QPushButton:disabled {{
                color: {TEXT_MUTED};
                border: 1px solid {BORDER};
                background-color: {BG_PANEL};
            }}
            QPushButton#primaryBtn {{
                background-color: {ACCENT_BLUE};
                border: 1px solid {ACCENT_BLUE};
                color: #ffffff;
            }}
            QPushButton#primaryBtn:hover {{
                background-color: #6aa1ff;
            }}
            QPushButton#primaryBtn:disabled {{
                background-color: {BG_PANEL_ALT};
                border: 1px solid {BORDER};
                color: {TEXT_MUTED};
            }}
            QPushButton#stopBtn {{
                border: 1px solid {CRITICAL};
                color: {CRITICAL};
                background-color: transparent;
            }}
            QPushButton#stopBtn:hover {{
                background-color: {CRITICAL};
                color: #ffffff;
            }}
            QTableWidget {{
                background-color: {BG_PANEL};
                alternate-background-color: {BG_PANEL_ALT};
                border: 1px solid {BORDER};
                border-radius: 6px;
                gridline-color: {BORDER};
                color: {TEXT_PRIMARY};
            }}
            QHeaderView::section {{
                background-color: {BG_HEADER};
                color: {TEXT_SECOND};
                padding: 8px;
                border: none;
                border-bottom: 1px solid {BORDER_LIGHT};
                font-weight: 600;
                font-size: 11px;
                letter-spacing: 0.5px;
            }}
            QTableWidget::item {{ padding: 4px; }}
            QTextEdit {{
                background-color: {BG_HEADER};
                color: {TEXT_SECOND};
                border: 1px solid {BORDER};
                border-radius: 6px;
                font-family: {MONO_FONT_FAMILY};
                font-size: 12px;
                padding: 6px;
            }}
            QProgressBar {{
                background-color: {BG_PANEL_ALT};
                border: 1px solid {BORDER};
                border-radius: 4px;
                text-align: center;
                color: {TEXT_PRIMARY};
                height: 16px;
            }}
            QProgressBar::chunk {{
                background-color: {ACCENT_BLUE};
                border-radius: 4px;
            }}
            QStatusBar {{
                background-color: {BG_HEADER};
                color: {TEXT_MUTED};
                border-top: 1px solid {BORDER};
                font-size: 11px;
            }}
            QCheckBox {{ color: {TEXT_SECOND}; }}
            QCheckBox::indicator {{
                width: 15px; height: 15px;
                border: 1px solid {BORDER_LIGHT};
                border-radius: 3px;
                background-color: {BG_PANEL_ALT};
            }}
            QCheckBox::indicator:checked {{
                background-color: {ACCENT_BLUE};
                border: 1px solid {ACCENT_BLUE};
            }}
        """)

    # ---------------- layout ----------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        # --- Top bar ---
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title = QLabel("QSOC-Scanner")
        title.setFont(QFont(UI_FONT_FAMILY.split(",")[0].strip("'"), 18, QFont.Bold))
        title.setStyleSheet(f"color: {TEXT_PRIMARY};")
        subtitle = QLabel("Enterprise Port Reconnaissance Console")
        subtitle.setFont(QFont(UI_FONT_FAMILY.split(",")[0].strip("'"), 10))
        subtitle.setStyleSheet(f"color: {TEXT_MUTED};")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()

        badge = QLabel("AUTHORIZED TARGETS ONLY")
        badge.setStyleSheet(f"""
            color: {WARNING};
            border: 1px solid {WARNING};
            border-radius: 10px;
            padding: 4px 12px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.5px;
        """)
        header.addWidget(badge, alignment=Qt.AlignVCenter)
        root.addLayout(header)

        # --- Configuration panel ---
        config_box = QGroupBox("TARGET CONFIGURATION")
        config_layout = QGridLayout(config_box)
        config_layout.setSpacing(10)
        config_layout.setColumnStretch(1, 1)
        config_layout.setColumnStretch(3, 1)

        config_layout.addWidget(self._field_label("Target"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IPv4, IPv6, or hostname — e.g. 10.0.0.5 / ::1 / example.com")
        config_layout.addWidget(self.target_input, 0, 1, 1, 3)

        config_layout.addWidget(self._field_label("IP version"), 1, 0)
        self.ip_version_combo = QComboBox()
        self.ip_version_combo.addItems(["Auto-detect", "Force IPv4", "Force IPv6"])
        config_layout.addWidget(self.ip_version_combo, 1, 1)

        config_layout.addWidget(self._field_label("Protocol"), 1, 2)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "Both (TCP + UDP)"])
        config_layout.addWidget(self.protocol_combo, 1, 3)

        config_layout.addWidget(self._field_label("Port range"), 2, 0)
        self.start_port = QSpinBox()
        self.start_port.setRange(1, 65535)
        self.start_port.setValue(1)
        self.end_port = QSpinBox()
        self.end_port.setRange(1, 65535)
        self.end_port.setValue(65535)
        range_row = QHBoxLayout()
        range_row.setSpacing(8)
        range_row.addWidget(self.start_port)
        dash = QLabel("–")
        dash.setStyleSheet(f"color: {TEXT_MUTED};")
        range_row.addWidget(dash)
        range_row.addWidget(self.end_port)
        range_wrap = QWidget()
        range_wrap.setLayout(range_row)
        config_layout.addWidget(range_wrap, 2, 1)

        config_layout.addWidget(self._field_label("Preset"), 2, 2)
        self.preset_combo = QComboBox()
        self.preset_combo.addItems([
            "Custom range",
            "Full range (1–65535)",
            "Well-known ports (1–1023)",
            "Common services (top ~40)",
        ])
        self.preset_combo.setCurrentIndex(1)
        self.preset_combo.currentIndexChanged.connect(self._apply_preset)
        config_layout.addWidget(self.preset_combo, 2, 3)

        config_layout.addWidget(self._field_label("Threads"), 3, 0)
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(10, 1000)
        self.thread_spin.setValue(200)
        config_layout.addWidget(self.thread_spin, 3, 1)

        config_layout.addWidget(self._field_label("Timeout (s)"), 3, 2)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 50)  # tenths of a second
        self.timeout_spin.setValue(5)
        config_layout.addWidget(self.timeout_spin, 3, 3)

        self.consent_check = QCheckBox(
            "I confirm I own this target or have explicit written authorization to test it."
        )
        config_layout.addWidget(self.consent_check, 4, 0, 1, 4)

        root.addWidget(config_box)

        # --- Controls ---
        controls = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setObjectName("primaryBtn")
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addStretch()
        controls.addWidget(self.export_btn)
        root.addLayout(controls)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        root.addWidget(self.progress_bar)

        # --- Results + log split ---
        split = QHBoxLayout()
        split.setSpacing(14)

        results_box = QGroupBox("DISCOVERED PORTS")
        results_layout = QVBoxLayout(results_box)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Proto", "Port", "Service", "Risk", "Banner", "Note"])
        self.table.setAlternatingRowColors(True)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(4, QHeaderView.Stretch)
        header_view.setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(True)
        results_layout.addWidget(self.table)
        split.addWidget(results_box, 3)

        log_box = QGroupBox("ACTIVITY LOG")
        log_layout = QVBoxLayout(log_box)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        log_layout.addWidget(self.log_view)
        split.addWidget(log_box, 2)

        root.addLayout(split, 1)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Idle — configure a target and press Start Scan.")

    def _field_label(self, text):
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {TEXT_SECOND}; font-size: 12px;")
        return lbl

    # ---------------- presets ----------------
    def _apply_preset(self, idx):
        if idx == 1:
            self.start_port.setValue(1)
            self.end_port.setValue(65535)
        elif idx == 2:
            self.start_port.setValue(1)
            self.end_port.setValue(1023)
        elif idx == 3:
            self.start_port.setValue(1)
            self.end_port.setValue(9200)  # broad sweep; PORT_INTEL covers the common ones within range

    # ---------------- scan control ----------------
    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing target", "Please enter a target IP, IPv6 address, or hostname.")
            return
        if not self.consent_check.isChecked():
            QMessageBox.warning(
                self, "Authorization required",
                "You must confirm you own this target or have explicit written\n"
                "authorization before scanning. Unauthorized scanning may be illegal."
            )
            return

        start_p = self.start_port.value()
        end_p = self.end_port.value()
        if start_p > end_p:
            QMessageBox.warning(self, "Invalid range", "Start port must be less than or equal to end port.")
            return

        protocol_map = {0: "tcp", 1: "udp", 2: "both"}
        mode = protocol_map[self.protocol_combo.currentIndex()]
        force_ipv6 = self.ip_version_combo.currentIndex() == 2

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setSortingEnabled(True)
        self.log_view.clear()
        self._log("Authorization confirmed by operator.", "info")
        self._log(f"Starting {mode.upper()} scan against {target} ...", "info")

        self.worker = ScanWorker(
            target=target,
            start_port=start_p,
            end_port=end_p,
            mode=mode,
            threads=self.thread_spin.value(),
            timeout=self.timeout_spin.value() / 10.0,
            force_ipv6=force_ipv6,
        )
        self.worker.progress.connect(self._on_progress)
        self.worker.port_found.connect(self._on_port_found)
        self.worker.log_line.connect(self._log)
        self.worker.finished_scan.connect(self._on_finished)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status.showMessage(f"Scanning {target} : ports {start_p}-{end_p} [{mode.upper()}] ...")
        self.worker.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self._log("Stop requested by operator — finishing in-flight checks...", "warn")
        self.stop_btn.setEnabled(False)

    def _on_progress(self, done, total):
        pct = int((done / total) * 100) if total else 0
        self.progress_bar.setValue(pct)

    def _on_port_found(self, proto, port, service, risk, note, banner):
        row = self.table.rowCount()
        self.table.setSortingEnabled(False)
        self.table.insertRow(row)

        proto_item = QTableWidgetItem(proto)
        port_item = QTableWidgetItem()
        port_item.setData(Qt.DisplayRole, port)
        service_item = QTableWidgetItem(service)
        risk_item = QTableWidgetItem(risk)
        banner_item = QTableWidgetItem(banner if banner else "—")
        note_item = QTableWidgetItem(note)

        risk_color = QColor(RISK_COLOR.get(risk, TEXT_MUTED))
        risk_item.setForeground(risk_color)
        port_item.setForeground(QColor(ACCENT_BLUE))
        proto_item.setForeground(QColor(TEXT_SECOND))

        for col, item in enumerate([proto_item, port_item, service_item, risk_item, banner_item, note_item]):
            self.table.setItem(row, col, item)

        self.table.setSortingEnabled(True)

    def _on_finished(self, elapsed, open_count):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status.showMessage(f"Scan finished in {elapsed:.2f}s — {open_count} open port(s) found.")
        self._log(f"Done — {open_count} open port(s) discovered.", "info")

    def _log(self, text, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "info": TEXT_SECOND,
            "warn": WARNING,
            "error": CRITICAL,
            "open": SUCCESS,
        }
        color = color_map.get(level, TEXT_SECOND)
        self.log_view.append(
            f"<span style='color:{TEXT_MUTED}'>[{ts}]</span> "
            f"<span style='color:{color}'>{text}</span>"
        )

    # ---------------- export ----------------
    def export_report(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "Nothing to export", "Run a scan first.")
            return
        target = self.target_input.text().strip() or "unknown_target"
        safe_target = re.sub(r"[^\w\.\-]", "_", target)
        filename = f"qsoc_scan_report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w") as f:
                f.write("QSOC-SCANNER — PORT RECONNAISSANCE REPORT\n")
                f.write("=" * 70 + "\n")
                f.write(f"Target:    {target}\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"{'PROTO':<7}{'PORT':<8}{'SERVICE':<24}{'RISK':<10}{'BANNER':<28}NOTE\n")
                f.write("-" * 110 + "\n")
                for row in range(self.table.rowCount()):
                    vals = [self.table.item(row, c).text() for c in range(6)]
                    f.write(f"{vals[0]:<7}{vals[1]:<8}{vals[2]:<24}{vals[3]:<10}{vals[4]:<28}{vals[5]}\n")
            QMessageBox.information(self, "Export complete", f"Report saved to:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))


# ----------------------------------------------------------------------------
# ENTRY POINT
# ----------------------------------------------------------------------------
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    splash = SplashScreen()
    main_win = QSocScannerMain()

    def show_main():
        splash.close()
        main_win.show()

    splash.finished.connect(show_main)
    splash.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
