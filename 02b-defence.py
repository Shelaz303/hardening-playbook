#!/usr/bin/env python3
"""
02b-defence.py - Service-level defence + listening port scan.

RUN:
    sudo python3 02b-defence.py            -> DRY RUN (nothing changes)
    sudo python3 02b-defence.py --apply    -> APPLY CHANGES

WHAT IT DOES:
    * Scans listening ports, flags suspicious/unknown ones (WARN ONLY, never touches them)
    * Detects which scored services are running
    * Enables fail2ban jails for each running service
    * Hardens each service's config (no open relay, TLS required, no zone transfer, etc.)
    * Backs up every config before editing
    * Validates each config, reverts the service if it fails
    * Skips every service that is not installed

SAFETY:
    * Backups: /root/hardening-backup-<ts>/
    * Log:     /root/hardening-<ts>.log
"""
import os, sys, re, shutil, subprocess, time
from pathlib import Path

# ======================================================================================
#                         CONFIG
# ======================================================================================
ENABLE_SERVICE_HARDENING = True   # False = only jails + scan, skip config edits
ENABLE_FAIL2BAN_JAILS    = True
SCAN_PORTS               = True   # Warn about suspicious/unknown listeners
REFRESH_BASELINE         = True

# ======================================================================================
#                         BOOTSTRAP
# ======================================================================================
APPLY = "--apply" in sys.argv
DRY = not APPLY

if os.geteuid() != 0:
    sys.exit("Run as root:  sudo python3 02b-defence.py [--apply]")

TS = time.strftime("%Y%m%d-%H%M%S")
BK = Path(f"/root/hardening-backup-{TS}")
LOG = Path(f"/root/hardening-{TS}.log")
if APPLY:
    BK.mkdir(parents=True, exist_ok=True)

RESULTS = []
DETECTED = {}


# ======================================================================================
#                         HELPERS
# ======================================================================================
def _log(tag, msg):
    line = f"[{tag}] {msg}"
    print(line)
    if APPLY:
        with LOG.open("a") as f:
            f.write(line + "\n")

def log(msg):   _log("+", msg)
def warn(msg):  _log("!", msg)
def fail(msg):  _log("X", msg)

def record(step, status, detail=""):
    RESULTS.append((step, status, detail))

def run(cmd, timeout=60):
    if DRY:
        print(f"    DRY: {cmd}")
        return 0, "", ""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        warn(f"TIMEOUT after {timeout}s: {cmd[:80]}")
        return 124, "", "timeout"
    if APPLY:
        with LOG.open("a") as f:
            f.write(f"$ {cmd}\n{r.stdout}{r.stderr}\n")
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def out(cmd, timeout=15):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception:
        return ""

def backup(path):
    p = Path(path)
    if APPLY and p.exists():
        dest = BK / str(p).lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(p, dest)
        except Exception as e:
            warn(f"backup failed for {path}: {e}")

def which(binary):
    """Fast, reliable: is this binary in PATH?"""
    return shutil.which(binary) is not None

def is_active(service):
    return out(f"systemctl is-active {service} 2>/dev/null", timeout=5) == "active"


# ======================================================================================
#                         STEP 0: SCAN LISTENING PORTS (warn only)
# ======================================================================================
# Ports the script knows how to handle
KNOWN_PORTS = {
    21:    "FTP",
    22:    "SSH",
    25:    "Postfix (SMTP)",
    53:    "BIND (DNS)",
    80:    "Web (HTTP)",
    110:   "Dovecot (POP3)",
    143:   "Dovecot (IMAP)",
    443:   "Web (HTTPS)",
    465:   "Postfix (SMTPS)",
    587:   "Postfix (Submission)",
    993:   "Dovecot (IMAPS)",
    995:   "Dovecot (POP3S)",
}

# Ports that should never be exposed
SUSPICIOUS_PORTS = {
    23:    "Telnet (insecure)",
    111:   "rpcbind (attack surface)",
    135:   "MS RPC",
    137:   "NetBIOS",
    138:   "NetBIOS",
    139:   "NetBIOS",
    445:   "SMB (attack surface)",
    1433:  "MSSQL",
    2049:  "NFS (attack surface)",
    3306:  "MySQL/MariaDB",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis (often unauthenticated)",
    8080:  "Alt HTTP",
    8443:  "Alt HTTPS",
    9200:  "Elasticsearch (often unauthenticated)",
    11211: "Memcached (amplification risk)",
    27017: "MongoDB (often unauthenticated)",
}

def scan_listeners():
    if not SCAN_PORTS:
        record("scan", "SKIP", "disabled")
        return

    log("SCAN LISTENING PORTS (warn only, never touches anything)")
    output = out("ss -tulpnH", timeout=15)
    if not output:
        warn("Could not read listening sockets (ss failed or empty)")
        record("scan", "WARN", "ss returned nothing")
        return

    suspicious = []
    unknown = []

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        proc = " ".join(parts[6:]) if len(parts) > 6 else "(unknown process)"

        match = re.search(r":(\d+)$", local)
        if not match:
            continue
        port = int(match.group(1))

        if port in SUSPICIOUS_PORTS:
            warn(f"SUSPICIOUS: {proto} {port} [{SUSPICIOUS_PORTS[port]}] <- {proc}")
            suspicious.append(port)
        elif port not in KNOWN_PORTS:
            warn(f"UNKNOWN: {proto} {port} <- {proc}")
            unknown.append(port)

    if suspicious:
        warn(f"Suspicious ports open: {sorted(set(suspicious))}")
        warn("These should be closed or firewalled immediately.")
    if unknown:
        warn(f"Unknown listening ports: {sorted(set(unknown))}")
        warn("If scored, add to EXTRA_TCP_PORTS in 02-harden.py and rerun.")
        warn("If not scored, disable the service.")

    status = "PASS" if not (suspicious or unknown) else "WARN"
    record("scan", status, f"suspicious={len(set(suspicious))} unknown={len(set(unknown))}")


# ======================================================================================
#                         STEP 1: DETECT SERVICES
# ======================================================================================
SERVICE_CANDIDATES = {
    "postfix":   ("Postfix",   [25, 465, 587]),
    "dovecot":   ("Dovecot",   [110, 143, 993, 995]),
    "named":     ("BIND",      [53]),
    "bind9":     ("BIND",      [53]),
    "apache2":   ("Apache",    [80, 443]),
    "nginx":     ("Nginx",     [80, 443]),
    "lighttpd":  ("Lighttpd",  [80, 443]),
    "vsftpd":    ("vsftpd",    [21]),
    "proftpd":   ("ProFTPd",   [21]),
    "exim4":     ("Exim",      [25, 465, 587]),
}

def detect_services():
    global DETECTED
    log("DETECT SERVICES")
    running = []
    skipped = set()
    for unit, (label, ports) in SERVICE_CANDIDATES.items():
        if label in skipped or label in [r.split("(")[0] for r in running]:
            continue
        if is_active(unit):
            DETECTED[label] = True
            running.append(f"{label}({unit})")
        else:
            DETECTED.setdefault(label, False)
            skipped.add(label)
    log(f"Running services: {running or 'none matched'}")
    if skipped:
        log(f"Not running (skipped): {sorted(skipped)}")
    record("detect", "PASS", f"{len(running)} found")


# ======================================================================================
#                         STEP 2: FAIL2BAN JAILS
# ======================================================================================
def fail2ban_jails():
    if not ENABLE_FAIL2BAN_JAILS:
        record("fail2ban_jails", "SKIP", "disabled")
        return

    log("FAIL2BAN JAILS")

    if not which("fail2ban-client"):
        warn("fail2ban not installed — run 02-harden.py first")
        record("fail2ban_jails", "FAIL", "fail2ban missing")
        return

    jails = []
    if DETECTED.get("Postfix"):
        jails.append(("postfix", "25,465,587", "/var/log/mail.log", 3, "2h"))
    if DETECTED.get("Dovecot"):
        jails.append(("dovecot", "110,143,993,995", "/var/log/mail.log", 5, "1h"))
    if DETECTED.get("Apache"):
        jails.append(("apache-auth", "80,443", "/var/log/apache2/error.log", 5, "1h"))
        jails.append(("apache-badbots", "80,443", "/var/log/apache2/access.log", 2, "1h"))
    if DETECTED.get("Nginx"):
        jails.append(("nginx-http-auth", "80,443", "/var/log/nginx/error.log", 5, "1h"))
        jails.append(("nginx-botsearch", "80,443", "/var/log/nginx/access.log", 2, "1h"))
    if DETECTED.get("BIND"):
        jails.append(("named-refused", "53", "/var/log/syslog", 5, "1h"))
    if DETECTED.get("vsftpd"):
        jails.append(("vsftpd", "21", "/var/log/vsftpd.log", 3, "1h"))
    if DETECTED.get("Exim"):
        jails.append(("exim", "25,465,587", "/var/log/exim4/mainlog", 3, "2h"))

    if not jails:
        log("No jails to enable (no scored services running)")
        record("fail2ban_jails", "PASS", "no jails needed")
        return

    lines = ["# Auto-generated by 02b-defence.py", ""]
    for name, ports, logpath, retry, bantime in jails:
        lines.append(f"[{name}]")
        lines.append(f"enabled  = true")
        lines.append(f"port     = {ports}")
        lines.append(f"logpath  = {logpath}")
        lines.append(f"maxretry = {retry}")
        lines.append(f"bantime  = {bantime}")
        lines.append("")

    config_path = "/etc/fail2ban/jail.d/scored-services.conf"
    if DRY:
        print(f"    DRY: write {config_path} with {len(jails)} jails: {[j[0] for j in jails]}")
    else:
        backup(config_path)
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)
        Path(config_path).write_text("\n".join(lines))
        os.chmod(config_path, 0o644)
        log(f"Wrote {config_path} with jails: {[j[0] for j in jails]}")

    run("systemctl restart fail2ban", timeout=30)
    time.sleep(2)

    active, failed = [], []
    for name, *_ in jails:
        st = out(f"fail2ban-client status {name} 2>/dev/null", timeout=10)
        if "Status for the jail" in st:
            active.append(name)
        else:
            failed.append(name)

    if active:
        log(f"Active jails: {active}")
    if failed:
        warn(f"Failed to start jails: {failed}  (check log format)")

    status = "PASS" if not failed else "WARN"
    record("fail2ban_jails", status, f"active={len(active)} failed={len(failed)}")


# ======================================================================================
#                         STEP 3: POSTFIX HARDENING
# ======================================================================================
POSTFIX_LINES = [
    "smtpd_banner = $myhostname ESMTP",
    "disable_vrfy_command = yes",
    "smtpd_helo_required = yes",
    "smtpd_tls_security_level = may",
    "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination",
]

def harden_postfix():
    if not DETECTED.get("Postfix") or not ENABLE_SERVICE_HARDENING:
        return
    log("POSTFIX HARDENING")
    cfg = Path("/etc/postfix/main.cf")
    if not cfg.exists():
        warn("postfix main.cf not found")
        record("postfix", "FAIL", "config not found")
        return

    backup(str(cfg))
    content = cfg.read_text()
    added = []
    for line in POSTFIX_LINES:
        key = line.split("=")[0].strip()
        content = re.sub(rf"(?m)^{re.escape(key)}\s*=.*$", "", content)
        content = content.rstrip() + "\n" + line + "\n"
        added.append(key)

    if DRY:
        print(f"    DRY: append {len(added)} postfix lines to {cfg}")
    else:
        cfg.write_text(content)
        rc, _, err = run("postfix check", timeout=30)
        if rc != 0:
            warn(f"postfix config invalid: {err}")
            shutil.copy2(BK / "etc/postfix/main.cf", cfg)
            record("postfix", "FAIL", "config invalid, reverted")
            return
        run("systemctl reload postfix 2>/dev/null || systemctl restart postfix", timeout=30)
        if is_active("postfix"):
            log(f"Postfix hardened: {added}")
            record("postfix", "PASS", f"added {len(added)} lines")
        else:
            warn("Postfix failed to restart")
            record("postfix", "FAIL", "service did not restart")


# ======================================================================================
#                         STEP 4: DOVECOT HARDENING
# ======================================================================================
DOVECOT_LINES = [
    "ssl = required",
    "disable_plaintext_auth = yes",
]

def harden_dovecot():
    if not DETECTED.get("Dovecot") or not ENABLE_SERVICE_HARDENING:
        return
    log("DOVECOT HARDENING")
    cfg = Path("/etc/dovecot/conf.d/10-ssl.conf")
    if not cfg.exists():
        cfg = Path("/etc/dovecot/dovecot.conf")
    if not cfg.exists():
        warn("dovecot config not found")
        record("dovecot", "FAIL", "config not found")
        return

    backup(str(cfg))
    content = cfg.read_text()
    added = []
    for line in DOVECOT_LINES:
        key = line.split("=")[0].strip()
        content = re.sub(rf"(?m)^#?\s*{re.escape(key)}\s*=.*$", "", content)
        content = content.rstrip() + "\n" + line + "\n"
        added.append(key)

    if DRY:
        print(f"    DRY: set {len(added)} dovecot options in {cfg}")
    else:
        cfg.write_text(content)
        rc, _, err = run("dovecot -n >/dev/null 2>&1", timeout=30)
        if rc != 0:
            warn(f"dovecot config invalid: {err}")
            shutil.copy2(BK / str(cfg).lstrip("/"), cfg)
            record("dovecot", "FAIL", "config invalid, reverted")
            return
        run("systemctl restart dovecot", timeout=30)
        if is_active("dovecot"):
            log(f"Dovecot hardened: {added}")
            record("dovecot", "PASS", f"set {len(added)} options")
        else:
            warn("Dovecot failed to restart")
            record("dovecot", "FAIL", "service did not restart")


# ======================================================================================
#                         STEP 5: BIND HARDENING
# ======================================================================================
BIND_LINES = [
    'version "not currently available";',
    "allow-transfer { none; };",
    "recursion no;",
]

def harden_bind():
    if not DETECTED.get("BIND") or not ENABLE_SERVICE_HARDENING:
        return
    log("BIND HARDENING")
    candidates = ["/etc/bind/named.conf.options",
                  "/etc/named.conf",
                  "/etc/bind/named.conf.local"]
    cfg = next((Path(p) for p in candidates if Path(p).exists()), None)
    if not cfg:
        warn("BIND config not found")
        record("bind", "FAIL", "config not found")
        return

    backup(str(cfg))
    content = cfg.read_text()
    if all(line in content for line in BIND_LINES):
        log("BIND already hardened")
        record("bind", "PASS", "already hardened")
        return

    inserted = False
    for line in BIND_LINES:
        key = line.split()[0]
        if key in content:
            content = re.sub(rf"(?m)^\s*{re.escape(key)}.*$", f"    {line}", content)
        else:
            m = re.search(r"options\s*\{", content)
            if m and not inserted:
                idx = m.end()
                content = content[:idx] + "\n    " + "\n    ".join(BIND_LINES) + "\n" + content[idx:]
                inserted = True

    if DRY:
        print(f"    DRY: harden {cfg}")
    else:
        cfg.write_text(content)
        rc, _, err = run("named-checkconf", timeout=30)
        if rc != 0:
            warn(f"BIND config invalid: {err}")
            shutil.copy2(BK / str(cfg).lstrip("/"), cfg)
            record("bind", "FAIL", "config invalid, reverted")
            return
        run("systemctl restart named 2>/dev/null || systemctl restart bind9", timeout=30)
        if is_active("named") or is_active("bind9"):
            log("BIND hardened: version hidden, transfers denied, recursion off")
            record("bind", "PASS", "hardened")
        else:
            warn("BIND failed to restart")
            record("bind", "FAIL", "service did not restart")


# ======================================================================================
#                         STEP 6: APACHE HARDENING
# ======================================================================================
APACHE_LINES = ["ServerTokens Prod", "ServerSignature Off"]

def harden_apache():
    if not DETECTED.get("Apache") or not ENABLE_SERVICE_HARDENING:
        return
    log("APACHE HARDENING")
    cfg_dir = Path("/etc/apache2/conf-available")
    cfg_dir.mkdir(exist_ok=True)
    drop_in = cfg_dir / "99-hardening.conf"
    content = "\n".join(APACHE_LINES) + "\n" + \
              "<Directory />\n    Options -Indexes\n    AllowOverride None\n</Directory>\n"

    if DRY:
        print(f"    DRY: write {drop_in} and enable")
    else:
        backup(str(drop_in))
        drop_in.write_text(content)
        run("a2enconf 99-hardening", timeout=30)
        test_out = out("apachectl configtest 2>&1", timeout=30)
        if "Syntax OK" not in test_out:
            warn("Apache config invalid, disabling drop-in")
            run("a2disconf 99-hardening", timeout=15)
            record("apache", "FAIL", "config invalid, reverted")
            return
        run("systemctl reload apache2", timeout=30)
        if is_active("apache2"):
            log("Apache hardened: version hidden, indexes off")
            record("apache", "PASS", "hardened")
        else:
            warn("Apache failed to reload")
            record("apache", "FAIL", "service not active")


# ======================================================================================
#                         STEP 7: NGINX HARDENING
# ======================================================================================
NGINX_LINES = ["server_tokens off;", "autoindex off;"]

def harden_nginx():
    if not DETECTED.get("Nginx") or not ENABLE_SERVICE_HARDENING:
        return
    log("NGINX HARDENING")
    drop_in = Path("/etc/nginx/conf.d/99-hardening.conf")
    content = "\n".join(NGINX_LINES) + "\n"

    if DRY:
        print(f"    DRY: write {drop_in}")
    else:
        backup(str(drop_in))
        drop_in.write_text(content)
        test_out = out("nginx -t 2>&1", timeout=30)
        if "successful" not in test_out:
            warn("Nginx config invalid")
            drop_in.unlink(missing_ok=True)
            record("nginx", "FAIL", "config invalid, reverted")
            return
        run("systemctl reload nginx", timeout=30)
        if is_active("nginx"):
            log("Nginx hardened: version hidden, indexes off")
            record("nginx", "PASS", "hardened")
        else:
            warn("Nginx failed to reload")
            record("nginx", "FAIL", "service not active")


# ======================================================================================
#                         STEP 8: REFRESH BASELINE
# ======================================================================================
def refresh_baseline():
    if not REFRESH_BASELINE:
        record("baseline", "SKIP", "disabled")
        return
    log("REFRESH BASELINE")
    if DRY:
        print("    DRY: refresh /root/baseline")
        return
    b = Path("/root/baseline")
    b.mkdir(exist_ok=True)
    for src, dst in (("/etc/passwd", "passwd"), ("/etc/group", "group"),
                     ("/etc/crontab", "crontab")):
        if Path(src).exists():
            shutil.copy(src, b / dst)
    (b / "ports.txt").write_text(out("ss -tulpn | awk 'NR>1{print $1,$5}' | sort", timeout=30) + "\n")
    (b / "suid.txt").write_text(
        out("find / -xdev -perm -4000 -type f 2>/dev/null | sort", timeout=120) + "\n"
    )
    (b / "enabled-units.txt").write_text(
        out("systemctl list-unit-files --state=enabled --no-pager", timeout=30) + "\n"
    )
    (b / "fail2ban-jails.txt").write_text(out("fail2ban-client status 2>/dev/null") + "\n")
    record("baseline", "PASS", "refreshed")


# ======================================================================================
#                                   MAIN
# ======================================================================================
def main():
    print("=" * 70)
    print(f"MODE: {'DRY RUN - nothing changes' if DRY else 'APPLYING CHANGES'}")
    print("=" * 70)

    steps = [
        ("scan",        scan_listeners),
        ("detect",      detect_services),
        ("fail2ban",    fail2ban_jails),
        ("postfix",     harden_postfix),
        ("dovecot",     harden_dovecot),
        ("bind",        harden_bind),
        ("apache",      harden_apache),
        ("nginx",       harden_nginx),
        ("baseline",    refresh_baseline),
    ]

    try:
        for name, fn in steps:
            print()
            try:
                fn()
            except KeyboardInterrupt:
                raise
            except Exception as e:
                fail(f"{name} FAILED: {e}")
                record(name, "FAIL", str(e)[:120])
    except KeyboardInterrupt:
        print()
        fail("Interrupted")
        record("INTERRUPTED", "FAIL", "Ctrl+C")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for step, status, detail in RESULTS:
        icon = {"PASS": "+", "WARN": "!", "FAIL": "X", "SKIP": "-"}.get(status, "?")
        print(f"  [{icon}] {step:<14} {status:<5} {detail}")

    print()
    if DRY:
        print("Dry run finished. Run with --apply to apply changes.")
    else:
        print(f"Log:     {LOG}")
        print(f"Backups: {BK}")
        print()
        print("VERIFY:")
        print("  sudo fail2ban-client status")
        print("  sudo ss -tlnp")


if __name__ == "__main__":
    main()
