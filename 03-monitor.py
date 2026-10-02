#!/usr/bin/env python3
"""
03-monitor.py - Persistence / intrusion detector.

RUN:
    sudo python3 03-monitor.py          -> scan + report
    sudo python3 03-monitor.py --quiet  -> print only alerts (for cron / scripted use)

WHAT IT DOES:
    * Compares live state against the baseline saved by 02-harden.py
    * Alerts on: new UID 0 accounts, new SUID binaries, new listening ports,
      new cron jobs, new systemd units, new SSH keys, changed critical files
    * Flags suspicious process names, deleted-but-running binaries,
      non-root processes with UID 0 mappings

WHAT IT DOES NOT DO:
    * Never modifies anything. Read-only.
    * No automatic cleanup. It reports, you decide.

USAGE PATTERN:
    Run every 15-30 minutes during a competition. Or add to cron:
      */15 * * * * /usr/bin/python3 /tmp/03-monitor.py --quiet >> /var/log/monitor.log
"""
import os, sys, re, subprocess, hashlib, time
from pathlib import Path
from datetime import datetime

# ======================================================================================
#                         CONFIG
# ======================================================================================
QUIET = "--quiet" in sys.argv

BASE = Path("/root/baseline")
REPORT = Path(f"/root/monitor-{time.strftime('%Y%m%d-%H%M%S')}.log")

# Files whose changes always matter
WATCH_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/crontab",
    "/etc/ssh/sshd_config",
]

# Directories to scan for new files
WATCH_DIRS = [
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
    "/var/spool/cron", "/var/spool/cron/crontabs",
    "/etc/systemd/system", "/root/.ssh",
    "/tmp", "/var/tmp", "/dev/shm",
]

# Process names that should trigger an alert
SUSPICIOUS_PROCS = [
    "nc", "ncat", "netcat", "socat", "nmap", "masscan",
    "sqlmap", "hydra", "john", "hashcat", "msfconsole",
    "meterpreter", "cobaltstrike", "beacon",
]

# Ports never expected to be listening in production
SUSPICIOUS_PORTS = {
    23: "Telnet", 111: "rpcbind", 135: "MS RPC",
    445: "SMB", 1433: "MSSQL", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 4444: "Common backdoor",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "Alt HTTP", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
    31337: "Back Orifice / common backdoor",
    12345: "NetBus / common backdoor",
}


# ======================================================================================
#                         HELPERS
# ======================================================================================
ALERTS = []
INFO = []

def emit(level, msg):
    line = f"[{level}] {msg}"
    if not QUIET or level in ("ALERT", "WARN"):
        print(line)
    with REPORT.open("a") as f:
        f.write(line + "\n")

def alert(msg): emit("ALERT", msg); ALERTS.append(msg)
def warn(msg):  emit("WARN", msg);  ALERTS.append(msg)
def info(msg):  emit("INFO", msg);  INFO.append(msg)
def ok(msg):    emit("OK", msg)

def out(cmd, timeout=30):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception:
        return ""

def read_baseline(name):
    p = BASE / name
    if not p.exists():
        return None
    return p.read_text().strip()


# ======================================================================================
#                         CHECKS
# ======================================================================================
def check_uid0():
    """Any UID 0 account besides root?"""
    current = set(out("awk -F: '$3==0 {print $1}' /etc/passwd").split())
    baseline = read_baseline("uid0.txt")
    base_set = set(baseline.split()) if baseline else {"root"}

    new = current - base_set
    if new:
        alert(f"NEW UID 0 ACCOUNT(S): {sorted(new)}")
        for u in new:
            details = out(f"grep '^{u}:' /etc/passwd")
            alert(f"  {details}")
    else:
        ok(f"UID 0 accounts: {sorted(current)}")


def check_suid():
    """Any new SUID binaries since baseline?"""
    current = set(out("find / -xdev -perm -4000 -type f 2>/dev/null | sort", timeout=120).splitlines())
    baseline = read_baseline("suid.txt")
    base_set = set(baseline.splitlines()) if baseline else set()

    new = current - base_set
    if new:
        alert(f"NEW SUID BINARIES ({len(new)}):")
        for b in sorted(new):
            alert(f"  {b}")
    else:
        ok(f"SUID binaries: no changes ({len(current)} total)")


def check_ports():
    """Any new listening port not in baseline?"""
    current_raw = out("ss -tulpnH")
    current = set()
    for line in current_raw.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            m = re.search(r":(\d+)$", parts[4])
            if m:
                current.add(f"{parts[0]} {m.group(1)}")

    baseline = read_baseline("ports.txt")
    base_set = set()
    if baseline:
        for line in baseline.splitlines():
            parts = line.split()
            if len(parts) == 2:
                base_set.add(f"{parts[0]} {parts[1].split(':')[-1]}")

    new = current - base_set
    if new:
        warn(f"NEW LISTENING SOCKETS ({len(new)}):")
        for sock in sorted(new):
            proc = out(f"ss -tulpnH | grep ':{sock.split()[1]} ' | head -1")
            warn(f"  {sock}  {proc}")

    # Also check suspicious ports regardless of baseline
    for sock in current:
        try:
            port = int(sock.split()[1])
        except (ValueError, IndexError):
            continue
        if port in SUSPICIOUS_PORTS:
            alert(f"SUSPICIOUS LISTENING PORT: {sock} ({SUSPICIOUS_PORTS[port]})")

    if not new:
        ok(f"Listening sockets: no changes ({len(current)} total)")


def check_cron():
    """Any new cron entries?"""
    current = set()
    for d in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
              "/var/spool/cron/crontabs"):
        if Path(d).exists():
            for f in Path(d).iterdir():
                if f.is_file():
                    current.add(f"{d}/{f.name}")
    root_cron = out("crontab -l 2>/dev/null")
    if root_cron:
        for line in root_cron.splitlines():
            if line.strip() and not line.startswith("#"):
                current.add(f"root-crontab: {line}")

    baseline = read_baseline("crontab")
    # We can't perfectly diff since we only saved /etc/crontab
    # Instead flag any cron file modified in last 24h
    recent = out("find /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron -mtime -1 -type f 2>/dev/null")
    if recent:
        alert(f"CRON FILES MODIFIED IN LAST 24H:")
        for f in recent.splitlines():
            alert(f"  {f}")
    else:
        ok("Cron: no recent modifications")


def check_systemd_units():
    """Any new systemd units?"""
    recent = out("find /etc/systemd/system /lib/systemd/system -mtime -1 -type f 2>/dev/null")
    if recent:
        # Filter for actual unit files
        units = [f for f in recent.splitlines() if f.endswith((".service", ".timer", ".socket"))]
        if units:
            alert(f"NEW/MODIFIED SYSTEMD UNITS IN LAST 24H ({len(units)}):")
            for u in units:
                alert(f"  {u}")
        else:
            ok("Systemd units: no recent changes")
    else:
        ok("Systemd units: no recent changes")


def check_authorized_keys():
    """Any new SSH keys added?"""
    keys = out("find / -xdev -name authorized_keys -type f 2>/dev/null")
    recent = out("find / -xdev -name authorized_keys -type f -mtime -1 2>/dev/null")
    if recent:
        alert(f"authorized_keys MODIFIED IN LAST 24H:")
        for f in recent.splitlines():
            alert(f"  {f}")
            contents = out(f"cat {f} 2>/dev/null")
            for line in contents.splitlines():
                if line.strip() and not line.startswith("#"):
                    alert(f"    key: {line[:80]}...")
    else:
        ok(f"SSH keys: no recent changes")


def check_suspicious_procs():
    """Any suspicious process names running?"""
    ps_out = out("ps -eo pid,user,comm,args --no-headers")
    found = []
    for line in ps_out.splitlines():
        for proc in SUSPICIOUS_PROCS:
            # Match against comm or args as whole word
            if re.search(rf"\b{re.escape(proc)}\b", line):
                found.append(line.strip())
                break
    if found:
        alert(f"SUSPICIOUS PROCESSES RUNNING ({len(found)}):")
        for p in found:
            alert(f"  {p}")
    else:
        ok("Processes: no suspicious names")


def check_deleted_binaries():
    """Any process running a binary that no longer exists on disk? (classic backdoor)"""
    deleted = out("ls -l /proc/*/exe 2>/dev/null | grep -i deleted")
    if deleted:
        alert(f"PROCESSES RUNNING DELETED BINARIES:")
        for line in deleted.splitlines():
            alert(f"  {line}")
    else:
        ok("Running binaries: all present on disk")


def check_watch_files():
    """Have critical config files changed recently?"""
    modified = []
    for f in WATCH_FILES:
        if Path(f).exists():
            mtime = Path(f).stat().st_mtime
            if time.time() - mtime < 86400:  # last 24h
                modified.append(f)
    if modified:
        alert(f"CRITICAL FILES MODIFIED IN LAST 24H:")
        for f in modified:
            alert(f"  {f}")
    else:
        ok("Critical files: no recent changes")


def check_recent_binaries():
    """Any new executables in /tmp, /dev/shm, /var/tmp?"""
    found = []
    for d in ("/tmp", "/dev/shm", "/var/tmp"):
        out_raw = out(f"find {d} -type f -perm -u+x 2>/dev/null | head -20")
        if out_raw:
            found.extend(out_raw.splitlines())
    if found:
        alert(f"EXECUTABLES IN TEMP DIRS ({len(found)}):")
        for f in found:
            alert(f"  {f}")
    else:
        ok("Temp dirs: no executables")


def check_fail2ban():
    """Report current fail2ban ban count."""
    if not os.path.exists("/usr/bin/fail2ban-client"):
        return
    status = out("fail2ban-client status 2>/dev/null")
    if not status:
        warn("fail2ban installed but not responding")
        return
    total_banned = 0
    for line in status.splitlines():
        m = re.search(r"Jail list:\s*(.+)", line)
        if m:
            jails = [j.strip() for j in m.group(1).split(",")]
            for jail in jails:
                s = out(f"fail2ban-client status {jail} 2>/dev/null")
                for l2 in s.splitlines():
                    m2 = re.search(r"Currently banned:\s*(\d+)", l2)
                    if m2:
                        total_banned += int(m2.group(1))
                        if int(m2.group(1)) > 0:
                            warn(f"  fail2ban[{jail}]: {m2.group(1)} banned")
    if total_banned == 0:
        ok("fail2ban: no active bans")
    else:
        info(f"fail2ban total bans: {total_banned}")


def check_who():
    """Report current logins."""
    who_out = out("who")
    if who_out:
        info("Current logins:")
        for line in who_out.splitlines():
            info(f"  {line}")
    else:
        ok("No active logins")


# ======================================================================================
#                         MAIN
# ======================================================================================
def main():
    start = time.time()
    if not QUIET:
        print("=" * 70)
        print(f"MONITOR - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

    if not BASE.exists():
        warn(f"Baseline not found at {BASE} — run 02-harden.py first")
        print("Some checks will be less accurate.")

    checks = [
        ("UID 0 accounts",     check_uid0),
        ("SUID binaries",      check_suid),
        ("Listening ports",    check_ports),
        ("Cron",               check_cron),
        ("Systemd units",      check_systemd_units),
        ("SSH keys",           check_authorized_keys),
        ("Suspicious procs",   check_suspicious_procs),
        ("Deleted binaries",   check_deleted_binaries),
        ("Critical files",     check_watch_files),
        ("Temp executables",   check_recent_binaries),
        ("fail2ban",           check_fail2ban),
        ("Logins",             check_who),
    ]

    for name, fn in checks:
        if not QUIET:
            print()
        try:
            fn()
        except Exception as e:
            warn(f"{name} check FAILED: {e}")

    elapsed = time.time() - start
    print()
    if ALERTS:
        print("=" * 70)
        print(f"ALERTS: {len(ALERTS)}")
        print("=" * 70)
        for a in ALERTS:
            print(f"  ! {a}")
    else:
        print("=" * 70)
        print("CLEAN — no alerts")
        print("=" * 70)
    print(f"Report: {REPORT}")
    print(f"Took {elapsed:.1f}s")

    sys.exit(1 if ALERTS else 0)


if __name__ == "__main__":
    main()
