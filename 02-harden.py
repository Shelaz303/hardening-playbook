#!/usr/bin/env python3
"""
02-harden.py - Competition Linux hardening. Auto-generates SSH keys. Minimal human interaction.

RUN:
    sudo python3 02-harden.py            -> DRY RUN (nothing changes)
    sudo python3 02-harden.py --apply    -> APPLY CHANGES

OPTIONAL FLAGS:
    --pubkey "ssh-ed25519 AAAA..."       -> use this pubkey instead of generating one
    --port 49222                         -> move SSH to this port (default: keep current)

WHAT IT DOES AUTOMATICALLY:
    * Generates an ed25519 SSH key for the SSH user (if none exists)
    * Installs the pubkey, disables password auth
    * Verifies SSH works before finishing
    * Reverts automatically if verification fails (no lockout)
    * Locks backdoor UID 0 accounts
    * Firewalls only a strict allowlist of ports
    * Configures fail2ban, auditd, PAM faillock, sysctl, etc.

SAFETY:
    * Backups: /root/hardening-backup-<ts>/
    * Log:     /root/hardening-<ts>.log
    * After a successful run, the private key is at ~<user>/.ssh/id_ed25519
"""
import os, sys, re, shutil, subprocess, secrets, string, time, grp, pwd
from pathlib import Path

# ======================================================================================
#                         CONFIG (usually no edits needed)
# ======================================================================================
ADMIN_IP_OVERRIDE   = None        # None = auto-detect from default route
SSH_USERS_OVERRIDE  = []          # [] = auto-detect (SUDO_USER or first login user)
SSH_PORT_OVERRIDE   = None        # None = keep current port
PUBKEY_OVERRIDE     = ""          # "" = auto-generate
EXTRA_TCP_PORTS     = []          # scored ports not in SAFE list (e.g. [8080, 8443])
EXTRA_UDP_PORTS     = []          # e.g. [123]

ROTATE_PASSWORDS       = False
DISABLE_JUNK           = True
ENABLE_UNATTENDED      = True
WIPE_TMP_ON_BOOT       = True
INSTALL_AIDE           = False    # slow; off by default
ENABLE_FAILLOCK        = True
BLACKLIST_MODULES      = True
SET_IMMUTABLE_SSH      = True
AIDE_TIMEOUT_SECONDS   = 300

SAFE_TCP_PORTS = {22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995}
SAFE_UDP_PORTS = {53, 123}

# ======================================================================================
#                         CLI ARG PARSING
# ======================================================================================
APPLY = "--apply" in sys.argv
DRY = not APPLY

for i, a in enumerate(sys.argv):
    if a == "--pubkey" and i + 1 < len(sys.argv):
        PUBKEY_OVERRIDE = sys.argv[i + 1]
    elif a.startswith("--pubkey="):
        PUBKEY_OVERRIDE = a.split("=", 1)[1]
    elif a == "--port" and i + 1 < len(sys.argv):
        try: SSH_PORT_OVERRIDE = int(sys.argv[i + 1])
        except ValueError: pass
    elif a.startswith("--port="):
        try: SSH_PORT_OVERRIDE = int(a.split("=", 1)[1])
        except ValueError: pass

if os.geteuid() != 0:
    sys.exit("Run as root:  sudo python3 02-harden.py [--apply]")

TS = time.strftime("%Y%m%d-%H%M%S")
BK = Path(f"/root/hardening-backup-{TS}")
LOG = Path(f"/root/hardening-{TS}.log")
if APPLY:
    BK.mkdir(parents=True, exist_ok=True)

RESULTS = []
IMMUTABLE_FILES = []
ADMIN_IP, SSH_USERS, SSH_PORT, PUBKEY, TCP_PORTS, UDP_PORTS = "", [], 22, "", [], []


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

def run(cmd, timeout=180):
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

def out(cmd, timeout=30):
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

def strip_immutable(path):
    if DRY: return
    p = Path(path)
    if p.exists():
        subprocess.run(f"chattr -i '{path}'", shell=True, capture_output=True)

def apply_immutable(path):
    if DRY: return
    p = Path(path)
    if p.exists():
        subprocess.run(f"chattr +i '{path}'", shell=True, capture_output=True)
        if str(path) not in IMMUTABLE_FILES:
            IMMUTABLE_FILES.append(str(path))

def write(path, content, mode=0o644):
    if DRY:
        print(f"    DRY: write {path} ({len(content.splitlines())} lines)")
        return
    strip_immutable(path)
    backup(path)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content)
    os.chmod(path, mode)

def installed(pkg):
    return subprocess.run(f"dpkg -s {pkg}", shell=True, capture_output=True).returncode == 0

def pkg_install(pkgs):
    missing = [p for p in pkgs if not installed(p)]
    if not missing: return True
    rc, _, _ = run(f"apt-get install -y {' '.join(missing)}", timeout=600)
    return rc == 0


# ======================================================================================
#                      KEY GENERATION + INSTALLATION
# ======================================================================================
def ensure_key_for_user(user):
    """Ensure user has an ed25519 keypair. Returns pubkey string (or '')."""
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        warn(f"User '{user}' does not exist")
        return ""

    sshdir = Path(pw.pw_dir) / ".ssh"
    keyfile = sshdir / "id_ed25519"
    pubfile = Path(str(keyfile) + ".pub")

    if pubfile.exists() and pubfile.stat().st_size > 0:
        log(f"Reusing existing key for '{user}'")
        return pubfile.read_text().strip()

    if DRY:
        print(f"    DRY: would generate ed25519 key for '{user}' at {keyfile}")
        return "ssh-ed25519 AAAA_DRY_RUN_FAKE_KEY user@dry"

    sshdir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(sshdir, 0o700)
    r = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-a", "100", "-N", "",
         "-f", str(keyfile), "-C", f"{user}@harden"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        warn(f"ssh-keygen failed for '{user}': {r.stderr.strip()}")
        return ""

    for p in (sshdir, keyfile, pubfile):
        try: shutil.chown(p, pw.pw_uid, pw.pw_gid)
        except Exception: pass
    os.chmod(keyfile, 0o600)
    os.chmod(pubfile, 0o644)

    log(f"Generated ed25519 key for '{user}': {keyfile}")
    return pubfile.read_text().strip()


def install_pubkey(user, pubkey):
    """Install pubkey into user's authorized_keys."""
    if not pubkey: return False
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return False

    sshdir = Path(pw.pw_dir) / ".ssh"
    ak = sshdir / "authorized_keys"

    if DRY:
        print(f"    DRY: install pubkey into {ak}")
        return True

    sshdir.mkdir(mode=0o700, exist_ok=True)
    existing = ak.read_text().splitlines() if ak.exists() else []
    if pubkey not in existing:
        existing.append(pubkey)
    ak.write_text("\n".join([l for l in existing if l.strip()]) + "\n")
    os.chmod(sshdir, 0o700)
    os.chmod(ak, 0o600)
    try:
        shutil.chown(sshdir, pw.pw_uid, pw.pw_gid)
        shutil.chown(ak, pw.pw_uid, pw.pw_gid)
    except Exception:
        pass
    return True


# ======================================================================================
#                     SSH ACCESS VERIFICATION
# ======================================================================================
def verify_ssh_access():
    """Try SSH to 127.0.0.1 using each user's key. Return True if any works."""
    if DRY:
        log("DRY: skipping access verification")
        return True

    for user in SSH_USERS:
        try:
            pw = pwd.getpwnam(user)
        except KeyError:
            continue
        keyfile = Path(pw.pw_dir) / ".ssh" / "id_ed25519"
        if not keyfile.exists():
            continue

        cmd = (f"ssh -o BatchMode=yes -o ConnectTimeout=5 "
               f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
               f"-p {SSH_PORT} -i {keyfile} {user}@127.0.0.1 'echo OK'")
        rc, stdout, _ = run(cmd, timeout=15)
        if rc == 0 and "OK" in stdout:
            log(f"Access verified: {user} can SSH on port {SSH_PORT}")
            return True

    warn("Could not verify SSH access")
    return False


def emergency_revert(reason):
    warn(f"EMERGENCY REVERT: {reason}")
    conf = "/etc/ssh/sshd_config.d/00-hardening.conf"
    if Path(conf).exists():
        strip_immutable(conf)
        Path(conf).unlink(missing_ok=True)
    run("systemctl restart ssh || systemctl restart sshd", timeout=30)
    warn("Removed SSH drop-in. Password auth should work again.")


# ======================================================================================
#                              STEP 0: DETECT ENVIRONMENT
# ======================================================================================
def detect_env():
    global ADMIN_IP, SSH_USERS, SSH_PORT, PUBKEY, TCP_PORTS, UDP_PORTS

    log("DETECT ENVIRONMENT")

    iface = out("ip route show default | awk '/default/ {print $5}' | head -1")
    ip_cidr = out(f"ip -4 addr show {iface} | awk '/inet / {{print $2}}' | head -1")
    ADMIN_IP = ADMIN_IP_OVERRIDE or ip_cidr or ""
    log(f"Subnet: {ADMIN_IP or '(auto-detect failed, SSH open rate-limited)'}")

    if SSH_USERS_OVERRIDE:
        SSH_USERS = list(SSH_USERS_OVERRIDE)
    else:
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user:
            SSH_USERS = [sudo_user]
        else:
            login = out("awk -F: '$3>=1000 && $7!~/nologin|false/ {print $1}' /etc/passwd").split()
            SSH_USERS = login[:3]
    log(f"SSH users: {SSH_USERS}")

    if SSH_PORT_OVERRIDE:
        SSH_PORT = SSH_PORT_OVERRIDE
    else:
        detected = out("sshd -T 2>/dev/null | awk '/^port /{print $2; exit}'")
        SSH_PORT = int(detected) if detected.isdigit() else 22
    log(f"SSH port: {SSH_PORT}")

    # Resolve or generate pubkey
    if PUBKEY_OVERRIDE.strip():
        PUBKEY = PUBKEY_OVERRIDE.strip()
        log("PUBKEY: using override")
    elif SSH_USERS:
        PUBKEY = ensure_key_for_user(SSH_USERS[0])
        if PUBKEY:
            log("PUBKEY: resolved/generated")
        else:
            warn("PUBKEY: failed to generate; password auth will stay ON")
    else:
        warn("No SSH user found; cannot generate key")

    TCP_PORTS = sorted(SAFE_TCP_PORTS | set(EXTRA_TCP_PORTS))
    UDP_PORTS = sorted(SAFE_UDP_PORTS | set(EXTRA_UDP_PORTS))
    log(f"Firewall TCP: {TCP_PORTS}")
    log(f"Firewall UDP: {UDP_PORTS}")

    record("detect", "PASS", f"port={SSH_PORT} users={SSH_USERS}")


# ======================================================================================
#                              STEP 1: RECON
# ======================================================================================
def recon():
    log("RECON")
    print("--- listening ---")
    print(out("ss -tulpn") or "(none)")
    print("--- UID 0 ---")
    print(out("awk -F: '$3==0 {print $1}' /etc/passwd"))
    record("recon", "PASS", "snapshot")


# ======================================================================================
#                              STEP 2: ACCOUNTS
# ======================================================================================
def accounts():
    log("ACCOUNTS")
    issues = []
    strip_immutable("/etc/sudoers")

    for line in Path("/etc/passwd").read_text().splitlines():
        f = line.split(":")
        if len(f) > 6 and f[2] == "0" and f[0] != "root":
            warn(f"EXTRA UID 0: {f[0]} -> locking")
            run(f"passwd -l {f[0]}")
            run(f"usermod -s /usr/sbin/nologin {f[0]}")
            issues.append(f"UID0:{f[0]}")

    for line in Path("/etc/shadow").read_text().splitlines():
        f = line.split(":")
        if len(f) > 1 and f[1] == "" and not f[0].startswith("!"):
            warn(f"Empty pw: {f[0]} -> locking")
            run(f"passwd -l {f[0]}")
            issues.append(f"emptypw:{f[0]}")

    try:
        sudoers = grp.getgrnam("sudo").gr_mem
    except KeyError:
        sudoers = []
    if sudoers:
        run("passwd -l root")
        log("Locked root password")

    nopasswd = out("grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null").splitlines()
    for l in nopasswd:
        warn(f"NOPASSWD: {l.strip()}")
    if nopasswd:
        run("sed -i '/NOPASSWD/ s/^/#/' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true")

    sd = "/etc/sudoers.d/99-hardening"
    write(sd, "Defaults timestamp_timeout=5\n"
              "Defaults passwd_tries=3\n"
              "Defaults !visiblepw\n"
              "Defaults use_pty\n"
              "Defaults logfile=/var/log/sudo.log\n"
              "Defaults env_reset\n"
              "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n", 0o440)
    rc, _, _ = run(f"visudo -c -f {sd}")
    if rc != 0:
        warn("sudoers drop-in invalid -> removed")
        if APPLY: Path(sd).unlink(missing_ok=True)

    pam_su = Path("/etc/pam.d/su")
    if pam_su.exists():
        lines = pam_su.read_text().splitlines()
        if not any("pam_wheel.so" in l and not l.lstrip().startswith("#") for l in lines):
            wheel = "auth       required   pam_wheel.so use_uid group=sudo"
            idx = next((i for i, l in enumerate(lines)
                        if "pam_rootok.so" in l and not l.lstrip().startswith("#")), -1)
            lines.insert(idx + 1, wheel)
            write("/etc/pam.d/su", "\n".join(lines) + "\n")

    txt = Path("/etc/login.defs").read_text()
    txt = re.sub(r"(?m)^PASS_MAX_DAYS.*", "PASS_MAX_DAYS   90", txt)
    txt = re.sub(r"(?m)^PASS_MIN_DAYS.*", "PASS_MIN_DAYS   1", txt)
    txt = re.sub(r"(?m)^PASS_WARN_AGE.*", "PASS_WARN_AGE   7", txt)
    txt = re.sub(r"(?m)^UMASK.*", "UMASK           027", txt)
    write("/etc/login.defs", txt)

    for u in pwd.getpwall():
        if 0 < u.pw_uid < 1000 and not re.search(r"nologin|false$", u.pw_shell):
            run(f"usermod -s /usr/sbin/nologin {u.pw_name}")

    record("accounts", "WARN" if issues else "PASS", "; ".join(issues) if issues else "clean")


# ======================================================================================
#                              STEP 3: SSH
# ======================================================================================
def ssh():
    log("SSH")
    for f in ("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/00-hardening.conf"):
        strip_immutable(f)

    # Install pubkey for every allowed user
    users_with_keys = []
    for user in SSH_USERS:
        user_pub = PUBKEY if PUBKEY.strip() else ensure_key_for_user(user)
        if user_pub and install_pubkey(user, user_pub):
            users_with_keys.append(user)
        else:
            warn(f"No usable key for '{user}'")

    # Password auth: 'no' only if EVERY user has a key
    pwauth = "no"
    for user in SSH_USERS:
        if user not in users_with_keys:
            pwauth = "yes"
            warn(f"'{user}' has no key -> PasswordAuthentication stays ON")
            break

    if not users_with_keys:
        pwauth = "yes"
        warn("No keys installed -> PasswordAuthentication stays ON")

    conf = f"""Port {SSH_PORT}
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Banner /etc/issue.net
PermitUserEnvironment no
PermitRootLogin no
PasswordAuthentication {pwauth}
PubkeyAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
UseDNS no
"""
    if SSH_USERS:
        conf += f"AllowUsers {' '.join(SSH_USERS)}\n"

    conf_path = "/etc/ssh/sshd_config.d/00-hardening.conf"
    write("/etc/issue.net", "Authorized use only. Activity is monitored and logged.\n")
    write(conf_path, conf)

    if APPLY:
        rc, _, err = run("sshd -t")
        if rc != 0:
            warn(f"sshd -t failed: {err}")
            Path(conf_path).unlink(missing_ok=True)
            record("ssh", "FAIL", "invalid sshd config")
            return
        if "ssh.socket" in out("systemctl list-unit-files"):
            run("systemctl disable --now ssh.socket")
            run("systemctl enable ssh.service")
        run("systemctl restart ssh || systemctl restart sshd")
        eff = out("sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|maxauthtries) '")
        log(f"Effective: {eff.replace(chr(10), ' | ')}")

        if not verify_ssh_access():
            emergency_revert("SSH access verification failed")
            record("ssh", "FAIL", "reverted")
            return
    else:
        run("sshd -t")

    record("ssh", "PASS", f"port={SSH_PORT} pwauth={pwauth}")


# ======================================================================================
#                              STEP 4: FIREWALL
# ======================================================================================
def firewall():
    log("FIREWALL (ufw)")
    if not shutil.which("ufw"):
        run("apt-get install -y ufw")
    for c in ("ufw --force reset", "ufw default deny incoming", "ufw default allow outgoing",
              "ufw default deny routed", "ufw allow in on lo"):
        run(c)
    if ADMIN_IP:
        run(f"ufw limit from {ADMIN_IP} to any port {SSH_PORT} proto tcp")
    else:
        run(f"ufw limit {SSH_PORT}/tcp")
    for p in TCP_PORTS:
        if p in (22, SSH_PORT): continue
        run(f"ufw allow {p}/tcp")
    for p in UDP_PORTS:
        run(f"ufw allow {p}/udp")
    run("ufw logging medium")
    run("ufw --force enable")
    if APPLY:
        print(out("ufw status numbered"))
    record("firewall", "PASS", f"tcp={TCP_PORTS} udp={UDP_PORTS}")


# ======================================================================================
#                              STEP 5: SYSCTL
# ======================================================================================
def sysctl():
    log("KERNEL (sysctl)")
    write("/etc/sysctl.d/99-hardening.conf", """net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.core_pattern = |/bin/false
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
dev.tty.legacy_tiocsti = 0
""")
    run("sysctl --system")

    if BLACKLIST_MODULES:
        write("/etc/modprobe.d/99-hardening-filesystems.conf", """install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install sctp /bin/true
install dccp /bin/true
install tipc /bin/true
install rds /bin/true
install usb-storage /bin/true
""")
        run("modprobe -r cramfs freevxfs jffs2 hfs hfsplus squashfs udf sctp dccp tipc rds usb-storage 2>/dev/null || true")
    record("sysctl", "PASS", "kernel + modules")


# ======================================================================================
#                              STEP 6: PERMISSIONS
# ======================================================================================
def permissions():
    log("FILE PERMISSIONS")
    for path, mode in (("/etc/passwd", 0o644), ("/etc/group", 0o644), ("/etc/shadow", 0o640),
                       ("/etc/gshadow", 0o640), ("/etc/ssh/sshd_config", 0o600), ("/root", 0o700),
                       ("/boot/grub/grub.cfg", 0o600), ("/etc/crontab", 0o644),
                       ("/etc/sudoers", 0o440), ("/etc/sudoers.d", 0o750),
                       ("/etc/security/opasswd", 0o600)):
        if not Path(path).exists(): continue
        strip_immutable(path)
        if DRY:
            print(f"    DRY: chmod {mode:o} {path}")
        else:
            try: os.chmod(path, mode)
            except Exception as e: warn(f"chmod {path}: {e}")
    run("chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || true")
    run("chown root:root /etc/sudoers /etc/sudoers.d 2>/dev/null || true")
    record("permissions", "PASS", "critical modes")


# ======================================================================================
#                              STEP 7: SERVICES
# ======================================================================================
JUNK_SERVICES = ["avahi-daemon", "avahi-autoipd", "cups", "cups-browsed", "bluetooth",
                 "ModemManager", "packagekit", "usbmuxd", "speech-dispatcher",
                 "whoopsie", "kerneloops", "apport",
                 "nfs-server", "nfs-kernel-server", "rpcbind", "rpc-statd"]

def junk_services():
    if not DISABLE_JUNK:
        record("services", "SKIP", "disabled")
        return
    log("SERVICE MINIMISATION")
    units = out("systemctl list-unit-files")
    disabled = []
    for s in JUNK_SERVICES:
        if re.search(rf"^{s}\.", units, re.M):
            run(f"systemctl disable --now {s} 2>/dev/null || systemctl disable {s}")
            disabled.append(s)
    record("services", "PASS", f"disabled {len(disabled)}: {disabled}")


# ======================================================================================
#                              STEP 8: DEFENCE TOOLS
# ======================================================================================
def defence_tools():
    log("FAIL2BAN + AUDITD")
    pkgs = ["fail2ban", "auditd", "libpam-pwquality", "rkhunter", "lynis"]
    if ENABLE_UNATTENDED: pkgs.append("unattended-upgrades")
    pkg_install(pkgs)

    ignore = f"ignoreip = 127.0.0.1/8 {ADMIN_IP}\n" if ADMIN_IP else ""
    write("/etc/fail2ban/jail.local", f"""[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 4
{ignore}backend = systemd

[sshd]
enabled = true
port = {SSH_PORT}
""")
    run("systemctl enable --now fail2ban")
    run("systemctl restart fail2ban")

    write("/etc/audit/rules.d/99-hardening.rules", """-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload -p wa -k preload
-w /root/.ssh/ -p wa -k rootssh
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
""")
    run("augenrules --load")
    run("systemctl enable --now auditd")

    if INSTALL_AIDE:
        if pkg_install(["aide"]):
            if APPLY and not Path("/var/lib/aide/aide.db").exists():
                log(f"AIDE init (timeout {AIDE_TIMEOUT_SECONDS}s)...")
                rc, _, _ = run("aideinit -y -f 2>/dev/null || aide --init 2>/dev/null",
                               timeout=AIDE_TIMEOUT_SECONDS)
                if rc == 124:
                    warn("AIDE init timed out (continuing)")
                for src, dst in (("/var/lib/aide/aide.db.new", "/var/lib/aide/aide.db"),
                                 ("/var/lib/aide/aide.db.new.gz", "/var/lib/aide/aide.db.gz")):
                    if Path(src).exists() and not Path(dst).exists():
                        shutil.move(src, dst)

    if APPLY:
        for svc in ("fail2ban", "auditd"):
            if out(f"systemctl is-active {svc}") == "active":
                log(f"{svc} active")
            else:
                warn(f"{svc} NOT active")
    record("defence_tools", "PASS", "fail2ban + auditd")


# ======================================================================================
#                              STEP 9: PAM
# ======================================================================================
def pam_misc():
    log("PAM")
    write("/etc/security/pwquality.conf", """minlen = 12
minclass = 3
maxrepeat = 3
maxclassrepeat = 4
dictcheck = 1
usercheck = 1
enforcing = 1
""")
    write("/etc/security/limits.d/99-nocore.conf", "* hard core 0\n")

    if ENABLE_FAILLOCK:
        write("/etc/security/faillock.conf", """deny = 5
unlock_time = 900
fail_interval = 900
audit
silent
""")
        write("/usr/share/pam-configs/faillock", """Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
    [default=die]                   pam_faillock.so authfail
    sufficient                      pam_faillock.so authsucc
Account-Type: Primary
Account:
    required                        pam_faillock.so
""")
        if APPLY:
            run("pam-auth-update --enable faillock --force")
    record("pam", "PASS", "pwquality + faillock")


# ======================================================================================
#                              STEP 10: EXTRAS
# ======================================================================================
def extras():
    if ENABLE_UNATTENDED:
        write("/etc/apt/apt.conf.d/20auto-upgrades", """APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
""")
        run("systemctl enable --now unattended-upgrades")
    if WIPE_TMP_ON_BOOT:
        write("/etc/tmpfiles.d/tmp.conf", "D /tmp 1777 root root -\nD /var/tmp 1777 root root 30d\n")
    if out("systemctl is-active systemd-timesyncd") != "active":
        run("systemctl enable --now systemd-timesyncd")
    write("/etc/issue", "Authorized use only. Activity is monitored and logged.\\n")
    write("/etc/issue.net", "Authorized use only. Activity is monitored and logged.\\n")
    record("extras", "PASS", "updates + tmp + time + banner")


# ======================================================================================
#                              STEP 11: BASELINE
# ======================================================================================
def baseline():
    log("BASELINE")
    if DRY:
        print("    DRY: save baseline")
        return
    b = Path("/root/baseline")
    b.mkdir(exist_ok=True)
    for src, dst in (("/etc/passwd", "passwd"), ("/etc/group", "group"), ("/etc/crontab", "crontab")):
        if Path(src).exists():
            shutil.copy(src, b / dst)
    (b / "suid.txt").write_text(out("find / -xdev -perm -4000 -type f 2>/dev/null | sort") + "\n")
    (b / "ports.txt").write_text(out("ss -tulpn | awk 'NR>1{print $1,$5}' | sort") + "\n")
    (b / "enabled-units.txt").write_text(out("systemctl list-unit-files --state=enabled --no-pager") + "\n")
    (b / "uid0.txt").write_text(out("awk -F: '$3==0 {print $1}' /etc/passwd") + "\n")
    record("baseline", "PASS", "saved to /root/baseline")


# ======================================================================================
#                              STEP 12: FINALISE
# ======================================================================================
def finalise():
    if not SET_IMMUTABLE_SSH:
        record("finalise", "SKIP", "disabled")
        return
    if DRY:
        print("    DRY: chattr +i on sshd_config, sudoers")
        record("finalise", "PASS", "dry")
        return
    log("FINALISE: immutable bits")
    for f in ("/etc/ssh/sshd_config",
              "/etc/ssh/sshd_config.d/00-hardening.conf",
              "/etc/sudoers"):
        apply_immutable(f)
    record("finalise", "PASS", f"{len(IMMUTABLE_FILES)} files immutable")


# ======================================================================================
#                                   MAIN
# ======================================================================================
def main():
    print("=" * 70)
    print(f"MODE: {'DRY RUN - nothing changes' if DRY else 'APPLYING CHANGES'}")
    print("=" * 70)

    steps = [
        ("detect",      detect_env),
        ("recon",       recon),
        ("accounts",    accounts),
        ("ssh",         ssh),
        ("firewall",    firewall),
        ("sysctl",      sysctl),
        ("permissions", permissions),
        ("services",    junk_services),
        ("defence",     defence_tools),
        ("pam",         pam_misc),
        ("extras",      extras),
        ("baseline",    baseline),
        ("finalise",    finalise),
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

    # Summary
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
        # Show key location
        for user in SSH_USERS:
            try:
                pw = pwd.getpwnam(user)
                keyfile = Path(pw.pw_dir) / ".ssh" / "id_ed25519"
                if keyfile.exists():
                    print(f"\nPRIVATE KEY for '{user}': {keyfile}")
                    print(f"  Copy this key somewhere safe (AI chat / notes file).")
                    print(f"  Run:  sudo cat {keyfile}")
            except KeyError:
                pass
        print("\nMANUAL TODO:")
        print("  1. Copy the private key above (if generated).")
        print("  2. Test SSH from another terminal before closing this session.")
        print("  3. GRUB password (interactive, not scriptable).")


if __name__ == "__main__":
    main()
