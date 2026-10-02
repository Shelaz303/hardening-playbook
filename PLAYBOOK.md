# Competition Playbook — Linux Blue Team
Everything you need. Read top to bottom, run in order.

Replace USER/REPO with your GitHub username and repo name. Only 3 places.

==============================================================
SECTION 0 — SETUP (do this in the first 60 seconds)
==============================================================

Open TWO terminals. In BOTH, SSH into the target with the password they gave you.

Terminal 1 = WORK SESSION (you run everything here)
Terminal 2 = SAFETY SESSION (leave idle, never close, lifeline if SSH breaks)

On your WORK SESSION (Terminal 1), run this to sanity-check your identity:

    whoami
    ip -4 addr show | grep inet
    hostname


==============================================================
SECTION 1 — SSH HARDENING (manual, ~2 minutes)
==============================================================

Do this BEFORE the script. If it breaks, you still have the script to run.

--- 1a. Remove passphrase from your key (or make a new one) ---

If ~/.ssh/id_ed25519 exists and prompts for a passphrase:

    ssh-keygen -p -f ~/.ssh/id_ed25519 -N ""

Type the old passphrase once. Done.

If no key exists yet:

    ssh-keygen -t ed25519 -a 100 -N "" -f ~/.ssh/id_ed25519

--- 1b. Install your own pubkey ---

    mkdir -p ~/.ssh && chmod 700 ~/.ssh
    cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys

--- 1c. Test key auth works BEFORE disabling passwords ---

    ssh -o BatchMode=yes -i ~/.ssh/id_ed25519 <user>@127.0.0.1 'echo OK'

MUST print OK with no prompt. If it prompts or errors, STOP. Fix the key.
Do NOT proceed to 1d until this prints OK.

--- 1d. Back up sshd_config ---

    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

--- 1e. Edit sshd_config ---

    sudo nano /etc/ssh/sshd_config

Make sure these lines exist (add or uncomment):

    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes
    PermitEmptyPasswords no
    MaxAuthTries 3
    LoginGraceTime 30
    X11Forwarding no
    AllowTcpForwarding no
    ClientAliveInterval 300
    ClientAliveCountMax 2

Save: Ctrl+O, Enter, Ctrl+X.

--- 1f. Validate BEFORE restarting ---

    sudo sshd -t

Prints nothing = valid. Prints an error = do NOT restart, fix it first.

--- 1g. Restart sshd ---

    sudo systemctl restart ssh

--- 1h. Verify from SAFETY SESSION (Terminal 2) ---

In Terminal 2, open a NEW connection (don't close the old one):

    ssh <user>@<target-ip>

If it logs in without a password: GOOD. You can close Terminal 1.
If it fails: restore in Terminal 1:

    sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    sudo systemctl restart ssh


==============================================================
SECTION 2 — FETCH AND RUN THE HARDEN SCRIPT
==============================================================

--- 2a. Fetch the script ---

    curl -sL https://raw.githubusercontent.com/USER/REPO/main/02-harden.py -o /tmp/02-harden.py
    wc -l /tmp/02-harden.py

Should show around 550 lines. If 0 or an HTML error page, the URL is wrong.

--- 2b. Dry run (mandatory, changes nothing) ---

    sudo python3 /tmp/02-harden.py

Read the output. Check:
- Firewall TCP allowlist includes every scored service
- Any EXTRA UID 0 line = backdoor account (script locks it)
- Any NOPASSWD line = privilege escalation (script comments it out)
- Zero FAIL lines

--- 2c. Apply ---

    sudo python3 /tmp/02-harden.py --apply

Do NOT press Ctrl+C. Takes 2-5 minutes.

--- 2d. Read the SUMMARY at the bottom ---

Every [+] PASS = good.
[!] WARN = note it, usually not blocking.
[X] FAIL = investigate before moving on.


==============================================================
SECTION 3 — VERIFY THE HARDENING
==============================================================

Run these to confirm the script worked:

    sudo ufw status numbered
    sudo fail2ban-client status sshd
    sudo ss -tlnp
    nmap -sT -p- 127.0.0.1

What "good" looks like:
- ufw shows ~11 TCP rules + 2 UDP + loopback, default deny incoming
- fail2ban shows the sshd jail active
- ss -tlnp shows only scored services listening
- nmap confirms the same from outside perspective

Also confirm SSH config took:

    sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|maxauthtries) '


==============================================================
SECTION 4 — ONGOING DEFENSE (every 15-30 min)
==============================================================

Run these in the WORK SESSION periodically.

--- Who is logged in right now ---

    w

Any IP that is not your team = suspicious.

--- Any backdoor accounts appeared ---

    awk -F: '$3==0 {print $1}' /etc/passwd

Should always be ONLY: root

--- What is listening now ---

    sudo ss -tlnp

Any port not in your scored list = attacker service or missed service.

--- What is fail2ban blocking ---

    sudo fail2ban-client status sshd

Currently banned IPs appear here.

--- Live auth events ---

    sudo tail -50 /var/log/auth.log

Look for repeated "Failed password" or "Invalid user" from one IP.

--- Recent file changes ---

    sudo find /etc /root /home -mtime -1 -type f 2>/dev/null

Any file modified that you didn't touch = investigate.

--- New SUID binaries ---

    sudo find / -xdev -perm -4000 -type f -mtime -1 2>/dev/null

Attackers use SUID for privilege escalation. You should see none.


==============================================================
SECTION 5 — EMERGENCY RECOVERY
==============================================================

--- Locked out of SSH ---
From console (VMware/hypervisor/whatever):

    sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    sudo systemctl restart ssh

If no backup exists:

    sudo chattr -i /etc/ssh/sshd_config.d/00-hardening.conf
    sudo rm /etc/ssh/sshd_config.d/00-hardening.conf
    sudo systemctl restart ssh

--- Unban a teammate from fail2ban ---

    sudo fail2ban-client set sshd unbanip <IP>

--- Restore everything from script backup ---

    sudo ls /root/hardening-backup-*/
    sudo cp -a /root/hardening-backup-<ts>/. /

--- Edit a file that is immutable ---

    sudo chattr -i /etc/sudoers

--- Reboot a service that is misbehaving ---

    sudo systemctl restart ssh
    sudo systemctl restart fail2ban
    sudo systemctl restart auditd


==============================================================
SECTION 6 — MANUAL TASKS THE SCRIPT CANNOT DO
==============================================================

--- GRUB password (prevents console password reset) ---

    sudo grub-mkpasswd-pbkdf2

Type a password. Copy the hash output (starts with grub.pbkdf2.sha512...).

    sudo nano /etc/grub.d/40_custom

Add at the bottom:

    set superusers="admin"
    password_pbkdf2 admin <paste-hash-here>

Save. Then:

    sudo update-grub

--- Test every scored service from ANOTHER host ---

Not from the target itself. If SMTP, DNS, HTTP, IMAP are scored, connect
from a second machine and confirm each answers.

--- Service-specific hardening ---

Postfix, Dovecot, BIND, Apache, Nginx have their own configs and are not
touched by the script. Review each service's config for:
- No version disclosure
- TLS required
- No open relay (mail)
- No zone transfers to public (DNS)
- No directory listing (web)


==============================================================
SECTION 7 — QUICK REFERENCE CARD
==============================================================

--- One-time setup commands ---

    ssh-keygen -p -f ~/.ssh/id_ed25519 -N ""
    ssh -o BatchMode=yes -i ~/.ssh/id_ed25519 <user>@127.0.0.1 'echo OK'

--- Script workflow ---

    curl -sL https://raw.githubusercontent.com/USER/REPO/main/02-harden.py -o /tmp/h.py
    wc -l /tmp/h.py
    sudo python3 /tmp/h.py
    sudo python3 /tmp/h.py --apply

--- Health checks ---

    sudo ufw status numbered
    sudo fail2ban-client status sshd
    sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|maxauthtries) '
    sudo ss -tlnp
    w
    awk -F: '$3==0 {print $1}' /etc/passwd

--- Recovery ---

    sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config && sudo systemctl restart ssh
    sudo fail2ban-client set sshd unbanip <IP>
    sudo chattr -i /etc/sudoers
    sudo ls /root/hardening-backup-*/

--- Red flags to look for ---

    UID 0 that is not root              = backdoor
    Listening port that is not scored   = attacker service or missed service
    Login from an unknown IP            = compromise
    New file in /etc/cron.d/ or /root/.ssh/ = persistence
    New SUID binary in last 24h         = privesc attempt

==============================================================
END OF PLAYBOOK
==============================================================
