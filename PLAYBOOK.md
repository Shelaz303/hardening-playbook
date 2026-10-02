# Competition Playbook — Linux Blue Team

Replace USER/REPO with your GitHub username and repo name.

==============================================================
HOW TO RUN — THE SEQUENCE (read this first)
==============================================================

Run everything in this exact order. Each step takes 1-5 minutes.

  STEP 1.  Open TWO terminals. SSH into the target in both.
           Terminal 1 = WORK (you type here)
           Terminal 2 = SAFETY (leave idle, never close)

  STEP 2.  Manual SSH hardening          (Section 1, ~2 min)
           Fix key, install pubkey, edit sshd_config, restart, verify.

  STEP 3.  Fetch the main harden script  (Section 2a)
           curl the script from GitHub.

  STEP 4.  Dry run the main script       (Section 2b)
           sudo python3 /tmp/02-harden.py
           Read the output. No FAIL lines? Continue.

  STEP 5.  Apply the main script         (Section 2c)
           sudo python3 /tmp/02-harden.py --apply

  STEP 6.  Fetch the service-defence script (Section 2e)
           curl the script from GitHub.

  STEP 7.  Dry run the service script
           sudo python3 /tmp/02b-defence.py

  STEP 8.  Apply the service script
           sudo python3 /tmp/02b-defence.py --apply

  STEP 9.  Verify everything             (Section 3)
           ufw status, fail2ban status, nmap localhost.

  STEP 10. Defend. Every 15-30 min run the checks in Section 4.

That is the whole flow. Same steps on every box. No per-competition edits.

==============================================================
SECTION 0 — SETUP (first 60 seconds)
==============================================================

Open TWO terminals. In BOTH, SSH into the target with the password they gave you.

Terminal 1 = WORK SESSION (you run everything here)
Terminal 2 = SAFETY SESSION (leave idle, never close, lifeline if SSH breaks)

On WORK SESSION, sanity-check your identity:

    whoami
    ip -4 addr show | grep inet
    hostname


==============================================================
SECTION 1 — SSH HARDENING (manual, ~2 minutes)
==============================================================

Do this BEFORE the scripts. If it breaks, you still have scripts to run.

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
SECTION 2 — RUN THE SCRIPTS (main + service defence)
==============================================================

--- 2a. Fetch the main harden script ---

    curl -sL https://raw.githubusercontent.com/USER/REPO/main/02-harden.py -o /tmp/02-harden.py
    wc -l /tmp/02-harden.py

Should show around 550 lines. If 0 or an HTML error page, the URL is wrong.

--- 2b. Dry run the main script (mandatory, changes nothing) ---

    sudo python3 /tmp/02-harden.py

Read the output. Check:
- Firewall TCP allowlist includes every scored service
- Any EXTRA UID 0 line = backdoor account (script locks it)
- Any NOPASSWD line = privilege escalation (script comments it out)
- Zero FAIL lines

--- 2c. Apply the main script ---

    sudo python3 /tmp/02-harden.py --apply

Do NOT press Ctrl+C. Takes 2-5 minutes.

--- 2d. Read the SUMMARY at the bottom ---

Every [+] PASS = good.
[!] WARN = note it, usually not blocking.
[X] FAIL = investigate before moving on.

--- 2e. Fetch, dry-run, apply the service-defence script ---

    curl -sL https://raw.githubusercontent.com/USER/REPO/main/02b-defence.py -o /tmp/02b.py
    wc -l /tmp/02b.py
    sudo python3 /tmp/02b.py
    sudo python3 /tmp/02b.py --apply

What 02b does:
- Detects which services are running (mail, web, DNS, FTP)
- Enables fail2ban jails for each running service
- Hardens each service's config (no open relay, TLS required, no zone transfer)
- Backs up + validates + auto-reverts on failure
- Skips services that are not running (safe on any box)

--- 2f. Read the 02b SUMMARY ---

Expected shape:

    [+] detect          PASS  N found
    [+] fail2ban_jails  PASS  active=X failed=0
    [+] postfix         PASS  added 5 lines         (only if postfix running)
    [+] dovecot         PASS  set 2 options         (only if dovecot running)
    [+] apache          PASS  hardened              (only if apache running)
    [+] nginx           PASS  hardened              (only if nginx running)
    [+] baseline        PASS  refreshed


==============================================================
SECTION 3 — VERIFY THE HARDENING
==============================================================

    sudo ufw status numbered
    sudo fail2ban-client status
    sudo fail2ban-client status sshd
    sudo ss -tlnp
    nmap -sT -p- 127.0.0.1

What "good" looks like:
- ufw shows ~11 TCP rules + 2 UDP + loopback, default deny incoming
- fail2ban shows the sshd jail active, plus any service jails from 02b
- ss -tlnp shows only scored services listening
- nmap confirms the same from outside perspective

Confirm SSH config took:

    sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|maxauthtries) '


==============================================================
SECTION 4 — ONGOING DEFENSE (every 15-30 min)
==============================================================

    w
    awk -F: '$3==0 {print $1}' /etc/passwd
    sudo ss -tlnp
    sudo fail2ban-client status sshd
    sudo tail -50 /var/log/auth.log
    sudo find /etc /root /home -mtime -1 -type f 2>/dev/null
    sudo find / -xdev -perm -4000 -type f -mtime -1 2>/dev/null


==============================================================
SECTION 5 — EMERGENCY RECOVERY
==============================================================

--- Locked out of SSH ---
From console:

    sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    sudo systemctl restart ssh

If no backup:

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

--- Reboot a service ---

    sudo systemctl restart ssh
    sudo systemctl restart fail2ban
    sudo systemctl restart auditd


==============================================================
SECTION 6 — MANUAL TASKS THE SCRIPTS CANNOT DO
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

--- Anything not covered by 02b ---

If the box runs a scored service that 02b doesn't handle (custom app,
Redis, MQTT, etc.), it needs manual review. Check:
- No version disclosure
- TLS required
- Auth required
- Not exposed to the world if it should be internal


==============================================================
SECTION 7 — QUICK REFERENCE CARD
==============================================================

--- One-time setup ---

    ssh-keygen -p -f ~/.ssh/id_ed25519 -N ""
    ssh -o BatchMode=yes -i ~/.ssh/id_ed25519 <user>@127.0.0.1 'echo OK'

--- Full run sequence (copy-paste) ---

    # Main harden
    curl -sL https://raw.githubusercontent.com/USER/REPO/main/02-harden.py -o /tmp/h.py
    wc -l /tmp/h.py
    sudo python3 /tmp/h.py
    sudo python3 /tmp/h.py --apply

    # Service defence
    curl -sL https://raw.githubusercontent.com/USER/REPO/main/02b-defence.py -o /tmp/02b.py
    wc -l /tmp/02b.py
    sudo python3 /tmp/02b.py
    sudo python3 /tmp/02b.py --apply

--- Health checks ---

    sudo ufw status numbered
    sudo fail2ban-client status
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

--- Red flags ---

    UID 0 that is not root                  = backdoor
    Listening port that is not scored       = attacker service or missed service
    Login from an unknown IP                = compromise
    New file in /etc/cron.d/ or /root/.ssh/ = persistence
    New SUID binary in last 24h             = privesc attempt

==============================================================
END OF PLAYBOOK
==============================================================
