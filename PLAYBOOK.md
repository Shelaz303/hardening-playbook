# Competition Playbook — Linux Blue Team

Replace USER/REPO below with your GitHub username and repo name.

## Before You Start
1. Open TWO terminals. SSH into the target in both (with given password).
2. Terminal 1 = work session. Terminal 2 = safety session, leave idle, never close.

## Step 1 — Fetch the hardening script
    curl -sL https://raw.githubusercontent.com/USER/REPO/main/02-harden.py -o /tmp/02-harden.py
    wc -l /tmp/02-harden.py
Should show ~600 lines.

## Step 2 — Dry run (mandatory, nothing changes)
    sudo python3 /tmp/02-harden.py
Read the output. Look for:
- Firewall port allowlist: must include every scored service
- EXTRA UID 0 line: backdoor account, script will lock it
- NOPASSWD line: privilege escalation, script will comment it out
- Zero FAIL lines

## Step 3 — Apply
    sudo python3 /tmp/02-harden.py --apply
Do NOT press Ctrl+C. Takes 2-5 minutes.

## Step 4 — Save the private key (CRITICAL)
The script prints the key path at the end. Run:
    sudo cat /home/<user>/.ssh/id_ed25519
Copy the ENTIRE output (BEGIN to END). Paste into AI chat or a notes file.
This is your login key now. Lose it and you need console access.

## Step 5 — Verify SSH still works
In Terminal 2 (safety session):
    exit
    nano ~/mykey
    # paste the private key, Ctrl+O, Enter, Ctrl+X
    chmod 600 ~/mykey
    ssh -i ~/mykey <user>@<target-ip>
Works? Close Terminal 1. Fails? Emergency revert below.

## Step 6 — Verify hardening
    sudo ufw status numbered
    sudo fail2ban-client status sshd
    sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|maxauthtries|allowusers) '
    sudo ss -tlnp
    nmap -sT -p- 127.0.0.1

## Step 7 — Ongoing defense (every 15-30 min)
    w
    awk -F: '$3==0 {print $1}' /etc/passwd
    sudo ss -tlnp
    sudo fail2ban-client status sshd
    sudo tail -50 /var/log/auth.log

Red flags:
- UID 0 account that is not root = backdoor
- Listening port that is not scored = attacker service
- Login from unknown IP = compromise
- New files in /etc/cron.d/, /etc/systemd/system/, /root/.ssh/ = persistence

## Emergency Recovery
Locked out of SSH (from console):
    sudo chattr -i /etc/ssh/sshd_config.d/00-hardening.conf
    sudo rm /etc/ssh/sshd_config.d/00-hardening.conf
    sudo systemctl restart ssh

Unban teammate:
    sudo fail2ban-client set sshd unbanip <IP>

Restore from backup:
    sudo ls /root/hardening-backup-*/
    sudo cp -a /root/hardening-backup-<ts>/. /

Strip immutable to edit:
    sudo chattr -i /etc/ssh/sshd_config /etc/ssh/sshd_config.d/00-hardening.conf /etc/sudoers

See recent changes:
    sudo find /etc /root /home -mtime -1 -type f 2>/dev/null

New SUID binaries:
    sudo find / -xdev -perm -4000 -type f -mtime -1 2>/dev/null

## Manual tasks the script cannot do
- GRUB password (interactive prompt):
    sudo grub-mkpasswd-pbkdf2
    sudo nano /etc/grub.d/40_custom
    # add: set superusers="admin"  and: password_pbkdf2 admin <paste-hash>
    sudo update-grub
- Test every scored service from ANOTHER host.
- Service-specific hardening: Postfix, Dovecot, BIND, web server.

## Quick Reference
FETCH:  curl -sL https://raw.githubusercontent.com/USER/REPO/main/02-harden.py -o /tmp/h.py
DRY:    sudo python3 /tmp/h.py
APPLY:  sudo python3 /tmp/h.py --apply
KEY:    sudo cat ~/.ssh/id_ed25519
CHECK:  sudo fail2ban-client status sshd
UNBAN:  sudo fail2ban-client set sshd unbanip <IP>
REVERT: sudo rm /etc/ssh/sshd_config.d/00-hardening.conf && sudo systemctl restart ssh
