# Boot to root CTFs

Walkthroughs and notes of 'boot to root' CTFs mostly from VulnHub that I did for fun. I like to use vulnerable VMs from VulnHub (in addition to the ones I create) to organize hands-on penetration testing training sessions for junior security auditors/consultants :-)


#### Classic pentest methodology to do a Boot2root CTF...

##### Step 1 - Scanning and enumeration
```
   ➤ Network TCP/UDP port scans
   ➤ Service enumeration (HTTP,FTP,TFTP,SMB,NFS,SAMBA,SNMP,SMTP,..)
   ➤ User enumeration
   ➤ Vulnerability scans
   ➤ ...
   
Useful tools: nmap port scanner and (NSE) scripts, burp proxy, dirb/gobuster, nikto, various scripts (source:kali/Github/your owns),..
```
##### Step 2 - Gaining access
```
1. Exploiting security misconfiguration
   ➤ Anonymous access (e.g. FTP/TFTP/NFS/SMB, unprotected web admin console)
   ➤ Default or weak credentials (e.g. Web server, CMS, database, OS)
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
   ➤ Windows OS            (e.g. RCE: EternalBlue/MS17-010/CVE-2017-0143, MS14-068/CVE-2014-6324, MS08-067/CVE-2008-4250)
   ➤ ...
   
3. Exploiting Web application vulnerabilities
   ➤ SQL injections -> OS command execution (e.g. for MysQL: SELECT webshell INTO DUMPFILE '/path/to/webshell.php'; MSSQL: exec master..xp_cmdshell 'windows command')
   ➤ RFI & LFI
   ➤ Insecure upload function (i.e. webshell upload)
   ➤ OS command injections
   ➤ XXE (e.g. <!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/shadow" >]><foo>&xxe;</foo>]>)
   ➤ ...
   
Useful tools: various scripts, webshells, and reverse shells (source:kali/Github/your owns), searchsploit/ExploitDB, metasploit framework, burp proxy, sqlmap, kadimus, hydra, ncrack, impacket framework, CrackMapExec, DBvis..
```
##### Step 3 - Post-exploitation and Privilege escalation to become "root" or "Local System"
```
1. Exploiting security misconfiguration
   ➤ Windows OS (e.g. weak service permissions, weak file permissions, weak registry permissions, weak passwords, password reuse, clear-text passwords stored in scripts, unattended install files, AlwaysInstallElevated trick..)
   ➤ Linux OS   (e.g. SUDO misconfiguration, SUID misconfiguration, CRON misconfiguration, weak file permissions, weak passwords, password reuse, clear-text passwords in scripts and .bash_history..)
   
2. Exploiting unpatched known vulnerabilities 
   ➤ Linux local exploit   (e.g. Dirtyc0w CVE-2016-5195, eBPF exploit CVE-2017-16995, Overlayfs exploit CVE-2015-1328)
   ➤ Windows local exploit (e.g. HOT/ROTTEN/JUICY POTATO exploits, MS16-032 Secondary Logon Handle Privesc)
   ➤ Exploit for any vulnerable service/software running with "Local System" or local administrator privilege
   
Useful tools: various scripts such as 'LinEnum', 'LinPEAS', 'Linux Exploit suggester', 'WinPEAS','PowerSploit/PowerUp', 'Sherlock' and your owns,  searchsploit/ExploitDB, metasploit framework,..
```

##### Step 4 - Pivoting techniques to attack a second VM (or docker containers) only reachable from the 1rst one (some CTFs have several VMs :-))
```
1. Pivoting with SSH tunneling (e.g. dynamic port forward / socks5 proxy / use of proxychain)
2. Pivoting with Metasploit/Meterpreter (e.g. post/multi/manage/autoroute + socks5 proxy + use of proxychain; "portfwd add" rules)
3. Pivoting with RPIVOT (reverse socks4 proxy, it works like ssh dynamic port forwarding but in the opposite direction)
4. Pivoting with TCP tunnelling over HTTP via Webshells (e.g. Tunna webshell, reGeorg client/webshell)
5. Pivoting with SOCAT / RDP / VNC...
6. ...
```

##### Other - Mapping between a few boot2root VulnHub CTFs and common vulnerabilities/exploits

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
