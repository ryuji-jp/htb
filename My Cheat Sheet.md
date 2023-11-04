
# My Cheat Sheet

## 探索

### nmap
```
nmap -sC -sV -O -v -oV 10.10.10.17
```

## http/https 

### http 探索
```
gobuster dir -u http://shocker.htb/ -w /usr/share/wordlists/dirb/common.txt
```

### WordPress
```
wpscan --url https://brainfuck.htb --disable-tls-checks
```

### searchsploit
```
searchsploit wordpress plugin wp support
```

### searchsploit 詳細表示

```
searchsploit -x 41006.txt
```

### Word Press username 列挙
```
wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate u
```

### Word Press admin page

```
https://brainfuck.htb/wp-admin/
```
