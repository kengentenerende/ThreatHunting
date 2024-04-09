# THP Cheat Sheet

**Useful Links**
[The ThreatHunting Project](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts)

# Network Traffic Hunting

## Hunting Tools
- Wireshark - [PA Toolkit Plugin](https://github.com/pentesteracademy/patoolkit)
- NetworkMiner
- RSA NetWitness Investigator
- Zeek

## ARP Threats
- Tens, hundreds etc of ARP broadcast messages in a small amount of time
- Two identical MAC addresses in the network with different IP addresses

- Gratuitous ARP packets sent by attacker
> **_Wireshark_** select View > Name Resolution > Resolve Physical Addresses
> Check Spam ARP Requests, timing etc

**Normal ARP**
```
Ethernet II, Src: (MACADDR), Dst: ff:ff:ff:ff:ff:ff:
Opcode: request (1)
Target MAC address: 00:00:00:00:00:00:
```
```
Ethernet II, Src: (MACADDR), Dst: 00:20:56:a2:f4:d0
Opcode: reply (2)
Sender MAC address: 00:20:56:a2:f4:d0
```
**Suspicious ARP**
```
Who has 10.10.10.1?	Tell 10.10.10.100
Who has 10.10.10.2?	Tell 10.10.10.100
Who has 10.10.10.3?	Tell 10.10.10.100
Who has 10.10.10.5? Tell 10.10.10.100
```
**ARP Poisoning**

- Address Resolution Protocol Poisoning (also known as ARP Spoofing or Man In The Middle (MITM) attack) is a type of attack that involves network jamming/manipulating by sending malicious ARP packets to the default gateway. The ultimate aim is to manipulate the "IP to MAC address table" and sniff the traffic of the target host.

| Notes                                       | Wireshark filter                                                       |   |   |   |
|---------------------------------------------|------------------------------------------------------------------------|---|---|---|
| Global search                               | `arp`                                                                    |   |   |   |
| Opcode 1: ARP requests.                     | `arp.opcode == 1`                                                      |   |   |   |
| Opcode 2: ARP responses.                    | `arp.opcode == 2`                                                      |   |   |   |
| Opcode 2: ARP responses.                    | `arp.dst.hw_mac==00:00:00:00:00:00 `                                   |   |   |   |
| Hunt: Possible ARP poisoning detection      | `arp.duplicate-address-detected or arp.duplicate-address-frame`        |   |   |   |
| Hunt: Possible ARP flooding from detection: | `((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address`) |   |   |   |

## ICMP Threats
- **Type 8** & **Code 0** indicate packet is an echo request


**Suspicious ICMP**
- Watch for sprays of ping requests
- Unusual type/codes within packets of the request. 
	- *IE: Time Stamp Requests*
    > icmp.type==3 and icmp.code==3   

**ICMP Tunnelling**
- A large volume of ICMP traffic or anomalous packet sizes are indicators of ICMP tunnelling. Still, the adversaries could create custom packets that match the regular ICMP packet size (64 bytes), so it is still cumbersome to detect these tunnelling activities. 

| Notes  | Wireshark filters    |  |  |  |
|---|---|---|---|---|
| Global search    | icmp           |  |  |  |
| "ICMP" options for grabbing the low-hanging fruits:<br>   <br>- Packet length.<br>- ICMP destination addresses.<br>- Encapsulated protocol signs in ICMP payload.       | data.len > 64 and icmp           |  |  |  |

## TCP Threats
*3-way handshack: SYN, SYN/ACK, ACK*
- SYN Packets sprays, smart TCP attacks, port scanning on single or multiple IPs
- Many TCP SYN packets without corresponding SYN/ACK packets

> [Wireshark TCP Reference](https://www.wireshark.org/docs/dfref/t/tcp.html)
> **_Wireshark_** Edit > Preferences > Protocols > TCP > *(Uncheck Box)*Relative sequence numbers

**Normal TCP**
```
Transmission Control Protocol, Seq: 0
Flags: 0x002 (SYN)
```
```
Transmission Control Protocol, Seq: 0, Ack: 1,
Flags: 0x012 (SYN, ACK)
[SEQ/ACK analysis]
[This is an ACK to the segment in frame: 2]
[The RTT to ACK the segment was: 0.0001100 seconds]
```
## DHCP Threats
DORA (DHCP Discover, DHCP Offer, DHCP Request, DHCP Acknowledgement)
*UDP Ports 67-68*
*Look for DHCP Server Identifier in Wireshark*

**DHCP**

```
User Datagram Protocol, Src Port: 68, Dst Port: 67
Bootstrap Protocol (Discover)
Options: (53) DHCP Message Type (Discover)
	Your (client) IP address: 0.0.0.0
	Length: 1
	DHCP: Discover (1)
```
```
Option: (53) DHCP Message Type (Offer)
	Length: 1
	DHCP: Offer (2)
```
| Notes    | Wireshark Filter   |  |  |  |
|---|---|---|---|---|
| Global search.    | `dhcp or bootp`           |  |  |  |
| Filtering the proper DHCP packet options is vital to finding an event of interest. <br>    <br>"DHCP Request" packets contain the hostname information<br>"DHCP ACK" packets represent the accepted requests<br>"DHCP NAK" packets represent denied requests   <br>Due to the nature of the protocol, only "Option 53" ( request type) has   predefined static values. You should filter the packet type first, and then   you can filter the rest of the options by "applying as column" or   use the advanced filters like "contains" and "matches".    | `Request: dhcp.option.dhcp == 3`   <br>`ACK: dhcp.option.dhcp == 5`<br>`NAK: dhcp.option.dhcp == 6 `      |  |  |  |
| "DHCP Request" options for   grabbing the low-hanging fruits:<br>   <br>    <br>Option 12: Hostname.<br>Option 50: Requested IP address.<br>Option 51: Requested IP lease time.<br>Option 61: Client's MAC address.       | `dhcp.option.hostname contains "keyword"`           |  |  |  |
| "DHCP ACK" options for   grabbing the low-hanging fruits:<br>      <br>Option 15: Domain name.  <br>Option 51: Assigned IP lease time.       | `dhcp.option.domain_name contains "keyword"`           |  |  |  |
| "DHCP NAK" options for grabbing the low-hanging fruits:<br>    <br>Option 56: Message (rejection details/reason).       | As the message could be unique according to the case/situation, <br>It is suggested   to read the message instead of filtering it. <br>Thus, the analyst could create a   more reliable hypothesis/result by understanding the event circumstances.    |  |  |  |

## DNS Threats
- Port 53, should only be **UDP** not **TCP**
- DNS traffic should only go to DNS servers
- Should see DNS Responses to DNS Queries
> [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/d/dns.html)
> Look for DNS Queries with no DNS responses or vice versa.
> Zone Tranfers occur over TCP/53

**ENCODED-COMMANDS.MALICIOUSDOMAIN.COM**

- When this query is routed to the C2 server, the server sends the actual malicious commands to the host. As the DNS queries are a natural part of the networking activity, these packets have the chance of not being detected by network perimeters. A security analyst should know how to investigate the DNS packet lengths and target addresses to spot these anomalies. 

| Notes                                       | Wireshark filter                                            |
|------------------------------------------------------------------|----------------------------------------|
| Global search                                                    | `dns`                                    |
| DNS options for grabbing the low-hanging fruits:                 | `dns contains "dnscat"`                |
| - Query length.                                                    | `dns.qry.name.len > 15 and !mdns`      |
| - Anomalous and non-regular names in DNS addresses.                |                                        |
| - Long DNS addresses with encoded subdomain addresses.             |                                        |
| - Known patterns like dnscat and dns2tcp.                          |                                        |
| - Statistical analysis like the anomalous volume of DNS requests for a particular target. |                                    |
| - !mdns: Disable local link device queries.                        |                                        |

## HTTP/HTTPS Threats
**HTTP**
Port 80, 8080 - plantext traffic, typically in FQDN format.

- Traffic should *not* be encrypted in common HTTP ports
- Search for URL encoded queries for sql injection, lfi-rfi activity
- User-Agent for possible scanners - *IE: sqlmap*
- TCP Spurious Retransmission -> Investigate [TCP Zero Window](https://wiki.wireshark.org/TCP%20ZeroWindow)

| Notes    |    <br>Wireshark Filter    |  |  |  |
|---|---|---|---|---|
| Global search<br>Note: HTTP2 is a revision of the HTTP protocol for better performance and security.<br>It supports binary data transfer and request&response multiplexing.    | `http`<br>`http2`           |  |  |  |
| "HTTP Request Methods" for   grabbing the low-hanging fruits:<br>    <br>- GET <br>- POST<br>- Request: Listing all requests       | `http.request.method == "GET"`  <br>`http.request.method == "POST"`   <br>`http.request`           |  |  |  |
| "HTTP Response Status Codes" for   grabbing the low-hanging fruits:<br>      <br>- 200 OK: Request successful.<br>- 301 Moved Permanently: Resource is moved to a new URL/path (permanently).<br>- 302 Moved Temporarily: Resource is moved to a new URL/path (temporarily).<br>- 400 Bad Request: Server didn't understand the request.<br>- 401 Unauthorised: URL needs authorisation (login, etc.).<br>- 403 Forbidden: No access to the requested URL. <br>- 404 Not Found: Server can't find the requested URL.<br>- 405 Method  Not Allowed: Used method is not suitable or blocked.<br>- 408 Request Timeout: Request look longer than server wait time.<br>- 500 Internal Server Error: Request not completed, unexpected error.<br>- 503 Service Unavailable: Request not completed server or service is down.       | `http.response.code == 200`  <br>`http.response.code == 401`  <br>`http.response.code == 403`<br>`http.response.code == 404`<br>`http.response.code == 405`<br>`http.response.code == 503 `          |  |  |  |
| "HTTP Parameters" for grabbing the low-hanging fruits:<br>   <br>- User agent: Browser and operating system identification to a web server application.<br>- Request URI: Points the requested resource from the server.<br>- Full *URI: Complete URI information. <br>  <br>*URI: Uniform Resource Identifier.    | `http.user_agent contains "nmap"`<br>`http.request.uri contains "admin"`<br>`http.request.full_uri contains "admin" `          |  |  |  |
| "HTTP Parameters" for grabbing the low-hanging fruits: <br>    <br>- Server: Server service name.<br>- Host: Hostname of the server<br>- Connection: Connection status.<br>- Line-based text data: Cleartext data provided by the server. <br>- HTML Form URL Encoded: Web  form information.       | `http.server contains "apache"`<br>`http.host contains "keyword"`<br>`http.host == "keyword"` <br>`http.connection == "Keep-Alive"`    <br>`data-text-lines contains "keyword"  `         |  |  |  |

> **_Wireshark_** Statistics > Conversations >  TCP Tab

> **_Wireshark_** Statics > Protocol Hierarchy

> **_Wireshark_** File Export Objects > HTML

> **_Wireshark_** Statics > Endpoints

> **_Wireshark_** Statics > Conversions

Wireshark References
> HTTP Filters [here](https://www.wireshark.org/docs/dfref/h/http.html) and [here](https://www.wireshark.org/docs/dfref/h/http2.html)
> HTTPS Filters [here](https://www.wireshark.org/docs/dfref/s/ssl.html)

**HTTPS**
Ports 443, 8443 TCP Encrypted Traffic and in FQDN Format
- Look for traffic *not* encrypted and SSL packet details are empty
- Look for Server Key Exchange and Client key Exchange packet

**Normal HTTPS**
```
Content Type = Handshake
Handshake Protocol: Client Hello
Version: TLS 1.2
Cipher Suites: (11 suites)
Compression Method: (1 method)
```
**Decrypting HTTPS Traffic**

> "right-click" menu or "Edit --> Preferences --> Protocols --> TLS" menu to add/remove key log file

**User Agent Analysis**
| Notes    | Wireshark Filter    |  |  |  |
|---|---|---|---|---|
| Global search.    | `http.user_agent`           |  |  |  |
| Research outcomes for grabbing the low-hanging fruits: <br>    <br>- Different user agent information from the same host in a short time notice.<br>- Non-standard and custom user agent info.<br>- Subtle spelling differences. ("Mozilla" is not the same as "Mozlilla" or "Mozlila")<br>- Audit tools info like Nmap, Nikto, Wfuzz and sqlmap in the user agent field.<br>- Payload data in the user agent field.       | `(http.user_agent contains "sqlmap") or (http.user_agent contains"Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")`           |  |  |  |
 
## Unknown Traffic Threats
- Inspect protocols on network for strange protocols. *IE: IRC Chats, C2 Servers etc*
> **_Wireshark_** Analyze > Enable Protocols

# Network Hunting & Forensics

**Zeek**

[Zeek Cheat Sheet](https://darkdefender.medium.com/the-zeek-cut-cheat-sheet-d16663439ef4)

[Active Countermeasures Lab](https://activecm.github.io/threat-hunting-labs/)

**Zeek-Cut**

```
head conn.log | zeek-cut -c id.orig_h id.orig_p id.resp_h id.resp_p proto service duration
```
- Use `head` to check for fields
- `zeek-cut` to reduce the columns
```
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head
```
- Sort command. * `-n` will sort based on numeric order * `-r` will reverse the sort so that the largest numbers are at the top * `-k 7` tells sort to use the 7th column, which is our duration column
```
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | grep udp | sort -nrk 7 | head
```
- UDP Connection with longest duration
```
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head
```

`awk` is a powerful scripting tool. However, the syntax starts to get very messy all on one line like this.

- `BEGIN{ FS="\t" } `- Set the FS (field separator) variable to a tab character. This is what is separating columns in our Zeek logs as well as what we want to use in our output. BEGIN means this instruction is only executed one time, before any data is processed.
- `{ arr[$1 FS $2 FS $3 FS $4] += $5 }` - Creates an array (named arr) and adds up the duration ($5 is the fifth field, which is our duration). The important part here is that we are using the concatenation of the first four fields ($1 through $4) as our array key. Which means that as long as the source and destination IPs, destination port, and protocol remain the same it will add the duration to the total. `awk` executes this instruction repeatedly for every line of data.
- `END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }` - Here we are looping through all the elements in the array and printing out the results. `END` signifies that `awk` only executes this instruction one time, after processing all the data.

```
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head
```

Here is a breakdown of the above command:

- `cat dns.log | zeek-cut query `- Ignore everything but the query field, which tells us what domain was requested.
- `sort | uniq` - Remove all duplicate queries.
- `rev` - Takes each query and reverses the string, so that www.google.com becomes moc.elgoog.www. The reason we do this is to strip the query down to the top level domain (TLD), like .com or .net, and the next portion of the domain.
- `cut -d '.' -f 1-2` - Split the full query on every period and keep the first and second elements (e.g moc.elgoog.www -> moc.elgoog).
- `rev` - Reverse the string again to bring it back to normal.
- `sort | uniq -c` - Remove and count duplicates.
- `sort -nr | head` - Output the entries with the most duplicates.

```
cat dns.log | zeek-cut query answers | grep 'r-1x\.com' | cut -f 2 | cut -d ' ' -f 3 | egrep '([0-9]{0,3}\.)[0-9]{0,3}' | sort | uniq
```
Here's the breakdown of your command:

- `cat dns.log`: Reads the content of the dns.log file.
- `zeek-cut query answers`: Extracts the columns "query" and "answers" using zeek-cut.
- `grep r-1x\.com:` Filters lines containing the string 'r-1x.com'.
- `cut -f 2`: Extracts the second field (column) using a space as the delimiter.
- `cut -d ' ' -f 3`: Further extracts the third field using a space as the delimiter.
- `egrep '([0-9]{0,3}\.)[0-9]{0,3}'`: Uses extended grep to filter lines containing a specific pattern of numbers (IPv4 Address)
- `sort`: Sorts the lines.
- `uniq`: Removes duplicate lines, assuming the input is sorted.

| Use Case                                            | Description                                                                                         |   |   |   |
|-----------------------------------------------------|-----------------------------------------------------------------------------------------------------|---|---|---|
| `sort \| uniq  `                                      | Remove duplicate values.                                                                            |   |   |   |
| `sort \| uniq -c   `                                  | Remove duplicates and count the number of occurrences for each value.                               |   |   |   |
| `sort -nr  `                                          | Sort values numerically and recursively.                                                            |   |   |   |
| `rev`                                                 | Reverse string characters.                                                                          |   |   |   |
|  `cut -f 1`                                           | Cut field 1.                                                                                        |   |   |   |
| `cut -d '.' -f 1-2`                                   | Split the string on every dot and print keep the first two fields.                                  |   |   |   |
| `grep -v 'test'`                                      | Display lines that  don't match the "test" string.                                                  |   |   |   |
| `grep -v -e 'test1' -e   'test2'   `                  | Display lines that don't match one or both "test1" and "test2" strings.                             |   |   |   |
| `file`                                                | View file information.                                                                              |   |   |   |
| `grep -rin Testvalue1 * \|   column -t \| less -S`    | Search the "Testvalue1" string everywhere, organise column spaces and view the output with less.    |   |   |   |
| `wc -l`    | Used to count the number of lines in a file    |   |   |   |

**TShark**
> tshark -r sample.pcap -T fields -e ip.src -e ip.dst -e udp.dstport -e frame.time_delta_displayed 'ip.src==192.168.88.2 && ip.dst==165.227.88.15' | head -25

> tshark -r sample.pcap -T fields -E separator=, -e ip.len -e frame.time_delta_displayed 'ip.src==192.168.88.2 && ip.dst==165.227.88.15' > sample.csv

The tshark arguments are:

- `-r sample.pcap` - The path to your pcap file.
- `-T fields` - Tell tshark to output values of the specified fields.
- `-e ip.src -e ip.dst -e udp.dstport -e frame.time_delta_displayed `- These options are telling tshark which fields should be printed. In this case, we want the source and destination IP, the destination port (you could also try tcp.dstport) and the time since the previous packet was sent. This syntax is the same as used in Wireshark. 
- `ip.src==192.168.88.2 && ip.dst==165.227.88.15` - The filter to be used. This uses Wireshark’s display filter syntax. In this case we are telling tshark to only process packets sent from 192.168.88.2 to 165.227.88.15.
- `> sample.csv` - Output file

> tshark -r sample.pcap -T fields -e dns.qry.name udp.dstport==53 | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -10

The tshark arguments are explained here:

- `-r sample.pcap` - The path to your pcap file.
- `-T fields` - Tell tshark to output values of the specified fields.
- `-e dns.qry.name` - The field to print from every DNS packet. This syntax is the same as used in Wireshark. You can find a list of other DNS-related fields in Wiresharks’ documentation.
- `udp.dstport==53` - The filter to be used. This uses Wireshark’s display filter syntax. In this case we are telling tshark to only process packets sent to UDP port 53.

# Webshell Analysis
- Reference suspicious files on servers/web servers
- Look for cmd.exe powershell.exe or eval()
- Analyze IIS and Apache logs
- Use baselines for locating new processes, drivers, intsalled applications, files/services
- Analyze suspicious JPEG images

**Webshell PHP Functions**
> eval()

> base64_decode()

> str_rot13()

> gzinflate()

> $_POST['password'])

**JPEG PHP Exif**
[exiftool(-k)](http://www.sno.phy.queensu.ca/~phil/exiftool/)
```
<?php
echo "Find file *.jpg :<br />\n List file may be negative :<br />\n";
$exifdata = array();
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator('.')) as $filename)
{
    //echo "$filename<br />\n";
        if      (strpos($filename,".jpg")==true or strpos($filename,".JPG")==true)
        {
                $exif = read_exif_data($filename);
/*1*/   if (isset($exif["Make"])) {
                        $exifdata["Make"] = ucwords(strtolower($exif["Make"]));
                        if (strpos($exifdata["Make"],"/e")==true) echo "$filename<br />\n";
                }
/*2*/   if (isset($exif["Model"])) {
                        $exifdata["Model"] = ucwords(strtolower($exif["Model"]));
                        if (strpos($exifdata["Model"],"/e")==true) echo "$filename<br />\n";
                }
/*3*/   if (isset($exif["Artist"])) {
                        $exifdata["Artist"] = ucwords(strtolower($exif["Artist"]));
                        if (strpos($exifdata["Artist"],"/e")==true) echo "$filename<br />\n";
                }
/*4*/   if (isset($exif["Copyright"])) {
                        $exifdata["Copyright"] = ucwords(strtolower($exif["Copyright"]));
                        if (strpos($exifdata["Copyright"],"/e")==true) echo "$filename<br />\n";
                }
/*5*/   if (isset($exif["ImageDescription"])) {
                        $exifdata["ImageDescription"] = ucwords(strtolower($exif["ImageDescription"]));
                        if (strpos($exifdata["ImageDescription"],"/e")==true) echo "$filename<br />\n";
                }
/*6*/   if (isset($exif["UserComment"])) {
                        $exifdata["UserComment"] = ucwords(strtolower($exif["UserComment"]));
                        if (strpos($exifdata["UserComment"],"/e")==true) echo "$filename<br />\n";
                }
        }
}
echo "Done!";
?>
```

**Linux Commands**
```
find. -type f -name '*.php' -mtime -1
find. -type f -name '*.txt' -mtime -1
find. -type f -name '*.php' | xargs grep -l "eval *("
find. -type f -name '*.txt' | xargs grep -l "eval *("
find. -type f -name '*.php' | xargs grep -l "base64_decode*("
```
```
find . -type f -name '*.php' | xargs grep -l "(mail|fsocketopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("
find . -type f -name '*.txt' | xargs grep -l "(mail|fsocketopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("
```
**Windows Commands**

[.ps1 scripts](https://github.com/securycore/ThreatHunting)

[Get-FullPathFileStacking.ps1](https://gist.github.com/anonymous/e8ced9c92a689e4cdb67fe0417cd272c)
```
 .\Get-FullPathFileStacking.ps1 c:\inetpub\wwwroot\test
```

[Get-TimeDiffFileStacking.ps1](https://gist.github.com/anonymous/dcfa7cb4933b30954737ccbf51024c1a)
```
.\Get-TimeDiffFileStacking.ps1 c:\inetpub\wwwroot\test "7/12/2017 9:00am"
```
[Get-W3WPChildren.ps1](https://gist.github.com/anonymous/140f4455ede789f7c3c3419946d1bd66)

[Compare-FileHashesList.ps1](https://github.com/WiredPulse/PowerShell/blob/9bf3161a641dc6da4dd1a4ca2e2c908a1b30f92d/System_Information/Compare-FileHashesList.ps1)
```
.\Compare-FileHashesList.ps1 -ReferenceFile C:\inetpub\Baseline-Test.csv -DifferenceFile C:\inetpub\MD5-Test.csv
```
```
.\Compare-FileHashesList.ps1 -ReferenceFile C:\inetpub\Baseline-Test.csv -DifferenceFile C:\inetpub\MD5-Test.csv | Format-Table -AutoSize
```


- Traverse PHP files with suspicious commands
```
get-childitem -recurse include "*.php" | select-string "(mail|fsockopen|pfsockopen|exec\b|system\b|passthru|eval\b|base64_decode)" | %{"$($_.filename):$($_.line)"}| Out-Gridview
```
- Get MD5 for Baselining
```
Get-ChildItem -path c:\inetpub\wwwroot\test -file -recurse | Get-FileHash -Algorithm MD5 | Export-CSV c:\inetpub\MD5-Test.csv
``` 

**Webshell Toolkit**

[Log Parser Studio Tool](https://gallery.technet.microsoft.com/office/Log-Parser-Studio-cd458765) - IIS Web Logs

```
Sample Script
SELECT TOP 100 date, time, s-sitename, s-ip, cs-method, cs-uri-stem, cs-uri-query, s-port, cs-username, c-ip, cs(User-Agent), cs(Referer), sc-status, sc-substatus, sc-win32-status, sc-bytes, cs-bytes, time-taken
FROM '[LOGFILEPATH]' 
ORDER BY date
```
```
Select Top 20 cs-uri-stem, cs-uri-query, count(*) as Total, MAX(time-taken) as MaxTime, AVG(time-taken) as AvgTime
From '[LOGFILEPATH]'
Group By cs-uri-stem, cs-uri-query
Order by Total DESC
```
```
Select cs-uri-stem, TO_UPPERCASE(EXTRACT_EXTENSION(cs-uri-stem)) as Extension, Count(*) as [Total Hits]
From '[LOGFILEPATH]'
Where Extension like '%asp%' and sc-status=200
Group by cs-uri-stem, Extension
Order by [Total Hits] Desc
```

[Loki](https://github.com/loki-project/loki)
> MD5/SHA1/SHA256 hashes\
> Yara rules\
> Hard/soft filenames based on regular expressions\

> loki -p c:\inetpub\wwwroot\test

[NeoPI](https://github.com/Neohapsis/NeoPI)
> Python script - detect obfuscated/encrypted content

> python neopi.py "C:\inetpub\wwwroot" -a -A

[BackdoorMan](https://github.com/cys3c/BackdoorMan)
> Python script - Detect malicious code in **PHP** scripts
> Detects shells via signature database
> Recognize web backdoors
> Use [shellray](https://shellray.com/)/[VirusTotal](https://virustotal.com/) and [UnPHP](http://www.unphp.net/)

[PHP-Malware-Finder](https://github.com/nbs-system/php-malware-finder)
> Find obfuscated code
> Yara Rules

[UnPHP](http://www.unphp.net/)
> Online PHP Obfuscator

[Web Shell Detector](http://www.shelldetector.com/)
> PHP, Perl, ASP and ASPX detection
> Signature database

[NPROCWATCH](http://udurrani.com/0fff/tl.html)
> Display new spawned processes after  NPROCWATCH was executed

*Others*
[Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/)
[Invoke-ExchangeWebShellHunter](https://github.com/FixTheExchange/Invoke-ExchangeWebShellHunter)

## Malware Analysis

**Windows Event Logs**

>Successful Logon (ID 4624)

>Failed Logon (ID 4625)

>Kerberos Authentication (ID 4768)

>Kerberos Service Ticket (ID 4776)

>Assignment of Administrator Rights (ID 4672)

>Unknown username or password (ID 529)

>Account logon time restriction violation (ID 530)

>Account currently disabled (ID 531)

>User account has expired (ID 532)

>User not allowed to logon to the computer (ID 533)

>User has not been granted the requested logon type (ID 534)

>The account's password has expired (ID 535)

>The NetLogon component is not active (ID 536)

>The logon attempt failed for other reasons (ID 537)

>Account lockout (ID 539)

>Log clearing (ID 1102 and 104)


**Detection Tools**



## Powershell Tools
[Kansa](https://github.com/davehull/Kansa)
>Incident response, breach hunts, building baselines
> Reference links [here](http://trustedsignal.blogspot.com/search/label/Kansa) and [here](http://www.powershellmagazine.com/2014/07/18/kansa-a-powershell-based-incident-response-framework/)

[PSHunt](https://github.com/Infocyte/PSHunt)
>Scan remote endpoints for IOCS

[NOAH](https://github.com/giMini/NOAH)

# Intel-driven Threat Hunting
- [Hunting for APT in network logs (PPT)](https://www.slideshare.net/OlehLevytskyi1/hunting-for-apt-in-network-logs-workshop-presentation)
- [Hunting for APT in network logs - Oleh Levytskyi, Bogdan Vennyk](https://www.youtube.com/watch?v=PmwFpwTCy88&t=5979s)

## Initial Access: RDP Bruteforce
`Field of Interest:`
- sourcetype=`bro:rdp:json`
- cookie
- id.orig_h
- id.orig_p=`Incrementing Port`
- id.resp_h
- id.resp_p=`3389`

```
index="rdp_bruteforce" sourcetype="bro:rdp:json" id.resp_p=3389
| transaction cookie
| eval total_srcp=mvcount(src_port)
| table cookie, id.orig_h, total_srcp, id.resp_h, id.resp_p
```

## Initial Access: SSH Bruteforce
`Field of Interest:`
- sourcetype=`bro:ssh:json`
- id.orig_h
- id.orig_p=`Incrementing Port`
- id.resp_h
- id.resp_p=`3389`
- server
- client

```
index="ssh_bruteforce" sourcetype="bro:ssh:json" id.resp_p=22
| transaction id.orig_h
| eval total_srcp=mvcount(src_port)
| table id.orig_h, total_srcp, id.resp_h, id.resp_p, server, client
```

## Initial Access: Beaconing
`Field of Interest:`
- sourcetype=`bro:http:json`
- id.orig_h
- id.orig_p
- id.resp_h
- id.resp_p
- user_agent

uri_path=
- `/ca`
- `/dpixel`
- `/__utm.gif`
- `/pixel.gif`
- `/g.pixel`
- `/dot.gif`
- `/updates.rss`
- `/fwlink`
- `/cm`
- `/cx`
- `/pixel`
- `/match`
- `/visit.js`
- `/load	  `
- `/push`
- `/ptj`
- `/j.ad`
- `/ga.js`
- `/en_US/all.js`
- `/activity`
- `/IE9CompatViewList.xml`

**Beacon URI Path**
```
index="cobaltstrike_beacon" sourcetype="bro:http:json" 192.168.151.181
| transaction user_agent
| table uri_path, user_agent, src_ip, dest_ip
```
**Beacon URI Path**
```
index=* (uri_path=*/ca* OR */dpixel* OR */__utm.gif* OR */pixel.gif* OR */g.pixel* OR */dot.gif* OR */updates.rss* OR */fwlink* OR */cm* OR */cx* OR */pixel* OR */match* OR */visit.js* OR */load* OR */push* OR */ptj* OR */j.ad* OR */ga.js* OR */en_US/all.js* OR */activity* OR */IE9CompatViewList.xml* OR */submit.php*)
| dedup uri_path
| transaction dest_ip
| table dest_ip, src_ip, uri_path, user_agent
```

Reference:
- [Cobalt Strike Analysis and Tutorial: How Malleable C2 Profiles Make Cobalt Strike Difficult to Detect](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/)