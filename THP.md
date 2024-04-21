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

**Beaconing Detection**
```
index="cobaltstrike_beacon" sourcetype="bro:http:json" 192.168.151.181
| transaction user_agent
| table uri_path, user_agent, src_ip, dest_ip
```
**Beacon - URI Path**
```
index=* (uri_path=*/ca* OR */dpixel* OR */__utm.gif* OR */pixel.gif* OR */g.pixel* OR */dot.gif* OR */updates.rss* OR */fwlink* OR */cm* OR */cx* OR */pixel* OR */match* OR */visit.js* OR */load* OR */push* OR */ptj* OR */j.ad* OR */ga.js* OR */en_US/all.js* OR */activity* OR */IE9CompatViewList.xml* OR */submit.php*)
| dedup uri_path
| transaction dest_ip
| table dest_ip, src_ip, uri_path, user_agent
```
**Beaconing - Time Interval**
```
index="cobaltstrike_beacon" sourcetype="bro:http:json" dest=192.168.151.181 src=10.0.10.20
| timechart count
OR
index="cobaltstrike_beacon" sourcetype="bro:http:json" dest=192.168.151.181 src=10.0.10.20
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| convert ctime(prevtime)
| stats count by _time, prevtime, timedelta
```
**Beaconing - Response Byte**
```
index="cobaltstrike_beacon" sourcetype="bro:conn:json" dest=192.168.151.181 src=10.0.10.100
| stats count by _time, resp_bytes
| fields - count
OR
index="cobaltstrike_beacon" sourcetype="bro:conn:json" dest=192.168.151.181 src=10.0.10.100
| stats count by _time, resp_bytes, src_ip, dest_ip
| transaction resp_bytes
| fields - count
```

Reference:
- [Cobalt Strike Analysis and Tutorial: How Malleable C2 Profiles Make Cobalt Strike Difficult to Detect](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/)

## Reconnaissance: Network Scanning
`Field of Interest:`
- source=`*conn.log`
- dest_port
- dest_ip
- src_ip
- _time

**General Checking of Destiantion Port**
```
source=*conn.log
| transaction dest_port, dest_ip
| dedup dest_port, dest_ip
| table dest_port, dest_ip, src_ip, _time
```
**Basic Scanning**
```
source=*conn.log
| bin span=5m _time
| transaction dest_ip, src_ip
| eval total_dsrprt=mvcount(dest_port)
| where total_dsrprt >= 1000
| table total_dsrprt, dest_ip, src_ip
```
```
source=*conn.log
| bin span=5m _time
| stats dc(dest_port) as num_dest_port, values(dest_ip) as dest_ip by _time, src_ip
| where num_dest_port >= 1000
```
NMAP scan was successfully detected, but there are couple things which should be taken into
consideration:
- Threshold for unique destination ports is more or equal than 1000. From our observations, when
adversaries get initial access, they hunt for specific ports like SMB or RDP, up to 10 ports at a time.
- Other IPs were marked as scanned, beside the one scanned by NMAP.

**Successful Scanning of OpenPort**
```
source=*conn.log
| bin span=5m _time
| transaction dest_ip, src_ip
| eval total_dsrprt=mvcount(dest_port)
| where total_dsrprt >= 1000
| table total_dsrprt, dest_ip, src_ip
```
```
source=*conn.log orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0./12, 10.0.0.0/8)
| bin span=5m _time
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip
| where num_dest_port >= 1000
```

During port scanning NMAP is trying to establish TCP handshake on each port and if it is successful it means the port is open. Also remote service can return its banner, so in that case NMAP will get some data back, but the amount of data NMAP sends to the scanning port is always the same and it's zero (beside TCP handshake itself). Unless we care about external connections they can be excluded to reduce false-positive rate.

## Reconnaissance: DCE/RRC SMB Share Enumeration
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- id.orig_h
- id.resp_h
- id.resp_p=`445`
- endpoint
- operation
- _time


```
sourcetype="bro:dce_rpc:json" 
| transaction endpoint
| table _time, id.orig_h, , id.resp_h, id.resp_p, endpoint, operation
```
```
sourcetype="bro:dce_rpc:json" operation=NetrShareEnum endpoint=srvsvc
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
`operation=NetrShareEnum`: This filter narrows down the events to those where the operation field equals `NetrShareEnum`. The `NetrShareEnum` operation is part of the Server Service (often referred to as srvsvc), which can be used to retrieve a list of shared resources on a system. Monitoring this operation is crucial because attackers could use it to gain information about network shares as a part of reconnaissance activities.

## Credential Access: Kerberos Bruteforce Detection
`Field of Interest:`
- sourcetype=`bro:kerberos:json` or `kerberos.log`
- client
- error_msg
- id.orig_h
- id.resp_h
- request_type=`AS`
- _time

**Kerberos Bruteforce Detection**
```
sourcetype="bro:kerberos:json"
success="false" request_type=AS
| stats count as attempts, dc(client) as total_clients, values(error_msg) as error_messages by id.orig_h, id.resp_h
| table id.orig_h, id.resp_h, attempts, total_clients, error_messages
| where attempts>30
```
```
sourcetype="bro:kerberos:json" 
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Client" values(error_msg) by _time, id.orig_h, id.resp_h
| where count>30
```

Kerberos requests
- AS-REQ = User presents password, gets TGT
- TGS-REQ = User presents TGT, gets Service Ticket

No. Abbreviation Function
- 10 AS-REQ Request Ticket-Granting Ticket
- 11 AS-REP Ticket-Granting Ticket
- 12 TGS-REQ Request Service Ticket
- 13 TGS-REP Service Ticket
- 30 KRB-ERROR error

[MIT Kerberos Documentation - Encryption types](https://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html#:~:text=Kerberos%20can%20use%20a%20variety,confidentiality%20and%20integrity%20to%20data.)


## Credential Access: Kerberoasting Detection
`Field of Interest:`
- sourcetype=`bro:kerberos:json` or `kerberos.log`
- client
- service
- id.orig_h
- id.resp_h
- request_type=`TGS`
- cipher=`"rc4-hmac"`
- forwardable=`"true"`
- renewable=`"true"`
- _time

```
sourcetype="bro:kerberos:json" request_type=TGS cipher="rc4-hmac" forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
```
This query is valuable for security monitoring and auditing within environments that use Kerberos for authentication. 
- `cipher="rc4-hmac"`: This is significant because while RC4-HMAC was once common, it is now considered less secure than newer encryption types like AES. Monitoring its usage can help identify older or potentially insecure configurations.
- `forwardable="true"`: Forwardable tickets allow the client (or an intermediary on behalf of the client) to request additional TGS tickets to different services on behalf of the user, increasing flexibility but also potentially increasing security risk if misused.
- `renewable="true"`: Renewable tickets can be renewed without the client needing to re-authenticate using their password, which is useful for long-running jobs or services.


## Credential Access: Kerberoasting Detection
`Field of Interest:`
- sourcetype=`bro:kerberos:json` or `kerberos.log`
- client
- id.orig_h
- id.resp_h
- request_type=`TGS`
- _time

```
sourcetype="bro:kerberos:json"
| where client!="_"
| bin _time span=1m
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
| where request_types=="TGS" AND unique_request_types==1
```
Potential Golden Ticket attacks by focusing on unusual TGS request patterns within Kerberos logs
[detect_kerberos_attacks.sh](https://github.com/exp0se/detect_kerberos_attacks/blob/master/detect_kerberos_attacks.sh)

## Credential Access: DCSync Attack Detection
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- endpoint
- operation
- id.orig_h
- id.resp_h
- operation=`DRSGetNCChanges`
- _time

```
sourcetype="bro:dce_rpc:json" operation=DRSGetNCChanges
| transaction endpoint
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
Extract and analyze logs related to a specific DCE/RPC operation, specifically `DRSGetNCChanges`, which is crucial in Active Directory environments for replication of directory changes.

`operation=DRSGetNCChanges`: This filter restricts the logs to those where the operation field is set to `DRSGetNCChanges`. This operation is significant in the context of Windows Server Active Directory as it is used by domain controllers to replicate directory objects and changes. In security monitoring, watching this operation is critical because unauthorized or malicious replication requests can indicate attempts at creating backdoors or extracting sensitive directory information.

## Lateral Movement
Lateral movement attacks
Exploitation of Remote Services
- Zerologon
- Print Nightmare

Remote Services
- RDP
- SMB
- DCOM
- SSH
- VNC
- WinRM

Use Alternate Authentication Material
- Pass-the-hash
- Pass-the-ticket

## Lateral Movement: PSExec CobaltStrike Execution Detection
`Field of Interest:`
- sourcetype=`bro:smb_files:json` or `smb_files.log`
- name=`"*.exe"`, `"*.dll"`, `"*.bat"`
- path=`"*\\c$"`, `"*\\ADMIN$"`
- id.orig_h
- id.resp_h
- _time


```
index="cobalt_strike_psexec"
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
```
```
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
| transaction name
| table name, path, action id.orig_h,  id.resp_h, id.resp_p
```
Check for SMB (Server Message Block) file access events, specifically focusing on potentially sensitive or executable file types within high-risk administrative shares

## Lateral Movement: Fileless PSExec Execution (SharpNoPSExec) using Service Creation
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`"CreateServiceW"`, `"CreateServiceA"`, `"StartServicew"`, `"StartServiceA"`,
`"ChangeServiceConfigW"`
- endpoint
- operation
- id.orig_h
- id.resp_h
- _time

```
sourcetype="bro:dce_rpc:json"
operation IN ("CreateServiceW", "CreateServiceA", "StartServicew", "StartServiceA",
"ChangeServiceConfigW")
| transaction endpoint
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
```
index="change_service_config" endpoint=svcctl sourcetype="bro:dce_rpc:json"
operation IN ("CreateServiceW", "CreateServiceA", "StartServicew", "StartServiceA",
"ChangeServiceConfigW")
| transaction endpoint
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
Analyze and monitor specific DCE/RPC activities related to service control operations in Windows environments
- Unauthorized or malicious service creation or modification, which could be part of an attacker's efforts to establish persistence or escalate privileges on a system.
- Start of services that may be unusual or unauthorized, potentially indicating that an attacker is activating malicious services designed to perform harmful actions.

[SharpNoPSExec - File less command execution for lateral movement](https://github.com/juliourena/SharpNoPSExec/blob/master/SharpNoPSExec/Program.cs)

## Lateral Movement: Possible ZeroLogon Activity Detection 
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`"NetrServerReqChallenge"` OR `"NetrServerAuthenticate3"` OR `"NetrServerPasswordSet2"`
- endpoint
- id.orig_h
- id.resp_h
- _time

```
endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| transaction endpoint
| table endpoint, operation _time, id.orig_h, id.resp_h
```
```
index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| stats count values(operation) as operation values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100
```

Firstly, the vulnerability is exploited by sending specially crafted `NetrServerReqChallenge`, `NetrServerAuthenticate3` and `NetrServerPasswordSet2` DCERPC requests to initially bind to and use the NETLOGON interface. This is followed by sending specific Opnum like 2, 26 and 30 to set the domain controller password to NULL. Filters the events to only include those related to three specific Netlogon operations:
- `NetrServerReqChallenge`: Part of the authentication sequence where the server challenges the client to prove its identity.
- `NetrServerAuthenticate3`: Used for establishing a secure channel and authenticating clients and servers in the domain.
- `NetrServerPasswordSet2`: Used to change the machine account password, which if done maliciously, can disrupt domain communications or facilitate unauthorized access.

[Network Threat Hunting for Zerologon Exploits (CVE-2020-1472)](https://arista.my.site.com/AristaCommunity/s/article/Network-Threat-Hunting-for-Zerologon-Exploits-CVE-2020-1472)

## Lateral Movement: Print Spooler Activity Detection 
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`RpcAddPrinterDriverEx`
- endpoint
- id.orig_h
- id.resp_h
- _time

```
sourcetype="bro:dce_rpc:json" operation=RpcAddPrinterDriverEx OR operation=RpcEnumPrinterDrivers
| transaction endpoint
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
```
index="printnightmare" endpoint=spoolss operation=RpcAddPrinterDriverEx OR operation=RpcEnumPrinterDrivers
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

Heuristics are simple check for PrintNightmare:
- \pipe\spoolss in named_pipe
- spoolss in endpoint
- RpcEnumPrinterDrivers OR RpcAddPrinterDriverEx in operation

Reference:
- [Simple policy to detect CVE-2021-1675](https://github.com/initconf/cve-2021-1675-printnightmare)
- [PrintNightmare (CVE-2021-1675)](https://community.netwitness.com/t5/netwitness-community-blog/printnightmare-cve-2021-1675/ba-p/625335)


## Lateral Movement: DCOM Execution Detection 
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`RpcAddPrinterDriverEx`
- endpoint
- id.orig_h
- id.resp_h
- _time


```
sourcetype="bro:dce_rpc:json" endpoint=IDispatch 
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
```
sourcetype="*bro:dce_rpc:json*" endpoint=IDispatch
| transaction id.orig_h
| table operation, id.orig_h, id.resp_h, endpoint, _time
```

- `endpoint=IDispatch`: This filter targets log entries where the endpoint involved is IDispatch. IDispatch is a part of the Component Object Model (COM) in Microsoft Windows, which enables an application to call functions of objects implemented in other applications or (often) remote processes. The use of `IDispatch` can be particularly interesting from a security perspective because it could be used in methods involving automation, remote procedure calls, or interacting with processes across different security contexts.

[LATERAL MOVEMENT VIA DCOM: ROUND 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

## Exfiltration: CobaltStrike Data Exfiltration
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`RpcAddPrinterDriverEx`
- endpoint
- id.orig_h
- id.resp_h
- _time


Cobalt Strike data exfiltration detection steps
1. Filter out check-in beacon data
2. In case of HTTP beacons, they are using GET requests, so we can just look for POST requests
payload data (packet content without HTTP header).
3. In case of HTTPS beaconing you need to find this value statistically and filter it out manually.

**CobaltStrike data exfiltration using HTTP Beacon**
```
sourcetype="bro:http:json" method=POST dest_ip=192.168.151.181
| stats sum(request_body_len) as TB by src, dest, dest_port
| eval TB = TB/1024/1024
```
Converts the total bytes into megabytes for easier interpretation

**CobaltStrike HTTPS - Find Beacon**
```
index="cobaltstrike_exfiltration_https"sourcetype="bro:conn:json"
| eventstats count as total by src, dest, dest_port
| stats count by src, dest, dest_port, total, resp_bytes
| eval percent = (count/total)*100
| where percent > 70 AND total > 50
| table percent, total, src, dest, dest_port, dest_port, resp_bytesB by src, dest, dest_port
```
OR
```
index="cobaltstrike_exfiltration_https" sourcetype="bro:conn:json"
| eventstats count as total by src, dest, dest_port
| stats count by src, dest, dest_port, total, resp_bytes
| eval percent = (count/total)*100
| where percent > 70 AND total > 50
| table percent, total, src, dest, dest_port, dest_port, resp_bytes
```
**CobaltStrike HTTPS - Filter-out Beacon**
```
index="cobaltstrike_exfiltration_https" sourcetype="bro:conn:json" resp_bytes!=316 dest=192.168.151.181 dest_port=443
| stats sum(orig_bytes) as TB by src, dest, dest_port
| eval TB = TB/1024/1024
```

## Exfiltration: CobaltStrike Data Exfiltration - Data Transfer Size Limit
```
index="exfiltration_data_size_limits" sourcetype="bro:conn:json"
| bin span=1m time
| rename id.origin_host as src_ip, id.resp_host as dest_ip, id.resp_p as dest_port, orig_ip_bytes as bytes_out
| stats count by _time, bytes_out
```

## Exfiltration: DNS Exfiltration
`Field of Interest:`
- sourcetype=`bro:dns:json` or `dns.log`
- query
- id.orig_h
- id.resp_h
- _time

**Timechart DNS**
```
sourcetype="bro:dns:json" blue.letsgohunt.online
| timechart span=1s count by dest_ip
```
**Average Length of the Subdomain**
```
sourcetype="bro:dns:json" "blue.letsgohunt.online"
| eval query=mvdedup(query)
| rex field=query "(?<ut_identifier>(?:\w+\.)+)(?<ut_subdomain>[^\.]+[^\.]+)\.(?<ut_domain>[^\.]+\.[^\.]+)$"
| eval sublen = len(ut_identifier)
| table ut_identifier ut_subdomain ut_domain sublen
```
**Unusual Long Subdomain**
```
sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="* amazonaws.com *" AND query!="*._google cast.*" AND query!="_ldap.*"
| stats count(query) as req_by_day by id.orig_h, id.resp_h
| sort - req_by_day
```
```
sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="* amazonaws.com *" AND query!="*._google cast.*" AND query!="_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h
| where req_by_day>60
| table _time, id.orig_h, id.resp_h, req_by_day
```

## Impact: Encryption - **Ransomware behavior 1**
- Start
- Enumerate files
- Read file(read file content) - `SMB:: FILE_OPEN`
- Encrypt file (encryption in memory)
- Write file (Write encrypted data to a file) - `SMB: FILE_RENAME`
- The same file

```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```


## Impact: Encryption - **Ransomware behavior 2**
- Start
- Enumerate files
- Read file (read file content)
- Delete original file
- Encrypt file (encryption in memory)
- Write new file (Write encrypted data to a file)

```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```
```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
| bin _time span=5m
```

## Impact: Encryption - **Ransomware behavior 3**

Ransomware behavior 3
- Start
- Enumerate files
- Read file (read file content) `SMB::FILE_OPEN`
- Encrypt file (encryption in memory)
- Write file with specific extension (Write encrypted data) `SMB::FILE_RENAME`

```
sourcetype="bro:smb_files:json" action="SMB::FILE_RENAME"
| bin _time span=5m
| rex field="name" "\.(?<new_file_name_extension>[^\.]*$)"
| rex field="prev_name" "\.(?<old_file_name_extension>[^\.]*$)"
| stats count by _time, id.orig_h, id.resp_p, name, source, old_file_name_extension, new_file_name_extension
| where new_file_name_extension!=old_file_name_extension
| stats count by _time, id.orig_h, id.resp_p, source, new_file_name_extension
| where count>20
| sort - count
```
**Check for Unique FileExtension**
```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_RENAME")
| eval base_length = len(prev_name)
| eval new_extension = substr(name, base_length + 1)
| where isnotnull(new_extension) AND new_extension != ""
| stats count by new_extension, src_ip, dest_ip
| sort - count
| table new_extension, count, src_ip, dest_ip
```
```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| rex field=name "^(?<base_file>.*?)(?:\.(?<extension>[^\.]+))?$"
| stats values(base_file) as filenames by extension, src_ip, dest_ip
| sort - count(filenames)
| table extension, filenames, src_ip, dest_ip
```